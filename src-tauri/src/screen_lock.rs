//! Screen-lock ("session lock") detection — one thin probe per platform.
//!
//! Backs the `screenLock` auto-lock trigger: the vault drops N minutes
//! after the *desktop session* locks, rather than after N minutes of
//! inactivity. The distinction matters because the two signals disagree
//! in both directions — someone reading a long document is idle but
//! present, and someone who locked their screen and left the building
//! is "active" as far as the WebView is concerned the moment a TOTP
//! field keeps polling in the background.
//!
//! The shape here is deliberately a **poll**, not a subscription. Each
//! platform exposes an event source (D-Bus signals, WM_WTSSESSION_CHANGE,
//! NSDistributedNotificationCenter), but each one also needs its own
//! long-lived listener plumbing — a signal stream, a message-only window
//! with its own message loop, an Objective-C observer. A `probe()` that
//! answers "locked right now?" is the same answer with a fraction of the
//! platform surface, and the caller already runs a timer. The cost is
//! bounded imprecision: `auto_lock::SCREEN_POLL_PERIOD` (5 s), which is
//! noise next to the minute-granularity delays the UI offers.
//!
//! `None` means "this platform/session can't tell us" — never guess
//! `false` there. A wrong `false` silently disables the whole trigger;
//! the caller surfaces `None` to the UI instead (see
//! `commands::auth::screen_lock_available`).

/// `Some(true)` locked, `Some(false)` unlocked, `None` when the platform
/// can't answer (no D-Bus screensaver service, no GUI session, unsupported
/// OS). Cheap enough to call every few seconds.
pub async fn probe() -> Option<bool> {
    imp::probe().await
}

#[cfg(target_os = "linux")]
mod imp {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;

    use tokio::sync::OnceCell;
    use zbus::Connection;

    /// Ceiling on a single D-Bus round-trip. A screensaver service that
    /// hangs must not wedge the auto-lock poller — we'd rather report
    /// `None` for one tick and try again on the next.
    const CALL_TIMEOUT: Duration = Duration::from_secs(2);

    static SESSION_BUS: OnceCell<Connection> = OnceCell::const_new();
    static SYSTEM_BUS: OnceCell<Connection> = OnceCell::const_new();

    /// Which backend answered last time, so a KDE or logind-only session
    /// doesn't pay for two failing calls every 5 s. `0` = not yet known,
    /// otherwise the `Backend` discriminant + 1.
    static LAST_GOOD: AtomicU8 = AtomicU8::new(0);

    #[derive(Clone, Copy)]
    enum Backend {
        /// GNOME, and anything else shipping gnome-shell's screensaver.
        Gnome,
        /// The cross-desktop name: KDE (ksmserver), XFCE, Cinnamon, MATE
        /// all own it, as does gnome-shell.
        Freedesktop,
        /// systemd-logind's `LockedHint`. Last because it reflects what
        /// something *told* logind (`loginctl lock-session`), which some
        /// screensavers never do — but it's the only answer on a session
        /// with no screensaver D-Bus name at all.
        Logind,
    }

    const BACKENDS: [Backend; 3] = [Backend::Gnome, Backend::Freedesktop, Backend::Logind];

    impl Backend {
        fn tag(self) -> u8 {
            match self {
                Backend::Gnome => 1,
                Backend::Freedesktop => 2,
                Backend::Logind => 3,
            }
        }

        fn from_tag(tag: u8) -> Option<Self> {
            match tag {
                1 => Some(Backend::Gnome),
                2 => Some(Backend::Freedesktop),
                3 => Some(Backend::Logind),
                _ => None,
            }
        }
    }

    pub async fn probe() -> Option<bool> {
        // Re-try the backend that worked last, then everything else. The
        // order only matters for cost: all three answer the same question.
        if let Some(known) = Backend::from_tag(LAST_GOOD.load(Ordering::Relaxed)) {
            if let Some(locked) = query(known).await {
                return Some(locked);
            }
        }
        for backend in BACKENDS {
            if let Some(locked) = query(backend).await {
                LAST_GOOD.store(backend.tag(), Ordering::Relaxed);
                return Some(locked);
            }
        }
        LAST_GOOD.store(0, Ordering::Relaxed);
        None
    }

    async fn query(backend: Backend) -> Option<bool> {
        match backend {
            Backend::Gnome => {
                screensaver_active("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver").await
            }
            Backend::Freedesktop => {
                screensaver_active(
                    "org.freedesktop.ScreenSaver",
                    "/org/freedesktop/ScreenSaver",
                )
                .await
            }
            Backend::Logind => logind_locked_hint().await,
        }
    }

    /// `<iface>.GetActive` on the session bus. The interface name matches
    /// the well-known name for both screensaver flavours.
    async fn screensaver_active(name: &str, path: &str) -> Option<bool> {
        let conn = SESSION_BUS
            .get_or_try_init(Connection::session)
            .await
            .ok()?;
        let reply = tokio::time::timeout(
            CALL_TIMEOUT,
            conn.call_method(Some(name), path, Some(name), "GetActive", &()),
        )
        .await
        .ok()?
        .ok()?;
        reply.body().deserialize::<bool>().ok()
    }

    /// `LockedHint` on the caller's own logind session. `session/auto`
    /// is logind's alias for "the session this process belongs to", so
    /// we don't have to resolve an id out of `XDG_SESSION_ID`.
    async fn logind_locked_hint() -> Option<bool> {
        let conn = SYSTEM_BUS.get_or_try_init(Connection::system).await.ok()?;
        let reply = tokio::time::timeout(
            CALL_TIMEOUT,
            conn.call_method(
                Some("org.freedesktop.login1"),
                "/org/freedesktop/login1/session/auto",
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.login1.Session", "LockedHint"),
            ),
        )
        .await
        .ok()?
        .ok()?;
        let value: zbus::zvariant::OwnedValue = reply.body().deserialize().ok()?;
        bool::try_from(value).ok()
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_READOBJECTS, UOI_NAME,
    };

    /// The desktop that owns the input when nothing is locked. A locked
    /// workstation switches input to `Winlogon`; `OpenInputDesktop` then
    /// fails outright for a non-elevated process, which is the case we
    /// hit in practice.
    const DEFAULT_DESKTOP: &str = "Default";

    pub async fn probe() -> Option<bool> {
        Some(locked())
    }

    /// Reads the *input* desktop rather than subscribing to session
    /// notifications: no message-only window, no message loop, no
    /// wndproc grafted onto Tauri's window.
    ///
    /// Note this also reports `true` while a UAC consent prompt is up —
    /// that's the secure desktop, same mechanism. Harmless: a delayed
    /// trigger just restarts its countdown when the prompt closes, and
    /// an immediate one errs toward locking the vault.
    fn locked() -> bool {
        // SAFETY: `OpenInputDesktop` returns either null or a handle we
        // own; every path below closes it exactly once, and the name
        // buffer we hand to `GetUserObjectInformationW` is sized in
        // bytes as the API expects.
        unsafe {
            let desktop = OpenInputDesktop(0, 0, DESKTOP_READOBJECTS);
            if desktop.is_null() {
                return true;
            }
            let mut name = [0u16; 256];
            let mut needed: u32 = 0;
            let ok = GetUserObjectInformationW(
                desktop,
                UOI_NAME,
                name.as_mut_ptr().cast(),
                std::mem::size_of_val(&name) as u32,
                &mut needed,
            );
            CloseDesktop(desktop);
            if ok == 0 {
                // We could open the input desktop but not name it. It's
                // reachable, so treat the session as unlocked rather
                // than locking the vault on a permissions quirk.
                return false;
            }
            let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            !String::from_utf16_lossy(&name[..len]).eq_ignore_ascii_case(DEFAULT_DESKTOP)
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    /// Present and true only while the screen is locked. Absent entirely
    /// when it isn't — hence `Some(false)` on a lookup miss, not `None`.
    const LOCKED_KEY: &str = "CGSSessionScreenIsLocked";

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        /// Null when the process has no GUI session to describe (ssh,
        /// launchd daemon), which is exactly our `None`.
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    pub async fn probe() -> Option<bool> {
        // SAFETY: the Copy-rule return is either null (checked) or a
        // +1-retained dictionary handed straight to `wrap_under_create_rule`,
        // which takes ownership of that reference.
        let dict: CFDictionary<CFString, CFType> = unsafe {
            let raw = CGSessionCopyCurrentDictionary();
            if raw.is_null() {
                return None;
            }
            CFDictionary::wrap_under_create_rule(raw)
        };
        let Some(value) = dict.find(CFString::new(LOCKED_KEY)) else {
            return Some(false);
        };
        Some(
            value
                .downcast::<CFBoolean>()
                .map(bool::from)
                .unwrap_or(false),
        )
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod imp {
    pub async fn probe() -> Option<bool> {
        None
    }
}
