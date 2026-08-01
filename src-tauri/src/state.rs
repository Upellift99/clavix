use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::ssh_agent::SshAgentHandle;
// `Session` and `PendingTwoFactor` moved to `clavix_core::session` — they
// are vault state, not desktop state, and a second front end needs them
// as much as this one does. `AppState` below is what stays: the tray
// flags, the SSH agent, the auto-lock bookkeeping.
use clavix_core::session::{PendingTwoFactor, Session};

/// What starts the auto-lock countdown. Crosses the IPC boundary, so the
/// TypeScript union in `src/lib/generated/AutoLockTrigger.ts` is generated
/// from this — don't hand-mirror it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum AutoLockTrigger {
    /// Never auto-lock. The user's explicit "Jamais".
    Off,
    /// Time since the last sign of the user: mouse / keyboard in the
    /// WebView, or a session-touching command reaching `mark_activity`.
    Idle,
    /// Time since the *desktop session* locked, as reported by
    /// `screen_lock::probe`. Unlike `Idle` this ignores the renderer
    /// entirely — the screen being locked is the signal.
    ScreenLock,
}

/// The auto-lock configuration as a unit, because the two fields are only
/// meaningful together: `minutes` is a delay measured from whatever
/// `trigger` names, and `0` means "immediately" for `ScreenLock` while it
/// means "disabled" for `Idle`. Keeping them in one mutex also makes the
/// watchdog's read atomic — it can't observe a new trigger with the old
/// delay mid-update.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AutoLockSetting {
    pub trigger: AutoLockTrigger,
    /// Stored as `f64` to accommodate the sub-minute values the E2E suite
    /// seeds through localStorage; the production UI only ever writes
    /// non-negative integers.
    pub minutes: f64,
}

impl Default for AutoLockSetting {
    /// Inert until the renderer pushes the user's real preference on
    /// bootstrap — same as the old `auto_lock_minutes: None`. Defaulting
    /// to a live window here would lock vaults on a config the user
    /// never chose.
    fn default() -> Self {
        Self {
            trigger: AutoLockTrigger::Off,
            minutes: 0.0,
        }
    }
}

pub struct AppState {
    pub session: Mutex<Option<Session>>,
    pub ssh_agent: Mutex<Option<SshAgentHandle>>,
    /// In-flight SSH-agent signature confirmations, keyed by request id.
    /// The agent task parks a `oneshot::Sender` here and awaits the
    /// answer; `respond_ssh_agent_confirm` (driven by the confirmation
    /// dialog) removes and fulfils it. Entries are also dropped on
    /// timeout inside the agent's confirm callback.
    pub ssh_confirms: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<bool>>>,
    /// Monotonic id source for `ssh_confirms` requests.
    pub ssh_confirm_seq: Mutex<u64>,
    /// Keys the last agent start could not load, with the reason for each.
    /// Kept here rather than on `SshAgentHandle` because it describes the
    /// vault-to-agent load, not the running agent — and because it must
    /// outlive a failed start, where no handle exists at all. Lets
    /// `ssh_agent_status` explain a key count that looks short, instead of
    /// the explanation being visible only in the `start_ssh_agent` reply.
    pub ssh_skipped: Mutex<Vec<crate::commands::ssh::SkippedKey>>,
    /// Last user-driven activity (command invocation that touches the
    /// session). Updated by `mark_activity`. Backs the auto-lock watchdog
    /// spawned in `run()` — backend safety net so a frozen WebView or a
    /// disabled JS timer can't keep the vault unlocked indefinitely.
    pub last_activity: Mutex<Instant>,
    /// What arms the auto-lock watchdog and after how long. The frontend
    /// keeps this in sync via the `set_auto_lock` command; the watchdog
    /// spawned in `auto_lock::spawn` is the only reader.
    pub auto_lock: Mutex<AutoLockSetting>,
    /// When the desktop session was first *observed* locked, or `None`
    /// while it is unlocked (or while the screen-lock trigger is off, or
    /// while the platform can't tell us). Maintained exclusively by the
    /// poller in `auto_lock` from `screen_lock::probe` — deliberately not
    /// by `mark_activity`, because `totp_code` is polled once a second by
    /// the renderer and would otherwise clear this on a locked screen.
    pub screen_locked_since: Mutex<Option<Instant>>,
    /// Login that returned `TwoFactorRequired` parks its derived material
    /// here while the user reaches for their hardware key / authenticator.
    /// `webauthn_sign_challenge` and `login_with_two_factor` read from
    /// this slot rather than from JS-passed arguments — without this the
    /// renderer could swap the rpId anchor or the master key between the
    /// two IPC calls. Cleared on success, on auth failure, on
    /// `cancel_two_factor`, and after the TTL elapses.
    pub pending_2fa: Mutex<Option<PendingTwoFactor>>,
    /// Mirrors the renderer's `prefs.closeToTray`. Read by the
    /// `WindowEvent::CloseRequested` handler in `lib.rs::run` to
    /// decide whether the X button hides the window into the tray
    /// (true, default) or quits the process (false). An atomic so
    /// the window-event handler can read it without taking a mutex
    /// — close events fire on the main loop and any contention here
    /// would block UI input. Updated through
    /// `commands::tray::set_close_to_tray`.
    pub close_to_tray: AtomicBool,
    /// Same shape as `close_to_tray` but for the `_` minimise
    /// button: when true (default), a minimise transition is
    /// converted to a hide-into-tray. When false, the window goes
    /// to the taskbar like any other app. Read by the
    /// `WindowEvent::Resized` handler.
    pub minimize_to_tray: AtomicBool,
    /// Whether to also drop the dock / taskbar entry when the
    /// window is hidden into the tray. When true, the tray-hide
    /// path adds `set_skip_taskbar(true)` so GNOME / KDE / Windows
    /// drop the icon from the dock too — keeping only the tray
    /// icon as the visible affordance. The `raise_main_window`
    /// path clears the flag when the window comes back. Off by
    /// default on every platform: removing the dock entry surprises
    /// people who expect their app to always be there. Updated
    /// through `commands::tray::set_hide_dock_on_tray`.
    pub hide_dock_on_tray: AtomicBool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            ssh_agent: Mutex::new(None),
            ssh_confirms: Mutex::new(HashMap::new()),
            ssh_confirm_seq: Mutex::new(0),
            ssh_skipped: Mutex::new(Vec::new()),
            last_activity: Mutex::new(Instant::now()),
            auto_lock: Mutex::new(AutoLockSetting::default()),
            screen_locked_since: Mutex::new(None),
            pending_2fa: Mutex::new(None),
            // Hide-to-tray by default on Windows/macOS (KeePassXC,
            // Bitwarden Desktop shape), but off on Linux: GNOME ships
            // tray support behind an extension whose runtime state is
            // unreliable (ubuntu-appindicators is enabled-but-inactive
            // on a stock Ubuntu session, and Wayland restricts SNI
            // further). Defaulting to hide on Linux strands users with
            // an invisible window and no way back. The renderer
            // overwrites this from localStorage on bootstrap.
            close_to_tray: AtomicBool::new(!cfg!(target_os = "linux")),
            minimize_to_tray: AtomicBool::new(!cfg!(target_os = "linux")),
            hide_dock_on_tray: AtomicBool::new(false),
        }
    }
}

/// Bumps `last_activity` to now. Cheap; called at the start of any command
/// that proves the user is still around (sync, decrypt, refresh, etc).
///
/// Only ever call this from a command that follows a *discrete* user action.
/// Never from one the renderer polls on a timer: `totp_code` used to call it,
/// and since the TOTP field re-reads the code once a second, one visible TOTP
/// item was enough to keep this timestamp fresh forever and stop the auto-lock
/// watchdog from ever firing. A poll proves a timer is running, not that
/// anyone is there.
pub fn mark_activity(state: &AppState) {
    *state.last_activity.lock() = Instant::now();
}
