use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use parking_lot::Mutex;
use rsa::RsaPrivateKey;
use zeroize::ZeroizeOnDrop;

use crate::api::VaultwardenClient;
use crate::crypto::{MasterKey, MasterPasswordHash, SymmetricKey};
use crate::models::{Prelogin, SyncResponse, TokenSet};
use crate::ssh_agent::SshAgentHandle;

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
    /// `Some(n)` enables the auto-lock watchdog with an `n`-minute idle
    /// window. `None` disables it. Stored as `f64` to accommodate
    /// sub-minute values written by the E2E suite via localStorage; the
    /// production UI only ever writes positive integers. The frontend
    /// keeps this in sync via the `set_auto_lock_minutes` command.
    pub auto_lock_minutes: Mutex<Option<f64>>,
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
            auto_lock_minutes: Mutex::new(None),
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

/// Material derived during the `login` step that has to survive until
/// the user completes the second factor. Living here rather than being
/// re-derived on `login_with_two_factor` saves an Argon2id round (~1 s
/// on hardened settings), but the security win is the headline: the
/// rpId anchor used by `webauthn_sign_challenge` is now sourced from
/// here, not from a JS argument that a compromised renderer could
/// rewrite between calls.
#[derive(ZeroizeOnDrop)]
pub struct PendingTwoFactor {
    #[zeroize(skip)]
    pub server_url: String,
    #[zeroize(skip)]
    pub email: String,
    pub master_key: MasterKey,
    pub password_hash: MasterPasswordHash,
    #[zeroize(skip)]
    pub prelogin: Prelogin,
    #[zeroize(skip)]
    pub client: VaultwardenClient,
    /// Wall-clock instant the slot was opened. Anything older than the
    /// TTL is treated as expired by `take_pending_two_factor`.
    #[zeroize(skip)]
    pub created_at: Instant,
}

/// How long a `PendingTwoFactor` slot stays valid. Long enough that a
/// user can fish their YubiKey out of a bag and tap it; short enough
/// that a forgotten slot doesn't accumulate keying material in memory
/// indefinitely.
pub const PENDING_2FA_TTL_SECS: u64 = 300;

/// Bumps `last_activity` to now. Cheap; called at the start of any command
/// that proves the user is still around (sync, decrypt, refresh, etc).
pub fn mark_activity(state: &AppState) {
    *state.last_activity.lock() = Instant::now();
}

pub struct Session {
    pub client: VaultwardenClient,
    pub tokens: TokenSet,
    /// Wall-clock deadline after which `tokens.access_token` must be refreshed.
    /// Computed from `tokens.expires_in` at the time the token was issued,
    /// with a 30-second safety margin so we refresh slightly before the
    /// server considers the token dead.
    pub expires_at: Instant,
    pub user_key: SymmetricKey,
    pub private_key: Option<RsaPrivateKey>,
    pub org_keys: HashMap<String, SymmetricKey>,
    pub vault: Option<SyncResponse>,
}
