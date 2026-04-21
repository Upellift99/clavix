use std::collections::HashMap;
use std::time::Instant;

use parking_lot::Mutex;
use rsa::RsaPrivateKey;

use crate::api::VaultwardenClient;
use crate::crypto::SymmetricKey;
use crate::models::{SyncResponse, TokenSet};
use crate::ssh_agent::SshAgentHandle;

pub struct AppState {
    pub session: Mutex<Option<Session>>,
    pub ssh_agent: Mutex<Option<SshAgentHandle>>,
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
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            ssh_agent: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            auto_lock_minutes: Mutex::new(None),
        }
    }
}

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
