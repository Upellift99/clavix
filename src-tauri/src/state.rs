use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use rsa::RsaPrivateKey;

use crate::api::VaultwardenClient;
use crate::crypto::SymmetricKey;
use crate::models::{SyncResponse, TokenSet};
use crate::ssh_agent::SshAgentHandle;

#[derive(Default)]
pub struct AppState {
    pub session: Mutex<Option<Session>>,
    pub ssh_agent: Mutex<Option<SshAgentHandle>>,
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
