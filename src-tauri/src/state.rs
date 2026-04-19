use std::collections::HashMap;
use std::sync::Mutex;

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
    pub user_key: SymmetricKey,
    pub private_key: Option<RsaPrivateKey>,
    pub org_keys: HashMap<String, SymmetricKey>,
    pub vault: Option<SyncResponse>,
}
