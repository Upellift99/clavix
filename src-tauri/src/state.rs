use std::sync::Mutex;

use crate::api::VaultwardenClient;
use crate::models::{SyncResponse, TokenSet};

#[derive(Default)]
pub struct AppState {
    pub session: Mutex<Option<Session>>,
}

pub struct Session {
    pub client: VaultwardenClient,
    pub tokens: TokenSet,
    pub vault: Option<SyncResponse>,
}
