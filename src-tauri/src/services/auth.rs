use std::collections::HashMap;
use std::time::{Duration, Instant};

use rsa::RsaPrivateKey;
use secrecy::SecretString;
use tauri::State;

use crate::api::{DeviceInfo, VaultwardenClient};
use crate::crypto::{
    decrypt_private_key, decrypt_user_key, derive_master_key, derive_master_password_hash,
    MasterKey, MasterPasswordHash, SymmetricKey,
};
use crate::error::{Error, Result};
use crate::models::{Prelogin, TokenSet};
use crate::state::{AppState, Session};
use crate::store::{self, PersistedSession};

pub fn device_info() -> Result<DeviceInfo> {
    Ok(DeviceInfo {
        identifier: store::get_or_create_device_id()?,
        name: "Clavix".to_string(),
        device_type: 8,
    })
}

pub async fn prepare_credentials(
    server_url: &str,
    email: &str,
    password: &SecretString,
) -> Result<(VaultwardenClient, Prelogin, MasterKey, MasterPasswordHash)> {
    let client = VaultwardenClient::new(server_url)?;
    let pre = client.prelogin(email).await?;
    let master_key = derive_master_key(
        password,
        email,
        pre.kdf,
        pre.kdf_iterations,
        pre.kdf_memory,
        pre.kdf_parallelism,
    )?;
    let hash = derive_master_password_hash(&master_key, password);
    Ok((client, pre, master_key, hash))
}

pub fn extract_session_keys(
    master_key: &MasterKey,
    tokens: &TokenSet,
) -> Result<(SymmetricKey, Option<RsaPrivateKey>)> {
    let key_str = tokens.key.as_deref().ok_or_else(|| Error::Crypto {
        reason: "TokenSet is missing the 'key' field — cannot derive user key".into(),
    })?;
    let user_key = decrypt_user_key(master_key, key_str)?;

    let private_key = tokens
        .private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;

    Ok((user_key, private_key))
}

pub fn compute_expires_at(expires_in: u64) -> Instant {
    Instant::now() + Duration::from_secs(expires_in.saturating_sub(30).max(1))
}

pub fn store_session(
    state: &AppState,
    client: VaultwardenClient,
    tokens: TokenSet,
    user_key: SymmetricKey,
    private_key: Option<RsaPrivateKey>,
) {
    let expires_at = compute_expires_at(tokens.expires_in);
    let mut guard = state.session.lock().unwrap();
    *guard = Some(Session {
        client,
        tokens,
        expires_at,
        user_key,
        private_key,
        org_keys: HashMap::new(),
        vault: None,
    });
}

/// Refresh `tokens.access_token` if it is within 60 seconds of expiring.
/// No-op otherwise. Commands that hit the Vaultwarden API call this before
/// the first access-token use.
pub async fn ensure_fresh_tokens(state: &State<'_, AppState>) -> Result<()> {
    let (client, refresh) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        if s.expires_at > Instant::now() + Duration::from_secs(60) {
            return Ok(());
        }
        (s.client.clone(), s.tokens.refresh_token.clone())
    };

    let device = device_info()?;
    let mut new_tokens = client.refresh_token(&refresh, &device).await?;
    if new_tokens.refresh_token.is_empty() {
        new_tokens.refresh_token = refresh.clone();
    }

    let new_refresh = new_tokens.refresh_token.clone();
    let new_access = new_tokens.access_token.clone();
    let new_expires_in = new_tokens.expires_in;

    {
        let mut guard = state.session.lock().unwrap();
        if let Some(s) = guard.as_mut() {
            s.tokens.access_token = new_access;
            s.tokens.refresh_token = new_refresh.clone();
            s.tokens.expires_in = new_expires_in;
            s.expires_at = compute_expires_at(new_expires_in);
        }
    }

    if let Ok(Some(mut persisted)) = store::load_session() {
        if persisted.refresh_token != new_refresh {
            persisted.refresh_token = new_refresh;
            let _ = store::save_session(&persisted);
        }
    }

    Ok(())
}

pub fn persist_session(
    server_url: &str,
    email: &str,
    pre: &Prelogin,
    tokens: &TokenSet,
) -> Result<()> {
    let encrypted_user_key = tokens.key.clone().ok_or_else(|| Error::Crypto {
        reason: "TokenSet is missing the 'key' field — cannot persist session".into(),
    })?;

    let persisted = PersistedSession {
        server_url: server_url.to_string(),
        email: email.to_string(),
        refresh_token: tokens.refresh_token.clone(),
        kdf: pre.kdf,
        kdf_iterations: pre.kdf_iterations,
        kdf_memory: pre.kdf_memory,
        kdf_parallelism: pre.kdf_parallelism,
        encrypted_user_key,
        encrypted_private_key: tokens.private_key.clone(),
    };
    store::save_session(&persisted)
}
