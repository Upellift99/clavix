use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use crate::api::VaultwardenClient;
use crate::cache;
use crate::crypto::{decrypt_private_key, decrypt_user_key, derive_master_key};
use crate::error::{Error, Result};
use crate::models::{LoginResult, Prelogin, TokenSet, TwoFactorProvider};
use crate::services::auth::{
    device_info, extract_session_keys, persist_session, prepare_credentials, store_session,
};
use crate::state::AppState;
use crate::store;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAccount {
    pub server_url: String,
    pub email: String,
}

#[tauri::command]
pub fn stored_account() -> Result<Option<StoredAccount>> {
    Ok(store::load_session()?.map(|s| StoredAccount {
        server_url: s.server_url,
        email: s.email,
    }))
}

#[tauri::command]
pub async fn prelogin(server_url: String, email: String) -> Result<Prelogin> {
    let client = VaultwardenClient::new(&server_url)?;
    client.prelogin(&email).await
}

#[tauri::command]
pub async fn login(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginResult> {
    let password: SecretString = password.into();
    let (client, pre, master_key, hash) =
        prepare_credentials(&server_url, &email, &password).await?;
    let device = device_info()?;
    let result = client.login(&email, &hash, &device).await?;

    if let LoginResult::Success(ref tokens) = result {
        let (user_key, private_key) = extract_session_keys(&master_key, tokens)?;
        persist_session(&server_url, &email, &pre, tokens)?;
        store_session(&state, client, tokens.clone(), user_key, private_key);
    }

    Ok(result)
}

#[tauri::command]
pub async fn login_with_two_factor(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
    code: String,
    provider: u8,
) -> Result<TokenSet> {
    let typed_provider = TwoFactorProvider::try_from(provider)
        .map_err(|_| Error::TwoFactorProviderUnsupported { provider })?;
    let password: SecretString = password.into();
    let (client, pre, master_key, hash) =
        prepare_credentials(&server_url, &email, &password).await?;
    let device = device_info()?;
    let tokens = client
        .login_with_two_factor(&email, &hash, &device, typed_provider, &code)
        .await?;

    let (user_key, private_key) = extract_session_keys(&master_key, &tokens)?;
    persist_session(&server_url, &email, &pre, &tokens)?;
    store_session(&state, client, tokens.clone(), user_key, private_key);
    Ok(tokens)
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: String) -> Result<TokenSet> {
    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to unlock".into(),
    })?;

    let password: SecretString = password.into();
    let master_key = derive_master_key(
        &password,
        &persisted.email,
        persisted.kdf,
        persisted.kdf_iterations,
        persisted.kdf_memory,
        persisted.kdf_parallelism,
    )?;

    let user_key = decrypt_user_key(&master_key, &persisted.encrypted_user_key)?;
    let private_key = persisted
        .encrypted_private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;

    let client = VaultwardenClient::new(&persisted.server_url)?;
    let device = device_info()?;
    let mut tokens = client
        .refresh_token(&persisted.refresh_token, &device)
        .await?;

    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = persisted.refresh_token.clone();
    }

    let mut updated = persisted.clone();
    updated.refresh_token = tokens.refresh_token.clone();
    store::save_session(&updated)?;

    store_session(&state, client, tokens.clone(), user_key, private_key);
    Ok(tokens)
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<()> {
    let agent = {
        let mut slot = state.ssh_agent.lock().unwrap();
        slot.take()
    };
    if let Some(h) = agent {
        h.stop_sync();
    }
    let mut guard = state.session.lock().unwrap();
    *guard = None;
    Ok(())
}

#[tauri::command]
pub fn logout(state: State<'_, AppState>) -> Result<()> {
    let agent = {
        let mut slot = state.ssh_agent.lock().unwrap();
        slot.take()
    };
    if let Some(h) = agent {
        h.stop_sync();
    }
    {
        let mut guard = state.session.lock().unwrap();
        *guard = None;
    }
    store::clear_session()?;
    if let Err(e) = cache::clear_all() {
        eprintln!("[clavix] vault cache clear failed: {e}");
    }
    Ok(())
}
