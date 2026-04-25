use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use crate::api::VaultwardenClient;
use crate::cache;
use crate::crypto::{decrypt_private_key, decrypt_user_key, derive_master_key, encrypt_string};
use crate::error::{Error, Result};
use crate::models::{LoginResult, Prelogin, TokenSet, TwoFactorProvider};
use crate::services::auth::{
    device_info, extract_session_keys, persist_session, prepare_credentials, recover_refresh_token,
    store_session,
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
        persist_session(&server_url, &email, &pre, tokens, &user_key)?;
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
    persist_session(&server_url, &email, &pre, &tokens, &user_key)?;
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

    // Decrypt refresh token (or fall back to legacy clear-text for sessions
    // written before encryption landed; those are migrated below).
    let refresh_token_plain = recover_refresh_token(&persisted, &user_key)?;

    let client = VaultwardenClient::new(&persisted.server_url)?;
    let device = device_info()?;
    let mut tokens = client.refresh_token(&refresh_token_plain, &device).await?;

    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token_plain.clone();
    }

    // Re-encrypt and drop any legacy clear-text field.
    let encrypted_refresh = encrypt_string(&tokens.refresh_token, &user_key)?;
    let mut updated = persisted.clone();
    updated.refresh_token = None;
    updated.encrypted_refresh_token = Some(encrypted_refresh);
    store::save_session(&updated)?;

    store_session(&state, client, tokens.clone(), user_key, private_key);
    crate::state::mark_activity(&state);
    Ok(tokens)
}

/// Perform a WebAuthn / FIDO2 assertion against the user's USB security
/// key, for a Bitwarden-style challenge.  Returns the JSON string that
/// must be sent back to the server as `twoFactorToken` with provider=7.
///
/// `server_url` is the Vaultwarden URL the user typed into the login
/// form. It anchors the rpId validation so a hostile or MITM'd server
/// can't make us sign an assertion for an unrelated origin.
///
/// Blocking CTAP2 I/O is offloaded to the async runtime's blocking pool
/// so the Tauri main loop stays responsive while the user taps their key.
#[tauri::command]
pub async fn webauthn_sign_challenge(server_url: String, challenge_json: String) -> Result<String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::webauthn::sign_bitwarden_challenge(&challenge_json, &server_url)
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("webauthn blocking task panicked: {e}"),
    })?
}

#[tauri::command]
pub fn set_auto_lock_minutes(state: State<'_, AppState>, minutes: f64) -> Result<()> {
    let mut guard = state.auto_lock_minutes.lock();
    *guard = if minutes.is_finite() && minutes > 0.0 {
        Some(minutes)
    } else {
        None
    };
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<()> {
    let agent = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = agent {
        h.stop_sync();
    }
    let mut guard = state.session.lock();
    *guard = None;
    Ok(())
}

#[tauri::command]
pub fn logout(state: State<'_, AppState>) -> Result<()> {
    let agent = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = agent {
        h.stop_sync();
    }
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    store::clear_session()?;
    if let Err(e) = cache::clear_all() {
        eprintln!("[clavix] vault cache clear failed: {e}");
    }
    Ok(())
}
