mod api;
mod crypto;
mod error;
mod models;
mod state;

use std::sync::OnceLock;

use secrecy::SecretString;
use tauri::State;
use uuid::Uuid;

use api::{DeviceInfo, VaultwardenClient};
use crypto::{derive_master_key, derive_master_password_hash, MasterPasswordHash};
use error::{Error, Result};
use models::{LoginResult, Prelogin, SyncSummary, TokenSet, TwoFactorProvider};
use state::{AppState, Session};

fn device_info() -> DeviceInfo {
    static ID: OnceLock<String> = OnceLock::new();
    let identifier = ID.get_or_init(|| Uuid::new_v4().to_string()).clone();
    DeviceInfo {
        identifier,
        name: "Clavix".to_string(),
        device_type: 8,
    }
}

async fn prepare_credentials(
    server_url: &str,
    email: &str,
    password: SecretString,
) -> Result<(VaultwardenClient, MasterPasswordHash)> {
    let client = VaultwardenClient::new(server_url)?;
    let pre = client.prelogin(email).await?;
    let master_key = derive_master_key(
        &password,
        email,
        pre.kdf,
        pre.kdf_iterations,
        pre.kdf_memory,
        pre.kdf_parallelism,
    )?;
    let hash = derive_master_password_hash(&master_key, &password);
    Ok((client, hash))
}

fn store_session(state: &AppState, client: VaultwardenClient, tokens: TokenSet) {
    let mut guard = state.session.lock().unwrap();
    *guard = Some(Session {
        client,
        tokens,
        vault: None,
    });
}

#[tauri::command]
async fn prelogin(server_url: String, email: String) -> Result<Prelogin> {
    let client = VaultwardenClient::new(&server_url)?;
    client.prelogin(&email).await
}

#[tauri::command]
async fn login(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginResult> {
    let password: SecretString = password.into();
    let (client, hash) = prepare_credentials(&server_url, &email, password).await?;
    let result = client.login(&email, &hash, &device_info()).await?;

    if let LoginResult::Success(ref tokens) = result {
        store_session(&state, client, tokens.clone());
    }

    Ok(result)
}

#[tauri::command]
async fn login_with_two_factor(
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
    let (client, hash) = prepare_credentials(&server_url, &email, password).await?;
    let tokens = client
        .login_with_two_factor(&email, &hash, &device_info(), typed_provider, &code)
        .await?;

    store_session(&state, client, tokens.clone());
    Ok(tokens)
}

#[tauri::command]
async fn sync(state: State<'_, AppState>) -> Result<SyncSummary> {
    let (client, access_token) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };

    let response = client.sync(&access_token).await?;
    let summary = SyncSummary::from(&response);

    {
        let mut guard = state.session.lock().unwrap();
        if let Some(s) = guard.as_mut() {
            s.vault = Some(response);
        }
    }

    Ok(summary)
}

#[tauri::command]
fn logout(state: State<'_, AppState>) -> Result<()> {
    let mut guard = state.session.lock().unwrap();
    *guard = None;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            prelogin,
            login,
            login_with_two_factor,
            sync,
            logout
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
