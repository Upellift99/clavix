mod api;
mod crypto;
mod error;
mod models;

use std::sync::OnceLock;

use secrecy::SecretString;
use uuid::Uuid;

use api::{DeviceInfo, VaultwardenClient};
use crypto::{derive_master_key, derive_master_password_hash, MasterPasswordHash};
use error::{Error, Result};
use models::{LoginResult, Prelogin, TokenSet, TwoFactorProvider};

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

#[tauri::command]
async fn prelogin(server_url: String, email: String) -> Result<Prelogin> {
    let client = VaultwardenClient::new(&server_url)?;
    client.prelogin(&email).await
}

#[tauri::command]
async fn login(server_url: String, email: String, password: String) -> Result<LoginResult> {
    let password: SecretString = password.into();
    let (client, hash) = prepare_credentials(&server_url, &email, password).await?;
    client.login(&email, &hash, &device_info()).await
}

#[tauri::command]
async fn login_with_two_factor(
    server_url: String,
    email: String,
    password: String,
    code: String,
    provider: u8,
) -> Result<TokenSet> {
    let typed_provider = TwoFactorProvider::try_from(provider)
        .map_err(|_| Error::TwoFactorProviderUnsupported(provider))?;
    let password: SecretString = password.into();
    let (client, hash) = prepare_credentials(&server_url, &email, password).await?;
    client
        .login_with_two_factor(&email, &hash, &device_info(), typed_provider, &code)
        .await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            prelogin,
            login,
            login_with_two_factor
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
