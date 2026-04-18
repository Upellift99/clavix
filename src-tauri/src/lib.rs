mod api;
mod crypto;
mod error;
mod models;
mod state;

use std::collections::HashMap;
use std::sync::OnceLock;

use rsa::RsaPrivateKey;
use secrecy::SecretString;
use tauri::State;
use uuid::Uuid;

use api::{DeviceInfo, VaultwardenClient};
use crypto::{
    decrypt_name, decrypt_org_key, decrypt_private_key, decrypt_user_key, derive_master_key,
    derive_master_password_hash, MasterKey, MasterPasswordHash, SymmetricKey,
};
use error::{Error, Result};
use models::{
    CipherSummary, CipherType, FolderSummary, LoginResult, Prelogin, SyncResponse, SyncSummary,
    TokenSet, TwoFactorProvider, TypeCounts,
};
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
) -> Result<(VaultwardenClient, MasterKey, MasterPasswordHash)> {
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
    Ok((client, master_key, hash))
}

fn extract_session_keys(
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

fn store_session(
    state: &AppState,
    client: VaultwardenClient,
    tokens: TokenSet,
    user_key: SymmetricKey,
    private_key: Option<RsaPrivateKey>,
) {
    let mut guard = state.session.lock().unwrap();
    *guard = Some(Session {
        client,
        tokens,
        user_key,
        private_key,
        org_keys: HashMap::new(),
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
    let (client, master_key, hash) = prepare_credentials(&server_url, &email, password).await?;
    let result = client.login(&email, &hash, &device_info()).await?;

    if let LoginResult::Success(ref tokens) = result {
        let (user_key, private_key) = extract_session_keys(&master_key, tokens)?;
        store_session(&state, client, tokens.clone(), user_key, private_key);
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
    let (client, master_key, hash) = prepare_credentials(&server_url, &email, password).await?;
    let tokens = client
        .login_with_two_factor(&email, &hash, &device_info(), typed_provider, &code)
        .await?;

    let (user_key, private_key) = extract_session_keys(&master_key, &tokens)?;
    store_session(&state, client, tokens.clone(), user_key, private_key);
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

    let mut guard = state.session.lock().unwrap();
    let session = guard.as_mut().ok_or(Error::NotAuthenticated)?;

    session.org_keys = HashMap::new();
    for org in &response.profile.organizations {
        if let Some(key_str) = &org.key {
            match decrypt_org_key(&session.user_key, session.private_key.as_ref(), key_str) {
                Ok(key) => {
                    session.org_keys.insert(org.id.clone(), key);
                }
                Err(e) => {
                    eprintln!(
                        "[clavix] could not decrypt org key for {} ({}): {}",
                        org.id, org.name, e
                    );
                }
            }
        }
    }

    let summary = build_sync_summary(&response, &session.user_key, &session.org_keys);
    session.vault = Some(response);
    Ok(summary)
}

fn build_sync_summary(
    response: &SyncResponse,
    user_key: &SymmetricKey,
    org_keys: &HashMap<String, SymmetricKey>,
) -> SyncSummary {
    let mut type_counts = TypeCounts::default();
    for c in &response.ciphers {
        match c.kind {
            CipherType::Login => type_counts.login += 1,
            CipherType::SecureNote => type_counts.secure_note += 1,
            CipherType::Card => type_counts.card += 1,
            CipherType::Identity => type_counts.identity += 1,
            CipherType::SshKey => type_counts.ssh_key += 1,
        }
    }

    let folders: Vec<FolderSummary> = response
        .folders
        .iter()
        .map(|f| FolderSummary {
            id: f.id.clone(),
            name: decrypt_or_placeholder(&f.name, user_key),
        })
        .collect();

    let cipher_preview: Vec<CipherSummary> = response
        .ciphers
        .iter()
        .take(10)
        .map(|c| {
            let key = c
                .organization_id
                .as_ref()
                .and_then(|id| org_keys.get(id))
                .unwrap_or(user_key);
            CipherSummary {
                id: c.id.clone(),
                kind: c.kind as u8,
                name: decrypt_or_placeholder(&c.name, key),
                folder_id: c.folder_id.clone(),
                organization_id: c.organization_id.clone(),
                favorite: c.favorite,
            }
        })
        .collect();

    SyncSummary {
        email: response.profile.email.clone(),
        name: response.profile.name.clone(),
        item_count: response.ciphers.len(),
        folder_count: response.folders.len(),
        collection_count: response.collections.len(),
        organization_count: response.profile.organizations.len(),
        type_counts,
        folders,
        cipher_preview,
    }
}

fn decrypt_or_placeholder(encrypted: &str, key: &SymmetricKey) -> String {
    match decrypt_name(encrypted, key) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("[clavix] decrypt failed: {e}");
            "[decrypt failed]".to_string()
        }
    }
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
