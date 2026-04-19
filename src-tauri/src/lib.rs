mod api;
mod crypto;
mod error;
mod models;
mod state;
mod store;

use std::collections::HashMap;

use rsa::RsaPrivateKey;
use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use api::{DeviceInfo, VaultwardenClient};
use crypto::{
    decrypt_name, decrypt_org_key, decrypt_private_key, decrypt_user_key, derive_master_key,
    derive_master_password_hash, MasterKey, MasterPasswordHash, SymmetricKey,
};
use error::{Error, Result};
use models::{
    CipherDetail, CipherSummary, CipherType, CollectionSummary, FolderSummary, LoginDetail,
    LoginResult, OrganizationSummary, Prelogin, SyncResponse, SyncSummary, TokenSet,
    TwoFactorProvider, TypeCounts,
};
use state::{AppState, Session};
use store::PersistedSession;

fn device_info() -> Result<DeviceInfo> {
    Ok(DeviceInfo {
        identifier: store::get_or_create_device_id()?,
        name: "Clavix".to_string(),
        device_type: 8,
    })
}

async fn prepare_credentials(
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

fn persist_session(server_url: &str, email: &str, pre: &Prelogin, tokens: &TokenSet) -> Result<()> {
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAccount {
    pub server_url: String,
    pub email: String,
}

#[tauri::command]
fn stored_account() -> Result<Option<StoredAccount>> {
    Ok(store::load_session()?.map(|s| StoredAccount {
        server_url: s.server_url,
        email: s.email,
    }))
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
async fn unlock(state: State<'_, AppState>, password: String) -> Result<TokenSet> {
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

    let ciphers: Vec<CipherSummary> = response
        .ciphers
        .iter()
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
                collection_ids: c.collection_ids.clone(),
                favorite: c.favorite,
            }
        })
        .collect();

    let organizations: Vec<OrganizationSummary> = response
        .profile
        .organizations
        .iter()
        .map(|o| OrganizationSummary {
            id: o.id.clone(),
            name: o.name.clone(),
        })
        .collect();

    let collections: Vec<CollectionSummary> = response
        .collections
        .iter()
        .map(|c| {
            let key = org_keys.get(&c.organization_id).unwrap_or(user_key);
            CollectionSummary {
                id: c.id.clone(),
                organization_id: c.organization_id.clone(),
                name: decrypt_or_placeholder(&c.name, key),
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
        organizations,
        collections,
        ciphers,
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
fn get_cipher(state: State<'_, AppState>, id: String) -> Result<CipherDetail> {
    let guard = state.session.lock().unwrap();
    let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
    let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
        reason: "no vault synced yet — synchronise first".into(),
    })?;

    let cipher = vault
        .ciphers
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| Error::Storage {
            reason: format!("cipher not found: {id}"),
        })?;

    let key = cipher
        .organization_id
        .as_ref()
        .and_then(|oid| session.org_keys.get(oid))
        .unwrap_or(&session.user_key);

    let decrypt_opt = |s: &str| -> Option<String> { decrypt_name(s, key).ok() };

    let login = cipher.login.as_ref().map(|l| LoginDetail {
        username: l.username.as_deref().and_then(decrypt_opt),
        password: l.password.as_deref().and_then(decrypt_opt),
        uris: l
            .uris
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|u| u.uri.as_deref().and_then(decrypt_opt))
            .collect(),
        totp: l.totp.as_deref().and_then(decrypt_opt),
    });

    Ok(CipherDetail {
        id: cipher.id.clone(),
        kind: cipher.kind as u8,
        name: decrypt_name(&cipher.name, key).unwrap_or_else(|e| format!("[decrypt failed: {e}]")),
        notes: cipher.notes.as_deref().and_then(decrypt_opt),
        organization_id: cipher.organization_id.clone(),
        folder_id: cipher.folder_id.clone(),
        collection_ids: cipher.collection_ids.clone(),
        revision_date: cipher.revision_date.clone(),
        favorite: cipher.favorite,
        login,
    })
}

#[tauri::command]
async fn move_cipher_to_folder(
    state: State<'_, AppState>,
    cipher_id: String,
    folder_id: Option<String>,
) -> Result<()> {
    let (client, access_token, favorite) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = s.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;
        let cipher = vault
            .ciphers
            .iter()
            .find(|c| c.id == cipher_id)
            .ok_or_else(|| Error::Storage {
                reason: format!("cipher not found: {cipher_id}"),
            })?;
        (
            s.client.clone(),
            s.tokens.access_token.clone(),
            cipher.favorite,
        )
    };

    client
        .update_cipher_partial(&access_token, &cipher_id, folder_id.as_deref(), favorite)
        .await?;

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                cipher.folder_id = folder_id;
            }
        }
    }
    Ok(())
}

#[tauri::command]
fn lock(state: State<'_, AppState>) -> Result<()> {
    let mut guard = state.session.lock().unwrap();
    *guard = None;
    Ok(())
}

#[tauri::command]
fn logout(state: State<'_, AppState>) -> Result<()> {
    {
        let mut guard = state.session.lock().unwrap();
        *guard = None;
    }
    store::clear_session()?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            prelogin,
            login,
            login_with_two_factor,
            unlock,
            sync,
            lock,
            logout,
            stored_account,
            get_cipher,
            move_cipher_to_folder
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
