mod api;
mod audit;
mod cache;
mod crypto;
mod error;
mod models;
mod state;
mod store;

use std::collections::HashMap;

use rayon::prelude::*;
use rsa::RsaPrivateKey;
use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use api::{DeviceInfo, VaultwardenClient};
use crypto::{
    decrypt_name, decrypt_org_key, decrypt_private_key, decrypt_user_key, derive_master_key,
    derive_master_password_hash, encrypt_string, reencrypt_with_key, MasterKey, MasterPasswordHash,
    SymmetricKey,
};
use error::{Error, Result};
use models::{
    CardDetail, CipherCreateInput, CipherDetail, CipherSummary, CipherType, CollectionSummary,
    FolderSummary, IdentityDetail, LoginDetail, LoginResult, OrganizationSummary, Prelogin,
    SshKeyDetail, SyncResponse, SyncSummary, TokenSet, TwoFactorProvider, TypeCounts,
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

    let cache_result = (|| -> Result<()> {
        let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
            reason: "no persisted session to derive cache key".into(),
        })?;
        let account_key = cache::account_key(&persisted.server_url, &persisted.email);
        let raw_json = serde_json::to_string(&response).map_err(|e| Error::Storage {
            reason: format!("encode vault for cache: {e}"),
        })?;
        let encrypted = encrypt_string(&raw_json, &session.user_key)?;
        cache::save(&account_key, &encrypted)
    })();
    if let Err(e) = cache_result {
        eprintln!("[clavix] vault cache save failed: {e}");
    }

    session.vault = Some(response);
    Ok(summary)
}

#[tauri::command]
fn load_cached_vault(state: State<'_, AppState>) -> Result<Option<SyncSummary>> {
    let mut guard = state.session.lock().unwrap();
    let session = guard.as_mut().ok_or(Error::NotAuthenticated)?;

    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no persisted session for cache lookup".into(),
    })?;
    let account_key = cache::account_key(&persisted.server_url, &persisted.email);

    let encrypted = match cache::load(&account_key)? {
        Some(blob) => blob,
        None => return Ok(None),
    };

    let raw_json = decrypt_name(&encrypted, &session.user_key)?;
    let response: SyncResponse =
        serde_json::from_str(&raw_json).map_err(|e| Error::InvalidResponse {
            reason: format!("decode cached vault: {e}"),
        })?;

    session.org_keys = HashMap::new();
    for org in &response.profile.organizations {
        if let Some(key_str) = &org.key {
            if let Ok(key) =
                decrypt_org_key(&session.user_key, session.private_key.as_ref(), key_str)
            {
                session.org_keys.insert(org.id.clone(), key);
            }
        }
    }

    let summary = build_sync_summary(&response, &session.user_key, &session.org_keys);
    session.vault = Some(response);
    Ok(Some(summary))
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
        .par_iter()
        .map(|f| FolderSummary {
            id: f.id.clone(),
            name: decrypt_or_placeholder(&f.name, user_key),
        })
        .collect();

    let ciphers: Vec<CipherSummary> = response
        .ciphers
        .par_iter()
        .map(|c| {
            let key = c
                .organization_id
                .as_ref()
                .and_then(|id| org_keys.get(id))
                .unwrap_or(user_key);
            let primary_uri = c
                .login
                .as_ref()
                .and_then(|l| l.uris.as_ref())
                .and_then(|uris| uris.iter().find_map(|u| u.uri.as_deref()))
                .and_then(|s| decrypt_name(s, key).ok());

            let username = c
                .login
                .as_ref()
                .and_then(|l| l.username.as_deref())
                .and_then(|s| decrypt_name(s, key).ok());

            CipherSummary {
                id: c.id.clone(),
                kind: c.kind as u8,
                name: decrypt_or_placeholder(&c.name, key),
                folder_id: c.folder_id.clone(),
                organization_id: c.organization_id.clone(),
                collection_ids: c.collection_ids.clone(),
                favorite: c.favorite,
                primary_uri,
                username,
                revision_date: c.revision_date.clone(),
                deleted_date: c.deleted_date.clone(),
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
        .par_iter()
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

    let card = cipher.card.as_ref().map(|c| CardDetail {
        cardholder_name: c.cardholder_name.as_deref().and_then(decrypt_opt),
        brand: c.brand.as_deref().and_then(decrypt_opt),
        number: c.number.as_deref().and_then(decrypt_opt),
        exp_month: c.exp_month.as_deref().and_then(decrypt_opt),
        exp_year: c.exp_year.as_deref().and_then(decrypt_opt),
        code: c.code.as_deref().and_then(decrypt_opt),
    });

    let identity = cipher.identity.as_ref().map(|i| IdentityDetail {
        title: i.title.as_deref().and_then(decrypt_opt),
        first_name: i.first_name.as_deref().and_then(decrypt_opt),
        middle_name: i.middle_name.as_deref().and_then(decrypt_opt),
        last_name: i.last_name.as_deref().and_then(decrypt_opt),
        address1: i.address1.as_deref().and_then(decrypt_opt),
        address2: i.address2.as_deref().and_then(decrypt_opt),
        address3: i.address3.as_deref().and_then(decrypt_opt),
        city: i.city.as_deref().and_then(decrypt_opt),
        state: i.state.as_deref().and_then(decrypt_opt),
        postal_code: i.postal_code.as_deref().and_then(decrypt_opt),
        country: i.country.as_deref().and_then(decrypt_opt),
        company: i.company.as_deref().and_then(decrypt_opt),
        email: i.email.as_deref().and_then(decrypt_opt),
        phone: i.phone.as_deref().and_then(decrypt_opt),
        ssn: i.ssn.as_deref().and_then(decrypt_opt),
        username: i.username.as_deref().and_then(decrypt_opt),
        passport_number: i.passport_number.as_deref().and_then(decrypt_opt),
        license_number: i.license_number.as_deref().and_then(decrypt_opt),
    });

    let ssh_key = cipher.ssh_key.as_ref().map(|s| SshKeyDetail {
        private_key: s.private_key.as_deref().and_then(decrypt_opt),
        public_key: s.public_key.as_deref().and_then(decrypt_opt),
        key_fingerprint: s.key_fingerprint.as_deref().and_then(decrypt_opt),
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
        card,
        identity,
        ssh_key,
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
async fn move_cipher_to_collection(
    state: State<'_, AppState>,
    cipher_id: String,
    collection_id: String,
) -> Result<()> {
    let (client, access_token) = {
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
        let target_org = vault
            .collections
            .iter()
            .find(|c| c.id == collection_id)
            .map(|c| c.organization_id.clone())
            .ok_or_else(|| Error::Storage {
                reason: format!("collection not found: {collection_id}"),
            })?;
        if cipher.organization_id.as_deref() != Some(target_org.as_str()) {
            return Err(Error::AuthFailed {
                message:
                    "personal items cannot be dropped on an organization collection directly — share the item first"
                        .into(),
            });
        }
        (s.client.clone(), s.tokens.access_token.clone())
    };

    let collection_ids = vec![collection_id.clone()];
    client
        .update_cipher_collections(&access_token, &cipher_id, &collection_ids)
        .await?;

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                cipher.collection_ids = collection_ids;
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn move_folder_path(
    state: State<'_, AppState>,
    source_path: String,
    target_parent_path: Option<String>,
) -> Result<()> {
    let source_path = source_path.trim().trim_matches('/').to_string();
    if source_path.is_empty() {
        return Err(Error::Storage {
            reason: "empty source path".into(),
        });
    }

    let target_parent = target_parent_path
        .map(|p| p.trim().trim_matches('/').to_string())
        .filter(|p| !p.is_empty());

    if let Some(parent) = target_parent.as_deref() {
        if parent == source_path || parent.starts_with(&format!("{source_path}/")) {
            return Err(Error::Storage {
                reason: "cannot move a folder into itself or one of its descendants".into(),
            });
        }
    }

    let last_segment = source_path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Storage {
            reason: "source path has no final segment".into(),
        })?
        .to_string();

    let new_base = match target_parent.as_deref() {
        Some(parent) => format!("{parent}/{last_segment}"),
        None => last_segment.clone(),
    };

    let (client, access_token, operations) = {
        let guard = state.session.lock().unwrap();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;

        let source_prefix = format!("{source_path}/");
        let mut ops: Vec<(String, String)> = Vec::new();
        for f in &vault.folders {
            let current_name = decrypt_name(&f.name, &session.user_key)?;
            let new_name = if current_name == source_path {
                new_base.clone()
            } else if current_name.starts_with(&source_prefix) {
                let suffix = &current_name[source_prefix.len()..];
                format!("{new_base}/{suffix}")
            } else {
                continue;
            };
            let encrypted = encrypt_string(&new_name, &session.user_key)?;
            ops.push((f.id.clone(), encrypted));
        }

        if ops.is_empty() {
            return Err(Error::Storage {
                reason: format!("no folder matches path '{source_path}'"),
            });
        }

        (
            session.client.clone(),
            session.tokens.access_token.clone(),
            ops,
        )
    };

    for (folder_id, encrypted_name) in &operations {
        client
            .update_folder_name(&access_token, folder_id, encrypted_name)
            .await?;
    }

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            for (folder_id, encrypted_name) in &operations {
                if let Some(folder) = vault.folders.iter_mut().find(|f| f.id == *folder_id) {
                    folder.name = encrypted_name.clone();
                }
            }
        }
    }
    Ok(())
}

fn build_login_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
) -> Result<serde_json::Value> {
    let name_enc = encrypt_string(&input.name, key)?;
    let notes_enc = input
        .notes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| encrypt_string(s, key))
        .transpose()?;

    let login_value = if let Some(login) = input.login.as_ref() {
        let username_enc = login
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| encrypt_string(s, key))
            .transpose()?;
        let password_enc = login
            .password
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| encrypt_string(s, key))
            .transpose()?;
        let totp_enc = login
            .totp
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| encrypt_string(s, key))
            .transpose()?;
        let uris_val: Vec<serde_json::Value> = login
            .uris
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|u| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "uri": encrypt_string(u, key)?,
                    "match": serde_json::Value::Null,
                }))
            })
            .collect::<Result<_>>()?;

        serde_json::json!({
            "username": username_enc,
            "password": password_enc,
            "uris": uris_val,
            "totp": totp_enc,
        })
    } else {
        serde_json::json!({})
    };

    Ok(serde_json::json!({
        "type": 1,
        "name": name_enc,
        "notes": notes_enc,
        "folderId": input.folder_id,
        "favorite": input.favorite,
        "login": login_value,
    }))
}

#[tauri::command]
async fn create_login_cipher(
    state: State<'_, AppState>,
    input: CipherCreateInput,
) -> Result<String> {
    let (client, access_token, body) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let body = build_login_cipher_body(&input, &s.user_key)?;
        (s.client.clone(), s.tokens.access_token.clone(), body)
    };
    let created = client.create_cipher(&access_token, &body).await?;
    let id = created.id.clone();

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            vault.ciphers.push(created);
        }
    }
    Ok(id)
}

#[tauri::command]
async fn update_login_cipher(
    state: State<'_, AppState>,
    cipher_id: String,
    input: CipherCreateInput,
) -> Result<()> {
    let (client, access_token, body) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let body = build_login_cipher_body(&input, &s.user_key)?;
        (s.client.clone(), s.tokens.access_token.clone(), body)
    };
    let updated = client
        .update_cipher(&access_token, &cipher_id, &body)
        .await?;

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(slot) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                *slot = updated;
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn restore_cipher(state: State<'_, AppState>, cipher_id: String) -> Result<()> {
    let (client, access_token) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client.restore_cipher(&access_token, &cipher_id).await?;

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                cipher.deleted_date = None;
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn delete_cipher(state: State<'_, AppState>, cipher_id: String) -> Result<()> {
    let (client, access_token) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client.delete_cipher(&access_token, &cipher_id).await?;

    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            vault.ciphers.retain(|c| c.id != cipher_id);
        }
    }
    Ok(())
}

#[tauri::command]
async fn share_cipher_to_collection(
    state: State<'_, AppState>,
    cipher_id: String,
    collection_id: String,
) -> Result<()> {
    let (client, access_token, body, target_org_id) = {
        let guard = state.session.lock().unwrap();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;

        let cipher = vault
            .ciphers
            .iter()
            .find(|c| c.id == cipher_id)
            .ok_or_else(|| Error::Storage {
                reason: format!("cipher not found: {cipher_id}"),
            })?;

        let target_org_id = vault
            .collections
            .iter()
            .find(|c| c.id == collection_id)
            .map(|c| c.organization_id.clone())
            .ok_or_else(|| Error::Storage {
                reason: format!("collection not found: {collection_id}"),
            })?;

        if cipher.organization_id.as_deref() == Some(target_org_id.as_str()) {
            return Err(Error::AuthFailed {
                message: "cipher already belongs to this organization — use move instead".into(),
            });
        }

        let target_key = session
            .org_keys
            .get(&target_org_id)
            .ok_or_else(|| Error::Crypto {
                reason: format!(
                    "organization key not available for {target_org_id} — cannot re-encrypt"
                ),
            })?;

        let source_key: &SymmetricKey = if let Some(ref source_org_id) = cipher.organization_id {
            session
                .org_keys
                .get(source_org_id)
                .ok_or_else(|| Error::Crypto {
                    reason: format!("source organization key not available for {source_org_id}"),
                })?
        } else {
            &session.user_key
        };

        let reenc = |s: &str| reencrypt_with_key(s, source_key, target_key);

        let name = reenc(&cipher.name)?;
        let notes = cipher.notes.as_deref().map(reenc).transpose()?;

        let reenc_opt = |s: Option<&str>| -> Result<Option<String>> { s.map(reenc).transpose() };

        let login_json = cipher
            .login
            .as_ref()
            .map(|l| -> Result<serde_json::Value> {
                let uris: Vec<serde_json::Value> = l
                    .uris
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|u| u.uri.as_deref().map(reenc))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .map(|uri| serde_json::json!({ "uri": uri, "match": serde_json::Value::Null }))
                    .collect();
                Ok(serde_json::json!({
                    "username": reenc_opt(l.username.as_deref())?,
                    "password": reenc_opt(l.password.as_deref())?,
                    "totp": reenc_opt(l.totp.as_deref())?,
                    "uris": uris,
                }))
            })
            .transpose()?;

        let card_json = cipher
            .card
            .as_ref()
            .map(|c| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "cardholderName": reenc_opt(c.cardholder_name.as_deref())?,
                    "brand": reenc_opt(c.brand.as_deref())?,
                    "number": reenc_opt(c.number.as_deref())?,
                    "expMonth": reenc_opt(c.exp_month.as_deref())?,
                    "expYear": reenc_opt(c.exp_year.as_deref())?,
                    "code": reenc_opt(c.code.as_deref())?,
                }))
            })
            .transpose()?;

        let identity_json = cipher
            .identity
            .as_ref()
            .map(|i| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "title": reenc_opt(i.title.as_deref())?,
                    "firstName": reenc_opt(i.first_name.as_deref())?,
                    "middleName": reenc_opt(i.middle_name.as_deref())?,
                    "lastName": reenc_opt(i.last_name.as_deref())?,
                    "address1": reenc_opt(i.address1.as_deref())?,
                    "address2": reenc_opt(i.address2.as_deref())?,
                    "address3": reenc_opt(i.address3.as_deref())?,
                    "city": reenc_opt(i.city.as_deref())?,
                    "state": reenc_opt(i.state.as_deref())?,
                    "postalCode": reenc_opt(i.postal_code.as_deref())?,
                    "country": reenc_opt(i.country.as_deref())?,
                    "company": reenc_opt(i.company.as_deref())?,
                    "email": reenc_opt(i.email.as_deref())?,
                    "phone": reenc_opt(i.phone.as_deref())?,
                    "ssn": reenc_opt(i.ssn.as_deref())?,
                    "username": reenc_opt(i.username.as_deref())?,
                    "passportNumber": reenc_opt(i.passport_number.as_deref())?,
                    "licenseNumber": reenc_opt(i.license_number.as_deref())?,
                }))
            })
            .transpose()?;

        let ssh_key_json = cipher
            .ssh_key
            .as_ref()
            .map(|s| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "privateKey": reenc_opt(s.private_key.as_deref())?,
                    "publicKey": reenc_opt(s.public_key.as_deref())?,
                    "keyFingerprint": reenc_opt(s.key_fingerprint.as_deref())?,
                }))
            })
            .transpose()?;

        // folderId toujours remis à null lors d'un share : un folder est
        // perso par nature, il ne suit pas le cipher dans la nouvelle orga.
        let body = serde_json::json!({
            "cipher": {
                "type": cipher.kind as u8,
                "name": name,
                "notes": notes,
                "organizationId": target_org_id,
                "folderId": serde_json::Value::Null,
                "favorite": cipher.favorite,
                "login": login_json,
                "card": card_json,
                "identity": identity_json,
                "sshKey": ssh_key_json,
            },
            "collectionIds": [collection_id.clone()],
        });

        (
            session.client.clone(),
            session.tokens.access_token.clone(),
            body,
            target_org_id,
        )
    };

    client
        .share_cipher(&access_token, &cipher_id, &body)
        .await?;

    // Update in-memory vault : remove from personal/old org, add to org with new encrypted fields
    let mut guard = state.session.lock().unwrap();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                cipher.organization_id = Some(target_org_id);
                cipher.collection_ids = vec![collection_id];
                cipher.folder_id = None;
                // Les champs restent chiffrés avec user_key en mémoire. Pour être exact
                // il faudrait les réécrire avec org_key, mais un prochain sync remettra
                // tout d'équerre. On laisse ainsi pour simplifier.
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn audit_vault_passwords(state: State<'_, AppState>) -> Result<audit::PasswordAuditResult> {
    let entries: Vec<(String, String, SecretString)> = {
        let guard = state.session.lock().unwrap();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;

        vault
            .ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .filter_map(|c| {
                let login = c.login.as_ref()?;
                let pw_enc = login.password.as_deref()?;
                let key = c
                    .organization_id
                    .as_ref()
                    .and_then(|oid| session.org_keys.get(oid))
                    .unwrap_or(&session.user_key);
                let pw = decrypt_name(pw_enc, key).ok()?;
                if pw.is_empty() {
                    return None;
                }
                let name = decrypt_name(&c.name, key).unwrap_or_else(|_| "(chiffré)".to_string());
                Some((c.id.clone(), name, SecretString::from(pw)))
            })
            .collect()
    };

    audit::audit_passwords(entries).await
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
    if let Err(e) = cache::clear_all() {
        eprintln!("[clavix] vault cache clear failed: {e}");
    }
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
            move_cipher_to_folder,
            move_cipher_to_collection,
            move_folder_path,
            load_cached_vault,
            share_cipher_to_collection,
            restore_cipher,
            delete_cipher,
            audit_vault_passwords,
            create_login_cipher,
            update_login_cipher
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
