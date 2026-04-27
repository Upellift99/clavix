use std::collections::HashMap;

use tauri::State;

use crate::cache;
use crate::crypto::{decrypt_name, decrypt_org_key, encrypt_string};
use crate::error::{Error, Result};
use crate::models::{SyncResponse, SyncSummary};
use crate::services::auth::ensure_fresh_tokens;
use crate::services::vault::build_sync_summary;
use crate::state::AppState;
use crate::store;

#[tauri::command]
pub async fn sync(state: State<'_, AppState>) -> Result<SyncSummary> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };

    let response = client.sync(&access_token).await?;

    let mut guard = state.session.lock();
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

/// Create a new personal folder named `name`. Encrypts the name with
/// `user_key`, POSTs to `/folders`, and splices the new folder into the
/// current vault so it shows up without a full re-sync.
#[tauri::command]
pub async fn create_folder(state: State<'_, AppState>, name: String) -> Result<String> {
    ensure_fresh_tokens(&state).await?;
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::Storage {
            reason: "folder name cannot be empty".into(),
        });
    }
    let (client, access_token, encrypted_name) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let enc = encrypt_string(&trimmed, &s.user_key)?;
        (s.client.clone(), s.tokens.access_token.clone(), enc)
    };
    let folder = client.create_folder(&access_token, &encrypted_name).await?;
    let id = folder.id.clone();

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            // Replace the encrypted name with the plaintext one so the
            // front-end summary sees the folder immediately.
            let mut f = folder;
            f.name = trimmed;
            vault.folders.push(f);
        }
    }
    Ok(id)
}

/// Delete a personal folder by id. The Vaultwarden web UI doesn't
/// expose a delete control at all today (Vaultwarden bug — the
/// upstream Bitwarden HTTP path works fine), so this command is the
/// only way for a Clavix user to clean up legacy or duplicate
/// folders. Bitwarden detaches every cipher that referenced the
/// folder rather than cascade-deleting them; we mirror that locally
/// by clearing `folder_id` on every affected cipher so the UI doesn't
/// keep pointing at a folder that no longer exists.
#[tauri::command]
pub async fn delete_folder(state: State<'_, AppState>, folder_id: String) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client.delete_folder(&access_token, &folder_id).await?;

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            vault.folders.retain(|f| f.id != folder_id);
            for c in vault.ciphers.iter_mut() {
                if c.folder_id.as_deref() == Some(folder_id.as_str()) {
                    c.folder_id = None;
                }
            }
        }
    }
    Ok(())
}

/// Rename a personal folder. The new name is encrypted under the user
/// key and PUT to /folders/{id}; the local vault cache is updated in
/// place so the sidebar reflects the change without a full re-sync.
/// Trailing whitespace is trimmed and an empty string is rejected —
/// the upstream API would accept it but it produces a UI-broken
/// folder no one can address afterwards.
#[tauri::command]
pub async fn rename_folder(
    state: State<'_, AppState>,
    folder_id: String,
    name: String,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::Storage {
            reason: "folder name cannot be empty".into(),
        });
    }
    let (client, access_token, encrypted_name) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let enc = encrypt_string(&trimmed, &s.user_key)?;
        (s.client.clone(), s.tokens.access_token.clone(), enc)
    };
    client
        .update_folder_name(&access_token, &folder_id, &encrypted_name)
        .await?;

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            for f in vault.folders.iter_mut() {
                if f.id == folder_id {
                    // Stamp the plaintext name back so the next
                    // build_sync_summary sees it without a round-trip
                    // through the EncString decoder. Same trick
                    // `create_folder` uses.
                    f.name = trimmed.clone();
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub fn load_cached_vault(state: State<'_, AppState>) -> Result<Option<SyncSummary>> {
    crate::state::mark_activity(&state);
    let mut guard = state.session.lock();
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
