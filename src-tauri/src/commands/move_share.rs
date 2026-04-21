use tauri::State;
use uuid::Uuid;

use crate::cache;
use crate::crypto::{decrypt_name, encrypt_string, SymmetricKey};
use crate::error::{Error, Result};
use crate::services::auth::ensure_fresh_tokens;
use crate::services::cipher::{build_share_cipher_body, validate_move_to_collection};
use crate::services::vault::{compute_new_folder_base, plan_folder_renames};
use crate::state::AppState;

#[tauri::command]
pub async fn move_cipher_to_folder(
    state: State<'_, AppState>,
    cipher_id: String,
    folder_id: Option<String>,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, favorite) = {
        let guard = state.session.lock();
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

    let mut guard = state.session.lock();
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
pub async fn move_cipher_to_collection(
    state: State<'_, AppState>,
    cipher_id: String,
    collection_id: String,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token) = {
        let guard = state.session.lock();
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
        validate_move_to_collection(cipher.organization_id.as_deref(), &target_org)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };

    let collection_ids = vec![collection_id.clone()];
    client
        .update_cipher_collections(&access_token, &cipher_id, &collection_ids)
        .await?;

    let mut guard = state.session.lock();
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
pub async fn move_folder_path(
    state: State<'_, AppState>,
    source_path: String,
    target_parent_path: Option<String>,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;

    let (source_path, _target_parent, new_base) =
        compute_new_folder_base(&source_path, target_parent_path.as_deref())
            .map_err(|reason| Error::Storage { reason })?;

    let (client, access_token, operations) = {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;

        // Decrypt all names up-front so plan_folder_renames — which is
        // pure and unit-tested — can decide which folders participate
        // without caring about the crypto.
        let mut decrypted: Vec<(String, String)> = Vec::with_capacity(vault.folders.len());
        for f in &vault.folders {
            let name = decrypt_name(&f.name, &session.user_key)?;
            decrypted.push((f.id.clone(), name));
        }
        let plan = plan_folder_renames(&decrypted, &source_path, &new_base);
        if plan.is_empty() {
            return Err(Error::Storage {
                reason: format!("no folder matches path '{source_path}'"),
            });
        }
        let mut ops: Vec<(String, String)> = Vec::with_capacity(plan.len());
        for (id, new_name) in plan {
            ops.push((id, encrypt_string(&new_name, &session.user_key)?));
        }

        (
            session.client.clone(),
            session.tokens.access_token.clone(),
            ops,
        )
    };

    // Persist the full batch upfront with the *original* and *new* encrypted
    // names per folder. Each row is flipped to applied=1 on PUT success below.
    // A crash mid-batch leaves the unflipped rows queryable so a future
    // recovery flow can resume the rename from where we left off, instead of
    // losing the partial state silently.
    let op_id = Uuid::new_v4().to_string();
    let original_names: Vec<(String, String, String)> = {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;
        operations
            .iter()
            .filter_map(|(fid, new_enc)| {
                vault
                    .folders
                    .iter()
                    .find(|f| f.id == *fid)
                    .map(|f| (fid.clone(), f.name.clone(), new_enc.clone()))
            })
            .collect()
    };
    if let Err(e) = cache::save_folder_op_batch(&op_id, &original_names) {
        eprintln!("[clavix] folder op log write failed (non-fatal): {e}");
    }

    for (folder_id, encrypted_name) in &operations {
        client
            .update_folder_name(&access_token, folder_id, encrypted_name)
            .await?;
        if let Err(e) = cache::mark_folder_op_applied(&op_id, folder_id) {
            eprintln!("[clavix] folder op log update failed (non-fatal): {e}");
        }
    }

    let mut guard = state.session.lock();
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

#[tauri::command]
pub async fn share_cipher_to_collection(
    state: State<'_, AppState>,
    cipher_id: String,
    collection_id: String,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, body, target_org_id, encrypted_snapshot) = {
        let guard = state.session.lock();
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

        // Snapshot the cipher *before* we re-encrypt anything. The blob keeps
        // the original encrypted fields (under the original key) plus the org
        // membership at the time of the call. If the share PUT half-fails
        // server-side and the cipher ends up in a broken state, we still hold
        // the data needed to re-create it locally.
        let snapshot_blob = serde_json::to_string(cipher).map_err(|e| Error::Storage {
            reason: format!("serialise cipher snapshot: {e}"),
        })?;
        let encrypted_snapshot = encrypt_string(&snapshot_blob, &session.user_key)?;

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

        let body = build_share_cipher_body(
            cipher,
            source_key,
            target_key,
            &target_org_id,
            std::slice::from_ref(&collection_id),
        )?;

        (
            session.client.clone(),
            session.tokens.access_token.clone(),
            body,
            target_org_id,
            encrypted_snapshot,
        )
    };

    let snapshot_id = Uuid::new_v4().to_string();
    if let Err(e) =
        cache::save_cipher_snapshot(&snapshot_id, &cipher_id, "share", &encrypted_snapshot)
    {
        eprintln!("[clavix] cipher snapshot write failed (non-fatal): {e}");
    }

    client
        .share_cipher(&access_token, &cipher_id, &body)
        .await?;

    if let Err(e) = cache::mark_snapshot_completed(&snapshot_id) {
        eprintln!("[clavix] cipher snapshot completion failed (non-fatal): {e}");
    }

    // Update in-memory vault: remove from personal/old org, add to org with new
    // encrypted fields. The encrypted fields stay encrypted with the old key in
    // memory until the next sync; that's intentional for simplicity.
    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                cipher.organization_id = Some(target_org_id);
                cipher.collection_ids = vec![collection_id];
                cipher.folder_id = None;
            }
        }
    }
    Ok(())
}
