use tauri::State;

use crate::crypto::decrypt_name;
use crate::error::{Error, Result};
use crate::models::{
    CardDetail, CipherCreateInput, CipherDetail, IdentityDetail, LoginDetail, SshKeyDetail,
};
use crate::services::auth::ensure_fresh_tokens;
use crate::services::cipher::{build_cipher_body, build_login_cipher_body};
use crate::state::AppState;

#[tauri::command]
pub fn get_cipher(state: State<'_, AppState>, id: String) -> Result<CipherDetail> {
    crate::state::mark_activity(&state);
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
pub async fn create_login_cipher(
    state: State<'_, AppState>,
    input: CipherCreateInput,
) -> Result<String> {
    ensure_fresh_tokens(&state).await?;
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
pub async fn update_login_cipher(
    state: State<'_, AppState>,
    cipher_id: String,
    input: CipherCreateInput,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
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

enum CreateKind {
    Personal(serde_json::Value),
    Org {
        cipher: serde_json::Value,
        collection_ids: Vec<String>,
    },
}

/// Generic creation — accepts any cipher type (Login, SecureNote, Card,
/// Identity, SshKey) based on `input.cipher_type`, and either creates a
/// personal item or an org-scoped one depending on
/// `input.organization_id`. Org items use the matching org key for
/// encryption and hit the `/ciphers/create` endpoint with a
/// `collectionIds` wrapper.
#[tauri::command]
pub async fn create_cipher(state: State<'_, AppState>, input: CipherCreateInput) -> Result<String> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, kind) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let kind = match input.organization_id.as_deref() {
            Some(org_id) => {
                let org_key = s.org_keys.get(org_id).ok_or_else(|| Error::Crypto {
                    reason: format!("no key available for organization {org_id}"),
                })?;
                let cipher_body = build_cipher_body(&input, org_key)?;
                CreateKind::Org {
                    cipher: cipher_body,
                    collection_ids: input.collection_ids.clone(),
                }
            }
            None => CreateKind::Personal(build_cipher_body(&input, &s.user_key)?),
        };
        (s.client.clone(), s.tokens.access_token.clone(), kind)
    };
    let created = match kind {
        CreateKind::Personal(body) => client.create_cipher(&access_token, &body).await?,
        CreateKind::Org {
            cipher,
            collection_ids,
        } => {
            let body = serde_json::json!({
                "cipher": cipher,
                "collectionIds": collection_ids,
            });
            client.create_org_cipher(&access_token, &body).await?
        }
    };
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
pub async fn update_cipher(
    state: State<'_, AppState>,
    cipher_id: String,
    input: CipherCreateInput,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, body) = {
        let guard = state.session.lock().unwrap();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        // Pick the encryption key based on the cipher's *current* owner,
        // not what the editor is sending. Moves between personal and org
        // must go through the dedicated share / move command — attempting
        // them here would re-encrypt with the wrong key.
        let existing_org_id = s.vault.as_ref().and_then(|v| {
            v.ciphers
                .iter()
                .find(|c| c.id == cipher_id)
                .and_then(|c| c.organization_id.clone())
        });
        let key: &crate::crypto::SymmetricKey = match existing_org_id.as_deref() {
            Some(org_id) => s.org_keys.get(org_id).ok_or_else(|| Error::Crypto {
                reason: format!("no key available for organization {org_id}"),
            })?,
            None => &s.user_key,
        };
        let mut bound_input = input;
        bound_input.organization_id = existing_org_id;
        let body = build_cipher_body(&bound_input, key)?;
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
pub async fn restore_cipher(state: State<'_, AppState>, cipher_id: String) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
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
pub async fn delete_cipher(state: State<'_, AppState>, cipher_id: String) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
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
