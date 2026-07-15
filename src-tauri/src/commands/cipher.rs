use tauri::State;

use crate::crypto::decrypt_name;
use crate::error::{Error, Result};
use crate::models::{
    CardDetail, CipherCreateInput, CipherDetail, IdentityDetail, LoginDetail, SshKeyDetail,
};
use crate::services::auth::ensure_fresh_tokens;
use crate::services::cipher::{build_cipher_body, build_login_cipher_body, item_key, owning_key};
use crate::state::AppState;

#[tauri::command]
pub fn get_cipher(state: State<'_, AppState>, id: String) -> Result<CipherDetail> {
    crate::state::mark_activity(&state);
    let guard = state.session.lock();
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

    let owner = owning_key(cipher, &session.user_key, &session.org_keys);
    let item = item_key(cipher, owner);
    let key = item.as_ref().unwrap_or(owner);

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
        // Presence only — the seed stays in Rust (see `totp_code`).
        has_totp: l.totp.as_deref().is_some_and(|t| !t.is_empty()),
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
        // Presence only — the private key stays in Rust (see `reveal_field`).
        has_private_key: s.private_key.as_deref().is_some_and(|k| !k.is_empty()),
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

/// Decrypt a single secret field of a cipher on demand, by id + field name, so
/// full plaintext secrets are not eagerly returned by `get_cipher` and left in
/// long-lived JS reactive state. `field` is one of: "password", "cardNumber",
/// "cardCode", "ssn", "sshPrivateKey". Returns None when the field is
/// absent/empty.
#[tauri::command]
pub fn reveal_field(
    state: State<'_, AppState>,
    id: String,
    field: String,
) -> Result<Option<String>> {
    crate::state::mark_activity(&state);
    let guard = state.session.lock();
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
    let owner = owning_key(cipher, &session.user_key, &session.org_keys);
    let item = item_key(cipher, owner);
    let key = item.as_ref().unwrap_or(owner);

    let enc: Option<&str> = match field.as_str() {
        "password" => cipher.login.as_ref().and_then(|l| l.password.as_deref()),
        "cardNumber" => cipher.card.as_ref().and_then(|c| c.number.as_deref()),
        "cardCode" => cipher.card.as_ref().and_then(|c| c.code.as_deref()),
        "ssn" => cipher.identity.as_ref().and_then(|i| i.ssn.as_deref()),
        "sshPrivateKey" => cipher
            .ssh_key
            .as_ref()
            .and_then(|s| s.private_key.as_deref()),
        other => {
            return Err(Error::Storage {
                reason: format!("unknown reveal field: {other}"),
            })
        }
    };
    Ok(enc
        .and_then(|e| decrypt_name(e, key).ok())
        .filter(|s| !s.is_empty()))
}

/// Decrypt a login item's TOTP secret (otpauth URI or bare base32) by id,
/// under its item/owning key. Kept in Rust so the seed never reaches JS.
fn decrypt_totp_secret(state: &AppState, id: &str) -> Result<Option<String>> {
    let guard = state.session.lock();
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
    let owner = owning_key(cipher, &session.user_key, &session.org_keys);
    let item = item_key(cipher, owner);
    let key = item.as_ref().unwrap_or(owner);
    Ok(cipher
        .login
        .as_ref()
        .and_then(|l| l.totp.as_deref())
        .and_then(|t| decrypt_name(t, key).ok())
        .filter(|s| !s.is_empty()))
}

/// Current TOTP code + seconds remaining for a login item. Computed in Rust so
/// the shared secret stays out of the WebView (a leaked seed = permanent 2FA
/// bypass). The renderer polls this once a second for the live field.
#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, id: String) -> Result<crate::totp::TotpCode> {
    crate::state::mark_activity(&state);
    let secret = decrypt_totp_secret(&state, &id)?.ok_or_else(|| Error::Storage {
        reason: "item has no TOTP secret".into(),
    })?;
    crate::totp::code_now(&secret)
}

/// The raw TOTP secret, only for the editor (to edit it) and export (to write
/// it out) — the two legitimate places that need the seed itself rather than a
/// code. Everything else uses `totp_code`.
#[tauri::command]
pub fn reveal_login_totp(state: State<'_, AppState>, id: String) -> Result<Option<String>> {
    crate::state::mark_activity(&state);
    decrypt_totp_secret(&state, &id)
}

#[tauri::command]
pub async fn create_login_cipher(
    state: State<'_, AppState>,
    input: CipherCreateInput,
) -> Result<String> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, body) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let body = build_login_cipher_body(&input, &s.user_key)?;
        (s.client.clone(), s.tokens.access_token.clone(), body)
    };
    let created = client.create_cipher(&access_token, &body).await?;
    let id = created.id.clone();

    let mut guard = state.session.lock();
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
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let body = build_login_cipher_body(&input, &s.user_key)?;
        (s.client.clone(), s.tokens.access_token.clone(), body)
    };
    let updated = client
        .update_cipher(&access_token, &cipher_id, &body)
        .await?;

    let mut guard = state.session.lock();
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
        let guard = state.session.lock();
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

    let mut guard = state.session.lock();
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
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        // Pick the encryption key based on the cipher's *current* owner,
        // not what the editor is sending. Moves between personal and org
        // must go through the dedicated share / move command — attempting
        // them here would re-encrypt with the wrong key.
        let existing = s
            .vault
            .as_ref()
            .and_then(|v| v.ciphers.iter().find(|c| c.id == cipher_id));
        let existing_org_id = existing.and_then(|c| c.organization_id.clone());
        let existing_item_key = existing.and_then(|c| c.key.clone());

        let owner: &crate::crypto::SymmetricKey = match existing_org_id.as_deref() {
            Some(org_id) => s.org_keys.get(org_id).ok_or_else(|| Error::Crypto {
                reason: format!("no key available for organization {org_id}"),
            })?,
            None => &s.user_key,
        };

        // An item that carries its own key keeps it: re-encrypt the fields
        // under the item key and echo the wrapped key back untouched. Writing
        // the fields under the owning key instead would leave the server's
        // `key` in place and make the item undecryptable for every client,
        // this one included.
        let unwrapped = existing_item_key
            .as_deref()
            .map(|k| crate::crypto::decrypt_cipher_key(owner, k))
            .transpose()?;
        let key = unwrapped.as_ref().unwrap_or(owner);

        let mut bound_input = input;
        bound_input.organization_id = existing_org_id;
        let mut body = build_cipher_body(&bound_input, key)?;
        if let Some(wrapped) = existing_item_key {
            body.as_object_mut()
                .expect("build_cipher_body returns a map")
                .insert("key".into(), serde_json::Value::String(wrapped));
        }
        (s.client.clone(), s.tokens.access_token.clone(), body)
    };
    let updated = client
        .update_cipher(&access_token, &cipher_id, &body)
        .await?;

    let mut guard = state.session.lock();
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
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client.restore_cipher(&access_token, &cipher_id).await?;

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                cipher.deleted_date = None;
            }
        }
    }
    Ok(())
}

/// Move a cipher to the trash. Reversible via `restore_cipher` until
/// either the user empties the trash via `delete_cipher` (hard) or
/// another client wipes it. The vault keeps the row; only its
/// `deleted_date` is non-null.
#[tauri::command]
pub async fn soft_delete_cipher(state: State<'_, AppState>, cipher_id: String) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client.soft_delete_cipher(&access_token, &cipher_id).await?;

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                // Optimistic: any non-null value moves the cipher
                // into the trash bucket of every filter helper. The
                // next sync overwrites this with the authoritative
                // ISO 8601 timestamp from the server.
                cipher.deleted_date = Some("pending-sync".into());
            }
        }
    }
    Ok(())
}

/// Permanent delete: removes the cipher row from the server. Used
/// from inside the trash for the "Supprimer définitivement" action.
/// Soft-deleting first via `soft_delete_cipher` is the default path
/// for normal items.
#[tauri::command]
pub async fn delete_cipher(state: State<'_, AppState>, cipher_id: String) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client.delete_cipher(&access_token, &cipher_id).await?;

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            vault.ciphers.retain(|c| c.id != cipher_id);
        }
    }
    Ok(())
}
