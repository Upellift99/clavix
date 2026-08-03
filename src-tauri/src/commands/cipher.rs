use tauri::State;

use crate::session::ensure_fresh_tokens;
use crate::state::AppState;
use clavix_core::crypto::decrypt_name;
use clavix_core::error::{Error, Result};
use clavix_core::models::{
    AttachmentDetail, CardDetail, CipherCreateInput, CipherDetail, CustomFieldDetail,
    IdentityDetail, LoginDetail, PasswordHistoryEntry, SshKeyDetail,
};
use clavix_core::services::cipher::{
    build_cipher_body, build_login_cipher_body, build_update_cipher_body, item_key, owning_key,
};

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

    // A field is "present" when it decrypts to a non-empty value; secrets are
    // reported as booleans only and fetched on demand via `reveal_field`.
    let present =
        |s: Option<&str>| -> bool { s.and_then(decrypt_opt).is_some_and(|v| !v.is_empty()) };

    let login = cipher.login.as_ref().map(|l| LoginDetail {
        username: l.username.as_deref().and_then(decrypt_opt),
        has_password: present(l.password.as_deref()),
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
        has_number: present(c.number.as_deref()),
        exp_month: c.exp_month.as_deref().and_then(decrypt_opt),
        exp_year: c.exp_year.as_deref().and_then(decrypt_opt),
        has_code: present(c.code.as_deref()),
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
        has_ssn: present(i.ssn.as_deref()),
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

    // Custom fields keep their vault order — `reveal_field("custom:<i>")`
    // indexes into this same list, so re-ordering here would reveal the
    // wrong field.
    let fields = cipher
        .fields
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|f| {
            let kind = f.kind.unwrap_or(0);
            let hidden = kind == FIELD_KIND_HIDDEN;
            CustomFieldDetail {
                name: f.name.as_deref().and_then(decrypt_opt),
                kind,
                // Hidden fields are secrets and follow the same rule as
                // passwords: presence here, value on demand.
                value: if hidden {
                    None
                } else {
                    f.value.as_deref().and_then(decrypt_opt)
                },
                hidden,
            }
        })
        .collect();

    let attachments = cipher
        .attachments
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|a| AttachmentDetail {
            id: a.id.clone(),
            file_name: a.file_name.as_deref().and_then(decrypt_opt),
            size_name: a.size_name.clone(),
            size: a
                .size
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32,
        })
        .collect();

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
        fields,
        password_history_count: cipher
            .password_history
            .as_deref()
            .map_or(0, |h| h.len().min(u32::MAX as usize) as u32),
        attachments,
        reprompt: cipher.reprompt.unwrap_or(0) != 0,
    })
}

/// Bitwarden custom-field type for a hidden (secret) value.
const FIELD_KIND_HIDDEN: u8 = 1;

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
        // `custom:<index>` addresses a hidden custom field by its position
        // in the cipher's own `fields` list — the same order `get_cipher`
        // reports, so the renderer never has to name a secret field.
        custom if custom.starts_with("custom:") => {
            let index: usize = custom["custom:".len()..]
                .parse()
                .map_err(|_| Error::Storage {
                    reason: format!("malformed custom field selector: {custom}"),
                })?;
            cipher
                .fields
                .as_deref()
                .and_then(|f| f.get(index))
                .and_then(|f| f.value.as_deref())
        }
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

/// Past passwords of an item, newest first, decrypted on demand.
///
/// Same rule as every other secret: this is a command the user has to
/// reach for, not something `get_cipher` hands out. Entries that fail to
/// decrypt are dropped rather than shown as placeholders — an old
/// password is only useful if it is the real one.
#[tauri::command]
pub fn password_history(
    state: State<'_, AppState>,
    id: String,
) -> Result<Vec<PasswordHistoryEntry>> {
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

    Ok(cipher
        .password_history
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|h| {
            let password = h
                .password
                .as_deref()
                .and_then(|p| decrypt_name(p, key).ok())?;
            Some(PasswordHistoryEntry {
                password,
                last_used_date: h.last_used_date.clone(),
            })
        })
        .collect())
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
///
/// Deliberately does **not** call `mark_activity`. A timer firing on its own
/// is not a user being present, and at one call a second this was enough to
/// hold `last_activity` permanently fresh: with any TOTP item selected the
/// backend auto-lock watchdog could never reach its idle threshold, including
/// on a locked screen with nobody at the machine. The renderer's own idle
/// timer never counted these polls either — it only watches mouse and
/// keyboard — so dropping this makes the two agree rather than changing what
/// a user sees.
#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, id: String) -> Result<clavix_core::totp::TotpCode> {
    let secret = decrypt_totp_secret(&state, &id)?.ok_or_else(|| Error::Storage {
        reason: "item has no TOTP secret".into(),
    })?;
    clavix_core::totp::code_now(&secret)
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

        let owner: &clavix_core::crypto::SymmetricKey = match existing_org_id.as_deref() {
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
            .map(|k| clavix_core::crypto::decrypt_cipher_key(owner, k))
            .transpose()?;
        let key = unwrapped.as_ref().unwrap_or(owner);

        let mut bound_input = input;
        bound_input.organization_id = existing_org_id;
        // `build_update_cipher_body`, not `build_cipher_body`: the PUT
        // replaces the server's copy wholesale, so the password history
        // has to be carried across explicitly or it is deleted.
        let mut body = match existing {
            Some(cipher) => build_update_cipher_body(
                &bound_input,
                key,
                cipher,
                &clavix_core::time::now_iso8601(),
            )?,
            None => build_cipher_body(&bound_input, key)?,
        };
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

/// Copy an item. `name_suffix` is appended to the original's name (the
/// renderer supplies the localised " (copy)").
///
/// The copy is rebuilt from decrypted values inside Rust and re-encrypted
/// under the owning key, so no secret crosses to the WebView and the copy
/// never shares an item key with the original. Attachments are not
/// duplicated — see `cipher_to_create_input`.
#[tauri::command]
pub async fn duplicate_cipher(
    state: State<'_, AppState>,
    cipher_id: String,
    name_suffix: String,
) -> Result<String> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, kind) = {
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

        let owner = owning_key(cipher, &s.user_key, &s.org_keys);
        let item = item_key(cipher, owner);
        let read_key = item.as_ref().unwrap_or(owner);

        let mut input = clavix_core::services::cipher::cipher_to_create_input(cipher, read_key)?;
        input.name.push_str(&name_suffix);

        // The copy is written under the owning key, without an item key of
        // its own — `build_cipher_body` encrypts every field with the key
        // we hand it, and no `key` in the body means the server stores the
        // fields exactly that way.
        let body = build_cipher_body(&input, owner)?;
        let kind = if cipher.organization_id.is_some() {
            CreateKind::Org {
                cipher: body,
                collection_ids: input.collection_ids.clone(),
            }
        } else {
            CreateKind::Personal(body)
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

/// Hard ceiling on an attachment, enforced here as well as in the UI.
/// Attachment bytes make three round trips through memory (decoded,
/// encrypted, uploaded) and cross the IPC boundary as base64; a file
/// large enough to matter would take the WebView down before the server
/// ever refused it.
const ATTACHMENT_MAX_BYTES: usize = 100 * 1024 * 1024;

/// Decrypt an attachment and hand it back as base64.
///
/// Base64 rather than the `number[]` the KDBX import uses: a JSON array
/// of integers costs about four bytes per byte of file, which is a real
/// tax at attachment sizes. The renderer turns this back into a Blob and
/// offers it as a download — the plaintext never touches the disk from
/// our side.
#[tauri::command]
pub async fn download_attachment(
    state: State<'_, AppState>,
    cipher_id: String,
    attachment_id: String,
) -> Result<String> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token, url, file_key) = {
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
        let attachment = cipher
            .attachments
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find(|a| a.id == attachment_id)
            .ok_or_else(|| Error::Storage {
                reason: format!("attachment not found: {attachment_id}"),
            })?;

        let owner = owning_key(cipher, &s.user_key, &s.org_keys);
        let item = item_key(cipher, owner);
        let cipher_key = item.as_ref().unwrap_or(owner);
        // v2 attachments carry their own key, wrapped under the cipher
        // key. Legacy ones (no `key`) are encrypted under the cipher key
        // itself.
        let file_key = match attachment.key.as_deref() {
            Some(wrapped) => clavix_core::crypto::decrypt_cipher_key(cipher_key, wrapped)?,
            None => {
                clavix_core::crypto::SymmetricKey::from_bytes(cipher_key.to_bytes().as_slice())?
            }
        };

        // Fall back to the canonical path on our own server when the
        // vault carries no URL for the attachment.
        let url = attachment.url.clone().unwrap_or_else(|| {
            format!(
                "{}attachments/{cipher_id}/{attachment_id}",
                s.client.base_url()
            )
        });
        (
            s.client.clone(),
            s.tokens.access_token.clone(),
            url,
            file_key,
        )
    };

    let encrypted = client.download_attachment(&access_token, &url).await?;
    let plaintext = clavix_core::crypto::decrypt_buffer(&encrypted, &file_key)?;
    Ok(base64_encode(&plaintext))
}

/// Encrypt a file and attach it to an item.
///
/// `data_base64` is the raw file as the renderer read it. Everything the
/// server sees is encrypted here: the payload under a per-file key
/// generated for this upload, the file name under the cipher's key, and
/// the file key itself wrapped under the cipher's key.
#[tauri::command]
pub async fn upload_attachment(
    state: State<'_, AppState>,
    cipher_id: String,
    file_name: String,
    data_base64: String,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;

    let plaintext = base64_decode(&data_base64)?;
    if plaintext.is_empty() {
        return Err(Error::Storage {
            reason: "refusing to attach an empty file".into(),
        });
    }
    if plaintext.len() > ATTACHMENT_MAX_BYTES {
        return Err(Error::Storage {
            reason: format!(
                "attachment is {} bytes, over the {ATTACHMENT_MAX_BYTES}-byte limit",
                plaintext.len()
            ),
        });
    }

    let (client, access_token, encrypted_name, encrypted_data, wrapped_key) = {
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
        let owner = owning_key(cipher, &s.user_key, &s.org_keys);
        let item = item_key(cipher, owner);
        let cipher_key = item.as_ref().unwrap_or(owner);

        let file_key = clavix_core::crypto::SymmetricKey::generate();
        let encrypted_data = clavix_core::crypto::encrypt_buffer(&plaintext, &file_key)?;
        let wrapped_key = clavix_core::crypto::encrypt_cipher_key(&file_key, cipher_key)?;
        let encrypted_name = clavix_core::crypto::encrypt_string(&file_name, cipher_key)?;
        (
            s.client.clone(),
            s.tokens.access_token.clone(),
            encrypted_name,
            encrypted_data,
            wrapped_key,
        )
    };

    // `fileSize` is the size of the *ciphertext*: it is what the server
    // stores and what it checks the upload against.
    let slot = client
        .attachment_upload_slot(
            &access_token,
            &cipher_id,
            &serde_json::json!({
                "key": wrapped_key,
                "fileName": encrypted_name,
                "fileSize": encrypted_data.len(),
                "adminRequest": false,
            }),
        )
        .await?;
    let attachment_id = slot
        .get("attachmentId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidResponse {
            reason: "attachment/v2 response carried no attachmentId".into(),
        })?
        .to_owned();

    client
        .upload_attachment_data(
            &access_token,
            &cipher_id,
            &attachment_id,
            &encrypted_name,
            encrypted_data,
        )
        .await?;

    // The v2 response embeds the updated cipher; adopting it here means
    // the new attachment shows up without waiting for the next sync.
    if let Some(updated) = slot.get("cipherResponse") {
        if let Ok(cipher) = serde_json::from_value::<clavix_core::models::Cipher>(updated.clone()) {
            let mut guard = state.session.lock();
            if let Some(session) = guard.as_mut() {
                if let Some(vault) = session.vault.as_mut() {
                    if let Some(slot) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                        *slot = cipher;
                    }
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn delete_attachment(
    state: State<'_, AppState>,
    cipher_id: String,
    attachment_id: String,
) -> Result<()> {
    ensure_fresh_tokens(&state).await?;
    let (client, access_token) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        (s.client.clone(), s.tokens.access_token.clone())
    };
    client
        .delete_attachment(&access_token, &cipher_id, &attachment_id)
        .await?;

    let mut guard = state.session.lock();
    if let Some(session) = guard.as_mut() {
        if let Some(vault) = session.vault.as_mut() {
            if let Some(cipher) = vault.ciphers.iter_mut().find(|c| c.id == cipher_id) {
                if let Some(attachments) = cipher.attachments.as_mut() {
                    attachments.retain(|a| a.id != attachment_id);
                }
            }
        }
    }
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| Error::Storage {
            reason: format!("invalid base64 payload: {e}"),
        })
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
