use crate::crypto::{encrypt_string, SymmetricKey};
use crate::error::{Error, Result};
use crate::models::{CardInput, CipherCreateInput, IdentityInput, LoginInput, SshKeyInput};

fn enc_opt(s: Option<&str>, key: &SymmetricKey) -> Result<Option<String>> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| encrypt_string(s, key))
        .transpose()
}

fn enc_opt_raw(s: Option<&str>, key: &SymmetricKey) -> Result<Option<String>> {
    // Same as enc_opt but preserves whitespace (for multi-line SSH keys, notes,
    // passwords).  Only skips `None` and empty strings.
    s.filter(|s| !s.is_empty())
        .map(|s| encrypt_string(s, key))
        .transpose()
}

fn encrypt_login(login: &LoginInput, key: &SymmetricKey) -> Result<serde_json::Value> {
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

    Ok(serde_json::json!({
        "username": enc_opt(login.username.as_deref(), key)?,
        "password": enc_opt_raw(login.password.as_deref(), key)?,
        "uris": uris_val,
        "totp": enc_opt(login.totp.as_deref(), key)?,
    }))
}

fn encrypt_card(card: &CardInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "cardholderName": enc_opt(card.cardholder_name.as_deref(), key)?,
        "brand": enc_opt(card.brand.as_deref(), key)?,
        "number": enc_opt(card.number.as_deref(), key)?,
        "expMonth": enc_opt(card.exp_month.as_deref(), key)?,
        "expYear": enc_opt(card.exp_year.as_deref(), key)?,
        "code": enc_opt(card.code.as_deref(), key)?,
    }))
}

fn encrypt_identity(id: &IdentityInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "title": enc_opt(id.title.as_deref(), key)?,
        "firstName": enc_opt(id.first_name.as_deref(), key)?,
        "middleName": enc_opt(id.middle_name.as_deref(), key)?,
        "lastName": enc_opt(id.last_name.as_deref(), key)?,
        "address1": enc_opt(id.address1.as_deref(), key)?,
        "address2": enc_opt(id.address2.as_deref(), key)?,
        "address3": enc_opt(id.address3.as_deref(), key)?,
        "city": enc_opt(id.city.as_deref(), key)?,
        "state": enc_opt(id.state.as_deref(), key)?,
        "postalCode": enc_opt(id.postal_code.as_deref(), key)?,
        "country": enc_opt(id.country.as_deref(), key)?,
        "company": enc_opt(id.company.as_deref(), key)?,
        "email": enc_opt(id.email.as_deref(), key)?,
        "phone": enc_opt(id.phone.as_deref(), key)?,
        "ssn": enc_opt(id.ssn.as_deref(), key)?,
        "username": enc_opt(id.username.as_deref(), key)?,
        "passportNumber": enc_opt(id.passport_number.as_deref(), key)?,
        "licenseNumber": enc_opt(id.license_number.as_deref(), key)?,
    }))
}

fn encrypt_ssh_key(ssh: &SshKeyInput, key: &SymmetricKey) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "privateKey": enc_opt_raw(ssh.private_key.as_deref(), key)?,
        "publicKey": enc_opt(ssh.public_key.as_deref(), key)?,
        "keyFingerprint": enc_opt(ssh.key_fingerprint.as_deref(), key)?,
    }))
}

pub fn build_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
) -> Result<serde_json::Value> {
    let name_enc = encrypt_string(&input.name, key)?;
    let notes_enc = enc_opt_raw(input.notes.as_deref(), key)?;

    let mut body = serde_json::json!({
        "type": input.cipher_type,
        "name": name_enc,
        "notes": notes_enc,
        "folderId": input.folder_id,
        "favorite": input.favorite,
        "organizationId": input.organization_id,
    });
    let obj = body.as_object_mut().expect("json! returned a map");

    match input.cipher_type {
        1 => {
            let login = input.login.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=1 (Login) requires a login field".into(),
            })?;
            obj.insert("login".into(), encrypt_login(login, key)?);
        }
        2 => {
            // SecureNote: Bitwarden expects a SecureNote sub-object with type=0.
            obj.insert("secureNote".into(), serde_json::json!({ "type": 0 }));
        }
        3 => {
            let card = input.card.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=3 (Card) requires a card field".into(),
            })?;
            obj.insert("card".into(), encrypt_card(card, key)?);
        }
        4 => {
            let id = input.identity.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=4 (Identity) requires an identity field".into(),
            })?;
            obj.insert("identity".into(), encrypt_identity(id, key)?);
        }
        5 => {
            let ssh = input.ssh_key.as_ref().ok_or_else(|| Error::Storage {
                reason: "cipher_type=5 (SshKey) requires an sshKey field".into(),
            })?;
            obj.insert("sshKey".into(), encrypt_ssh_key(ssh, key)?);
        }
        n => {
            return Err(Error::Storage {
                reason: format!("unsupported cipher type: {n}"),
            });
        }
    }

    Ok(body)
}

/// Backwards-compatible alias — used to be the only builder.  Kept so
/// the existing `create_login_cipher` / `update_login_cipher` Tauri
/// commands stay valid.
pub fn build_login_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
) -> Result<serde_json::Value> {
    // Force Login type so an older frontend that omits `cipher_type`
    // still ends up creating a Login.
    let mut input = input.clone();
    input.cipher_type = 1;
    build_cipher_body(&input, key)
}
