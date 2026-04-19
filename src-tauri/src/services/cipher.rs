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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SymmetricKey;
    use crate::models::{CardInput, CipherCreateInput, IdentityInput, LoginInput, SshKeyInput};

    fn test_key() -> SymmetricKey {
        // 64 bytes of arbitrary but deterministic material — splits into
        // a 32-byte encryption key and a 32-byte MAC key inside the type.
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn base_input() -> CipherCreateInput {
        CipherCreateInput {
            name: "My item".into(),
            folder_id: None,
            favorite: false,
            notes: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            cipher_type: 1,
            organization_id: None,
            collection_ids: vec![],
        }
    }

    #[test]
    fn login_body_has_encrypted_login_subobject() {
        let mut input = base_input();
        input.login = Some(LoginInput {
            username: Some("alice".into()),
            password: Some("hunter2".into()),
            uris: vec!["https://example.com".into(), "".into()],
            totp: None,
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert_eq!(body["type"], 1);
        assert!(body["name"].as_str().unwrap().starts_with("2."));
        let login = &body["login"];
        assert!(login["username"].as_str().unwrap().starts_with("2."));
        assert!(login["password"].as_str().unwrap().starts_with("2."));
        assert!(login["totp"].is_null());
        let uris = login["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 1, "empty URI should be dropped");
        assert!(uris[0]["uri"].as_str().unwrap().starts_with("2."));
        assert!(uris[0]["match"].is_null());
    }

    #[test]
    fn secure_note_body_carries_sub_type_and_no_login() {
        let mut input = base_input();
        input.cipher_type = 2;
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert_eq!(body["type"], 2);
        assert_eq!(body["secureNote"]["type"], 0);
        assert!(body.get("login").is_none());
    }

    #[test]
    fn card_body_encrypts_each_field() {
        let mut input = base_input();
        input.cipher_type = 3;
        input.card = Some(CardInput {
            cardholder_name: Some("A. B.".into()),
            brand: None,
            number: Some("4111 1111 1111 1111".into()),
            exp_month: Some("12".into()),
            exp_year: Some("2030".into()),
            code: Some("123".into()),
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        let card = &body["card"];
        assert!(card["cardholderName"].as_str().unwrap().starts_with("2."));
        assert!(card["number"].as_str().unwrap().starts_with("2."));
        assert!(card["brand"].is_null(), "missing field stays null");
    }

    #[test]
    fn identity_body_encrypts_all_set_fields() {
        let mut input = base_input();
        input.cipher_type = 4;
        input.identity = Some(IdentityInput {
            first_name: Some("Alice".into()),
            last_name: Some("Doe".into()),
            email: Some("a@example.com".into()),
            ..Default::default()
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        let id = &body["identity"];
        assert!(id["firstName"].as_str().unwrap().starts_with("2."));
        assert!(id["lastName"].as_str().unwrap().starts_with("2."));
        assert!(id["email"].as_str().unwrap().starts_with("2."));
        assert!(id["ssn"].is_null());
    }

    #[test]
    fn ssh_key_body_preserves_private_key_whitespace() {
        let mut input = base_input();
        input.cipher_type = 5;
        input.ssh_key = Some(SshKeyInput {
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----\n".into()),
            public_key: Some("ssh-ed25519 AAAA".into()),
            key_fingerprint: Some("SHA256:xxx".into()),
        });
        let body = build_cipher_body(&input, &test_key()).unwrap();
        let ssh = &body["sshKey"];
        assert!(ssh["privateKey"].as_str().unwrap().starts_with("2."));
        assert!(ssh["publicKey"].as_str().unwrap().starts_with("2."));
    }

    #[test]
    fn org_scoping_injects_organization_id() {
        let mut input = base_input();
        input.cipher_type = 2;
        input.organization_id = Some("org-uuid".into());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert_eq!(body["organizationId"], "org-uuid");
    }

    #[test]
    fn missing_variant_payload_is_a_storage_error() {
        let mut input = base_input();
        input.cipher_type = 1; // says Login, but no login field
        input.login = None;
        let err = build_cipher_body(&input, &test_key()).unwrap_err();
        assert!(matches!(err, Error::Storage { .. }));
    }

    #[test]
    fn unsupported_cipher_type_errors_out() {
        let mut input = base_input();
        input.cipher_type = 99;
        let err = build_cipher_body(&input, &test_key()).unwrap_err();
        assert!(matches!(err, Error::Storage { .. }));
    }

    #[test]
    fn notes_are_encrypted_when_non_empty() {
        let mut input = base_input();
        input.cipher_type = 2;
        input.notes = Some("  a multi-line\nnote\n".into());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].as_str().unwrap().starts_with("2."));
    }

    #[test]
    fn blank_notes_stay_null() {
        let mut input = base_input();
        input.cipher_type = 2;
        input.notes = Some("   ".into());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].is_null());
    }
}
