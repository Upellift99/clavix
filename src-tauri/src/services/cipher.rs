use crate::crypto::{
    decrypt_cipher_key, encrypt_cipher_key, encrypt_string, reencrypt_with_key, SymmetricKey,
};
use crate::error::{Error, Result};
use crate::models::{CardInput, Cipher, CipherCreateInput, IdentityInput, LoginInput, SshKeyInput};
use std::collections::HashMap;

/// The key a cipher is *owned* by: the org key for an org item, the user
/// key otherwise. Falls back to the user key when the org key is missing
/// so callers still produce a `[decrypt failed]` placeholder instead of
/// aborting the whole listing.
pub fn owning_key<'a>(
    cipher: &Cipher,
    user_key: &'a SymmetricKey,
    org_keys: &'a HashMap<String, SymmetricKey>,
) -> &'a SymmetricKey {
    cipher
        .organization_id
        .as_ref()
        .and_then(|oid| org_keys.get(oid))
        .unwrap_or(user_key)
}

/// The key a cipher's *fields* are encrypted under.
///
/// Same as the owning key, except for items that carry their own key
/// (Bitwarden "cipher key encryption"), where the owning key only unwraps
/// the item key and every field hangs off the latter. Returns `None` for
/// the common no-item-key case so the caller can keep borrowing the
/// owning key rather than cloning it.
///
/// An item key that fails to unwrap yields `None`, degrading to the same
/// `[decrypt failed]` placeholder as any other undecryptable field — one
/// broken item must not take the listing down with it.
pub fn item_key(cipher: &Cipher, owning_key: &SymmetricKey) -> Option<SymmetricKey> {
    cipher
        .key
        .as_deref()
        .and_then(|k| decrypt_cipher_key(owning_key, k).ok())
}

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

/// Validates that a cipher can be moved into the given organisation
/// collection *as a straight move*. Cross-org moves (personal → org,
/// or org A → org B) require a full share — different key, different
/// endpoint. This helper centralises the rule so the frontend's error
/// message stays consistent even if the command is called from a new
/// entry point later.
pub fn validate_move_to_collection(
    cipher_organization_id: Option<&str>,
    target_collection_organization_id: &str,
) -> Result<()> {
    if cipher_organization_id == Some(target_collection_organization_id) {
        return Ok(());
    }
    Err(Error::AuthFailed {
        message: "personal items cannot be dropped on an organization collection directly — share the item first".into(),
    })
}

/// Builds the request body for POST /ciphers/share. Re-encrypts every
/// encrypted field of `cipher` from `source_key` to `target_key` and
/// returns a JSON value ready to hand to the API client. `folderId` is
/// intentionally dropped — a folder is personal by nature and does not
/// follow the cipher into the target organization.
pub fn build_share_cipher_body(
    cipher: &Cipher,
    source_key: &SymmetricKey,
    target_key: &SymmetricKey,
    target_org_id: &str,
    collection_ids: &[String],
) -> Result<serde_json::Value> {
    // An item with its own key moves without touching its fields: they are
    // encrypted under the item key, which travels with the item. Only the
    // wrapper changes, from the source key to the target org key. Items
    // without one have every field rewrapped, source → target, as before.
    let unwrapped = item_key(cipher, source_key);
    let (from_key, to_key) = match &unwrapped {
        Some(ik) => (ik, ik),
        None => (source_key, target_key),
    };
    let rewrapped_key = unwrapped
        .as_ref()
        .map(|ik| encrypt_cipher_key(ik, target_key))
        .transpose()?;

    let reenc = |s: &str| reencrypt_with_key(s, from_key, to_key);
    let reenc_opt = |s: Option<&str>| -> Result<Option<String>> { s.map(reenc).transpose() };

    let name = reenc(&cipher.name)?;
    let notes = reenc_opt(cipher.notes.as_deref())?;

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

    Ok(serde_json::json!({
        "cipher": {
            "type": cipher.kind as u8,
            "key": rewrapped_key,
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
        "collectionIds": collection_ids,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_name, SymmetricKey};
    use crate::models::{
        CardInput, CipherCreateInput, CipherLogin, CipherLoginUri, CipherType, IdentityInput,
        LoginInput, SshKeyInput,
    };

    fn test_key() -> SymmetricKey {
        // 64 bytes of arbitrary but deterministic material — splits into
        // a 32-byte encryption key and a 32-byte MAC key inside the type.
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn other_test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(47);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn base_cipher(kind: CipherType, source_key: &SymmetricKey) -> Cipher {
        Cipher {
            id: "cipher-id".into(),
            kind,
            key: None,
            name: encrypt_string("My item", source_key).unwrap(),
            notes: None,
            organization_id: None,
            folder_id: Some("personal-folder-id".into()),
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            favorite: false,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
        }
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

    fn item_test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(3);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    /// Sharing an item that owns its key must NOT rewrap its fields under
    /// the org key — the fields stay under the item key, and only the item
    /// key is rewrapped. Rewrapping the fields while the server keeps the
    /// old `key` would leave the item undecryptable for every client.
    #[test]
    fn share_body_rewraps_the_item_key_and_leaves_fields_under_it() {
        let user = test_key();
        let org = other_test_key();
        let item = item_test_key();

        let mut cipher = base_cipher(CipherType::Login, &item);
        cipher.key = Some(encrypt_cipher_key(&item, &user).unwrap());
        cipher.login = Some(CipherLogin {
            username: Some(encrypt_string("alice", &item).unwrap()),
            password: Some(encrypt_string("hunter2", &item).unwrap()),
            totp: None,
            uris: Some(vec![CipherLoginUri {
                uri: Some(encrypt_string("https://example.com", &item).unwrap()),
            }]),
        });

        let body =
            build_share_cipher_body(&cipher, &user, &org, "org-1", &["col-1".into()]).unwrap();
        let c = &body["cipher"];

        // The wrapped key travels, rewrapped under the org key, and unwraps
        // back to the very same item key.
        let rewrapped = c["key"].as_str().expect("shared item keeps its key");
        let unwrapped = decrypt_cipher_key(&org, rewrapped).unwrap();
        assert_eq!(unwrapped.to_bytes().as_slice(), item.to_bytes().as_slice());

        // ...and the fields are still readable with the item key, not the org key.
        assert_eq!(
            decrypt_name(c["name"].as_str().unwrap(), &unwrapped).unwrap(),
            "My item"
        );
        assert_eq!(
            decrypt_name(c["login"]["password"].as_str().unwrap(), &unwrapped).unwrap(),
            "hunter2"
        );
        assert!(decrypt_name(c["name"].as_str().unwrap(), &org).is_err());
    }

    /// The pre-existing path: no item key, so every field is rewrapped
    /// source → target and no `key` is sent.
    #[test]
    fn share_body_without_item_key_rewraps_fields_under_the_org_key() {
        let user = test_key();
        let org = other_test_key();
        let cipher = base_cipher(CipherType::Login, &user);

        let body =
            build_share_cipher_body(&cipher, &user, &org, "org-1", &["col-1".into()]).unwrap();
        let c = &body["cipher"];

        assert!(c["key"].is_null());
        assert_eq!(
            decrypt_name(c["name"].as_str().unwrap(), &org).unwrap(),
            "My item"
        );
    }

    #[test]
    fn item_key_is_none_when_the_owning_key_is_wrong() {
        let user = test_key();
        let stranger = other_test_key();
        let item = item_test_key();

        let mut cipher = base_cipher(CipherType::Login, &item);
        cipher.key = Some(encrypt_cipher_key(&item, &stranger).unwrap());

        assert!(item_key(&cipher, &user).is_none());
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
    fn empty_notes_stay_null() {
        // Empty-string notes must not be encrypted — otherwise we'd emit
        // an EncString that the server would happily round-trip and the
        // detail pane would later show a blank encrypted blob. Pure
        // whitespace is *not* trimmed because the same code path also
        // encrypts passwords and SSH private keys where spaces matter.
        let mut input = base_input();
        input.cipher_type = 2;
        input.notes = Some(String::new());
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].is_null());

        input.notes = None;
        let body = build_cipher_body(&input, &test_key()).unwrap();
        assert!(body["notes"].is_null());
    }

    // ============ build_share_cipher_body ============

    #[test]
    fn share_body_drops_folder_id() {
        // folderId must be null in the share payload even when the cipher
        // currently sits inside a personal folder: folders are personal
        // and do not follow a cipher into an organization.
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);
        assert!(cipher.folder_id.is_some());

        let body = build_share_cipher_body(&cipher, &source, &target, "target-org", &[]).unwrap();
        assert!(body["cipher"]["folderId"].is_null());
    }

    #[test]
    fn share_body_reencrypts_name_with_target_key() {
        // The decisive invariant of share: after re-encryption, the name
        // must open under the target (org) key and NOT under the original
        // (personal or source-org) key. A bug here would either leak the
        // item as unreadable to all org members, or tie org data to a key
        // only the original owner can read.
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);

        let body = build_share_cipher_body(&cipher, &source, &target, "target-org", &[]).unwrap();
        let name = body["cipher"]["name"].as_str().unwrap();

        assert_eq!(decrypt_name(name, &target).unwrap(), "My item");
        assert!(
            decrypt_name(name, &source).is_err(),
            "name must no longer open under the source key"
        );
    }

    #[test]
    fn share_body_sets_target_org_and_collection_ids() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::SecureNote, &source);
        cipher.organization_id = Some("old-org".into());

        let body = build_share_cipher_body(
            &cipher,
            &source,
            &target,
            "target-org",
            &["coll-a".into(), "coll-b".into()],
        )
        .unwrap();

        assert_eq!(body["cipher"]["organizationId"], "target-org");
        let colls = body["collectionIds"].as_array().unwrap();
        assert_eq!(colls.len(), 2);
        assert_eq!(colls[0], "coll-a");
        assert_eq!(colls[1], "coll-b");
    }

    #[test]
    fn share_body_preserves_favorite_and_type() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::Card, &source);
        cipher.favorite = true;

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        assert_eq!(body["cipher"]["type"], CipherType::Card as u8);
        assert_eq!(body["cipher"]["favorite"], true);
    }

    #[test]
    fn share_body_reencrypts_login_subfields_and_uris() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::Login, &source);
        cipher.login = Some(CipherLogin {
            username: Some(encrypt_string("alice", &source).unwrap()),
            password: Some(encrypt_string("hunter2", &source).unwrap()),
            totp: Some(encrypt_string("otpauth://x", &source).unwrap()),
            uris: Some(vec![
                CipherLoginUri {
                    uri: Some(encrypt_string("https://a.example", &source).unwrap()),
                },
                CipherLoginUri {
                    uri: Some(encrypt_string("https://b.example", &source).unwrap()),
                },
            ]),
        });

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let login = &body["cipher"]["login"];
        assert_eq!(
            decrypt_name(login["username"].as_str().unwrap(), &target).unwrap(),
            "alice"
        );
        assert_eq!(
            decrypt_name(login["password"].as_str().unwrap(), &target).unwrap(),
            "hunter2"
        );
        assert_eq!(
            decrypt_name(login["totp"].as_str().unwrap(), &target).unwrap(),
            "otpauth://x"
        );
        let uris = login["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(
            decrypt_name(uris[0]["uri"].as_str().unwrap(), &target).unwrap(),
            "https://a.example"
        );
        assert!(uris[0]["match"].is_null());
    }

    #[test]
    fn share_body_reencrypts_ssh_private_key() {
        // The SSH private key is the most sensitive field — any corruption
        // in the re-encryption loses the user's identity. Verify end-to-end
        // that the original PEM round-trips verbatim under the target key.
        let source = test_key();
        let target = other_test_key();
        let pem =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabcdef\n-----END OPENSSH PRIVATE KEY-----\n";
        let mut cipher = base_cipher(CipherType::SshKey, &source);
        cipher.ssh_key = Some(crate::models::CipherSshKey {
            private_key: Some(encrypt_string(pem, &source).unwrap()),
            public_key: Some(encrypt_string("ssh-ed25519 AAAA", &source).unwrap()),
            key_fingerprint: None,
        });

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let ssh = &body["cipher"]["sshKey"];
        assert_eq!(
            decrypt_name(ssh["privateKey"].as_str().unwrap(), &target).unwrap(),
            pem
        );
        assert!(ssh["keyFingerprint"].is_null());
    }

    #[test]
    fn share_body_keeps_optional_fields_null_when_absent() {
        // A SecureNote has none of login/card/identity/sshKey set; the
        // corresponding body fields must remain null so the server keeps
        // the cipher as a pure SecureNote instead of accidentally
        // promoting it.
        let source = test_key();
        let target = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        let c = &body["cipher"];
        assert!(c["login"].is_null());
        assert!(c["card"].is_null());
        assert!(c["identity"].is_null());
        assert!(c["sshKey"].is_null());
        assert!(c["notes"].is_null());
    }

    #[test]
    fn share_body_reencrypts_notes_when_present() {
        let source = test_key();
        let target = other_test_key();
        let mut cipher = base_cipher(CipherType::SecureNote, &source);
        cipher.notes = Some(encrypt_string("line 1\nline 2\n", &source).unwrap());

        let body = build_share_cipher_body(&cipher, &source, &target, "org", &[]).unwrap();
        assert_eq!(
            decrypt_name(body["cipher"]["notes"].as_str().unwrap(), &target).unwrap(),
            "line 1\nline 2\n"
        );
    }

    #[test]
    fn share_body_errors_when_source_key_cannot_decrypt() {
        // Mismatched source key must bubble up as a crypto error, not
        // produce a body ciphertext nobody can read.
        let source = test_key();
        let target = other_test_key();
        let wrong = other_test_key();
        let cipher = base_cipher(CipherType::SecureNote, &source);

        let err = build_share_cipher_body(&cipher, &wrong, &target, "org", &[]).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::Crypto { .. } | crate::error::Error::InvalidResponse { .. }
        ));
    }

    // ============ validate_move_to_collection ============

    #[test]
    fn move_to_collection_allows_same_org() {
        assert!(validate_move_to_collection(Some("org-1"), "org-1").is_ok());
    }

    #[test]
    fn move_to_collection_rejects_personal_into_org() {
        // The UX rule: drag-drop a personal item onto an org collection
        // silently "would" re-encrypt under the org key, which is a
        // security-sensitive change disguised as a move. Force the user
        // through the explicit share path instead.
        let err = validate_move_to_collection(None, "org-1").unwrap_err();
        assert!(matches!(err, Error::AuthFailed { .. }));
    }

    #[test]
    fn move_to_collection_rejects_cross_org() {
        let err = validate_move_to_collection(Some("org-a"), "org-b").unwrap_err();
        assert!(matches!(err, Error::AuthFailed { .. }));
    }
}
