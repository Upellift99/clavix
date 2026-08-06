//! Password-protected vault exports.
//!
//! # Why not Bitwarden's format
//!
//! Bitwarden's password-protected export decrypts, in one step, to a
//! JSON document holding the whole vault in the clear. Ours doesn't:
//! `data` is a [`SyncResponse`] whose items are still individually
//! encrypted, just under a **fresh vault key** generated for the file
//! and wrapped under the file password. Two consequences, both
//! deliberate:
//!
//! - The plaintext vault never exists as one blob, in the file or in
//!   memory. Opening an export decrypts a key, not a vault.
//! - A reader that can render a [`SyncResponse`] can render an export.
//!   Every existing read path — `build_sync_summary`, `get_cipher`,
//!   `reveal_field`, `totp_code` — works on one unchanged, with the
//!   vault key in the slot the user key normally occupies.
//!
//! The cost is that the file is Clavix-shaped rather than a flat,
//! eyeball-readable JSON dump. The plain CSV export stays for
//! interoperability with other password managers.
//!
//! # File layout
//!
//! ```json
//! {
//!   "format": "clavix.vault.encrypted",
//!   "version": 1,
//!   "kdf": { "type": 1, "iterations": 3, "memoryMib": 64, "parallelism": 4 },
//!   "salt": "<16 random bytes, base64>",
//!   "headerAuth": "2.iv|ct|mac",
//!   "protectedKey": "2.iv|ct|mac",
//!   "data": "2.iv|ct|mac"
//! }
//! ```
//!
//! `headerAuth` is the encryption of the canonical header. An
//! `EncString`'s MAC only covers `iv || ct`, so without this the KDF
//! parameters and the salt would sit outside any integrity check.
//! Bitwarden encrypts a random GUID in the equivalent slot and gets
//! only a password check; encrypting the header instead gets the
//! password check *and* binds the parameters, for the same cost.
//!
//! Note the ordering that makes this safe: the KDF floors in
//! [`derive_file_key`] are enforced *before* any derivation, so a file
//! claiming `iterations: 1` is rejected outright rather than being
//! caught later by a MAC failure.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    derive_file_key, encrypt_bytes, encrypt_string, reencrypt_with_key, stretch_master_key,
    EncString, SymmetricKey,
};
use crate::error::{Error, Result};
use crate::models::{
    Cipher, CipherAttachment, CipherCard, CipherField, CipherIdentity, CipherLogin, CipherLoginUri,
    CipherPasswordHistory, CipherSshKey, Collection, Folder, KdfType, SyncResponse,
};
use crate::services::cipher::{item_key, owning_key};

pub const FORMAT_TAG: &str = "clavix.vault.encrypted";
pub const FORMAT_VERSION: u32 = 1;

/// Argon2id parameters for newly written exports. Chosen to be
/// noticeably heavier than the login KDF: an export file is a
/// long-lived artefact that may sit on a USB stick for years, and the
/// user pays this cost twice in the file's lifetime — once writing it,
/// once reading it — rather than at every unlock.
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_MEMORY_MIB: u32 = 64;
pub const DEFAULT_PARALLELISM: u32 = 4;

/// Refuse to parse anything larger. A vault of a few thousand items
/// serialises to a handful of megabytes; the cap is what stops a
/// hostile file from forcing a huge allocation before we have looked
/// at a single byte of it.
pub const MAX_EXPORT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    #[serde(rename = "type")]
    pub kind: KdfType,
    pub iterations: u32,
    #[serde(default)]
    pub memory_mib: Option<u32>,
    #[serde(default)]
    pub parallelism: Option<u32>,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            kind: KdfType::Argon2id,
            iterations: DEFAULT_ITERATIONS,
            memory_mib: Some(DEFAULT_MEMORY_MIB),
            parallelism: Some(DEFAULT_PARALLELISM),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExport {
    pub format: String,
    pub version: u32,
    pub kdf: KdfParams,
    /// Base64, 16 bytes minimum. Random per file — one precomputation
    /// must not cover two exports.
    pub salt: String,
    pub header_auth: String,
    pub protected_key: String,
    pub data: String,
}

/// The header fields, in a fixed order, as authenticated by
/// `headerAuth`. Serialising a struct (rather than a map) is what
/// makes the bytes reproducible: serde emits struct fields in
/// declaration order, so writer and reader agree without a canonical
/// JSON library.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalHeader<'a> {
    format: &'a str,
    version: u32,
    kdf: &'a KdfParams,
    salt: &'a str,
}

fn canonical_header(format: &str, version: u32, kdf: &KdfParams, salt: &str) -> Result<String> {
    serde_json::to_string(&CanonicalHeader {
        format,
        version,
        kdf,
        salt,
    })
    .map_err(|e| Error::Crypto {
        reason: format!("canonical header serialisation: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Re-keying the vault
// ---------------------------------------------------------------------------

/// Re-encrypt `vault` under a freshly generated vault key.
///
/// Returns the rewritten [`SyncResponse`] and the key it is encrypted
/// under. The caller wraps that key under the file password.
///
/// Three deliberate transformations:
///
/// - **Item keys are dropped.** Bitwarden may give a cipher its own key
///   wrapped under the owning key; here every field is re-encrypted
///   directly under the vault key and `key` is set to `None`, so
///   `item_key` returns `None` on read and the owning key is used.
///   Simpler, and the export shares no key material with the original.
/// - **Attachments are dropped.** Their payloads live on the server,
///   not in `SyncResponse` — carrying the metadata would describe files
///   the export cannot restore.
/// - **`organizationId` is kept.** The UI filters on it. On read, every
///   organisation id present is mapped to the same vault key, so
///   `owning_key` resolves without a real org key.
pub fn build_export(
    vault: &SyncResponse,
    user_key: &SymmetricKey,
    org_keys: &HashMap<String, SymmetricKey>,
) -> Result<(SyncResponse, SymmetricKey)> {
    let vault_key = SymmetricKey::generate();

    let folders = vault
        .folders
        .iter()
        .map(|f| {
            Ok(Folder {
                id: f.id.clone(),
                name: reencrypt_with_key(&f.name, user_key, &vault_key)?,
                revision_date: f.revision_date.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let collections = vault
        .collections
        .iter()
        .map(|c| {
            // Collection names are encrypted under their org key. An
            // org whose key we never unwrapped (no items reached for)
            // would fail here, so fall back to leaving the name as-is
            // rather than aborting the whole export: a collection with
            // an unreadable name is a smaller loss than no backup.
            let name = match org_keys.get(&c.organization_id) {
                Some(org_key) => reencrypt_with_key(&c.name, org_key, &vault_key)?,
                None => c.name.clone(),
            };
            Ok(Collection {
                id: c.id.clone(),
                organization_id: c.organization_id.clone(),
                name,
                external_id: c.external_id.clone(),
                read_only: c.read_only,
                hide_passwords: c.hide_passwords,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Trashed items are left out, matching what the CSV export already
    // does. Trash is what the user discarded; a backup that quietly
    // resurrects it on restore would be a surprise, not a service.
    let ciphers = vault
        .ciphers
        .iter()
        .filter(|c| c.deleted_date.is_none())
        .map(|c| reencrypt_cipher(c, user_key, org_keys, &vault_key))
        .collect::<Result<Vec<_>>>()?;

    Ok((
        SyncResponse {
            profile: vault.profile.clone(),
            folders,
            collections,
            ciphers,
        },
        vault_key,
    ))
}

fn reencrypt_cipher(
    cipher: &Cipher,
    user_key: &SymmetricKey,
    org_keys: &HashMap<String, SymmetricKey>,
    to: &SymmetricKey,
) -> Result<Cipher> {
    let owner = owning_key(cipher, user_key, org_keys);
    let item = item_key(cipher, owner);
    let from = item.as_ref().unwrap_or(owner);

    let reenc = |s: &str| reencrypt_with_key(s, from, to);
    let reenc_opt = |s: Option<&str>| -> Result<Option<String>> { s.map(&reenc).transpose() };

    Ok(Cipher {
        id: cipher.id.clone(),
        kind: cipher.kind,
        // Dropped on purpose — see `build_export`.
        key: None,
        name: reenc(&cipher.name)?,
        notes: reenc_opt(cipher.notes.as_deref())?,
        organization_id: cipher.organization_id.clone(),
        folder_id: cipher.folder_id.clone(),
        collection_ids: cipher.collection_ids.clone(),
        revision_date: cipher.revision_date.clone(),
        deleted_date: cipher.deleted_date.clone(),
        favorite: cipher.favorite,
        login: cipher
            .login
            .as_ref()
            .map(|l| -> Result<CipherLogin> {
                Ok(CipherLogin {
                    username: reenc_opt(l.username.as_deref())?,
                    password: reenc_opt(l.password.as_deref())?,
                    totp: reenc_opt(l.totp.as_deref())?,
                    uris: l
                        .uris
                        .as_ref()
                        .map(|uris| {
                            uris.iter()
                                .map(|u| {
                                    Ok(CipherLoginUri {
                                        uri: reenc_opt(u.uri.as_deref())?,
                                    })
                                })
                                .collect::<Result<Vec<_>>>()
                        })
                        .transpose()?,
                })
            })
            .transpose()?,
        card: cipher
            .card
            .as_ref()
            .map(|c| -> Result<CipherCard> {
                Ok(CipherCard {
                    cardholder_name: reenc_opt(c.cardholder_name.as_deref())?,
                    brand: reenc_opt(c.brand.as_deref())?,
                    number: reenc_opt(c.number.as_deref())?,
                    exp_month: reenc_opt(c.exp_month.as_deref())?,
                    exp_year: reenc_opt(c.exp_year.as_deref())?,
                    code: reenc_opt(c.code.as_deref())?,
                })
            })
            .transpose()?,
        identity: cipher
            .identity
            .as_ref()
            .map(|i| -> Result<CipherIdentity> {
                Ok(CipherIdentity {
                    title: reenc_opt(i.title.as_deref())?,
                    first_name: reenc_opt(i.first_name.as_deref())?,
                    middle_name: reenc_opt(i.middle_name.as_deref())?,
                    last_name: reenc_opt(i.last_name.as_deref())?,
                    address1: reenc_opt(i.address1.as_deref())?,
                    address2: reenc_opt(i.address2.as_deref())?,
                    address3: reenc_opt(i.address3.as_deref())?,
                    city: reenc_opt(i.city.as_deref())?,
                    state: reenc_opt(i.state.as_deref())?,
                    postal_code: reenc_opt(i.postal_code.as_deref())?,
                    country: reenc_opt(i.country.as_deref())?,
                    company: reenc_opt(i.company.as_deref())?,
                    email: reenc_opt(i.email.as_deref())?,
                    phone: reenc_opt(i.phone.as_deref())?,
                    ssn: reenc_opt(i.ssn.as_deref())?,
                    username: reenc_opt(i.username.as_deref())?,
                    passport_number: reenc_opt(i.passport_number.as_deref())?,
                    license_number: reenc_opt(i.license_number.as_deref())?,
                })
            })
            .transpose()?,
        ssh_key: cipher
            .ssh_key
            .as_ref()
            .map(|s| -> Result<CipherSshKey> {
                Ok(CipherSshKey {
                    private_key: reenc_opt(s.private_key.as_deref())?,
                    public_key: reenc_opt(s.public_key.as_deref())?,
                    key_fingerprint: reenc_opt(s.key_fingerprint.as_deref())?,
                })
            })
            .transpose()?,
        fields: cipher
            .fields
            .as_ref()
            .map(|fields| {
                fields
                    .iter()
                    .map(|f| {
                        Ok(CipherField {
                            kind: f.kind,
                            name: reenc_opt(f.name.as_deref())?,
                            value: reenc_opt(f.value.as_deref())?,
                            linked_id: f.linked_id,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?,
        password_history: cipher
            .password_history
            .as_ref()
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| {
                        Ok(CipherPasswordHistory {
                            last_used_date: e.last_used_date.clone(),
                            password: reenc_opt(e.password.as_deref())?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?,
        reprompt: cipher.reprompt,
        // Dropped on purpose — see `build_export`.
        attachments: None::<Vec<CipherAttachment>>,
    })
}

// ---------------------------------------------------------------------------
// Sealing / opening
// ---------------------------------------------------------------------------

/// Wrap an already re-keyed vault into an encrypted export file.
pub fn seal(
    vault: &SyncResponse,
    vault_key: &SymmetricKey,
    password: &SecretString,
    kdf: &KdfParams,
) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt_b64 = STANDARD.encode(salt);

    let file_key = stretch_master_key(&derive_file_key(
        password,
        &salt,
        kdf.kind,
        kdf.iterations,
        kdf.memory_mib,
        kdf.parallelism,
    )?)?;

    let header = canonical_header(FORMAT_TAG, FORMAT_VERSION, kdf, &salt_b64)?;
    let plaintext = serde_json::to_vec(vault).map_err(|e| Error::Crypto {
        reason: format!("vault serialisation: {e}"),
    })?;

    let file = EncryptedExport {
        format: FORMAT_TAG.to_string(),
        version: FORMAT_VERSION,
        kdf: kdf.clone(),
        salt: salt_b64,
        header_auth: encrypt_string(&header, &file_key)?,
        protected_key: encrypt_bytes(vault_key.to_bytes().as_slice(), &file_key)?,
        data: encrypt_bytes(&plaintext, &file_key)?,
    };

    serde_json::to_vec_pretty(&file).map_err(|e| Error::Crypto {
        reason: format!("export serialisation: {e}"),
    })
}

/// Open an encrypted export, returning the vault and the key its items
/// are encrypted under.
///
/// A wrong password surfaces as [`Error::ExportWrongPassword`], a
/// damaged or foreign file as [`Error::ExportMalformed`]. Keeping them
/// apart matters: only one of the two is worth retyping a password for.
pub fn open(bytes: &[u8], password: &SecretString) -> Result<(SyncResponse, SymmetricKey)> {
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err(Error::ExportMalformed {
            reason: format!(
                "file too large: {} bytes (max {} MiB)",
                bytes.len(),
                MAX_EXPORT_BYTES / (1024 * 1024)
            ),
        });
    }

    let file: EncryptedExport =
        serde_json::from_slice(bytes).map_err(|e| Error::ExportMalformed {
            reason: format!("not a Clavix export envelope: {e}"),
        })?;

    if file.format != FORMAT_TAG {
        return Err(Error::ExportMalformed {
            reason: format!("unknown format tag {:?}", file.format),
        });
    }
    if file.version != FORMAT_VERSION {
        return Err(Error::ExportMalformed {
            reason: format!(
                "unsupported export version {} (this build reads {FORMAT_VERSION})",
                file.version
            ),
        });
    }

    let salt = STANDARD
        .decode(&file.salt)
        .map_err(|e| Error::ExportMalformed {
            reason: format!("salt is not valid base64: {e}"),
        })?;

    // Floors first: a file claiming `iterations: 1` is rejected here,
    // before we spend anything deriving from it.
    let file_key = stretch_master_key(&derive_file_key(
        password,
        &salt,
        file.kdf.kind,
        file.kdf.iterations,
        file.kdf.memory_mib,
        file.kdf.parallelism,
    )?)?;

    // The header check doubles as the password check: it is the
    // cheapest authenticated ciphertext in the file, so a wrong
    // password is rejected without touching the vault blob.
    let header_plain = EncString::parse(&file.header_auth)
        .and_then(|e| e.decrypt_string_sym(&file_key))
        .map_err(|_| Error::ExportWrongPassword)?;

    let expected = canonical_header(&file.format, file.version, &file.kdf, &file.salt)?;
    if header_plain != expected {
        return Err(Error::ExportMalformed {
            reason: "header does not match its authenticated copy — the file has been edited"
                .into(),
        });
    }

    let key_bytes = EncString::parse(&file.protected_key)
        .and_then(|e| e.decrypt_sym(&file_key))
        .map_err(|_| Error::ExportMalformed {
            reason: "protected vault key failed to decrypt".into(),
        })?;
    let vault_key = SymmetricKey::from_bytes(&key_bytes)?;

    let data = EncString::parse(&file.data)
        .and_then(|e| e.decrypt_sym(&file_key))
        .map_err(|_| Error::ExportMalformed {
            reason: "vault payload failed to decrypt".into(),
        })?;
    let vault: SyncResponse =
        serde_json::from_slice(&data).map_err(|e| Error::ExportMalformed {
            reason: format!("vault payload is not a valid sync response: {e}"),
        })?;

    Ok((vault, vault_key))
}

/// Every organisation id appearing in an opened export, mapped to the
/// vault key.
///
/// The export flattens all ownership onto one key but keeps
/// `organizationId` so the UI can still filter by organisation.
/// `owning_key` looks org items up in this map, so it has to resolve —
/// to the vault key, since that is what the items are encrypted under.
#[allow(clippy::implicit_hasher)]
pub fn org_key_map(
    vault: &SyncResponse,
    vault_key: &SymmetricKey,
) -> HashMap<String, SymmetricKey> {
    let mut map = HashMap::new();
    for id in vault
        .ciphers
        .iter()
        .filter_map(|c| c.organization_id.as_deref())
        .chain(vault.collections.iter().map(|c| c.organization_id.as_str()))
        .chain(vault.profile.organizations.iter().map(|o| o.id.as_str()))
    {
        if !map.contains_key(id) {
            map.insert(
                id.to_string(),
                SymmetricKey::from_bytes(vault_key.to_bytes().as_slice())
                    .expect("a 64-byte key round-trips"),
            );
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{decrypt_name, encrypt_string};
    use crate::models::{CipherType, Organization, Profile};

    fn key() -> SymmetricKey {
        SymmetricKey::generate()
    }

    fn pw() -> SecretString {
        SecretString::from("correct-horse-battery-staple".to_string())
    }

    /// `unwrap_err` would require `Debug` on the Ok side, and the Ok
    /// side carries a `SymmetricKey` — which deliberately has no
    /// `Debug` impl so key material can't be printed into a log or a
    /// panic message. Unwrap by hand rather than weaken that.
    fn expect_err(result: Result<(SyncResponse, SymmetricKey)>) -> Error {
        match result {
            Ok(_) => panic!("expected an error, got a readable vault"),
            Err(e) => e,
        }
    }

    /// One cipher of each type, every encrypted field populated, so a
    /// field the re-key walk forgets shows up as a decrypt failure
    /// rather than passing silently.
    fn cipher(id: &str, kind: CipherType, k: &SymmetricKey) -> Cipher {
        let e = |s: &str| encrypt_string(s, k).unwrap();
        Cipher {
            id: id.into(),
            kind,
            key: None,
            name: e("My item"),
            notes: Some(e("some notes")),
            organization_id: None,
            folder_id: Some("folder-1".into()),
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            favorite: true,
            login: (kind == CipherType::Login).then(|| CipherLogin {
                username: Some(e("alice")),
                password: Some(e("s3cret")),
                totp: Some(e("JBSWY3DPEHPK3PXP")),
                uris: Some(vec![CipherLoginUri {
                    uri: Some(e("https://example.test")),
                }]),
            }),
            card: (kind == CipherType::Card).then(|| CipherCard {
                cardholder_name: Some(e("Alice")),
                brand: Some(e("Visa")),
                number: Some(e("4111111111111111")),
                exp_month: Some(e("12")),
                exp_year: Some(e("2030")),
                code: Some(e("123")),
            }),
            identity: (kind == CipherType::Identity).then(|| CipherIdentity {
                title: Some(e("Ms")),
                first_name: Some(e("Alice")),
                middle_name: Some(e("Q")),
                last_name: Some(e("Example")),
                address1: Some(e("1 Rue de la Paix")),
                address2: Some(e("Bat. B")),
                address3: Some(e("Apt 4")),
                city: Some(e("Paris")),
                state: Some(e("IDF")),
                postal_code: Some(e("75002")),
                country: Some(e("FR")),
                company: Some(e("ACME")),
                email: Some(e("alice@example.test")),
                phone: Some(e("+33100000000")),
                ssn: Some(e("123-45-6789")),
                username: Some(e("alice")),
                passport_number: Some(e("X1234567")),
                license_number: Some(e("D9876543")),
            }),
            ssh_key: (kind == CipherType::SshKey).then(|| CipherSshKey {
                private_key: Some(e("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")),
                public_key: Some(e("ssh-ed25519 AAAA")),
                key_fingerprint: Some(e("SHA256:abc")),
            }),
            fields: Some(vec![CipherField {
                kind: Some(1),
                name: Some(e("hidden field")),
                value: Some(e("hidden value")),
                linked_id: None,
            }]),
            password_history: Some(vec![CipherPasswordHistory {
                last_used_date: Some("2026-01-01T00:00:00Z".into()),
                password: Some(e("old-password")),
            }]),
            reprompt: Some(1),
            attachments: Some(vec![CipherAttachment {
                id: "att-1".into(),
                url: Some("https://server.test/att".into()),
                file_name: Some(e("secret.pdf")),
                key: Some(e("wrapped-key")),
                size: Some("1024".into()),
                size_name: Some("1 KB".into()),
            }]),
        }
    }

    fn vault(user_key: &SymmetricKey) -> SyncResponse {
        SyncResponse {
            profile: Profile {
                id: "profile-1".into(),
                email: "alice@example.test".into(),
                name: Some("Alice".into()),
                organizations: vec![Organization {
                    id: "org-1".into(),
                    name: "ACME".into(),
                    key: None,
                }],
            },
            folders: vec![Folder {
                id: "folder-1".into(),
                name: encrypt_string("Personal", user_key).unwrap(),
                revision_date: None,
            }],
            collections: vec![],
            ciphers: vec![
                cipher("c-login", CipherType::Login, user_key),
                cipher("c-note", CipherType::SecureNote, user_key),
                cipher("c-card", CipherType::Card, user_key),
                cipher("c-identity", CipherType::Identity, user_key),
                cipher("c-ssh", CipherType::SshKey, user_key),
            ],
        }
    }

    fn roundtrip(user_key: &SymmetricKey) -> (SyncResponse, SymmetricKey) {
        let source = vault(user_key);
        let (rekeyed, vault_key) = build_export(&source, user_key, &HashMap::new()).unwrap();
        let bytes = seal(&rekeyed, &vault_key, &pw(), &KdfParams::default()).unwrap();
        open(&bytes, &pw()).unwrap()
    }

    #[test]
    fn round_trip_preserves_every_encrypted_field() {
        let user_key = key();
        let (opened, vault_key) = roundtrip(&user_key);

        assert_eq!(opened.ciphers.len(), 5);
        assert_eq!(
            decrypt_name(&opened.folders[0].name, &vault_key).unwrap(),
            "Personal"
        );

        for c in &opened.ciphers {
            assert_eq!(decrypt_name(&c.name, &vault_key).unwrap(), "My item");
            assert_eq!(
                decrypt_name(c.notes.as_deref().unwrap(), &vault_key).unwrap(),
                "some notes"
            );
            let field = &c.fields.as_ref().unwrap()[0];
            assert_eq!(
                decrypt_name(field.value.as_deref().unwrap(), &vault_key).unwrap(),
                "hidden value"
            );
            assert_eq!(
                decrypt_name(
                    c.password_history.as_ref().unwrap()[0]
                        .password
                        .as_deref()
                        .unwrap(),
                    &vault_key
                )
                .unwrap(),
                "old-password"
            );
        }
    }

    #[test]
    fn round_trip_preserves_the_types_csv_cannot_carry() {
        let user_key = key();
        let (opened, vault_key) = roundtrip(&user_key);
        let by_id = |id: &str| opened.ciphers.iter().find(|c| c.id == id).unwrap().clone();

        let card = by_id("c-card");
        let card_fields = card.card.as_ref().unwrap();
        assert_eq!(
            decrypt_name(card_fields.number.as_deref().unwrap(), &vault_key).unwrap(),
            "4111111111111111"
        );

        let identity = by_id("c-identity");
        let id_fields = identity.identity.as_ref().unwrap();
        assert_eq!(
            decrypt_name(id_fields.passport_number.as_deref().unwrap(), &vault_key).unwrap(),
            "X1234567"
        );
        assert_eq!(
            decrypt_name(id_fields.address3.as_deref().unwrap(), &vault_key).unwrap(),
            "Apt 4"
        );

        let ssh = by_id("c-ssh");
        assert_eq!(
            decrypt_name(
                ssh.ssh_key
                    .as_ref()
                    .unwrap()
                    .private_key
                    .as_deref()
                    .unwrap(),
                &vault_key
            )
            .unwrap(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
        );

        let login = by_id("c-login");
        let l = login.login.as_ref().unwrap();
        assert_eq!(
            decrypt_name(l.password.as_deref().unwrap(), &vault_key).unwrap(),
            "s3cret"
        );
        assert_eq!(
            decrypt_name(
                l.uris.as_ref().unwrap()[0].uri.as_deref().unwrap(),
                &vault_key
            )
            .unwrap(),
            "https://example.test"
        );
    }

    #[test]
    fn export_shares_no_key_material_with_the_source_vault() {
        let user_key = key();
        let (opened, _) = roundtrip(&user_key);
        // Every field must have been rewrapped: the original key must
        // not open anything in the export.
        for c in &opened.ciphers {
            assert!(
                decrypt_name(&c.name, &user_key).is_err(),
                "cipher {} still decrypts under the source key",
                c.id
            );
        }
    }

    #[test]
    fn item_keys_and_attachments_are_dropped() {
        let user_key = key();
        let (opened, _) = roundtrip(&user_key);
        for c in &opened.ciphers {
            assert!(c.key.is_none(), "item key survived on {}", c.id);
            assert!(
                c.attachments.is_none(),
                "attachment metadata survived on {} — the payloads are server-side \
                 and cannot be restored from this file",
                c.id
            );
        }
    }

    #[test]
    fn trashed_items_are_left_out() {
        let user_key = key();
        let mut source = vault(&user_key);
        let mut trashed = cipher("c-trashed", CipherType::Login, &user_key);
        trashed.deleted_date = Some("2026-01-01T00:00:00Z".into());
        source.ciphers.push(trashed);

        let (rekeyed, _) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        assert!(
            !rekeyed.ciphers.iter().any(|c| c.id == "c-trashed"),
            "a backup must not resurrect what the user threw away"
        );
        assert_eq!(rekeyed.ciphers.len(), 5);
    }

    #[test]
    fn plain_metadata_survives_the_re_key() {
        let user_key = key();
        let (opened, _) = roundtrip(&user_key);
        let login = opened.ciphers.iter().find(|c| c.id == "c-login").unwrap();
        assert_eq!(login.folder_id.as_deref(), Some("folder-1"));
        assert!(login.favorite);
        assert_eq!(login.reprompt, Some(1));
        assert_eq!(opened.profile.email, "alice@example.test");
    }

    #[test]
    fn wrong_password_is_reported_as_such() {
        let user_key = key();
        let source = vault(&user_key);
        let (rekeyed, vault_key) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        let bytes = seal(&rekeyed, &vault_key, &pw(), &KdfParams::default()).unwrap();

        let err = expect_err(open(&bytes, &SecretString::from("wrong".to_string())));
        assert!(
            matches!(err, Error::ExportWrongPassword),
            "expected ExportWrongPassword, got {err:?}"
        );
    }

    #[test]
    fn a_downgraded_kdf_is_refused_by_the_floors() {
        let user_key = key();
        let source = vault(&user_key);
        let (rekeyed, vault_key) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        let bytes = seal(&rekeyed, &vault_key, &pw(), &KdfParams::default()).unwrap();

        let mut file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        file["kdf"]["iterations"] = serde_json::json!(1);
        let tampered = serde_json::to_vec(&file).unwrap();

        // Rejected before any derivation happens, by the KDF floors —
        // not later by a MAC failure.
        let err = expect_err(open(&tampered, &pw()));
        assert!(
            matches!(err, Error::Crypto { .. }),
            "expected the KDF floor to reject this, got {err:?}"
        );
    }

    #[test]
    fn an_edited_header_does_not_open() {
        let user_key = key();
        let source = vault(&user_key);
        let (rekeyed, vault_key) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        let bytes = seal(&rekeyed, &vault_key, &pw(), &KdfParams::default()).unwrap();

        // Raise the memory cost: above the floor, so the floors let it
        // through, but it changes the derived key and must not open.
        let mut file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        file["kdf"]["memoryMib"] = serde_json::json!(32);
        let tampered = serde_json::to_vec(&file).unwrap();

        assert!(
            open(&tampered, &pw()).is_err(),
            "an edited KDF parameter must not yield a readable vault"
        );
    }

    #[test]
    fn a_tampered_payload_is_malformed_not_a_password_problem() {
        let user_key = key();
        let source = vault(&user_key);
        let (rekeyed, vault_key) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        let bytes = seal(&rekeyed, &vault_key, &pw(), &KdfParams::default()).unwrap();

        let mut file: EncryptedExport = serde_json::from_slice(&bytes).unwrap();
        // Flip a byte inside the payload ciphertext, leaving the header
        // (and so the password check) intact.
        let mut parts: Vec<String> = file.data.splitn(2, '.').map(str::to_string).collect();
        let body: Vec<&str> = parts[1].split('|').collect();
        let mut ct = STANDARD.decode(body[1]).unwrap();
        ct[0] ^= 0x01;
        parts[1] = format!("{}|{}|{}", body[0], STANDARD.encode(&ct), body[2]);
        file.data = parts.join(".");

        let err = expect_err(open(&serde_json::to_vec(&file).unwrap(), &pw()));
        assert!(
            matches!(err, Error::ExportMalformed { .. }),
            "a corrupt payload must not read as a wrong password: {err:?}"
        );
    }

    #[test]
    fn a_foreign_file_is_rejected_before_any_derivation() {
        let err = expect_err(open(
            br#"{"encrypted":true,"passwordProtected":true}"#,
            &pw(),
        ));
        assert!(matches!(err, Error::ExportMalformed { .. }), "got {err:?}");
    }

    #[test]
    fn each_export_uses_a_fresh_salt_and_vault_key() {
        let user_key = key();
        let source = vault(&user_key);

        let (a, ka) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        let (b, kb) = build_export(&source, &user_key, &HashMap::new()).unwrap();
        assert_ne!(
            ka.to_bytes().as_slice(),
            kb.to_bytes().as_slice(),
            "two exports must not share a vault key"
        );

        let fa: EncryptedExport =
            serde_json::from_slice(&seal(&a, &ka, &pw(), &KdfParams::default()).unwrap()).unwrap();
        let fb: EncryptedExport =
            serde_json::from_slice(&seal(&b, &kb, &pw(), &KdfParams::default()).unwrap()).unwrap();
        assert_ne!(fa.salt, fb.salt, "salts must be per-file");
    }

    #[test]
    fn org_items_resolve_through_the_flattened_key_map() {
        let user_key = key();
        let org_key = key();
        let mut org_keys = HashMap::new();
        org_keys.insert(
            "org-1".to_string(),
            SymmetricKey::from_bytes(org_key.to_bytes().as_slice()).unwrap(),
        );

        let mut source = vault(&user_key);
        let mut org_item = cipher("c-org", CipherType::Login, &org_key);
        org_item.organization_id = Some("org-1".into());
        source.ciphers.push(org_item);
        source.collections.push(Collection {
            id: "col-1".into(),
            organization_id: "org-1".into(),
            name: encrypt_string("Shared", &org_key).unwrap(),
            external_id: None,
            read_only: false,
            hide_passwords: false,
        });

        let (rekeyed, vault_key) = build_export(&source, &user_key, &org_keys).unwrap();
        let bytes = seal(&rekeyed, &vault_key, &pw(), &KdfParams::default()).unwrap();
        let (opened, opened_key) = open(&bytes, &pw()).unwrap();

        // The org item is now under the vault key, and `owning_key`
        // must still resolve it — that is what org_key_map is for.
        let map = org_key_map(&opened, &opened_key);
        let org_item = opened.ciphers.iter().find(|c| c.id == "c-org").unwrap();
        let owner = owning_key(org_item, &opened_key, &map);
        assert_eq!(decrypt_name(&org_item.name, owner).unwrap(), "My item");
        assert_eq!(
            decrypt_name(&opened.collections[0].name, &opened_key).unwrap(),
            "Shared"
        );
    }
}
