//! Registers test users on a Vaultwarden instance and seeds a canonical
//! fixture set used by the E2E specs.
//!
//! Primary account (`E2E_EMAIL`, no 2FA):
//! - 1 personal Login ("GitHub")
//! - 1 personal SecureNote ("Welcome note")
//! - 1 personal Card ("E2E Card")
//! - 1 personal Identity ("E2E Identity")
//! - 1 personal SSH key ("E2E SSH Key"), real ed25519 keypair
//! - 1 personal Login with TOTP ("TOTP demo")
//! - 1 personal Folder ("E2E Folder") with the SecureNote moved into it
//! - 1 organization ("E2E Org") with two collections ("Shared", "Audit")
//! - 1 org-scoped Login ("Team Secret") in the "Shared" collection
//!
//! Secondary account (`e2e-2fa@clavix.test`, TOTP 2FA enabled):
//! - 2FA bootstrapped against `TWO_FA_SECRET_BASE32` (deterministic so
//!   tests can recompute valid codes at login time).
//! - 1 personal Login ("Behind 2FA") to make sync visible.
//!
//! Reuses the app's real crypto path (`derive_master_key`,
//! `stretch_master_key`, `encrypt_bytes/string`, `build_cipher_body`) so
//! a regression in register / cipher-create / encryption shows up here
//! before hitting the UI tests.
//!
//! Run with:
//!     E2E_SERVER_URL=http://127.0.0.1:8765 \
//!     E2E_EMAIL=e2e@clavix.test \
//!     E2E_PASSWORD=correct-horse-battery-staple \
//!     cargo run --example e2e_seed

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use secrecy::SecretString;
use serde_json::{json, Value};
use sha1::Sha1;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey as SshPrivateKey};

use clavix_lib::api::{DeviceInfo, VaultwardenClient};
use clavix_lib::crypto::{
    decrypt_user_key, derive_master_key, derive_master_password_hash, encrypt_bytes,
    encrypt_string, stretch_master_key, MasterPasswordHash, SymmetricKey,
};
use clavix_lib::error::{Error, Result};
use clavix_lib::models::{
    CardInput, CipherCreateInput, IdentityInput, KdfType, LoginInput, LoginResult, SshKeyInput,
    TwoFactorProvider,
};
use clavix_lib::services::cipher::build_cipher_body;

// Must match PASSWORD_ITERATIONS in tests/e2e/docker-compose.yml. Short
// iterations keep local test runs snappy; the crypto surface we exercise
// is the same either way.
const KDF_ITERATIONS: u32 = 100_000;

const ORG_NAME: &str = "E2E Org";
const COLLECTION_DEFAULT: &str = "Shared";
const COLLECTION_SECONDARY: &str = "Audit";
const FOLDER_NAME: &str = "E2E Folder";

// 2FA-enabled secondary account. The secret is deterministic so future
// 2FA-aware specs can recompute valid TOTP codes from the constant
// without having to scrape stdout.
const TWO_FA_EMAIL: &str = "e2e-2fa@clavix.test";
const TWO_FA_PASSWORD: &str = "two-factor-fixture";
const TWO_FA_SECRET_BASE32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let server_url = env::var("E2E_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8765".into());
    let email = env::var("E2E_EMAIL").unwrap_or_else(|_| "e2e@clavix.test".into());
    let password =
        env::var("E2E_PASSWORD").unwrap_or_else(|_| "correct-horse-battery-staple".into());
    let password_secret: SecretString = password.into();

    // --- derive the master key chain the same way the app does ---
    let master_key = derive_master_key(
        &password_secret,
        &email,
        KdfType::Pbkdf2,
        KDF_ITERATIONS,
        None,
        None,
    )?;
    let master_hash = derive_master_password_hash(&master_key, &password_secret);
    let stretched = stretch_master_key(&master_key)?;

    // --- mint a fresh 64-byte user key and encrypt it under the stretched MK ---
    let mut user_key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut user_key_bytes);
    let encrypted_user_key = encrypt_bytes(&user_key_bytes, &stretched)?;
    let user_sym_key = SymmetricKey::from_bytes(&user_key_bytes)?;

    // --- RSA-2048 keypair so the account can later own / share orgs ---
    //   publicKey: raw base64 of SPKI DER (no "2." / "4." prefix)
    //   encryptedPrivateKey: PKCS#8 DER of the private key, symmetric-
    //     encrypted under the user key (not the stretched master key —
    //     Bitwarden's spec is explicit on this).
    let (public_key, rsa_private_key) = generate_user_keypair()?;
    let priv_pkcs8 = rsa_private_key
        .to_pkcs8_der()
        .map_err(|e| crypto_err(format!("export user RSA private key: {e}")))?;
    let encrypted_private_key = encrypt_bytes(priv_pkcs8.as_bytes(), &user_sym_key)?;
    let public_key_spki = public_key
        .to_public_key_der()
        .map_err(|e| crypto_err(format!("export user RSA public key: {e}")))?;
    let public_key_b64 = STANDARD.encode(public_key_spki.as_bytes());

    // --- register on Vaultwarden (idempotent: 400 = user already exists) ---
    let http = reqwest::Client::new();
    let base = server_url.trim_end_matches('/');
    let register_url = format!("{base}/identity/accounts/register");
    let body = json!({
        "email": email,
        "name": "E2E User",
        "masterPasswordHash": master_hash.as_str(),
        "masterPasswordHint": null,
        "key": encrypted_user_key,
        "keys": {
            "publicKey": public_key_b64,
            "encryptedPrivateKey": encrypted_private_key,
        },
        "kdf": 0, // 0 = PBKDF2
        "kdfIterations": KDF_ITERATIONS,
        "referenceData": null,
    });
    let resp = http.post(&register_url).json(&body).send().await?;
    let status = resp.status();
    if !status.is_success() && status.as_u16() != 400 {
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!("register: {text}"),
        });
    }
    eprintln!("[seed] registered {email} on {base} ({status})");

    // --- login via the real client to pick up access_token + server-stored key ---
    let client = VaultwardenClient::new(&server_url)?;
    let device = DeviceInfo {
        identifier: "e2e-seed-device-0000-0000-00000000".into(),
        name: "E2E Seed".into(),
        device_type: 8,
    };
    let tokens = match client.login(&email, &master_hash, &device).await? {
        LoginResult::Success(t) => t,
        LoginResult::TwoFactorRequired { .. } => {
            return Err(Error::AuthFailed {
                message: "unexpected 2FA prompt on a fresh test account".into(),
            });
        }
    };
    let token_key = tokens.key.as_deref().ok_or_else(|| Error::Crypto {
        reason: "login response has no 'key' field — cannot derive user key".into(),
    })?;
    let user_key = decrypt_user_key(&master_key, token_key)?;

    // --- personal ciphers: one of each supported type ---
    seed_personal(
        &client,
        &tokens.access_token,
        &user_key,
        login_input("GitHub", "octocat", "tentacles", "https://github.com", None),
    )
    .await?;
    let note_id = seed_personal(
        &client,
        &tokens.access_token,
        &user_key,
        secure_note_input(
            "Welcome note",
            "This is a seeded note for the Clavix E2E tests.",
        ),
    )
    .await?;
    seed_personal(
        &client,
        &tokens.access_token,
        &user_key,
        card_input("E2E Card"),
    )
    .await?;
    seed_personal(
        &client,
        &tokens.access_token,
        &user_key,
        identity_input("E2E Identity"),
    )
    .await?;
    seed_personal(
        &client,
        &tokens.access_token,
        &user_key,
        ssh_key_input("E2E SSH Key")?,
    )
    .await?;
    // otpauth-style URI — the frontend auto-parses these to show the code.
    seed_personal(
        &client,
        &tokens.access_token,
        &user_key,
        login_input(
            "TOTP demo",
            "totp-user",
            "pw",
            "https://totp.example",
            Some("otpauth://totp/ACME:totp-user?secret=JBSWY3DPEHPK3PXP&issuer=ACME"),
        ),
    )
    .await?;
    eprintln!("[seed] created 6 personal ciphers (login, note, card, identity, ssh, totp)");

    // --- personal folder, with the SecureNote dropped into it ---
    let folder = client
        .create_folder(
            &tokens.access_token,
            &encrypt_string(FOLDER_NAME, &user_key)?,
        )
        .await?;
    client
        .update_cipher_partial(&tokens.access_token, &note_id, Some(&folder.id), false)
        .await?;
    eprintln!("[seed] created folder '{FOLDER_NAME}' with 1 cipher inside");

    // --- spin up an org with its default collection, then add a 2nd collection
    //     and one org-scoped cipher ---
    let (org_id, default_collection_id, org_sym_key) =
        create_organization(&http, base, &tokens.access_token, &email, &public_key).await?;
    let _secondary_collection_id = create_collection(
        &http,
        base,
        &tokens.access_token,
        &org_id,
        &org_sym_key,
        COLLECTION_SECONDARY,
    )
    .await?;
    seed_org_cipher(
        &client,
        &tokens.access_token,
        &org_sym_key,
        login_input(
            "Team Secret",
            "team",
            "shared-password",
            "https://internal.example",
            None,
        ),
        &org_id,
        &[default_collection_id],
    )
    .await?;
    eprintln!("[seed] seeded org '{ORG_NAME}' with 2 collections and 1 org cipher");

    // --- secondary account with TOTP 2FA enabled ---
    seed_two_factor_account(&http, &server_url, base).await?;

    Ok(())
}

/// Bootstraps a separate fixture account with TOTP 2FA pre-enabled.
/// Idempotent: if the account already exists with 2FA on, login goes
/// through `login_with_two_factor` (using a TOTP code derived from
/// `TWO_FA_SECRET_BASE32`) and the activation step is skipped.
async fn seed_two_factor_account(
    http: &reqwest::Client,
    server_url: &str,
    base: &str,
) -> Result<()> {
    let password_secret: SecretString = TWO_FA_PASSWORD.to_string().into();
    let master_key = derive_master_key(
        &password_secret,
        TWO_FA_EMAIL,
        KdfType::Pbkdf2,
        KDF_ITERATIONS,
        None,
        None,
    )?;
    let master_hash = derive_master_password_hash(&master_key, &password_secret);
    let stretched = stretch_master_key(&master_key)?;

    let mut user_key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut user_key_bytes);
    let encrypted_user_key = encrypt_bytes(&user_key_bytes, &stretched)?;
    let user_sym_key = SymmetricKey::from_bytes(&user_key_bytes)?;

    let (public_key, rsa_private_key) = generate_user_keypair()?;
    let priv_pkcs8 = rsa_private_key
        .to_pkcs8_der()
        .map_err(|e| crypto_err(format!("export 2FA user RSA private key: {e}")))?;
    let encrypted_private_key = encrypt_bytes(priv_pkcs8.as_bytes(), &user_sym_key)?;
    let public_key_spki = public_key
        .to_public_key_der()
        .map_err(|e| crypto_err(format!("export 2FA user RSA public key: {e}")))?;
    let public_key_b64 = STANDARD.encode(public_key_spki.as_bytes());

    let register_url = format!("{base}/identity/accounts/register");
    let body = json!({
        "email": TWO_FA_EMAIL,
        "name": "E2E 2FA User",
        "masterPasswordHash": master_hash.as_str(),
        "masterPasswordHint": null,
        "key": encrypted_user_key,
        "keys": {
            "publicKey": public_key_b64,
            "encryptedPrivateKey": encrypted_private_key,
        },
        "kdf": 0,
        "kdfIterations": KDF_ITERATIONS,
        "referenceData": null,
    });
    let resp = http.post(&register_url).json(&body).send().await?;
    let status = resp.status();
    if !status.is_success() && status.as_u16() != 400 {
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!("register 2FA user: {text}"),
        });
    }
    eprintln!("[seed] registered {TWO_FA_EMAIL} on {base} ({status})");

    let client = VaultwardenClient::new(server_url)?;
    let device = DeviceInfo {
        identifier: "e2e-2fa-seed-device-0000-0000-00000000".into(),
        name: "E2E 2FA Seed".into(),
        device_type: 8,
    };

    // Plain login first. Branches:
    //   Success → fresh account, enable TOTP now.
    //   TwoFactorRequired → re-run, account already has TOTP. Verify the
    //     stored secret still matches by completing the 2FA login flow,
    //     then skip activation.
    let login_result = client.login(TWO_FA_EMAIL, &master_hash, &device).await?;
    let already_enabled = match login_result {
        LoginResult::Success(tokens) => {
            enable_totp_2fa(http, base, &tokens.access_token, &master_hash).await?;
            // After enabling, seed one fixture cipher under the user_key
            // we just minted server-side. The token_key from `tokens`
            // already lets us derive the live user_key.
            let token_key = tokens.key.as_deref().ok_or_else(|| Error::Crypto {
                reason: "2FA-user login response has no 'key' field".into(),
            })?;
            let user_key = decrypt_user_key(&master_key, token_key)?;
            seed_personal(
                &client,
                &tokens.access_token,
                &user_key,
                login_input(
                    "Behind 2FA",
                    "two-factor",
                    "post-totp",
                    "https://2fa.example",
                    None,
                ),
            )
            .await?;
            false
        }
        LoginResult::TwoFactorRequired { .. } => {
            let code = current_totp_token(TWO_FA_SECRET_BASE32)?;
            let _tokens = client
                .login_with_two_factor(
                    TWO_FA_EMAIL,
                    &master_hash,
                    &device,
                    TwoFactorProvider::Authenticator,
                    &code,
                )
                .await?;
            true
        }
    };

    eprintln!(
        "[seed] 2FA account {} (secret={TWO_FA_SECRET_BASE32})",
        if already_enabled {
            "already had TOTP enabled, verified login_with_two_factor"
        } else {
            "TOTP enabled and 'Behind 2FA' cipher seeded"
        }
    );
    Ok(())
}

/// Activates TOTP-based 2FA on an authenticated account by submitting
/// `TWO_FA_SECRET_BASE32` plus a current TOTP code derived from it.
/// Vaultwarden validates the (key, token) pair, then stores the key as
/// the account's authenticator secret.
async fn enable_totp_2fa(
    http: &reqwest::Client,
    base: &str,
    access_token: &str,
    master_hash: &MasterPasswordHash,
) -> Result<()> {
    let token = current_totp_token(TWO_FA_SECRET_BASE32)?;
    let url = format!("{base}/api/two-factor/authenticator");
    let body = json!({
        "masterPasswordHash": master_hash.as_str(),
        "key": TWO_FA_SECRET_BASE32,
        "token": token,
    });
    let resp = http
        .put(&url)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!("enable TOTP: {text}"),
        });
    }
    Ok(())
}

/// Computes the 6-digit RFC 6238 TOTP code for the current 30 s window
/// against the given base32-encoded secret.
fn current_totp_token(secret_base32: &str) -> Result<String> {
    let secret_bytes = base32_decode(secret_base32)
        .map_err(|e| crypto_err(format!("base32 decode TOTP secret: {e}")))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| crypto_err(format!("system time before unix epoch: {e}")))?
        .as_secs();
    Ok(format!("{:06}", totp_code(&secret_bytes, now / 30)))
}

/// RFC 6238 TOTP / RFC 4226 HOTP truncation. `counter` is the time step
/// (already divided by the 30 s period). Returns the raw 6-digit value;
/// callers format with leading zeros.
fn totp_code(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);
    value % 1_000_000
}

/// Minimal RFC 4648 base32 decoder (uppercase A-Z + 2-7, padding tolerated).
/// Adding a `base32` crate dep just for the seed isn't worth it.
fn base32_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    let trimmed = input.trim_end_matches('=').to_ascii_uppercase();
    let mut out = Vec::with_capacity(trimmed.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for c in trimmed.chars() {
        let v: u32 = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => 26 + (c as u32 - '2' as u32),
            _ => return Err(format!("invalid base32 char {c:?}")),
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn crypto_err(msg: String) -> Error {
    Error::Crypto { reason: msg }
}

fn generate_user_keypair() -> Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| crypto_err(format!("generate RSA private key: {e}")))?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((public_key, private_key))
}

/// Encrypts `plaintext` under the RSA public key using OAEP-SHA1 and
/// wraps the ciphertext as Bitwarden's EncString type 4 (`"4.<b64>"`),
/// which is the format Vaultwarden expects for the `key` field of a
/// new organization.
fn rsa_oaep_sha1_encrypt(pub_key: &RsaPublicKey, plaintext: &[u8]) -> Result<String> {
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha1>();
    let ciphertext = pub_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|e| crypto_err(format!("RSA-OAEP-SHA1 encrypt: {e}")))?;
    Ok(format!("4.{}", STANDARD.encode(&ciphertext)))
}

async fn create_organization(
    http: &reqwest::Client,
    base: &str,
    access_token: &str,
    billing_email: &str,
    user_public_key: &RsaPublicKey,
) -> Result<(String, String, SymmetricKey)> {
    let mut org_key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut org_key_bytes);
    let org_sym_key = SymmetricKey::from_bytes(&org_key_bytes)?;

    let encrypted_org_key = rsa_oaep_sha1_encrypt(user_public_key, &org_key_bytes)?;
    let encrypted_collection_name = encrypt_string(COLLECTION_DEFAULT, &org_sym_key)?;

    let url = format!("{base}/api/organizations");
    let body = json!({
        "name": ORG_NAME,
        "billingEmail": billing_email,
        "key": encrypted_org_key,
        "collectionName": encrypted_collection_name,
        "planType": 0,
    });

    let resp = http
        .post(&url)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!(
                "create org: {}",
                String::from_utf8_lossy(&bytes).into_owned()
            ),
        });
    }
    let response: Value = serde_json::from_slice(&bytes)
        .map_err(|e| crypto_err(format!("parse org creation response: {e}")))?;
    let org_id = response
        .get("id")
        .or_else(|| response.get("Id"))
        .and_then(Value::as_str)
        .ok_or_else(|| crypto_err("org creation response missing 'id'".into()))?
        .to_string();

    // Vaultwarden doesn't echo the default collection's id in the org
    // creation response — look it up so the caller can seed org ciphers
    // into it.
    let default_collection_id =
        fetch_default_collection_id(http, base, access_token, &org_id).await?;

    eprintln!(
        "[seed] created org '{ORG_NAME}' (id={org_id}) with default collection '{COLLECTION_DEFAULT}' (id={default_collection_id})"
    );
    Ok((org_id, default_collection_id, org_sym_key))
}

async fn fetch_default_collection_id(
    http: &reqwest::Client,
    base: &str,
    access_token: &str,
    org_id: &str,
) -> Result<String> {
    let url = format!("{base}/api/organizations/{org_id}/collections");
    let resp = http.get(&url).bearer_auth(access_token).send().await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!(
                "list collections: {}",
                String::from_utf8_lossy(&bytes).into_owned()
            ),
        });
    }
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|e| crypto_err(format!("parse collections listing: {e}")))?;
    let data = payload
        .get("data")
        .or_else(|| payload.get("Data"))
        .and_then(Value::as_array)
        .ok_or_else(|| crypto_err("collections listing missing 'data' array".into()))?;
    let first = data
        .first()
        .ok_or_else(|| crypto_err("no default collection returned by server".into()))?;
    let id = first
        .get("id")
        .or_else(|| first.get("Id"))
        .and_then(Value::as_str)
        .ok_or_else(|| crypto_err("collection entry missing 'id'".into()))?;
    Ok(id.to_string())
}

async fn create_collection(
    http: &reqwest::Client,
    base: &str,
    access_token: &str,
    org_id: &str,
    org_key: &SymmetricKey,
    name: &str,
) -> Result<String> {
    let url = format!("{base}/api/organizations/{org_id}/collections");
    let body = json!({
        "name": encrypt_string(name, org_key)?,
        "groups": [],
        "users": [],
        "externalId": null,
    });

    let resp = http
        .post(&url)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!(
                "create collection: {}",
                String::from_utf8_lossy(&bytes).into_owned()
            ),
        });
    }
    let response: Value = serde_json::from_slice(&bytes)
        .map_err(|e| crypto_err(format!("parse collection creation response: {e}")))?;
    let id = response
        .get("id")
        .or_else(|| response.get("Id"))
        .and_then(Value::as_str)
        .ok_or_else(|| crypto_err("collection creation response missing 'id'".into()))?
        .to_string();
    eprintln!("[seed] created collection '{name}' (id={id}) in org {org_id}");
    Ok(id)
}

async fn seed_personal(
    client: &VaultwardenClient,
    access_token: &str,
    user_key: &SymmetricKey,
    input: CipherCreateInput,
) -> Result<String> {
    let body = build_cipher_body(&input, user_key)?;
    let cipher = client.create_cipher(access_token, &body).await?;
    Ok(cipher.id)
}

async fn seed_org_cipher(
    client: &VaultwardenClient,
    access_token: &str,
    org_key: &SymmetricKey,
    mut input: CipherCreateInput,
    org_id: &str,
    collection_ids: &[String],
) -> Result<String> {
    input.organization_id = Some(org_id.into());
    let cipher_body = build_cipher_body(&input, org_key)?;
    let wrapped = json!({
        "cipher": cipher_body,
        "collectionIds": collection_ids,
    });
    let cipher = client.create_org_cipher(access_token, &wrapped).await?;
    Ok(cipher.id)
}

// --- CipherCreateInput factories ------------------------------------

fn login_input(
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
    totp: Option<&str>,
) -> CipherCreateInput {
    CipherCreateInput {
        name: name.into(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: Some(LoginInput {
            username: Some(username.into()),
            password: Some(password.into()),
            uris: vec![uri.into()],
            totp: totp.map(Into::into),
        }),
        card: None,
        identity: None,
        ssh_key: None,
        cipher_type: 1,
        organization_id: None,
        collection_ids: Vec::new(),
    }
}

fn secure_note_input(name: &str, notes: &str) -> CipherCreateInput {
    CipherCreateInput {
        name: name.into(),
        folder_id: None,
        favorite: false,
        notes: Some(notes.into()),
        login: None,
        card: None,
        identity: None,
        ssh_key: None,
        cipher_type: 2,
        organization_id: None,
        collection_ids: Vec::new(),
    }
}

fn card_input(name: &str) -> CipherCreateInput {
    CipherCreateInput {
        name: name.into(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: None,
        card: Some(CardInput {
            cardholder_name: Some("E2E Test".into()),
            brand: Some("Visa".into()),
            number: Some("4111111111111111".into()),
            exp_month: Some("12".into()),
            exp_year: Some("2099".into()),
            code: Some("123".into()),
        }),
        identity: None,
        ssh_key: None,
        cipher_type: 3,
        organization_id: None,
        collection_ids: Vec::new(),
    }
}

fn identity_input(name: &str) -> CipherCreateInput {
    CipherCreateInput {
        name: name.into(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: None,
        card: None,
        identity: Some(IdentityInput {
            title: Some("Dr".into()),
            first_name: Some("E2E".into()),
            last_name: Some("Tester".into()),
            email: Some("e2e@clavix.test".into()),
            country: Some("FR".into()),
            ..Default::default()
        }),
        ssh_key: None,
        cipher_type: 4,
        organization_id: None,
        collection_ids: Vec::new(),
    }
}

fn ssh_key_input(name: &str) -> Result<CipherCreateInput> {
    let mut rng = rand::thread_rng();
    let private = SshPrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| crypto_err(format!("generate ed25519 ssh key: {e}")))?;
    let openssh_private = private
        .to_openssh(LineEnding::LF)
        .map_err(|e| crypto_err(format!("encode ed25519 private to openssh: {e}")))?
        .to_string();
    let openssh_public = private
        .public_key()
        .to_openssh()
        .map_err(|e| crypto_err(format!("encode ed25519 public to openssh: {e}")))?;
    let fingerprint = private
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();

    Ok(CipherCreateInput {
        name: name.into(),
        folder_id: None,
        favorite: false,
        notes: None,
        login: None,
        card: None,
        identity: None,
        ssh_key: Some(SshKeyInput {
            private_key: Some(openssh_private),
            public_key: Some(openssh_public),
            key_fingerprint: Some(fingerprint),
        }),
        cipher_type: 5,
        organization_id: None,
        collection_ids: Vec::new(),
    })
}
