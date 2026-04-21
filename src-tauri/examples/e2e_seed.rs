//! Registers a test user on a Vaultwarden instance, creates a couple of
//! fixture ciphers, and spins up an organization with a default
//! collection so the share-cipher E2E has a destination to drop items
//! into. Used by `tests/e2e/wdio.conf.mjs` to prime the backend before
//! running WebdriverIO specs.
//!
//! Reuses the exact crypto path of the production app (derive_master_key,
//! stretch_master_key, encrypt_bytes/string) so a bug in the register /
//! cipher-create flow shows up here before it hits the UI tests.
//!
//! Run with:
//!     E2E_SERVER_URL=http://127.0.0.1:8765 \
//!     E2E_EMAIL=e2e@clavix.test \
//!     E2E_PASSWORD=correct-horse-battery-staple \
//!     cargo run --example e2e_seed

use std::env;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use secrecy::SecretString;
use serde_json::{json, Value};
use sha1::Sha1;

use clavix_lib::api::{DeviceInfo, VaultwardenClient};
use clavix_lib::crypto::{
    decrypt_user_key, derive_master_key, derive_master_password_hash, encrypt_bytes,
    encrypt_string, stretch_master_key, SymmetricKey,
};
use clavix_lib::error::{Error, Result};
use clavix_lib::models::{KdfType, LoginResult};

// Must match PASSWORD_ITERATIONS in tests/e2e/docker-compose.yml. Short
// iterations keep local test runs snappy; the crypto surface we exercise
// is the same either way.
const KDF_ITERATIONS: u32 = 100_000;

const ORG_NAME: &str = "E2E Org";
const ORG_COLLECTION_NAME: &str = "Shared";

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

    // --- create two fixture ciphers so the E2E spec has something to look at ---
    create_login_cipher(
        &client,
        &tokens.access_token,
        &user_key,
        "GitHub",
        "octocat",
        "tentacles",
        "https://github.com",
    )
    .await?;
    create_secure_note(
        &client,
        &tokens.access_token,
        &user_key,
        "Welcome note",
        "This is a seeded note for the Clavix E2E tests.",
    )
    .await?;
    eprintln!("[seed] created 2 fixture ciphers");

    // --- spin up an org so share-cipher tests have somewhere to land ---
    //     The org symmetric key is a fresh 64-byte blob, RSA-OAEP encrypted
    //     with the user public key so the server can hand it back to the
    //     creator on every /api/sync. collectionName is the default
    //     collection's name, symmetric-encrypted with the org key (that's
    //     the key the org's members will share).
    create_organization(&http, base, &tokens.access_token, &email, &public_key).await?;

    Ok(())
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
) -> Result<()> {
    let mut org_key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut org_key_bytes);
    let org_sym_key = SymmetricKey::from_bytes(&org_key_bytes)?;

    let encrypted_org_key = rsa_oaep_sha1_encrypt(user_public_key, &org_key_bytes)?;
    let encrypted_collection_name = encrypt_string(ORG_COLLECTION_NAME, &org_sym_key)?;

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
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: format!("create org: {text}"),
        });
    }
    eprintln!("[seed] created org '{ORG_NAME}' with default collection '{ORG_COLLECTION_NAME}'");
    Ok(())
}

async fn create_login_cipher(
    client: &VaultwardenClient,
    access_token: &str,
    key: &clavix_lib::crypto::SymmetricKey,
    name: &str,
    username: &str,
    password: &str,
    uri: &str,
) -> Result<()> {
    let body = json!({
        "type": 1, // Login
        "name": encrypt_string(name, key)?,
        "notes": Value::Null,
        "folderId": Value::Null,
        "favorite": false,
        "organizationId": Value::Null,
        "login": {
            "username": encrypt_string(username, key)?,
            "password": encrypt_string(password, key)?,
            "totp": Value::Null,
            "uris": [{
                "uri": encrypt_string(uri, key)?,
                "match": Value::Null,
            }],
        },
    });
    client.create_cipher(access_token, &body).await.map(|_| ())
}

async fn create_secure_note(
    client: &VaultwardenClient,
    access_token: &str,
    key: &clavix_lib::crypto::SymmetricKey,
    name: &str,
    notes: &str,
) -> Result<()> {
    let body = json!({
        "type": 2, // SecureNote
        "name": encrypt_string(name, key)?,
        "notes": encrypt_string(notes, key)?,
        "folderId": Value::Null,
        "favorite": false,
        "organizationId": Value::Null,
        "secureNote": { "type": 0 },
    });
    client.create_cipher(access_token, &body).await.map(|_| ())
}
