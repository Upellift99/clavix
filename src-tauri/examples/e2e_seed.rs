//! Registers a test user on a Vaultwarden instance and seeds a canonical
//! fixture set used by the E2E specs:
//!
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

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
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
    encrypt_string, stretch_master_key, SymmetricKey,
};
use clavix_lib::error::{Error, Result};
use clavix_lib::models::{
    CardInput, CipherCreateInput, IdentityInput, KdfType, LoginInput, LoginResult, SshKeyInput,
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
