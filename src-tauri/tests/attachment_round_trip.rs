//! Live attachment round-trip against the seeded Vaultwarden container.
//!
//! Mocked HTTP proves we send *something*; only a real server proves we
//! send what it accepts. The attachment flow is the one place in Clavix
//! where the wire format was written from the Bitwarden protocol rather
//! than from an existing working call: a two-step upload (reserve a slot
//! with the encrypted name, the wrapped file key and the *ciphertext*
//! length, then POST the bytes as multipart), and a download whose
//! payload is the binary EncString layout rather than the base64 text
//! form used everywhere else. Any of those details being wrong produces
//! a perfectly plausible request that Vaultwarden rejects — or worse,
//! stores in a way no other client can read.
//!
//! Ignored by default: it needs the container from
//! `tests/e2e/docker-compose.yml` plus `cargo run --example e2e_seed`.
//!
//!     docker compose -f tests/e2e/docker-compose.yml up -d
//!     cargo run --example e2e_seed
//!     cargo test --test attachment_round_trip -- --ignored --nocapture

use clavix_core::api::{DeviceInfo, VaultwardenClient};
use clavix_core::crypto::{
    decrypt_buffer, decrypt_cipher_key, decrypt_user_key, derive_master_key,
    derive_master_password_hash, encrypt_buffer, encrypt_cipher_key, encrypt_string, SymmetricKey,
};
use clavix_core::models::{CipherCreateInput, LoginInput, LoginResult};
use clavix_core::services::cipher::build_cipher_body;
use secrecy::SecretString;

const SERVER: &str = "http://127.0.0.1:8765";
const EMAIL: &str = "e2e@clavix.test";
const PASSWORD: &str = "correct-horse-battery-staple";

/// Deliberately not a round number of AES blocks, and with a NUL and a
/// high byte in it — an attachment is arbitrary binary, and PKCS#7
/// padding bugs hide behind block-aligned test data.
fn payload() -> Vec<u8> {
    let mut bytes = b"clavix attachment round trip \x00\xff".to_vec();
    bytes.extend((0..1000u32).map(|i| (i % 251) as u8));
    bytes
}

struct Session {
    client: VaultwardenClient,
    access_token: String,
    user_key: SymmetricKey,
}

async fn login() -> Session {
    let client = VaultwardenClient::new(SERVER).expect("client init");
    let password: SecretString = PASSWORD.to_string().into();
    let prelogin = client.prelogin(EMAIL).await.expect("prelogin");
    let master_key = derive_master_key(
        &password,
        EMAIL,
        prelogin.kdf,
        prelogin.kdf_iterations,
        prelogin.kdf_memory,
        prelogin.kdf_parallelism,
    )
    .expect("master key");
    let hash = derive_master_password_hash(&master_key, &password);
    let device = DeviceInfo {
        identifier: "attachment-test-0000-0000-00000000".into(),
        name: "attachment round trip".into(),
        device_type: 8,
    };
    let tokens = match client.login(EMAIL, &hash, &device).await.expect("login") {
        LoginResult::Success(t) => t,
        LoginResult::TwoFactorRequired { .. } => panic!("primary test account must not have 2FA"),
    };
    let user_key = decrypt_user_key(
        &master_key,
        tokens.key.as_deref().expect("login response carries a key"),
    )
    .expect("user key");
    Session {
        client,
        access_token: tokens.access_token.clone(),
        user_key,
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the seeded Vaultwarden container"]
async fn attachment_survives_upload_and_download() {
    let session = login().await;

    // A dedicated cipher: hard-deleted at the end, so the shared seed
    // every other suite depends on is untouched.
    let input = CipherCreateInput {
        name: "Attachment round trip".into(),
        login: Some(LoginInput {
            username: Some("someone".into()),
            password: Some("irrelevant".into()),
            uris: vec![],
            totp: None,
        }),
        card: None,
        identity: None,
        ssh_key: None,
        cipher_type: 1,
        folder_id: None,
        favorite: false,
        notes: None,
        organization_id: None,
        collection_ids: vec![],
        fields: vec![],
        reprompt: false,
    };
    let body = build_cipher_body(&input, &session.user_key).expect("cipher body");
    let cipher = session
        .client
        .create_cipher(&session.access_token, &body)
        .await
        .expect("create cipher");

    // ---- upload -------------------------------------------------------
    let plaintext = payload();
    let file_key = SymmetricKey::generate();
    let encrypted = encrypt_buffer(&plaintext, &file_key).expect("encrypt payload");
    let wrapped_key = encrypt_cipher_key(&file_key, &session.user_key).expect("wrap file key");
    let encrypted_name = encrypt_string("round-trip.bin", &session.user_key).expect("encrypt name");

    let slot = session
        .client
        .attachment_upload_slot(
            &session.access_token,
            &cipher.id,
            &serde_json::json!({
                "key": wrapped_key,
                "fileName": encrypted_name,
                "fileSize": encrypted.len(),
                "adminRequest": false,
            }),
        )
        .await
        .expect("attachment/v2 slot");
    let attachment_id = slot["attachmentId"]
        .as_str()
        .expect("slot response carries attachmentId")
        .to_owned();

    session
        .client
        .upload_attachment_data(
            &session.access_token,
            &cipher.id,
            &attachment_id,
            &encrypted_name,
            encrypted.clone(),
        )
        .await
        .expect("multipart upload");

    // ---- read it back through a fresh sync ----------------------------
    let sync = session
        .client
        .sync(&session.access_token)
        .await
        .expect("sync");
    let stored = sync
        .ciphers
        .iter()
        .find(|c| c.id == cipher.id)
        .expect("cipher present after upload");
    let attachment = stored
        .attachments
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|a| a.id == attachment_id)
        .expect("attachment listed on the cipher");

    // The server must have kept the encrypted name and the wrapped key
    // verbatim — this is what makes the file readable by any client.
    assert_eq!(
        clavix_core::crypto::decrypt_name(
            attachment.file_name.as_deref().expect("file name"),
            &session.user_key
        )
        .expect("decrypt file name"),
        "round-trip.bin"
    );
    assert_eq!(
        attachment
            .size
            .as_deref()
            .and_then(|s| s.parse::<usize>().ok()),
        Some(encrypted.len()),
        "the server records the ciphertext length we declared"
    );

    let url = attachment.url.clone().expect("attachment url");
    let downloaded = session
        .client
        .download_attachment(&session.access_token, &url)
        .await
        .expect("download");
    assert_eq!(
        downloaded, encrypted,
        "bytes come back exactly as uploaded — no transcoding on the way through"
    );

    let unwrapped = decrypt_cipher_key(
        &session.user_key,
        attachment.key.as_deref().expect("wrapped attachment key"),
    )
    .expect("unwrap attachment key");
    assert_eq!(
        decrypt_buffer(&downloaded, &unwrapped).expect("decrypt payload"),
        plaintext,
        "the payload survives the round trip byte for byte"
    );

    // ---- delete -------------------------------------------------------
    session
        .client
        .delete_attachment(&session.access_token, &cipher.id, &attachment_id)
        .await
        .expect("delete attachment");

    let after = session
        .client
        .sync(&session.access_token)
        .await
        .expect("sync after delete");
    let stored = after
        .ciphers
        .iter()
        .find(|c| c.id == cipher.id)
        .expect("cipher still present");
    assert!(
        stored
            .attachments
            .as_deref()
            .unwrap_or_default()
            .iter()
            .all(|a| a.id != attachment_id),
        "the attachment is gone from the cipher"
    );

    session
        .client
        .delete_cipher(&session.access_token, &cipher.id)
        .await
        .expect("clean up the test cipher");
}

/// Custom fields, the reprompt flag and the password history are all new
/// keys in the cipher body. Vaultwarden accepts unknown keys silently and
/// drops what a PUT omits, so a mistake here is invisible until a user
/// notices their fields are gone — exactly the data loss this change set
/// exists to fix. Round-trip them through a real server.
#[tokio::test(flavor = "current_thread")]
#[ignore = "needs the seeded Vaultwarden container"]
async fn fields_reprompt_and_history_survive_a_write() {
    use clavix_core::crypto::decrypt_name;
    use clavix_core::models::CustomFieldInput;
    use clavix_core::services::cipher::build_update_cipher_body;

    let session = login().await;

    let mut input = CipherCreateInput {
        name: "Field round trip".into(),
        login: Some(LoginInput {
            username: Some("someone".into()),
            password: Some("first-password".into()),
            uris: vec![],
            totp: None,
        }),
        card: None,
        identity: None,
        ssh_key: None,
        cipher_type: 1,
        folder_id: None,
        favorite: false,
        notes: None,
        organization_id: None,
        collection_ids: vec![],
        fields: vec![
            CustomFieldInput {
                kind: 0,
                name: Some("Account".into()),
                value: Some("AC-42".into()),
                linked_id: None,
            },
            CustomFieldInput {
                kind: 1,
                name: Some("Recovery".into()),
                value: Some("code-123".into()),
                linked_id: None,
            },
        ],
        reprompt: true,
    };

    let created = session
        .client
        .create_cipher(
            &session.access_token,
            &build_cipher_body(&input, &session.user_key).expect("create body"),
        )
        .await
        .expect("create cipher");

    assert_eq!(created.reprompt, Some(1), "reprompt is stored as sent");
    let stored_fields = created.fields.as_deref().expect("fields stored");
    assert_eq!(stored_fields.len(), 2);
    assert_eq!(stored_fields[1].kind, Some(1), "hidden stays hidden");
    assert_eq!(
        decrypt_name(
            stored_fields[0].value.as_deref().expect("value"),
            &session.user_key
        )
        .expect("decrypt"),
        "AC-42"
    );

    // Now edit it the way the editor does: same fields, new password.
    input.login.as_mut().expect("login").password = Some("second-password".into());
    let body = build_update_cipher_body(
        &input,
        &session.user_key,
        &created,
        "2026-08-03T10:00:00.000Z",
    )
    .expect("update body");
    let updated = session
        .client
        .update_cipher(&session.access_token, &created.id, &body)
        .await
        .expect("update cipher");

    let history = updated
        .password_history
        .as_deref()
        .expect("password history stored");
    assert_eq!(history.len(), 1, "the replaced password was recorded");
    assert_eq!(
        decrypt_name(
            history[0].password.as_deref().expect("history password"),
            &session.user_key
        )
        .expect("decrypt"),
        "first-password"
    );
    assert_eq!(
        updated.fields.as_deref().map(<[_]>::len),
        Some(2),
        "custom fields survived the update instead of being wiped"
    );
    assert_eq!(updated.reprompt, Some(1));

    session
        .client
        .delete_cipher(&session.access_token, &created.id)
        .await
        .expect("clean up");
}
