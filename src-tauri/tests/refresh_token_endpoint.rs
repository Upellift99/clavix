//! Integration test for `VaultwardenClient::refresh_token`. The full
//! `ensure_fresh_tokens` orchestration in `services/auth.rs` is hard
//! to exercise from outside the Tauri runtime — it takes a
//! `State<'_, AppState>` plumbed through tauri::generate_handler!.
//! What we *can* drive end-to-end without booting Tauri is the HTTP
//! contract the orchestration ultimately depends on: when the live
//! access token is about to expire, the client posts the right
//! grant + refresh value to /identity/connect/token and decodes the
//! response into a fresh `TokenSet`.
//!
//! Mocked with `mockito` — no real Vaultwarden, no docker. Covers
//! one of the three scenarios listed in issue #24 (the other two
//! live in `persisted_session_disk.rs`).

use clavix_lib::api::{DeviceInfo, VaultwardenClient};

#[tokio::test(flavor = "current_thread")]
async fn refresh_token_posts_form_and_parses_new_token_set() {
    let mut server = mockito::Server::new_async().await;

    // Vaultwarden replies on /identity/connect/token with the same
    // shape on a refresh as on a password grant. The bits we care
    // about: access_token rotated, expires_in present, optional new
    // refresh_token (Vaultwarden may or may not rotate it).
    let mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("grant_type=refresh_token".into()),
            mockito::Matcher::Regex("refresh_token=stale-but-valid".into()),
            mockito::Matcher::Regex("client_id=connector".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{
                "access_token": "fresh-access-token",
                "refresh_token": "rotated-refresh-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "Key": "2.aGVsbG8=|d29ybGQ=|aGVsbG8=",
                "PrivateKey": null,
                "Kdf": 0,
                "KdfIterations": 600000
            }"#,
        )
        .create_async()
        .await;

    let client = VaultwardenClient::new(&server.url()).expect("client init");
    let device = DeviceInfo {
        identifier: "deadbeef-0000-0000-0000-000000000000".into(),
        name: "test".into(),
        device_type: 8,
    };

    let tokens = client
        .refresh_token("stale-but-valid", &device)
        .await
        .expect("refresh succeeds against the mock");

    assert_eq!(tokens.access_token, "fresh-access-token");
    assert_eq!(tokens.refresh_token, "rotated-refresh-token");
    assert_eq!(tokens.expires_in, 3600);
    assert_eq!(tokens.token_type, "Bearer");

    mock.assert_async().await;
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_token_surfaces_400_with_auth_failed_message() {
    // What happens when the refresh token has been revoked: the
    // server returns 400 with an OAuth-style error_description. The
    // client maps that to Error::AuthFailed so the UI can route the
    // user back to the login screen rather than retrying forever.
    let mut server = mockito::Server::new_async().await;

    let mock = server
        .mock("POST", "/identity/connect/token")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"invalid_grant","error_description":"Refresh token expired"}"#)
        .create_async()
        .await;

    let client = VaultwardenClient::new(&server.url()).expect("client init");
    let device = DeviceInfo {
        identifier: "deadbeef-0000-0000-0000-000000000000".into(),
        name: "test".into(),
        device_type: 8,
    };

    let err = client
        .refresh_token("revoked", &device)
        .await
        .expect_err("should surface 400 as AuthFailed");

    match err {
        clavix_lib::error::Error::AuthFailed { message } => {
            assert!(
                message.contains("Refresh token expired") || message.contains("invalid_grant"),
                "expected auth-failed message to carry the server's reason, got {message:?}",
            );
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }

    mock.assert_async().await;
}
