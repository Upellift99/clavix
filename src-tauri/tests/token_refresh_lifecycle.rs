//! Integration test: `services::auth::ensure_fresh_tokens` end-to-end.
//!
//! Bridges the two existing #24 tests:
//!
//!   - `refresh_token_endpoint.rs` proves the HTTP contract,
//!   - `persisted_session_disk.rs` proves the disk round-trip,
//!
//! and what was uncovered until now is the orchestration that ties
//! them together. Given a `Session` whose `expires_at` already drifted
//! past the 60 s safety margin, `ensure_fresh_tokens` must:
//!
//!   1. POST to `/identity/connect/token` against the live client,
//!   2. update in-memory `tokens.access_token` / `refresh_token` and
//!      `expires_at`,
//!   3. re-encrypt the rotated refresh token under the user key, and
//!   4. rewrite `session.json` so `encrypted_refresh_token` carries the
//!      rotated value while the legacy plaintext `refresh_token` is
//!      cleared.
//!
//! Two scenarios:
//!
//!   - On-disk session is already in the post-migration shape
//!     (`encrypted_refresh_token = Some(...)`, `refresh_token = None`).
//!     Verifies the in-place rotation path.
//!   - On-disk session is in the legacy shape (`refresh_token =
//!     Some(plaintext)`, `encrypted_refresh_token = None`). Verifies
//!     that the very next refresh upgrades the file to the encrypted
//!     form — the migration path that gets one shot per old client
//!     install and *must not* leave plaintext on disk afterwards.
//!
//! Plus a happy-path no-op assertion: with a future `expires_at`, the
//! function does not hit the network.
//!
//! Driven without Tauri: `ensure_fresh_tokens` was rewritten to take
//! `&AppState`, and the production call sites still pass
//! `&State<'_, AppState>` — `State<'r, T>: Deref<Target = T>` makes the
//! coercion free.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use clavix_lib::api::VaultwardenClient;
use clavix_lib::crypto::{encrypt_string, EncString, SymmetricKey};
use clavix_lib::models::{KdfType, TokenSet};
use clavix_lib::services::auth::ensure_fresh_tokens;
use clavix_lib::state::{AppState, Session};
use clavix_lib::store::{self, PersistedSession};
use tempfile::TempDir;

// SAFETY: `std::env::set_var` is process-wide. Cargo runs tests in
// parallel; this Mutex serialises every `XDG_DATA_HOME` mutation so
// no two tests see a torn view of the env. Same trick as in
// `persisted_session_disk.rs`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn test_user_key() -> SymmetricKey {
    // Same shape as the existing test fixture in services/auth.rs —
    // 64 bytes derived from a deterministic pattern, which keeps
    // the test free of any extra crypto setup.
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(11);
    }
    SymmetricKey::from_bytes(&bytes).unwrap()
}

fn install_session(
    state: &AppState,
    client: VaultwardenClient,
    refresh_token: &str,
    expires_at: Instant,
    user_key: SymmetricKey,
) {
    let mut g = state.session.lock();
    *g = Some(Session {
        client,
        tokens: TokenSet {
            access_token: "stale-access".into(),
            refresh_token: refresh_token.to_string(),
            expires_in: 3600,
            token_type: "Bearer".into(),
            key: None,
            private_key: None,
            kdf: None,
            kdf_iterations: None,
        },
        expires_at,
        user_key,
        private_key: None,
        org_keys: HashMap::new(),
        vault: None,
    });
}

fn persisted_skeleton(
    refresh_legacy: Option<String>,
    refresh_encrypted: Option<String>,
) -> PersistedSession {
    PersistedSession {
        server_url: "https://vault.test".into(),
        email: "alice@test".into(),
        refresh_token: refresh_legacy,
        encrypted_refresh_token: refresh_encrypted,
        kdf: KdfType::Pbkdf2,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        // The on-disk encrypted user key is irrelevant for
        // ensure_fresh_tokens: that field is only consumed by the
        // unlock path, which derives the in-memory user key. Here we
        // build the Session directly with a known key, so this stays
        // a placeholder.
        encrypted_user_key: "2.aGVsbG8=|d29ybGQ=|aGVsbG8=".into(),
        encrypted_private_key: None,
        yubikey_unlock: None,
    }
}

struct EnvGuard {
    prev: Option<std::ffi::OsString>,
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: TempDir,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: still serialised under ENV_LOCK; no concurrent reader.
        unsafe {
            match self.prev.take() {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }
}

fn temp_data_home() -> EnvGuard {
    let lock = ENV_LOCK.lock().expect("env lock not poisoned");
    let dir = TempDir::new().expect("tempdir");
    let prev = std::env::var_os("XDG_DATA_HOME");
    // SAFETY: serialised under ENV_LOCK; no other test thread reads
    // XDG_DATA_HOME while we own the guard.
    unsafe { std::env::set_var("XDG_DATA_HOME", dir.path()) };
    EnvGuard {
        prev,
        _lock: lock,
        _dir: dir,
    }
}

fn refresh_response_body(access: &str, refresh: &str) -> String {
    format!(
        r#"{{
            "access_token": "{access}",
            "refresh_token": "{refresh}",
            "expires_in": 3600,
            "token_type": "Bearer",
            "Key": null,
            "PrivateKey": null,
            "Kdf": 0,
            "KdfIterations": 600000
        }}"#
    )
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_rotates_in_memory_tokens_and_disk_when_already_encrypted() {
    let _env = temp_data_home();
    let key = test_user_key();

    // Pre-state on disk: post-migration shape — the encrypted refresh
    // token is the same plaintext we install in-memory below, so
    // failure to rewrite would leave the assertion `new_enc !=
    // old_enc` red.
    let old_enc = encrypt_string("stale-but-valid", &key).expect("encrypt");
    store::save_session(&persisted_skeleton(None, Some(old_enc.clone()))).expect("save");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("grant_type=refresh_token".into()),
            mockito::Matcher::Regex("refresh_token=stale-but-valid".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(refresh_response_body("fresh-access", "rotated-refresh"))
        .create_async()
        .await;

    let state = AppState::default();
    let client = VaultwardenClient::new(&server.url()).expect("client");
    // expires_at = 90 s ago, well past the 60 s safety margin so
    // ensure_fresh_tokens MUST refresh — anything less and we'd be
    // testing the wrong branch.
    let stale = Instant::now() - Duration::from_secs(90);
    install_session(&state, client, "stale-but-valid", stale, test_user_key());

    ensure_fresh_tokens(&state).await.expect("refresh succeeds");

    mock.assert_async().await;

    // (a) In-memory session reflects the rotation.
    {
        let g = state.session.lock();
        let s = g.as_ref().expect("session present");
        assert_eq!(s.tokens.access_token, "fresh-access");
        assert_eq!(s.tokens.refresh_token, "rotated-refresh");
        assert!(
            s.expires_at > Instant::now(),
            "expires_at should have moved into the future after refresh",
        );
    }

    // (b) On-disk session.json reflects the rotation, *still* without
    //     plaintext. Reading it back and decrypting under the same
    //     user key must surface the rotated value verbatim.
    let after = store::load_session().expect("load").expect("present");
    assert!(
        after.refresh_token.is_none(),
        "legacy plaintext field must stay cleared after refresh",
    );
    let new_enc = after
        .encrypted_refresh_token
        .expect("encrypted refresh present");
    assert_ne!(
        new_enc, old_enc,
        "encrypted refresh on disk must reflect the rotated server token",
    );
    let decrypted = EncString::parse(&new_enc)
        .expect("parse")
        .decrypt_string_sym(&key)
        .expect("decrypt");
    assert_eq!(decrypted, "rotated-refresh");
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_migrates_legacy_plaintext_session_to_encrypted_form() {
    // Migration scenario: a session.json written before the
    // refresh-token encryption landed has `refresh_token` set in
    // plaintext and no `encrypted_refresh_token`. The very first
    // refresh after the user upgrades must rewrite the file with the
    // encrypted form *and clear the plaintext field* — leaving
    // plaintext on disk would defeat the whole encryption-at-rest
    // story for users who installed >v0.1.7 and never re-logged.
    let _env = temp_data_home();
    let key = test_user_key();

    store::save_session(&persisted_skeleton(
        Some("legacy-plain-refresh".into()),
        None,
    ))
    .expect("save legacy");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/identity/connect/token")
        .match_body(mockito::Matcher::Regex(
            "refresh_token=legacy-plain-refresh".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(refresh_response_body("fresh-access", "rotated-refresh"))
        .create_async()
        .await;

    let state = AppState::default();
    let client = VaultwardenClient::new(&server.url()).expect("client");
    let stale = Instant::now() - Duration::from_secs(90);
    install_session(
        &state,
        client,
        "legacy-plain-refresh",
        stale,
        test_user_key(),
    );

    ensure_fresh_tokens(&state).await.expect("refresh succeeds");

    mock.assert_async().await;

    let after = store::load_session().expect("load").expect("present");
    assert!(
        after.refresh_token.is_none(),
        "legacy plaintext field MUST be cleared after migration; \
         leaving it set means a stolen disk image would still leak \
         the refresh token",
    );
    let new_enc = after
        .encrypted_refresh_token
        .expect("encrypted refresh present after migration");
    let decrypted = EncString::parse(&new_enc)
        .expect("parse")
        .decrypt_string_sym(&key)
        .expect("decrypt");
    assert_eq!(decrypted, "rotated-refresh");
}

#[tokio::test(flavor = "current_thread")]
async fn ensure_fresh_tokens_is_a_noop_when_expires_at_is_outside_the_safety_margin() {
    // Mirror image of the two refresh tests: with `expires_at` well
    // beyond `now + 60s`, ensure_fresh_tokens must short-circuit
    // without touching the network or the disk. A regression that
    // re-encrypts on every call (e.g. someone forgetting the
    // early-return guard) would make this test fail by hitting the
    // mock — mockito::Mock::assert_async panics on zero invocations
    // when expected exactly once, but here we use `expect(0)` to
    // make the no-call expectation explicit.
    let _env = temp_data_home();
    let key = test_user_key();

    let original_enc = encrypt_string("untouched", &key).expect("encrypt");
    store::save_session(&persisted_skeleton(None, Some(original_enc.clone()))).expect("save");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/identity/connect/token")
        .with_status(500)
        .expect(0)
        .create_async()
        .await;

    let state = AppState::default();
    let client = VaultwardenClient::new(&server.url()).expect("client");
    // expires_at is comfortably past the 60 s safety margin into the
    // future — ensure_fresh_tokens must not call refresh_token.
    let fresh = Instant::now() + Duration::from_secs(600);
    install_session(&state, client, "still-good", fresh, test_user_key());

    ensure_fresh_tokens(&state).await.expect("noop ok");

    mock.assert_async().await;

    // Disk must be untouched too — the `needs_write` guard protects
    // us from rewriting an identical session.json on every command.
    let after = store::load_session().expect("load").expect("present");
    assert_eq!(
        after.encrypted_refresh_token.as_deref(),
        Some(original_enc.as_str())
    );
    assert!(after.refresh_token.is_none());
}
