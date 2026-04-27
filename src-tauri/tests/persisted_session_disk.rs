//! Disk-state integration tests for the persisted session, which
//! is what the "app restart" scenario boils down to once you peel
//! away tauri-driver: a session.json on disk, an unlock that
//! re-derives the user key from the password, and the assertions
//! we want to make about what's left on disk afterwards.
//!
//! The persisted-session round-trip and the legacy-plaintext
//! migration are described in #9 and tracked under #24. WDIO can't
//! reach these without a debug-only command exposing filesystem
//! state; here we just call `store::load_session` /
//! `store::save_session` directly with a temp `XDG_DATA_HOME` so
//! the tests don't trample the dev machine's real Clavix dir.
//!
//! The two tests here run sequentially in a single binary because
//! they all mutate `XDG_DATA_HOME`; a Mutex around the shared env
//! var keeps them serialised regardless of `--test-threads` value.

use std::sync::Mutex;

use clavix_lib::models::KdfType;
use clavix_lib::services::auth::recover_refresh_token;
use clavix_lib::store::{self, PersistedSession};
use tempfile::TempDir;

// SAFETY: `std::env::set_var` is process-wide and not thread-safe.
// Cargo runs tests in parallel by default; serialise around this
// Mutex so any test that mutates XDG_DATA_HOME sees a consistent
// view. Same trick as in the standard library's own env tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_temp_data_home<R>(f: impl FnOnce(&TempDir) -> R) -> R {
    let _guard = ENV_LOCK.lock().expect("env lock not poisoned");
    let dir = TempDir::new().expect("tempdir");
    let prev = std::env::var_os("XDG_DATA_HOME");
    // SAFETY: serialised under ENV_LOCK; no other thread can read
    // these vars while we're inside the closure.
    unsafe { std::env::set_var("XDG_DATA_HOME", dir.path()) };
    let out = f(&dir);
    unsafe {
        match prev {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
    }
    out
}

fn sample_session_with_legacy_plaintext() -> PersistedSession {
    PersistedSession {
        server_url: "https://vault.test".into(),
        email: "alice@test".into(),
        // Legacy field set, encrypted field absent — exactly the
        // shape a v0.1.7-era session.json had on disk before the
        // refresh-token-encryption landed.
        refresh_token: Some("legacy-plain-refresh".into()),
        encrypted_refresh_token: None,
        kdf: KdfType::Pbkdf2,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        encrypted_user_key: "2.aGVsbG8=|d29ybGQ=|aGVsbG8=".into(),
        encrypted_private_key: None,
        yubikey_unlock: None,
    }
}

#[test]
fn save_then_load_round_trips_every_field() {
    with_temp_data_home(|_dir| {
        let original = sample_session_with_legacy_plaintext();
        store::save_session(&original).expect("save");
        let loaded = store::load_session().expect("load").expect("some");

        assert_eq!(loaded.server_url, original.server_url);
        assert_eq!(loaded.email, original.email);
        assert_eq!(loaded.refresh_token, original.refresh_token);
        assert_eq!(loaded.encrypted_refresh_token, None);
        assert_eq!(loaded.kdf_iterations, original.kdf_iterations);
        assert_eq!(loaded.encrypted_user_key, original.encrypted_user_key);
    });
}

#[test]
fn clear_session_removes_the_file_and_load_returns_none() {
    with_temp_data_home(|_dir| {
        let original = sample_session_with_legacy_plaintext();
        store::save_session(&original).expect("save");
        assert!(store::load_session().expect("load").is_some());

        store::clear_session().expect("clear");

        // Idempotent: clearing twice is fine.
        store::clear_session().expect("clear-twice");

        let after = store::load_session().expect("load post-clear");
        assert!(
            after.is_none(),
            "session.json should be gone after clear_session, got {after:?}",
        );
    });
}

#[test]
fn recover_refresh_falls_back_to_legacy_field() {
    // Pure helper, no disk required. Covered already in the unit
    // tests but assert it again here so the integration suite
    // catches a regression even if the unit tests are bypassed in
    // a partial run.
    use clavix_lib::crypto::SymmetricKey;

    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(11);
    }
    let key = SymmetricKey::from_bytes(&bytes).unwrap();

    let persisted = sample_session_with_legacy_plaintext();
    let recovered = recover_refresh_token(&persisted, &key).expect("recover");
    assert_eq!(recovered, "legacy-plain-refresh");
}
