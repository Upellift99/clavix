//! Integration test: a standalone session is fenced off from writes.
//!
//! A vault can now be opened with no server behind it — from the local
//! encrypted cache when the server is unreachable, or straight out of
//! an encrypted export file. Neither can push anything anywhere, and
//! the enforcement is deliberately *not* the UI hiding buttons: every
//! mutating command calls `ensure_fresh_tokens` first, and no read path
//! does, so refusing a tokenless session there fences off the whole
//! write surface in one place.
//!
//! These tests pin that property down from the engine side, without
//! Tauri and without a server: if someone later adds a write command
//! that skips `ensure_fresh_tokens`, the invariant these assert is the
//! one that was being relied on.

use std::collections::HashMap;

use clavix_core::crypto::SymmetricKey;
use clavix_core::error::Error;
use clavix_core::services::auth::{ensure_fresh_tokens, store_standalone_session, SessionSlot};
use clavix_core::session::SessionOrigin;

fn slot() -> SessionSlot {
    SessionSlot::new(None)
}

fn open_standalone(origin: SessionOrigin) -> SessionSlot {
    let s = slot();
    store_standalone_session(
        &s,
        origin,
        SymmetricKey::generate(),
        None,
        HashMap::new(),
        None,
    );
    s
}

#[tokio::test]
async fn a_cache_backed_session_refuses_writes() {
    let session = open_standalone(SessionOrigin::OfflineCache);
    let err = ensure_fresh_tokens(&session)
        .await
        .expect_err("a tokenless session must not pass the write firewall");
    assert!(
        matches!(err, Error::ReadOnlySession),
        "expected ReadOnlySession, got {err:?}"
    );
}

#[tokio::test]
async fn a_file_backed_session_refuses_writes() {
    let session = open_standalone(SessionOrigin::ExportFile);
    let err = ensure_fresh_tokens(&session)
        .await
        .expect_err("a tokenless session must not pass the write firewall");
    assert!(
        matches!(err, Error::ReadOnlySession),
        "expected ReadOnlySession, got {err:?}"
    );
}

#[tokio::test]
async fn no_session_at_all_still_reports_not_authenticated() {
    // The two must stay distinguishable: "sign in" and "this vault is
    // read-only" send the user to completely different places.
    let session = slot();
    let err = ensure_fresh_tokens(&session)
        .await
        .expect_err("no session means no writes either");
    assert!(
        matches!(err, Error::NotAuthenticated),
        "expected NotAuthenticated, got {err:?}"
    );
}

#[test]
fn standalone_origins_are_not_writable() {
    assert!(SessionOrigin::Server.is_writable());
    assert!(!SessionOrigin::OfflineCache.is_writable());
    assert!(!SessionOrigin::ExportFile.is_writable());
}

#[test]
fn a_standalone_session_exposes_no_client_or_token() {
    let session = open_standalone(SessionOrigin::ExportFile);
    let guard = session.lock();
    let s = guard.as_ref().expect("session present");

    assert!(!s.is_writable());
    assert!(
        matches!(s.client(), Err(Error::ReadOnlySession)),
        "reaching for the client must fail rather than panic"
    );
    assert!(
        matches!(s.access_token(), Err(Error::ReadOnlySession)),
        "reaching for the access token must fail rather than panic"
    );
}
