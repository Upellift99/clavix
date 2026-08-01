//! Where this app's `AppState` meets the engine's session slots.
//!
//! `clavix_core::services::auth` operates on the two mutexes it needs —
//! the session and the pending-2FA slot — and knows nothing about the
//! tray flags or the SSH agent that share the struct with them. These
//! wrappers hand it the right field so every command can keep passing
//! `&state`, and so the auto-lock bookkeeping that only exists on this
//! side stays attached to the calls that imply a live user.

use clavix_core::api::VaultwardenClient;
use clavix_core::crypto::SymmetricKey;
use clavix_core::error::Result;
use clavix_core::models::TokenSet;
use clavix_core::services::auth as core_auth;
use clavix_core::session::PendingTwoFactor;
use rsa::RsaPrivateKey;

use crate::state::{mark_activity, AppState};

/// Refresh the access token if it is close to expiring, and record that
/// the user is still around.
///
/// `mark_activity` lives here rather than in the engine because it feeds
/// the auto-lock watchdog, which is a desktop concern — but it belongs on
/// this call and not at the call sites: every command that reaches the
/// server goes through here, and a `mark_activity` that has to be
/// remembered separately is one that eventually isn't.
pub async fn ensure_fresh_tokens(state: &AppState) -> Result<()> {
    mark_activity(state);
    core_auth::ensure_fresh_tokens(&state.session).await
}

pub fn store_session(
    state: &AppState,
    client: VaultwardenClient,
    tokens: TokenSet,
    user_key: SymmetricKey,
    private_key: Option<RsaPrivateKey>,
) {
    core_auth::store_session(&state.session, client, tokens, user_key, private_key);
}

pub fn set_pending_two_factor(state: &AppState, pending: PendingTwoFactor) {
    core_auth::set_pending_two_factor(&state.pending_2fa, pending);
}

pub fn clear_pending_two_factor(state: &AppState) {
    core_auth::clear_pending_two_factor(&state.pending_2fa);
}

pub fn clear_pending_two_factor_if_stale(state: &AppState) {
    core_auth::clear_pending_two_factor_if_stale(&state.pending_2fa);
}

pub fn with_pending_two_factor<R>(
    state: &AppState,
    f: impl FnOnce(&PendingTwoFactor) -> Result<R>,
) -> Result<R> {
    core_auth::with_pending_two_factor(&state.pending_2fa, f)
}
