//! The unlocked vault, and the half-finished login that leads to it.
//!
//! Both types used to live in the desktop crate's `state::AppState`
//! alongside the tray flags and the SSH-agent handle. They're here now
//! because they're the only part of that struct a non-Tauri front end
//! (an iOS app, a CLI) would also need: everything in them is protocol
//! and key material, nothing is a window or a socket.
//!
//! `AppState` still owns the mutexes that hold them — this module
//! defines the values, not where a given front end parks them.

use std::collections::HashMap;
use std::time::Instant;

use rsa::RsaPrivateKey;
use zeroize::ZeroizeOnDrop;

use crate::api::VaultwardenClient;
use crate::crypto::{MasterKey, MasterPasswordHash, SymmetricKey};
use crate::models::{Prelogin, SyncResponse, TokenSet};

pub struct Session {
    pub client: VaultwardenClient,
    pub tokens: TokenSet,
    /// Wall-clock deadline after which `tokens.access_token` must be refreshed.
    /// Computed from `tokens.expires_in` at the time the token was issued,
    /// with a 30-second safety margin so we refresh slightly before the
    /// server considers the token dead.
    pub expires_at: Instant,
    pub user_key: SymmetricKey,
    pub private_key: Option<RsaPrivateKey>,
    pub org_keys: HashMap<String, SymmetricKey>,
    pub vault: Option<SyncResponse>,
}

/// Material derived during the `login` step that has to survive until
/// the user completes the second factor. Living here rather than being
/// re-derived on `login_with_two_factor` saves an Argon2id round (~1 s
/// on hardened settings), but the security win is the headline: the
/// rpId anchor used by `webauthn_sign_challenge` is now sourced from
/// here, not from a JS argument that a compromised renderer could
/// rewrite between calls.
#[derive(ZeroizeOnDrop)]
pub struct PendingTwoFactor {
    #[zeroize(skip)]
    pub server_url: String,
    #[zeroize(skip)]
    pub email: String,
    pub master_key: MasterKey,
    pub password_hash: MasterPasswordHash,
    #[zeroize(skip)]
    pub prelogin: Prelogin,
    #[zeroize(skip)]
    pub client: VaultwardenClient,
    /// Wall-clock instant the slot was opened. Anything older than the
    /// TTL is treated as expired by `take_pending_two_factor`.
    #[zeroize(skip)]
    pub created_at: Instant,
}

/// How long a `PendingTwoFactor` slot stays valid. Long enough that a
/// user can fish their YubiKey out of a bag and tap it; short enough
/// that a forgotten slot doesn't accumulate keying material in memory
/// indefinitely.
pub const PENDING_2FA_TTL_SECS: u64 = 300;
