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
use serde::Serialize;
use ts_rs::TS;
use zeroize::ZeroizeOnDrop;

use crate::api::VaultwardenClient;
use crate::crypto::{MasterKey, MasterPasswordHash, SymmetricKey};
use crate::error::{Error, Result};
use crate::models::{Prelogin, SyncResponse, TokenSet};

/// Where the vault in a session came from.
///
/// A session used to imply a live account on a reachable server. It no
/// longer does: a vault can also be opened from the local encrypted
/// cache when the server is down, or straight out of an encrypted
/// export file with no account at all. The two latter cases have no
/// tokens, and so no way to write anything back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum SessionOrigin {
    /// Signed in against the server. The only origin that can write.
    Server,
    /// Unlocked from the on-disk encrypted cache with the server
    /// unreachable. The account exists; it just can't be reached.
    OfflineCache,
    /// Opened from an encrypted export file. No account involved.
    ExportFile,
}

impl SessionOrigin {
    /// Whether this session can push changes anywhere.
    pub fn is_writable(self) -> bool {
        matches!(self, SessionOrigin::Server)
    }
}

pub struct Session {
    /// `None` for a standalone session — see [`SessionOrigin`]. Reach
    /// for it through [`Session::client`], which turns absence into the
    /// error the UI knows how to explain.
    pub client: Option<VaultwardenClient>,
    pub tokens: Option<TokenSet>,
    /// Wall-clock deadline after which `tokens.access_token` must be refreshed.
    /// Computed from `tokens.expires_in` at the time the token was issued,
    /// with a 30-second safety margin so we refresh slightly before the
    /// server considers the token dead. `None` when there are no tokens.
    pub expires_at: Option<Instant>,
    pub origin: SessionOrigin,
    pub user_key: SymmetricKey,
    pub private_key: Option<RsaPrivateKey>,
    pub org_keys: HashMap<String, SymmetricKey>,
    pub vault: Option<SyncResponse>,
}

impl Session {
    /// The API client, or [`Error::ReadOnlySession`] when there isn't one.
    ///
    /// In practice no caller should ever see that error: every command
    /// that reaches for the client goes through `ensure_fresh_tokens`
    /// first, which refuses a tokenless session outright. This is the
    /// backstop for a command that forgets to.
    pub fn client(&self) -> Result<&VaultwardenClient> {
        self.client.as_ref().ok_or(Error::ReadOnlySession)
    }

    /// The current access token, same contract as [`Session::client`].
    pub fn access_token(&self) -> Result<&str> {
        self.tokens
            .as_ref()
            .map(|t| t.access_token.as_str())
            .ok_or(Error::ReadOnlySession)
    }

    pub fn is_writable(&self) -> bool {
        self.origin.is_writable() && self.tokens.is_some()
    }
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
