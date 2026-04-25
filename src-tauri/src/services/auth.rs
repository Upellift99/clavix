use std::collections::HashMap;
use std::time::{Duration, Instant};

use rsa::RsaPrivateKey;
use secrecy::SecretString;
use tauri::State;

use crate::api::{DeviceInfo, VaultwardenClient};
use crate::crypto::{
    decrypt_private_key, decrypt_user_key, derive_master_key, derive_master_password_hash,
    encrypt_string, EncString, MasterKey, MasterPasswordHash, SymmetricKey,
};
use crate::error::{Error, Result};
use crate::models::{Prelogin, TokenSet};
use crate::state::{AppState, PendingTwoFactor, Session, PENDING_2FA_TTL_SECS};
use crate::store::{self, PersistedSession};

/// Recover the refresh token from a persisted session. Prefers the encrypted
/// field (current format); falls back to the legacy clear-text field for
/// session files written before refresh-token encryption landed. Old files are
/// migrated to the encrypted form on the next `save_session`.
pub fn recover_refresh_token(
    persisted: &PersistedSession,
    user_key: &SymmetricKey,
) -> Result<String> {
    if let Some(enc) = &persisted.encrypted_refresh_token {
        return EncString::parse(enc)?.decrypt_string_sym(user_key);
    }
    if let Some(legacy) = &persisted.refresh_token {
        return Ok(legacy.clone());
    }
    Err(Error::Storage {
        reason: "session has no refresh token (neither encrypted nor legacy)".into(),
    })
}

pub fn device_info() -> Result<DeviceInfo> {
    Ok(DeviceInfo {
        identifier: store::get_or_create_device_id()?,
        name: "Clavix".to_string(),
        device_type: 8,
    })
}

pub async fn prepare_credentials(
    server_url: &str,
    email: &str,
    password: &SecretString,
) -> Result<(VaultwardenClient, Prelogin, MasterKey, MasterPasswordHash)> {
    let client = VaultwardenClient::new(server_url)?;
    let pre = client.prelogin(email).await?;
    let master_key = derive_master_key(
        password,
        email,
        pre.kdf,
        pre.kdf_iterations,
        pre.kdf_memory,
        pre.kdf_parallelism,
    )?;
    let hash = derive_master_password_hash(&master_key, password);
    Ok((client, pre, master_key, hash))
}

pub fn extract_session_keys(
    master_key: &MasterKey,
    tokens: &TokenSet,
) -> Result<(SymmetricKey, Option<RsaPrivateKey>)> {
    let key_str = tokens.key.as_deref().ok_or_else(|| Error::Crypto {
        reason: "TokenSet is missing the 'key' field — cannot derive user key".into(),
    })?;
    let user_key = decrypt_user_key(master_key, key_str)?;

    let private_key = tokens
        .private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;

    Ok((user_key, private_key))
}

pub fn compute_expires_at(expires_in: u64) -> Instant {
    Instant::now() + Duration::from_secs(expires_in.saturating_sub(30).max(1))
}

pub fn store_session(
    state: &AppState,
    client: VaultwardenClient,
    tokens: TokenSet,
    user_key: SymmetricKey,
    private_key: Option<RsaPrivateKey>,
) {
    let expires_at = compute_expires_at(tokens.expires_in);
    let mut guard = state.session.lock();
    *guard = Some(Session {
        client,
        tokens,
        expires_at,
        user_key,
        private_key,
        org_keys: HashMap::new(),
        vault: None,
    });
}

/// Refresh `tokens.access_token` if it is within 60 seconds of expiring.
/// No-op otherwise. Commands that hit the Vaultwarden API call this before
/// the first access-token use.
pub async fn ensure_fresh_tokens(state: &State<'_, AppState>) -> Result<()> {
    crate::state::mark_activity(state);
    let (client, refresh) = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        if s.expires_at > Instant::now() + Duration::from_secs(60) {
            return Ok(());
        }
        (s.client.clone(), s.tokens.refresh_token.clone())
    };

    let device = device_info()?;
    let mut new_tokens = client.refresh_token(&refresh, &device).await?;
    if new_tokens.refresh_token.is_empty() {
        new_tokens.refresh_token = refresh.clone();
    }

    let new_refresh = new_tokens.refresh_token.clone();
    let new_access = new_tokens.access_token.clone();
    let new_expires_in = new_tokens.expires_in;

    // Re-encrypt the (possibly rotated) refresh token under the user key while
    // we still hold the session lock, so we never persist clear-text on disk.
    let encrypted_refresh = {
        let guard = state.session.lock();
        let s = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        encrypt_string(&new_refresh, &s.user_key)?
    };

    {
        let mut guard = state.session.lock();
        if let Some(s) = guard.as_mut() {
            s.tokens.access_token = new_access;
            s.tokens.refresh_token = new_refresh;
            s.tokens.expires_in = new_expires_in;
            s.expires_at = compute_expires_at(new_expires_in);
        }
    }

    if let Ok(Some(mut persisted)) = store::load_session() {
        let needs_write = persisted.encrypted_refresh_token.as_deref() != Some(&encrypted_refresh)
            || persisted.refresh_token.is_some();
        if needs_write {
            persisted.encrypted_refresh_token = Some(encrypted_refresh);
            persisted.refresh_token = None;
            let _ = store::save_session(&persisted);
        }
    }

    Ok(())
}

/// Park the in-flight 2FA login material so the second-factor IPC
/// calls can read from a Rust-owned slot instead of taking the same
/// values back from the renderer. Replaces (and zeroizes) any previous
/// pending login, so the user clicking "Se connecter" twice does not
/// leave keys hanging around for the longer of the two TTLs.
pub fn set_pending_two_factor(state: &AppState, pending: PendingTwoFactor) {
    let mut slot = state.pending_2fa.lock();
    *slot = Some(pending);
}

/// Drop and zeroize any pending 2FA slot. Cheap; safe to call when
/// nothing is pending.
pub fn clear_pending_two_factor(state: &AppState) {
    let mut slot = state.pending_2fa.lock();
    *slot = None;
}

/// Borrow the pending 2FA slot for a single async section. Returns an
/// error when nothing is pending or when the slot has gone stale past
/// the TTL — the stale path zeroizes the slot on the way out.
pub fn with_pending_two_factor<R>(
    state: &AppState,
    f: impl FnOnce(&PendingTwoFactor) -> Result<R>,
) -> Result<R> {
    let mut slot = state.pending_2fa.lock();
    let stale = slot
        .as_ref()
        .map(|p| p.created_at.elapsed() > Duration::from_secs(PENDING_2FA_TTL_SECS))
        .unwrap_or(false);
    if stale {
        *slot = None;
    }
    let pending = slot.as_ref().ok_or_else(|| Error::Storage {
        reason: "no 2FA login is pending — call `login` first".into(),
    })?;
    f(pending)
}

pub fn persist_session(
    server_url: &str,
    email: &str,
    pre: &Prelogin,
    tokens: &TokenSet,
    user_key: &SymmetricKey,
) -> Result<()> {
    let encrypted_user_key = tokens.key.clone().ok_or_else(|| Error::Crypto {
        reason: "TokenSet is missing the 'key' field — cannot persist session".into(),
    })?;

    let encrypted_refresh_token = encrypt_string(&tokens.refresh_token, user_key)?;

    let persisted = PersistedSession {
        server_url: server_url.to_string(),
        email: email.to_string(),
        refresh_token: None,
        encrypted_refresh_token: Some(encrypted_refresh_token),
        kdf: pre.kdf,
        kdf_iterations: pre.kdf_iterations,
        kdf_memory: pre.kdf_memory,
        kdf_parallelism: pre.kdf_parallelism,
        encrypted_user_key,
        encrypted_private_key: tokens.private_key.clone(),
    };
    store::save_session(&persisted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_string, SymmetricKey};
    use crate::models::KdfType;

    fn test_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn persisted_with(
        encrypted_refresh_token: Option<String>,
        refresh_token: Option<String>,
    ) -> PersistedSession {
        PersistedSession {
            server_url: "https://vault.example.com".into(),
            email: "u@e.com".into(),
            refresh_token,
            encrypted_refresh_token,
            kdf: KdfType::Pbkdf2,
            kdf_iterations: 600_000,
            kdf_memory: None,
            kdf_parallelism: None,
            encrypted_user_key: String::new(),
            encrypted_private_key: None,
        }
    }

    #[test]
    fn recover_refresh_prefers_encrypted_over_legacy() {
        // Both fields present (a file written mid-migration). The encrypted
        // field wins — the legacy plaintext must never be returned when a
        // properly-encrypted version exists, otherwise we'd leak plaintext
        // on disk through a channel we thought was closed.
        let key = test_key();
        let enc = encrypt_string("real-token", &key).unwrap();
        let p = persisted_with(Some(enc), Some("legacy-ignored".into()));

        let got = recover_refresh_token(&p, &key).unwrap();
        assert_eq!(got, "real-token");
    }

    #[test]
    fn recover_refresh_falls_back_to_legacy_when_no_encrypted() {
        // Session files written before the refresh-token encryption landed
        // only have the plaintext `refresh_token`. We must still be able to
        // unlock them — the caller is responsible for re-encrypting and
        // clearing the legacy field on the next save.
        let key = test_key();
        let p = persisted_with(None, Some("plain-token".into()));

        let got = recover_refresh_token(&p, &key).unwrap();
        assert_eq!(got, "plain-token");
    }

    #[test]
    fn recover_refresh_errors_when_neither_field_is_set() {
        let key = test_key();
        let p = persisted_with(None, None);

        let err = recover_refresh_token(&p, &key).unwrap_err();
        assert!(matches!(err, Error::Storage { .. }));
    }

    #[test]
    fn compute_expires_at_stays_ahead_of_now_and_applies_safety_margin() {
        // The 30-second safety margin means a token the server considers
        // valid for 60s must only be considered valid for ~30s locally, so
        // ensure_fresh_tokens gets a chance to refresh before the server
        // rejects the call.
        let before = Instant::now();
        let deadline = compute_expires_at(60);
        let after = Instant::now();

        let offset_lower = deadline.saturating_duration_since(after);
        let offset_upper = deadline.saturating_duration_since(before);
        assert!(offset_lower <= Duration::from_secs(30));
        assert!(offset_upper >= Duration::from_secs(29));
    }

    #[test]
    fn compute_expires_at_clamps_small_values_to_one_second() {
        // If the server returns a token already expired or about to expire,
        // saturating_sub(30) underflows to zero and max(1) kicks in so the
        // deadline is still strictly in the future (avoids an Instant in
        // the past that would make ensure_fresh_tokens loop forever).
        let now = Instant::now();
        let deadline_zero = compute_expires_at(0);
        let deadline_small = compute_expires_at(10);
        assert!(deadline_zero > now);
        assert!(deadline_small > now);
    }
}
