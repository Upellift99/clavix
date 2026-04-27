use std::time::Instant;

use secrecy::SecretString;
use serde::Serialize;
use tauri::State;

use crate::api::VaultwardenClient;
use crate::cache;
use crate::crypto::{
    decrypt_private_key, decrypt_user_key, derive_master_key, encrypt_string, SymmetricKey,
};
use crate::error::{Error, Result};
use crate::models::{LoginOk, LoginOutcome, LoginResult, Prelogin, TwoFactorProvider};
use crate::services::auth::{
    clear_pending_two_factor, device_info, extract_session_keys, persist_session,
    prepare_credentials, recover_refresh_token, set_pending_two_factor, store_session,
    with_pending_two_factor,
};
use crate::state::{AppState, PendingTwoFactor};
use crate::store;
use crate::yubikey_unlock;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAccount {
    pub server_url: String,
    pub email: String,
}

#[tauri::command]
pub fn stored_account() -> Result<Option<StoredAccount>> {
    Ok(store::load_session()?.map(|s| StoredAccount {
        server_url: s.server_url,
        email: s.email,
    }))
}

#[tauri::command]
pub async fn prelogin(server_url: String, email: String) -> Result<Prelogin> {
    let client = VaultwardenClient::new(&server_url)?;
    client.prelogin(&email).await
}

#[tauri::command]
pub async fn login(
    state: State<'_, AppState>,
    server_url: String,
    email: String,
    password: String,
) -> Result<LoginOutcome> {
    let password: SecretString = password.into();
    let (client, pre, master_key, hash) =
        prepare_credentials(&server_url, &email, &password).await?;
    let device = device_info()?;
    let result = client.login(&email, &hash, &device).await?;

    match result {
        LoginResult::Success(tokens) => {
            // Single-factor login won — drop any leftover pending slot
            // (e.g. a previous attempt that needed 2FA but never
            // finished) before opening the new session.
            clear_pending_two_factor(&state);
            let (user_key, private_key) = extract_session_keys(&master_key, &tokens)?;
            persist_session(&server_url, &email, &pre, &tokens, &user_key)?;
            store_session(&state, client, tokens, user_key, private_key);
            Ok(LoginOutcome::Success(LoginOk { email }))
        }
        LoginResult::TwoFactorRequired {
            providers,
            webauthn_challenge,
        } => {
            // Park the derived material so `webauthn_sign_challenge`
            // and `login_with_two_factor` can read from a Rust-owned
            // slot rather than re-receiving it from the renderer. The
            // renderer never needs to send back the server URL, the
            // email, or the password again — closes the gap where a
            // compromised JS could swap any of those between the two
            // IPC calls.
            set_pending_two_factor(
                &state,
                PendingTwoFactor {
                    server_url,
                    email,
                    master_key,
                    password_hash: hash,
                    prelogin: pre,
                    client,
                    created_at: Instant::now(),
                },
            );
            Ok(LoginOutcome::TwoFactorRequired {
                providers,
                webauthn_challenge,
            })
        }
    }
}

#[tauri::command]
pub async fn login_with_two_factor(
    state: State<'_, AppState>,
    code: String,
    provider: u8,
) -> Result<LoginOk> {
    let typed_provider = TwoFactorProvider::try_from(provider)
        .map_err(|_| Error::TwoFactorProviderUnsupported { provider })?;

    // Pull the pending slot's contents out under the lock, then drop
    // it so the secrets are zeroized as soon as the await below
    // finishes — success or failure.
    let (server_url, email, hash, master_key, prelogin, client) =
        with_pending_two_factor(&state, |p| {
            Ok((
                p.server_url.clone(),
                p.email.clone(),
                p.password_hash.clone(),
                p.master_key.clone(),
                p.prelogin.clone(),
                p.client.clone(),
            ))
        })?;

    let device = device_info()?;
    let tokens = match client
        .login_with_two_factor(&email, &hash, &device, typed_provider, &code)
        .await
    {
        Ok(tokens) => tokens,
        Err(err) => {
            // Wrong code: keep the pending slot alive so the user can
            // retry without redoing the Argon2id round. Other errors
            // (network, malformed response) clear the slot to be safe.
            if !matches!(err, Error::AuthFailed { .. }) {
                clear_pending_two_factor(&state);
            }
            return Err(err);
        }
    };

    let (user_key, private_key) = extract_session_keys(&master_key, &tokens)?;
    persist_session(&server_url, &email, &prelogin, &tokens, &user_key)?;
    store_session(&state, client, tokens, user_key, private_key);
    clear_pending_two_factor(&state);
    Ok(LoginOk { email })
}

/// Drop the parked 2FA login slot. Called by the frontend when the
/// user clicks "Annuler" on the 2FA screen, and as a defensive
/// cleanup whenever the session is reset.
#[tauri::command]
pub fn cancel_two_factor(state: State<'_, AppState>) -> Result<()> {
    clear_pending_two_factor(&state);
    Ok(())
}

#[tauri::command]
pub async fn unlock(state: State<'_, AppState>, password: String) -> Result<LoginOk> {
    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to unlock".into(),
    })?;

    let password: SecretString = password.into();
    let master_key = derive_master_key(
        &password,
        &persisted.email,
        persisted.kdf,
        persisted.kdf_iterations,
        persisted.kdf_memory,
        persisted.kdf_parallelism,
    )?;

    let user_key = decrypt_user_key(&master_key, &persisted.encrypted_user_key)?;
    let private_key = persisted
        .encrypted_private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;

    // Decrypt refresh token (or fall back to legacy clear-text for sessions
    // written before encryption landed; those are migrated below).
    let refresh_token_plain = recover_refresh_token(&persisted, &user_key)?;

    let client = VaultwardenClient::new(&persisted.server_url)?;
    let device = device_info()?;
    let mut tokens = client.refresh_token(&refresh_token_plain, &device).await?;

    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token_plain.clone();
    }

    // Re-encrypt and drop any legacy clear-text field.
    let encrypted_refresh = encrypt_string(&tokens.refresh_token, &user_key)?;
    let mut updated = persisted.clone();
    updated.refresh_token = None;
    updated.encrypted_refresh_token = Some(encrypted_refresh);
    store::save_session(&updated)?;

    let email = persisted.email.clone();
    store_session(&state, client, tokens, user_key, private_key);
    crate::state::mark_activity(&state);
    Ok(LoginOk { email })
}

/// Perform a WebAuthn / FIDO2 assertion against the user's USB security
/// key, for a Bitwarden-style challenge. Returns the JSON string that
/// must be sent back to the server as `twoFactorToken` with provider=7.
///
/// The rpId anchor used by `validate_rp_id` is read from the parked
/// `PendingTwoFactor` slot — the same `server_url` the user typed at
/// the start of `login()`. The renderer no longer passes it back: a
/// compromised JS layer could otherwise swap the anchor between the
/// `login` and `webauthn_sign_challenge` calls.
///
/// Blocking CTAP2 I/O is offloaded to the async runtime's blocking pool
/// so the Tauri main loop stays responsive while the user taps their key.
#[tauri::command]
pub async fn webauthn_sign_challenge(
    state: State<'_, AppState>,
    challenge_json: String,
) -> Result<String> {
    let server_url = with_pending_two_factor(&state, |p| Ok(p.server_url.clone()))?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::webauthn::sign_bitwarden_challenge(&challenge_json, &server_url)
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("webauthn blocking task panicked: {e}"),
    })?
}

/// Whether the persisted session has a Yubikey wrap on disk. Lets the
/// unlock view decide whether to render the "Toucher la Yubikey"
/// button. Returns `false` (rather than an error) when no session is
/// stored yet, so the caller can ignore the value during onboarding.
#[tauri::command]
pub fn yubikey_unlock_state() -> Result<bool> {
    Ok(store::load_session()?
        .map(|s| s.yubikey_unlock.is_some())
        .unwrap_or(false))
}

/// Wrap the in-memory user key under a freshly-enrolled FIDO2
/// credential and persist the resulting block. Requires an unlocked
/// session (the wrap target is the live user key — we never re-derive
/// it from the master password here, which keeps this command
/// password-free by construction). The blocking CTAP I/O is offloaded
/// to the runtime's blocking pool so the Tauri main loop stays
/// responsive while the user taps their key.
#[tauri::command]
pub async fn enroll_yubikey_unlock(state: State<'_, AppState>, pin: Option<String>) -> Result<()> {
    crate::state::mark_activity(&state);

    let user_key = clone_user_key(&state)?;

    let block = tauri::async_runtime::spawn_blocking(move || {
        yubikey_unlock::enroll(
            &yubikey_unlock::CtapHidDevice,
            yubikey_unlock::DEFAULT_RP_ID,
            pin.as_deref(),
            &user_key,
        )
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("yubikey enrol task panicked: {e}"),
    })??;

    let mut persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session — yubikey enrolment requires a previous master-password sign-in"
            .into(),
    })?;
    persisted.yubikey_unlock = Some(block);
    store::save_session(&persisted)?;
    Ok(())
}

/// Drop the on-disk Yubikey wrap. Requires the master password to
/// avoid the "logged-in laptop briefly unattended → attacker
/// disenrols silently" scenario from the threat model. We validate
/// the password by deriving and decrypting the existing
/// `encrypted_user_key`; that proves possession without contacting
/// the server.
///
/// The credential remains on the token. Removing it from the
/// authenticator requires a separate FIDO2 management flow we don't
/// run — `ykman fido credentials` is the user's tool for that.
#[tauri::command]
pub async fn disenroll_yubikey_unlock(state: State<'_, AppState>, password: String) -> Result<()> {
    crate::state::mark_activity(&state);

    let mut persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to disenrol from".into(),
    })?;

    let password: SecretString = password.into();
    let master_key = derive_master_key(
        &password,
        &persisted.email,
        persisted.kdf,
        persisted.kdf_iterations,
        persisted.kdf_memory,
        persisted.kdf_parallelism,
    )?;
    // Probe: if the password is wrong this errors out before we touch
    // the on-disk block, so a wrong-password call is a no-op rather
    // than a silent disenrolment.
    let _ = decrypt_user_key(&master_key, &persisted.encrypted_user_key)?;

    persisted.yubikey_unlock = None;
    store::save_session(&persisted)?;
    Ok(())
}

/// Release the cached user key by replaying the stored salt against
/// the registered FIDO2 credential. Drops the wrap and surfaces
/// `YubikeyStaleWrap` if the master password was rotated on another
/// client (detected via the user-key fingerprint). Beyond the
/// user-key recovery, the rest of the flow mirrors `unlock` byte-
/// for-byte: refresh the access token, re-encrypt the rotated
/// refresh token under the user key, restore the session.
#[tauri::command]
pub async fn unlock_with_yubikey(
    state: State<'_, AppState>,
    pin: Option<String>,
) -> Result<LoginOk> {
    let persisted = store::load_session()?.ok_or_else(|| Error::Storage {
        reason: "no stored session to unlock".into(),
    })?;
    let block = persisted
        .yubikey_unlock
        .clone()
        .ok_or_else(|| Error::Storage {
            reason: "no yubikey wrap stored — enrol after a master-password unlock first".into(),
        })?;

    let unwrap_result = tauri::async_runtime::spawn_blocking(move || {
        yubikey_unlock::unwrap_user_key(&yubikey_unlock::CtapHidDevice, &block, pin.as_deref())
    })
    .await
    .map_err(|e| Error::Crypto {
        reason: format!("yubikey unlock task panicked: {e}"),
    })?;

    let user_key_bytes = match unwrap_result {
        Ok(bytes) => bytes,
        Err(Error::YubikeyStaleWrap) => {
            // The wrap on disk no longer matches the server's user
            // key (master password rotated elsewhere). Drop it so the
            // unlock view stops offering the Yubikey button until a
            // fresh enrolment after master-password sign-in.
            if let Ok(Some(mut updated)) = store::load_session() {
                updated.yubikey_unlock = None;
                let _ = store::save_session(&updated);
            }
            return Err(Error::YubikeyStaleWrap);
        }
        Err(other) => return Err(other),
    };

    let user_key = SymmetricKey::from_bytes(user_key_bytes.as_slice())?;
    let private_key = persisted
        .encrypted_private_key
        .as_deref()
        .map(|pk| decrypt_private_key(&user_key, pk))
        .transpose()?;
    let refresh_token_plain = recover_refresh_token(&persisted, &user_key)?;

    let client = VaultwardenClient::new(&persisted.server_url)?;
    let device = device_info()?;
    let mut tokens = client.refresh_token(&refresh_token_plain, &device).await?;
    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token_plain.clone();
    }

    let encrypted_refresh = encrypt_string(&tokens.refresh_token, &user_key)?;
    let mut updated = persisted.clone();
    updated.refresh_token = None;
    updated.encrypted_refresh_token = Some(encrypted_refresh);
    store::save_session(&updated)?;

    let email = persisted.email.clone();
    store_session(&state, client, tokens, user_key, private_key);
    crate::state::mark_activity(&state);
    Ok(LoginOk { email })
}

/// Clone the unlocked user key out of the session lock for use by a
/// blocking CTAP task. Errors out (rather than silently failing) if
/// no session is open, so a frontend that calls enrol from the
/// unlock view by mistake gets a clean "not authenticated" message.
fn clone_user_key(state: &AppState) -> Result<SymmetricKey> {
    let guard = state.session.lock();
    let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
    // SymmetricKey is not Clone — round-trip through the 64-byte
    // representation, the same shape `from_bytes` already validates.
    let bytes = session.user_key.to_bytes();
    SymmetricKey::from_bytes(bytes.as_slice())
}

#[tauri::command]
pub fn set_auto_lock_minutes(state: State<'_, AppState>, minutes: f64) -> Result<()> {
    let mut guard = state.auto_lock_minutes.lock();
    *guard = if minutes.is_finite() && minutes > 0.0 {
        Some(minutes)
    } else {
        None
    };
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<()> {
    let agent = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = agent {
        h.stop_sync();
    }
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    // A pending 2FA slot only matters for an in-flight login; once the
    // session is locked there is no scenario where we want to keep
    // those secrets around.
    clear_pending_two_factor(&state);
    Ok(())
}

#[tauri::command]
pub fn logout(state: State<'_, AppState>) -> Result<()> {
    let agent = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = agent {
        h.stop_sync();
    }
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    clear_pending_two_factor(&state);
    store::clear_session()?;
    if let Err(e) = cache::clear_all() {
        eprintln!("[clavix] vault cache clear failed: {e}");
    }
    Ok(())
}
