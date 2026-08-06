//! Opening a vault with no server behind it.
//!
//! Two ways in, both landing on the same read-only session:
//!
//! - the offline cache, reached from `unlock` when the server cannot be
//!   contacted (see `commands::auth::unlock`);
//! - an encrypted export file, opened here with nothing but its own
//!   password — no account, no stored session, no network.
//!
//! The second is the emergency-restore case: the machine is new, the
//! server is gone, and all that survives is a backup file. It works
//! because an export is a `SyncResponse` re-keyed under a vault key
//! (see `clavix_core::export`), so dropping that key and that response
//! into the session slot makes every existing read path — the item
//! list, `get_cipher`, `reveal_field`, `totp_code` — work unchanged.
//!
//! Neither origin can write anything: `ensure_fresh_tokens` refuses a
//! session with no tokens, and every mutating command goes through it.

use tauri::State;

use crate::session::store_standalone_session;
use crate::state::AppState;
use clavix_core::error::{Error, Result};
use clavix_core::export;
use clavix_core::models::{LoginOk, SyncSummary};
use clavix_core::services::vault::build_sync_summary;
use clavix_core::session::SessionOrigin;
use secrecy::SecretString;

/// Open an encrypted export file as a standalone, read-only vault.
///
/// Deliberately refuses to run while another vault is open. Replacing a
/// live session with a file's contents would leave the UI showing one
/// vault's items under another's identity, and the account's own keys
/// would be dropped without the user having asked to sign out.
#[tauri::command]
pub fn open_export_file(
    state: State<'_, AppState>,
    bytes: Vec<u8>,
    file_password: String,
) -> Result<LoginOk> {
    if state.session.lock().is_some() {
        return Err(Error::Storage {
            reason: "a vault is already open — lock it before opening an export file".into(),
        });
    }

    let (vault, vault_key) = export::open(&bytes, &SecretString::from(file_password))?;

    // The export flattened every owner onto the vault key but kept
    // `organizationId` so the UI can still filter by organisation;
    // `owning_key` therefore has to resolve those ids to something.
    let org_keys = export::org_key_map(&vault, &vault_key);
    let email = vault.profile.email.clone();

    store_standalone_session(
        &state,
        SessionOrigin::ExportFile,
        vault_key,
        // An export carries no RSA private key: it holds no wrapped org
        // keys to unwrap, having flattened them all.
        None,
        org_keys,
        Some(vault),
    );
    crate::state::mark_activity(&state);

    Ok(LoginOk {
        email,
        origin: SessionOrigin::ExportFile,
    })
}

/// Build the item list for a standalone session opened from a file.
///
/// The cache path gets this from `load_cached_vault`; a file-backed
/// session already holds its `SyncResponse`, so it only needs the
/// summary built.
#[tauri::command]
pub fn standalone_summary(state: State<'_, AppState>) -> Result<SyncSummary> {
    crate::state::mark_activity(&state);
    let guard = state.session.lock();
    let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
    let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
        reason: "standalone session has no vault loaded".into(),
    })?;
    Ok(build_sync_summary(
        vault,
        &session.user_key,
        &session.org_keys,
    ))
}

/// How the open vault was reached, or `None` when nothing is open.
///
/// The UI asks on boot and after any state change: a session restored
/// behind the auto-lock, or one that fell back to the cache during an
/// unlock, must show the standalone banner without the renderer having
/// to remember what the last `unlock` returned.
#[tauri::command]
pub fn session_origin(state: State<'_, AppState>) -> Option<SessionOrigin> {
    state.session.lock().as_ref().map(|s| s.origin)
}
