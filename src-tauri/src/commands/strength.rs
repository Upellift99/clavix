//! Password-strength scoring over IPC.
//!
//! Two commands, for two different moments:
//!
//! - [`score_password`] scores a string the user is typing. Stateless,
//!   like `parse_kdbx` — it needs no session.
//! - [`score_cipher_password`] scores a password the user has *not*
//!   asked to see. It decrypts in Rust and returns only the verdict, so
//!   the item's detail pane can show a strength bar while the password
//!   itself stays masked and never crosses the IPC boundary.
//!
//! The generator deliberately calls neither: a CSPRNG draw over a known
//! alphabet has exactly computable entropy, and zxcvbn saturates on it.
//! That calculation lives in `src/lib/strength.ts`.

use tauri::State;

use crate::state::AppState;
use clavix_core::crypto::decrypt_name;
use clavix_core::error::{Error, Result};
use clavix_core::services::cipher::{item_key, owning_key};
use clavix_core::strength::{self, PasswordStrength};

/// Score an arbitrary password, penalised by `user_inputs` (item name,
/// username, domain — whatever the caller can supply).
///
/// No `AppState`: nothing here touches the vault, and keeping it
/// session-free means the export dialog can score a file password
/// before any vault is even open.
#[tauri::command]
pub fn score_password(password: String, user_inputs: Vec<String>) -> PasswordStrength {
    let refs: Vec<&str> = user_inputs.iter().map(String::as_str).collect();
    strength::score(&password, &refs)
}

/// Score a stored item's password without revealing it.
///
/// Deliberately *not* behind the per-item reprompt gate. Reprompt
/// protects the secret itself; this returns one of five buckets and
/// strictly less than `reveal_field` already does. Requiring it would
/// defeat the point — the whole reason this command exists is to show
/// the strength of a password the user has not unmasked.
///
/// Returns `None` when the item has no login password, so the caller
/// can tell "nothing to score" from "scored as very weak".
#[tauri::command]
pub fn score_cipher_password(
    state: State<'_, AppState>,
    id: String,
) -> Result<Option<PasswordStrength>> {
    crate::state::mark_activity(&state);
    let guard = state.session.lock();
    let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
    let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
        reason: "no vault synced yet — synchronise first".into(),
    })?;
    let cipher = vault
        .ciphers
        .iter()
        .find(|c| c.id == id)
        .ok_or_else(|| Error::Storage {
            reason: format!("cipher not found: {id}"),
        })?;

    let owner = owning_key(cipher, &session.user_key, &session.org_keys);
    let item = item_key(cipher, owner);
    let key = item.as_ref().unwrap_or(owner);

    let login = match cipher.login.as_ref() {
        Some(l) => l,
        None => return Ok(None),
    };
    let password = match login
        .password
        .as_deref()
        .and_then(|enc| decrypt_name(enc, key).ok())
        .filter(|p| !p.is_empty())
    {
        Some(p) => p,
        None => return Ok(None),
    };

    // Feed zxcvbn the item's own identifiers, so a password that merely
    // echoes them is scored as the giveaway it is rather than as an
    // ordinary word. Undecryptable fields are simply skipped.
    let mut inputs: Vec<String> = Vec::new();
    if let Ok(name) = decrypt_name(&cipher.name, key) {
        inputs.push(name);
    }
    if let Some(username) = login
        .username
        .as_deref()
        .and_then(|enc| decrypt_name(enc, key).ok())
    {
        inputs.push(username);
    }
    if let Some(uri) = login
        .uris
        .as_ref()
        .and_then(|uris| uris.iter().find_map(|u| u.uri.as_deref()))
        .and_then(|enc| decrypt_name(enc, key).ok())
    {
        inputs.push(uri);
    }

    let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    Ok(Some(strength::score(&password, &refs)))
}
