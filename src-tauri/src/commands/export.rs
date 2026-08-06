//! Encrypted export and import over IPC.
//!
//! File I/O stays in the renderer, deliberately. The project has no
//! dialog or filesystem plugin (see `capabilities/default.json`), and
//! adding two would buy nothing here: what must not reach the webview
//! is the *plaintext vault*, and it doesn't — [`export_encrypted`]
//! hands back a sealed file and [`import_encrypted`] takes one. Only
//! ciphertext crosses on the export side.
//!
//! The import side does return plaintext items, because the renderer
//! has to replay them through `api.createCipher` the same way the CSV
//! and KDBX paths do. `parse_kdbx` set that precedent; this follows it
//! rather than inventing a second import architecture.

use secrecy::SecretString;
use serde::Serialize;
use tauri::State;
use ts_rs::TS;

use crate::state::AppState;
use clavix_core::crypto::decrypt_name;
use clavix_core::error::{Error, Result};
use clavix_core::export::{self, KdfParams};
use clavix_core::models::CipherCreateInput;
use clavix_core::services::cipher::{cipher_to_create_input, item_key, owning_key};

/// One item out of an encrypted export, ready for `api.createCipher`.
#[derive(Debug, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct ImportedItem {
    pub item: CipherCreateInput,
    /// The item's folder *name*, empty at the vault root.
    ///
    /// A name rather than the export's folder id: that id means
    /// nothing in the vault being imported into. The renderer maps
    /// names onto existing folders and creates what's missing —
    /// exactly what it already does with a KDBX group path.
    pub folder_name: String,
}

/// Seal the current vault into a password-protected export file.
///
/// Returns the file bytes; the renderer saves them. The vault is
/// re-encrypted under a fresh key first, so the file shares no key
/// material with the account that produced it.
#[tauri::command]
pub fn export_encrypted(state: State<'_, AppState>, file_password: String) -> Result<Vec<u8>> {
    crate::state::mark_activity(&state);
    let guard = state.session.lock();
    let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
    let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
        reason: "no vault synced yet — synchronise first".into(),
    })?;

    let (rekeyed, vault_key) = export::build_export(vault, &session.user_key, &session.org_keys)?;
    export::seal(
        &rekeyed,
        &vault_key,
        &SecretString::from(file_password),
        &KdfParams::default(),
    )
}

/// Open an encrypted export and return its items in plaintext form.
///
/// Session-free, like `parse_kdbx`: the file carries its own key, so
/// nothing here needs an account. That is also what lets the export
/// dialog's counterpart work before any vault is open.
#[tauri::command]
pub fn import_encrypted(bytes: Vec<u8>, file_password: String) -> Result<Vec<ImportedItem>> {
    let (vault, vault_key) = export::open(&bytes, &SecretString::from(file_password))?;
    let org_keys = export::org_key_map(&vault, &vault_key);

    // Folder names first: items reference folders by id, and the
    // renderer needs the name to place them.
    let folder_names: std::collections::HashMap<&str, String> = vault
        .folders
        .iter()
        .filter_map(|f| {
            decrypt_name(&f.name, &vault_key)
                .ok()
                .map(|name| (f.id.as_str(), name))
        })
        .collect();

    vault
        .ciphers
        .iter()
        .map(|c| {
            let owner = owning_key(c, &vault_key, &org_keys);
            let unwrapped = item_key(c, owner);
            let key = unwrapped.as_ref().unwrap_or(owner);

            let mut input = cipher_to_create_input(c, key)?;
            let folder_name = c
                .folder_id
                .as_deref()
                .and_then(|id| folder_names.get(id).cloned())
                .unwrap_or_default();
            // The export's ids are meaningless here; the renderer
            // resolves placement from `folder_name` instead.
            input.folder_id = None;
            input.organization_id = None;
            input.collection_ids = Vec::new();

            Ok(ImportedItem {
                item: input,
                folder_name,
            })
        })
        .collect()
}
