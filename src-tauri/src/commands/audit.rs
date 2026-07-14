use secrecy::SecretString;
use tauri::State;

use crate::audit;
use crate::crypto::decrypt_name;
use crate::error::{Error, Result};
use crate::state::AppState;

#[tauri::command]
pub async fn audit_vault_passwords(
    state: State<'_, AppState>,
) -> Result<audit::PasswordAuditResult> {
    let entries: Vec<(String, String, SecretString)> = {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;

        vault
            .ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .filter_map(|c| {
                let login = c.login.as_ref()?;
                let pw_enc = login.password.as_deref()?;
                let owner = crate::services::cipher::owning_key(c, &session.user_key, &session.org_keys);
                let item = crate::services::cipher::item_key(c, owner);
                let key = item.as_ref().unwrap_or(owner);
                let pw = decrypt_name(pw_enc, key).ok()?;
                if pw.is_empty() {
                    return None;
                }
                let name = decrypt_name(&c.name, key).unwrap_or_else(|_| "(chiffré)".to_string());
                Some((c.id.clone(), name, SecretString::from(pw)))
            })
            .collect()
    };

    audit::audit_passwords(entries).await
}
