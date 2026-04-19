use crate::crypto::{encrypt_string, SymmetricKey};
use crate::error::Result;
use crate::models::CipherCreateInput;

pub fn build_login_cipher_body(
    input: &CipherCreateInput,
    key: &SymmetricKey,
) -> Result<serde_json::Value> {
    let name_enc = encrypt_string(&input.name, key)?;
    let notes_enc = input
        .notes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| encrypt_string(s, key))
        .transpose()?;

    let login_value = if let Some(login) = input.login.as_ref() {
        let username_enc = login
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| encrypt_string(s, key))
            .transpose()?;
        let password_enc = login
            .password
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| encrypt_string(s, key))
            .transpose()?;
        let totp_enc = login
            .totp
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| encrypt_string(s, key))
            .transpose()?;
        let uris_val: Vec<serde_json::Value> = login
            .uris
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|u| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "uri": encrypt_string(u, key)?,
                    "match": serde_json::Value::Null,
                }))
            })
            .collect::<Result<_>>()?;

        serde_json::json!({
            "username": username_enc,
            "password": password_enc,
            "uris": uris_val,
            "totp": totp_enc,
        })
    } else {
        serde_json::json!({})
    };

    Ok(serde_json::json!({
        "type": 1,
        "name": name_enc,
        "notes": notes_enc,
        "folderId": input.folder_id,
        "favorite": input.favorite,
        "login": login_value,
    }))
}
