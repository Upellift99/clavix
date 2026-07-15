//! KDBX (KeePass / KeePassXC native format) import.
//!
//! The CSV path lives entirely in the renderer (`src/lib/csv.ts` +
//! `ImportDialog.svelte`) because the format is plaintext. KDBX is
//! encrypted, so the parsing has to happen in Rust where the
//! `keepass` crate can do the heavy lifting (master password,
//! Argon2id KDF, AES-256 / ChaCha20 cipher, KDBX 3.x and 4.x). This
//! command is the only Rust side of the KDBX flow: take the raw
//! bytes + master password, return a flat list of entries the
//! renderer's existing import loop can replay.
//!
//! The shape of `KdbxEntry` deliberately matches the renderer's
//! `KeepassEntry` (CSV row) so the dialog can pour either source
//! into the same `api.createCipher(...)` loop without branching on
//! origin.

use keepass::db::{EntryRef, GroupRef};
use keepass::{Database, DatabaseKey};
use serde::Serialize;

use crate::error::{Error, Result};

/// One importable login row, ready for `api.createCipher`. Empty
/// strings rather than `None` for missing fields — matches the
/// existing CSV path so the renderer stays uniform.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdbxEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Either a base32 TOTP secret or a full `otpauth://` URI; the
    /// editor accepts both. Populated from the `otp` extra field
    /// (KeePassXC convention) when present.
    pub totp: String,
    /// Slash-joined path of the entry's group, root excluded. Empty
    /// for entries directly under the root group. Mirrors the CSV
    /// `Group` column the renderer already knows how to turn into
    /// folders.
    pub group: String,
}

/// Parse a KDBX 3.x / 4.x payload with `password` as the master key.
///
/// Returns the flat entry list. The bytes must be the full file
/// (header + body); we don't support keyfile or challenge-response
/// auth yet — that's a follow-up if anyone asks. Empty `title` AND
/// empty `password` rows are dropped: KeePassXC sometimes leaves
/// empty placeholder entries under the root group and they're never
/// useful in a Bitwarden vault.
/// A real KDBX database is well under this. The cap stops a compromised
/// renderer from forcing a huge native allocation by handing an oversized
/// buffer to the parser (memory DoS).
const MAX_KDBX_BYTES: usize = 64 * 1024 * 1024;

#[tauri::command]
pub fn parse_kdbx(bytes: Vec<u8>, password: String) -> Result<Vec<KdbxEntry>> {
    if bytes.len() > MAX_KDBX_BYTES {
        return Err(Error::Storage {
            reason: format!(
                "KDBX file too large: {} bytes (max {} MiB)",
                bytes.len(),
                MAX_KDBX_BYTES / (1024 * 1024)
            ),
        });
    }
    let key = DatabaseKey::new().with_password(&password);
    let db = Database::parse(&bytes, key).map_err(|e| {
        // The keepass crate distinguishes "wrong password" from
        // "malformed file" but the variant types are awkward to
        // match exhaustively across versions. Surface the message
        // verbatim — the most common cause is a wrong password and
        // the user reads it on the dialog.
        Error::AuthFailed {
            message: format!("KDBX open: {e}"),
        }
    })?;

    let mut out = Vec::new();
    walk_group(&db.root(), "", &mut out);
    out.retain(|e| !(e.title.is_empty() && e.password.is_empty()));
    Ok(out)
}

fn walk_group(group: &GroupRef<'_>, parent_path: &str, out: &mut Vec<KdbxEntry>) {
    // GroupRef derefs to Group, so `sub.name` reads through to the
    // underlying struct. Same for `groups()` / `entries()`, which
    // yield further GroupRef / EntryRef views borrowed from the
    // parent Database.
    for entry in group.entries() {
        out.push(KdbxEntry {
            title: entry.get_title().unwrap_or("").to_string(),
            username: entry.get_username().unwrap_or("").to_string(),
            password: entry.get_password().unwrap_or("").to_string(),
            url: entry.get_url().unwrap_or("").to_string(),
            notes: entry.get("Notes").unwrap_or("").to_string(),
            totp: extract_totp(&entry),
            group: parent_path.to_string(),
        });
    }
    for sub in group.groups() {
        let next_path = if parent_path.is_empty() {
            sub.name.clone()
        } else {
            format!("{parent_path}/{}", sub.name)
        };
        walk_group(&sub, &next_path, out);
    }
}

fn extract_totp(entry: &EntryRef<'_>) -> String {
    // KeePassXC writes the otpauth URI into a custom string field
    // named "otp"; older databases used "TOTP Seed" + "TOTP
    // Settings" pair. Either gets surfaced verbatim — Clavix's
    // editor accepts both shapes.
    if let Some(otp) = entry.get("otp") {
        if !otp.is_empty() {
            return otp.to_string();
        }
    }
    if let Some(seed) = entry.get("TOTP Seed") {
        if !seed.is_empty() {
            return seed.to_string();
        }
    }
    String::new()
}
