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

use std::io::Cursor;

use keepass::db::Group;
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
#[tauri::command]
pub fn parse_kdbx(bytes: Vec<u8>, password: String) -> Result<Vec<KdbxEntry>> {
    let key = DatabaseKey::new().with_password(&password);
    let db = Database::open(&mut Cursor::new(bytes), key).map_err(|e| {
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
    walk_group(&db.root, "", &mut out);
    out.retain(|e| !(e.title.is_empty() && e.password.is_empty()));
    Ok(out)
}

fn walk_group(group: &Group, parent_path: &str, out: &mut Vec<KdbxEntry>) {
    for child in &group.children {
        match child {
            keepass::db::Node::Group(g) => {
                let next_path = if parent_path.is_empty() {
                    g.name.clone()
                } else {
                    format!("{parent_path}/{}", g.name)
                };
                walk_group(g, &next_path, out);
            }
            keepass::db::Node::Entry(e) => {
                out.push(KdbxEntry {
                    title: e.get_title().unwrap_or("").to_string(),
                    username: e.get_username().unwrap_or("").to_string(),
                    password: e.get_password().unwrap_or("").to_string(),
                    url: e.get_url().unwrap_or("").to_string(),
                    notes: e.get("Notes").unwrap_or("").to_string(),
                    totp: extract_totp(e),
                    group: parent_path.to_string(),
                });
            }
        }
    }
}

fn extract_totp(entry: &keepass::db::Entry) -> String {
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
