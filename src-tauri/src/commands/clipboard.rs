//! Clipboard writes that know what they wrote.
//!
//! The renderer clears the clipboard 30 s after a copy. Clearing blindly
//! would also wipe whatever the user copied since, from Clavix or from
//! another app, so the clear only fires while the clipboard still holds
//! the value Clavix put there.
//!
//! Only a SHA-256 digest of the last write is kept, never the value, and
//! the comparison happens here: the webview gets no clipboard read
//! permission out of this.

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

static LAST_WRITE: Mutex<Option<[u8; 32]>> = Mutex::new(None);

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// Whether the clipboard still holds what Clavix wrote. A clipboard that
/// cannot be read as text (an image, empty, another app holding it in a
/// format we can't see) is not ours.
fn still_ours(last: Option<[u8; 32]>, current: Option<&str>) -> bool {
    match (last, current) {
        (Some(last), Some(current)) => digest(current) == last,
        _ => false,
    }
}

#[tauri::command]
pub fn clipboard_write(app: AppHandle, text: String) -> Result<(), String> {
    app.clipboard()
        .write_text(text.as_str())
        .map_err(|e| format!("clipboard write: {e}"))?;
    *LAST_WRITE.lock().unwrap_or_else(|p| p.into_inner()) = Some(digest(&text));
    Ok(())
}

/// Clear the clipboard if it still holds the last value Clavix wrote.
/// Returns whether it cleared. Either way Clavix forgets the digest.
#[tauri::command]
pub fn clipboard_clear_if_ours(app: AppHandle) -> Result<bool, String> {
    let last = LAST_WRITE.lock().unwrap_or_else(|p| p.into_inner()).take();
    let current = app.clipboard().read_text().ok();
    if !still_ours(last, current.as_deref()) {
        return Ok(false);
    }
    app.clipboard()
        .clear()
        .map_err(|e| format!("clipboard clear: {e}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_the_value_it_wrote() {
        let last = Some(digest("hunter2"));
        assert!(still_ours(last, Some("hunter2")));
        assert!(!still_ours(last, Some("something the user copied since")));
    }

    #[test]
    fn unreadable_or_unknown_clipboard_is_not_ours() {
        assert!(!still_ours(Some(digest("hunter2")), None));
        assert!(!still_ours(None, Some("hunter2")));
        assert!(!still_ours(None, None));
    }
}
