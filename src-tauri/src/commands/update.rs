use crate::error::Result;
use crate::update::{self, UpdateInfo};

/// Ask GitHub whether a newer Clavix has been published. No session required —
/// this is a plain outbound check that returns a small verdict to the WebView
/// (see `crate::update` for why it lives in Rust rather than JS). Errors are
/// propagated; the frontend swallows them so a failed check is silent.
#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo> {
    update::check_for_update().await
}
