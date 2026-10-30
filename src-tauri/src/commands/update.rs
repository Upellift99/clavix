#[cfg(feature = "update-check")]
use crate::update::{self, UpdateInfo};
#[cfg(feature = "update-check")]
use clavix_core::error::Result;

/// Ask GitHub whether a newer Clavix has been published. No session required —
/// this is a plain outbound check that returns a small verdict to the WebView
/// (see `crate::update` for why it lives in Rust rather than JS). Errors are
/// propagated; the frontend swallows them so a failed check is silent.
#[cfg(feature = "update-check")]
#[tauri::command]
pub async fn check_for_update() -> Result<UpdateInfo> {
    update::check_for_update().await
}

/// Whether this build can check for updates at all. Builds without the
/// `update-check` feature (distribution packages) leave updates to the package
/// manager, and the About dialog says so instead of offering a check.
#[tauri::command]
pub fn update_check_enabled() -> bool {
    cfg!(feature = "update-check")
}

/// This build's version (`CARGO_PKG_VERSION`). Offline, no session — lets the
/// About dialog show the running version instantly without a network round-trip.
#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
