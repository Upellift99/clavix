//! One-time move of the per-app directories from the old app identifier.
//!
//! Tauri names several directories after `identifier` in
//! `tauri.conf.json`: the WebView's storage (where the renderer keeps
//! every preference in `localStorage`) and the window-state file. The
//! project started as `com.clavixlabs.clavix`, a scaffold placeholder on
//! a domain we don't own, and moved to `org.clavix.Clavix`. Without this
//! move, every existing user would come back to default settings.
//!
//! The vault itself is not concerned: `clavix-core` keeps the session and
//! the cache under `<data_local_dir>/clavix`, which never depended on the
//! identifier.
//!
//! Runs from the setup of [`plugin`], which `run()` registers right after
//! the single-instance guard. A second launch exits inside the guard's own
//! setup, so only the instance that keeps running moves anything: an older
//! Clavix still in the tray during an upgrade keeps its directories. Plugins
//! are set up in registration order, so the move still happens before the
//! window-state plugin reads its file, and before the WebView opens its
//! storage when the window is created. Every failure is logged and skipped —
//! at worst the user sees default settings, the app still starts.

use std::path::{Path, PathBuf};

use tauri::plugin::{Builder, TauriPlugin};
use tauri::Runtime;

pub const LEGACY_IDENTIFIER: &str = "com.clavixlabs.clavix";
pub const IDENTIFIER: &str = "org.clavix.Clavix";

pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("legacy-app-dirs")
        .setup(|_app, _api| {
            migrate();
            Ok(())
        })
        .build()
}

fn migrate() {
    for base in base_dirs() {
        migrate_dir(&base.join(LEGACY_IDENTIFIER), &base.join(IDENTIFIER));
    }
}

/// The parents Tauri's path resolver joins the identifier to
/// (`app_config_dir`, `app_data_dir`, `app_local_data_dir`,
/// `app_cache_dir`), deduplicated since most of them coincide on a given
/// OS. On macOS, WKWebView also keeps its data store under
/// `~/Library/WebKit/<bundle id>`.
fn base_dirs() -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();
    let candidates = [
        dirs::config_dir(),
        dirs::data_dir(),
        dirs::data_local_dir(),
        dirs::cache_dir(),
        #[cfg(target_os = "macos")]
        dirs::home_dir().map(|home| home.join("Library/WebKit")),
    ];
    for base in candidates.into_iter().flatten() {
        if !bases.contains(&base) {
            bases.push(base);
        }
    }
    bases
}

/// Renames `old` to `new` when only `old` exists. A `new` that already
/// exists means the move happened, or the user already ran a build with
/// the new identifier: it wins, and `old` is left alone rather than
/// merged into it.
fn migrate_dir(old: &Path, new: &Path) {
    if !old.is_dir() || new.exists() {
        return;
    }
    if let Err(e) = std::fs::rename(old, new) {
        eprintln!(
            "[clavix] could not move {} to {} (non-fatal): {e}",
            old.display(),
            new.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_matches_tauri_conf() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"], IDENTIFIER);
    }

    #[test]
    fn moves_the_old_directory_when_the_new_one_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join(LEGACY_IDENTIFIER);
        let new = tmp.path().join(IDENTIFIER);
        std::fs::create_dir_all(old.join("localstorage")).unwrap();
        std::fs::write(old.join(".window-state.json"), "{}").unwrap();

        migrate_dir(&old, &new);

        assert!(!old.exists());
        assert!(new.join("localstorage").is_dir());
        assert_eq!(
            std::fs::read_to_string(new.join(".window-state.json")).unwrap(),
            "{}"
        );
    }

    #[test]
    fn leaves_both_alone_when_the_new_directory_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join(LEGACY_IDENTIFIER);
        let new = tmp.path().join(IDENTIFIER);
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("marker"), "old").unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("marker"), "new").unwrap();

        migrate_dir(&old, &new);

        assert_eq!(std::fs::read_to_string(old.join("marker")).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(new.join("marker")).unwrap(), "new");
    }

    #[test]
    fn does_nothing_on_a_fresh_install() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join(LEGACY_IDENTIFIER);
        let new = tmp.path().join(IDENTIFIER);

        migrate_dir(&old, &new);

        assert!(!old.exists());
        assert!(!new.exists());
    }
}
