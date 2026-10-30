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

/// Written into `new` once `old` has been moved there. Its presence is what
/// "migrated" means: `old` coming back afterwards (the old version started
/// again) is then left alone.
const MIGRATED_MARKER: &str = ".migrated-from-com.clavixlabs.clavix";

/// Moves `old` to `new` and marks it, unless `new` already carries the mark.
///
/// A `new` without the mark next to an `old` means an earlier move failed
/// (on Windows, WebView2 or an older instance still holding files in `old`)
/// and that run then started on an empty `new`. That directory only holds
/// what one session with default settings wrote, so it is set aside, not
/// deleted, and the move is retried.
fn migrate_dir(old: &Path, new: &Path) {
    if !old.is_dir() || new.join(MIGRATED_MARKER).exists() {
        return;
    }
    let aside = new.with_file_name(format!("{IDENTIFIER}.before-migration"));
    let set_aside = new.exists();
    if set_aside {
        if aside.exists() {
            eprintln!(
                "[clavix] {} is in the way of the migration and {} exists already; \
                 leaving both (non-fatal)",
                new.display(),
                aside.display()
            );
            return;
        }
        if let Err(e) = std::fs::rename(new, &aside) {
            eprintln!(
                "[clavix] could not set {} aside (non-fatal): {e}",
                new.display()
            );
            return;
        }
    }
    if let Err(e) = std::fs::rename(old, new) {
        eprintln!(
            "[clavix] could not move {} to {} (non-fatal): {e}",
            old.display(),
            new.display()
        );
        if set_aside {
            let _ = std::fs::rename(&aside, new);
        }
        return;
    }
    if let Err(e) = std::fs::write(new.join(MIGRATED_MARKER), "") {
        eprintln!(
            "[clavix] could not mark {} as migrated (non-fatal): {e}",
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
        assert!(new.join(MIGRATED_MARKER).exists());
    }

    #[test]
    fn leaves_an_old_directory_alone_once_migrated() {
        // The old version started again after the move and recreated `old`.
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join(LEGACY_IDENTIFIER);
        let new = tmp.path().join(IDENTIFIER);
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("prefs"), "old").unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("prefs"), "new").unwrap();
        std::fs::write(new.join(MIGRATED_MARKER), "").unwrap();

        migrate_dir(&old, &new);

        assert_eq!(std::fs::read_to_string(old.join("prefs")).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(new.join("prefs")).unwrap(), "new");
    }

    #[test]
    fn retries_after_a_failed_move_and_keeps_the_empty_run_aside() {
        // An earlier move failed and that run started on an unmarked `new`.
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join(LEGACY_IDENTIFIER);
        let new = tmp.path().join(IDENTIFIER);
        let aside = tmp.path().join(format!("{IDENTIFIER}.before-migration"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("prefs"), "user's").unwrap();
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("prefs"), "defaults").unwrap();

        migrate_dir(&old, &new);

        assert!(!old.exists());
        assert_eq!(
            std::fs::read_to_string(new.join("prefs")).unwrap(),
            "user's"
        );
        assert!(new.join(MIGRATED_MARKER).exists());
        assert_eq!(
            std::fs::read_to_string(aside.join("prefs")).unwrap(),
            "defaults"
        );
    }

    #[test]
    fn never_overwrites_a_directory_already_set_aside() {
        let tmp = tempfile::tempdir().unwrap();
        let old = tmp.path().join(LEGACY_IDENTIFIER);
        let new = tmp.path().join(IDENTIFIER);
        let aside = tmp.path().join(format!("{IDENTIFIER}.before-migration"));
        for (dir, content) in [(&old, "old"), (&new, "new"), (&aside, "aside")] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("prefs"), content).unwrap();
        }

        migrate_dir(&old, &new);

        for (dir, content) in [(&old, "old"), (&new, "new"), (&aside, "aside")] {
            assert_eq!(std::fs::read_to_string(dir.join("prefs")).unwrap(), content);
        }
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
