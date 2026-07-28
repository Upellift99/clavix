// NB: crypto, models, api, error, services are exposed publicly to let
// the `examples/e2e_seed.rs` tool reuse the exact same crypto path as
// the app. clavix_lib isn't published as a third-party crate, so
// widening these modules is a no-op for real consumers (there are none).
pub mod api;
mod audit;
mod auto_lock;
mod cache;
mod commands;
pub mod crypto;
pub mod error;
pub mod models;
mod screen_lock;
pub mod services;
mod ssh_agent;
// `state` is widened to `pub` so the integration test in
// `src-tauri/tests/token_refresh_lifecycle.rs` (issue #24) can
// build an `AppState` + `Session` from outside the Tauri runtime
// — `ensure_fresh_tokens` operates on a real session lock and
// can't be exercised end-to-end without one.
pub mod state;
// `store` is widened to `pub` for the integration tests in
// `src-tauri/tests/persisted_session_disk.rs` (issue #24): the
// session-lifecycle scenarios listed in #9 that don't fit a WDIO
// spec — disk-artifact assertions, restart-simulation — need direct
// access to load_session / save_session / clear_session.
pub mod store;
mod totp;
mod update;
mod webauthn;
mod yubikey_unlock;

use tauri::Manager;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .on_window_event(|window, event| {
            // Close-to-tray hook. The handler is a no-op when the
            // user disables the preference; otherwise it hides the
            // window and calls `prevent_close()` so Tauri leaves the
            // process up. See `commands::tray` for the full story.
            commands::tray::handle_window_event(window.app_handle(), event);
        })
        .setup(|app| {
            // Tray icon + right-click menu (Ouvrir / Verrouiller /
            // Quitter). Non-fatal if it fails — environments without
            // a system tray (CI under xvfb, some minimal WMs) just
            // run without the tray entry, which is the same shape
            // the app had pre-#38.
            commands::tray::build_tray(app.handle());

            // Auto-lock watchdog + desktop-session-lock poller. Backend
            // safety net for the idle trigger (a frozen WebView or a
            // disabled JS timer must not keep the vault unlocked), and the
            // sole owner of the screen-lock trigger — the renderer has no
            // way to see the session lock. See `auto_lock` for cadences.
            auto_lock::spawn(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::auth::stored_account,
            commands::auth::prelogin,
            commands::auth::login,
            commands::auth::login_with_two_factor,
            commands::auth::cancel_two_factor,
            commands::auth::unlock,
            commands::auth::lock,
            commands::auth::logout,
            commands::auth::set_auto_lock,
            commands::auth::screen_lock_available,
            commands::auth::webauthn_sign_challenge,
            commands::auth::yubikey_unlock_state,
            commands::auth::enroll_yubikey_unlock,
            commands::auth::disenroll_yubikey_unlock,
            commands::auth::unlock_with_yubikey,
            commands::vault::sync,
            commands::vault::load_cached_vault,
            commands::vault::create_folder,
            commands::vault::delete_folder,
            commands::vault::rename_folder,
            commands::cipher::get_cipher,
            commands::cipher::reveal_field,
            commands::cipher::totp_code,
            commands::cipher::reveal_login_totp,
            commands::cipher::create_login_cipher,
            commands::cipher::update_login_cipher,
            commands::cipher::create_cipher,
            commands::cipher::update_cipher,
            commands::cipher::restore_cipher,
            commands::cipher::soft_delete_cipher,
            commands::cipher::delete_cipher,
            commands::move_share::move_cipher_to_folder,
            commands::move_share::move_cipher_to_collection,
            commands::move_share::move_folder_path,
            commands::move_share::rename_folder_path,
            commands::move_share::share_cipher_to_collection,
            commands::audit::audit_vault_passwords,
            commands::ssh::start_ssh_agent,
            commands::ssh::stop_ssh_agent,
            commands::ssh::ssh_agent_status,
            commands::ssh::respond_ssh_agent_confirm,
            commands::ssh::decrypt_ssh_private_key,
            commands::ssh::generate_ssh_key,
            commands::ssh::ssh_auth_sock,
            commands::tray::set_close_to_tray,
            commands::tray::set_minimize_to_tray,
            commands::tray::set_hide_dock_on_tray,
            commands::tray::set_tray_locale,
            commands::import::parse_kdbx,
            commands::update::check_for_update,
            commands::update::app_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
