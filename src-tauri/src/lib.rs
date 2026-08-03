// The protocol, the crypto and the vault logic live in `clavix-core`
// (`core/`), which knows nothing about Tauri. What stays here is what
// needs a desktop: the IPC surface, the tray, the SSH agent, the USB
// security key, the auto-lock watchdog and the screen-lock probe.
mod auto_lock;
mod commands;
mod screen_lock;
// Adapts `AppState` to the engine's session slots — see the module docs.
pub mod session;
mod ssh_agent;
// `state` is widened to `pub` so the integration test in
// `src-tauri/tests/token_refresh_lifecycle.rs` (issue #24) can
// build an `AppState` + `Session` from outside the Tauri runtime
// — `ensure_fresh_tokens` operates on a real session lock and
// can't be exercised end-to-end without one.
pub mod state;
mod update;
mod webauthn;
mod yubikey_unlock;

use tauri::Manager;

use state::AppState;

/// Escape hatch for the single-instance lock. Set to any value to let
/// a second Clavix boot alongside a running one — needed by the E2E
/// suite (which relaunches the binary between specs while a dev build
/// may sit in the tray) and by anyone deliberately running two vaults.
const ALLOW_MULTIPLE_INSTANCES_ENV: &str = "CLAVIX_ALLOW_MULTIPLE_INSTANCES";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // Single-instance guard, registered before every other plugin as
    // the plugin's docs require. A second launch never reaches the rest
    // of this builder: the plugin hands argv over to the running
    // process (which just raises its window) and exits.
    //
    // Two windows are the visible symptom; the real damage is the SSH
    // agent. `ssh_agent.rs` unlinks any stale socket before binding, so
    // instance #2 starting its agent would take over
    // `$XDG_RUNTIME_DIR/clavix/agent.sock` — every ssh(1) already
    // pointing at SSH_AUTH_SOCK would then be served by a vault that is
    // very likely still locked, with no error explaining why the keys
    // vanished.
    if std::env::var_os(ALLOW_MULTIPLE_INSTANCES_ENV).is_none() {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // Reuse the tray's raise path: it handles the
            // hidden-to-tray and minimised cases, and carries the
            // GNOME/X11 focus dance we already needed there.
            commands::tray::raise_main_window(app);
        }));
    }

    builder
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
            commands::auth::verify_master_password,
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
            commands::cipher::duplicate_cipher,
            commands::cipher::password_history,
            commands::cipher::download_attachment,
            commands::cipher::upload_attachment,
            commands::cipher::delete_attachment,
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
