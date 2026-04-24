// NB: crypto, models, api, error, services are exposed publicly to let
// the `examples/e2e_seed.rs` tool reuse the exact same crypto path as
// the app. clavix_lib isn't published as a third-party crate, so
// widening these modules is a no-op for real consumers (there are none).
pub mod api;
mod audit;
mod cache;
mod commands;
pub mod crypto;
pub mod error;
pub mod models;
pub mod services;
mod ssh_agent;
mod state;
mod store;
mod webauthn;

use std::time::Duration;

use tauri::Manager;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            // Auto-lock watchdog. Backend safety net: if the WebView freezes
            // or the JS timer is disabled, the session must still drop after
            // the configured idle window. Polls every 30 s — slow enough to be
            // free, fast enough that worst-case overshoot is bounded.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let state = handle.state::<AppState>();
                    let Some(minutes) = *state.auto_lock_minutes.lock() else {
                        continue;
                    };
                    if !minutes.is_finite() || minutes <= 0.0 {
                        continue;
                    }
                    let idle = state.last_activity.lock().elapsed();
                    if idle < Duration::from_secs_f64(minutes * 60.0) {
                        continue;
                    }
                    let agent = state.ssh_agent.lock().take();
                    if let Some(h) = agent {
                        h.stop().await;
                    }
                    let mut session_guard = state.session.lock();
                    if session_guard.is_some() {
                        *session_guard = None;
                        eprintln!("[clavix] session auto-locked after {minutes} min idle");
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::auth::stored_account,
            commands::auth::prelogin,
            commands::auth::login,
            commands::auth::login_with_two_factor,
            commands::auth::unlock,
            commands::auth::lock,
            commands::auth::logout,
            commands::auth::set_auto_lock_minutes,
            commands::auth::webauthn_sign_challenge,
            commands::vault::sync,
            commands::vault::load_cached_vault,
            commands::vault::create_folder,
            commands::cipher::get_cipher,
            commands::cipher::create_login_cipher,
            commands::cipher::update_login_cipher,
            commands::cipher::create_cipher,
            commands::cipher::update_cipher,
            commands::cipher::restore_cipher,
            commands::cipher::delete_cipher,
            commands::move_share::move_cipher_to_folder,
            commands::move_share::move_cipher_to_collection,
            commands::move_share::move_folder_path,
            commands::move_share::share_cipher_to_collection,
            commands::audit::audit_vault_passwords,
            commands::ssh::start_ssh_agent,
            commands::ssh::stop_ssh_agent,
            commands::ssh::ssh_agent_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
