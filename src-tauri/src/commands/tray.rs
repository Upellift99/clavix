//! System-tray wiring (issue #38).
//!
//! Three responsibilities:
//!   - `build_tray` constructs the tray icon, its right-click menu
//!     ("Ouvrir" / "Verrouiller maintenant" / "Quitter") and the
//!     left-click toggle. Called once from `lib.rs::run` setup.
//!   - `handle_window_close` interprets `WindowEvent::CloseRequested`
//!     against the user's `close_to_tray` preference: hide-or-quit.
//!   - `set_close_to_tray` is the IPC the renderer calls every time
//!     the preference changes (and on bootstrap, to hydrate the
//!     Rust mirror from `localStorage`).
//!
//! Native menu strings are hard-coded in French. The renderer-side
//! Paraglide pipeline doesn't reach native menus; supporting English
//! tray entries would mean reading the user's locale from a config
//! file at startup and rebuilding the tray on language change. Out
//! of scope until someone asks.

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State, WindowEvent};

use crate::error::Result;
use crate::state::AppState;

const TRAY_ID: &str = "clavix-tray";
const ITEM_OPEN: &str = "tray.open";
const ITEM_LOCK: &str = "tray.lock";
const ITEM_QUIT: &str = "tray.quit";
const MAIN_WINDOW: &str = "clavix";

/// Renderer-driven flag that decides what the X button does.
/// Mirrors `prefs.closeToTray` in `src/lib/prefs.svelte.ts`. The
/// renderer calls this on bootstrap (to hydrate the Rust mirror)
/// and again every time the user toggles the preference.
#[tauri::command]
pub fn set_close_to_tray(state: State<'_, AppState>, value: bool) -> Result<()> {
    state
        .close_to_tray
        .store(value, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Sibling of `set_close_to_tray` for the `_` minimise button.
/// Decides whether minimising hides into the tray (true, default)
/// or sends the window to the taskbar (false). Same hydration
/// pattern from the renderer.
#[tauri::command]
pub fn set_minimize_to_tray(state: State<'_, AppState>, value: bool) -> Result<()> {
    state
        .minimize_to_tray
        .store(value, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Wire the tray icon onto an `AppHandle`. Failure is non-fatal: a
/// CI runner or a Linux desktop without a system tray (xvfb, plain
/// Sway without `waybar` etc.) just gets a working app without the
/// tray entry. Logs the reason so it's traceable in the dev console.
pub fn build_tray(app: &AppHandle) {
    let icon = match app.default_window_icon().cloned() {
        Some(icon) => icon,
        None => {
            eprintln!("[clavix] tray icon setup skipped: no default window icon");
            return;
        }
    };

    let result = (|| -> tauri::Result<()> {
        let open = MenuItem::with_id(app, ITEM_OPEN, "Ouvrir Clavix", true, None::<&str>)?;
        let lock = MenuItem::with_id(app, ITEM_LOCK, "Verrouiller maintenant", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, ITEM_QUIT, "Quitter", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&open, &lock, &quit])?;

        TrayIconBuilder::with_id(TRAY_ID)
            .icon(icon)
            .tooltip("Clavix")
            .menu(&menu)
            .on_menu_event(|app, event| match event.id.as_ref() {
                ITEM_OPEN => show_main_window(app),
                ITEM_LOCK => lock_session(app),
                ITEM_QUIT => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                // Left-click toggles. Right-click opens the menu
                // (handled by the menu wiring above) so we ignore it
                // here. Match on `Up` so the toggle fires once per
                // click rather than twice (Down + Up).
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    toggle_main_window(tray.app_handle());
                }
            })
            .build(app)?;
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("[clavix] tray icon setup failed (non-fatal): {e}");
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        match window.is_visible() {
            Ok(true) => {
                let _ = window.hide();
            }
            Ok(false) | Err(_) => {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }
    }
}

fn lock_session(app: &AppHandle) {
    let state = app.state::<AppState>();
    // Same teardown as `commands::auth::lock`. Inlined rather than
    // calling the Tauri command directly because we hold an
    // `AppHandle`, not the `State<'_, AppState>` shape Tauri's
    // dispatcher would hand us — and we don't need a return value.
    let agent = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(handle) = agent {
        handle.stop_sync();
    }
    {
        let mut guard = state.session.lock();
        *guard = None;
    }
    crate::services::auth::clear_pending_two_factor(&state);
}

/// Two-branch window-event hook:
///
///   - `CloseRequested` → if `close_to_tray` is set, hide the
///     window and call `prevent_close()` so Tauri leaves the
///     process up.
///   - `Resized` → on a minimise transition (`is_minimized()` true
///     after the resize), if `minimize_to_tray` is set, unminimise
///     + hide so the window lives in the tray rather than the
///     taskbar.
///
/// Both branches no-op when the corresponding preference is off.
/// Native cross-platform minimise detection has no dedicated
/// Tauri/tao event variant — `Resized` fires on every minimise
/// path on Windows and most Linux WMs, and `is_minimized()` then
/// confirms the transition. macOS minimise (cmd-M to dock) is best
/// effort: the Resized signal there isn't reliable, so the
/// preference may not always intercept on macOS until the upstream
/// API exposes a proper minimise event. Documented for the user.
pub fn handle_window_event(app: &AppHandle, event: &WindowEvent) {
    match event {
        WindowEvent::CloseRequested { api, .. } => {
            let state = app.state::<AppState>();
            if !state
                .close_to_tray
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                let _ = window.hide();
            }
            api.prevent_close();
        }
        WindowEvent::Resized(_) => {
            let state = app.state::<AppState>();
            if !state
                .minimize_to_tray
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                return;
            }
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                if matches!(window.is_minimized(), Ok(true)) {
                    // Unminimise first so `hide()` doesn't have to
                    // race the OS minimise animation. Cheap on
                    // Windows; a brief flicker on Linux WMs that
                    // animate minimise is acceptable for the
                    // intended UX (the window disappears into the
                    // tray, not the taskbar).
                    let _ = window.unminimize();
                    let _ = window.hide();
                }
            }
        }
        _ => {}
    }
}
