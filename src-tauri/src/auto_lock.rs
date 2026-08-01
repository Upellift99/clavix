//! Auto-lock watchdog: decides when an unlocked vault must drop, and
//! does the dropping.
//!
//! Two background tasks, one decision function:
//!
//!   * `watchdog` — every 30 s, unconditionally. The backend safety net
//!     for the `idle` trigger (the renderer's own timer in
//!     `src/lib/auto-lock.svelte.ts` is the primary guard, and can be
//!     defeated by a frozen WebView or a devtools-disabled timer), and
//!     the place the stale-2FA sweep lives.
//!   * `screen_poller` — every 5 s, but only while the `screenLock`
//!     trigger is armed and a session is actually open. Maintains
//!     `screen_locked_since` from `screen_lock::probe` and evaluates
//!     right after, so the "immediately" delay lands within one poll
//!     rather than waiting on the 30 s watchdog.
//!
//! Both funnel into `due()` — a pure read over `AppState` — and then
//! `lock_now()`. Keeping the decision pure is what makes the trigger
//! semantics unit-testable without a Tauri runtime; see the tests at the
//! bottom of this file.

use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};

use crate::state::{AppState, AutoLockTrigger};

/// Backend safety-net cadence. Slow enough to be free, fast enough that
/// worst-case overshoot past the configured window stays bounded.
const WATCHDOG_PERIOD: Duration = Duration::from_secs(30);

/// How often the desktop-session state is sampled while the screen-lock
/// trigger is armed. Bounds how late an "immediately" lock can be; also
/// bounds how long a stale `locked` observation survives after the user
/// comes back, which is why it's well under the watchdog period.
const SCREEN_POLL_PERIOD: Duration = Duration::from_secs(5);

/// Upper bound on a configured window (7 days). Past this the setting is
/// treated as garbage rather than honoured — the UI tops out at an hour.
const MAX_WINDOW_MINUTES: f64 = 7.0 * 24.0 * 60.0;

/// Starts both background tasks. Called once from `run()`'s setup hook.
pub fn spawn(app: &AppHandle) {
    let watchdog_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(WATCHDOG_PERIOD).await;
            let state = watchdog_handle.state::<AppState>();
            // Wipe an abandoned 2FA prompt's master-key material once it
            // outlives its TTL — runs every tick, independent of the
            // auto-lock config below.
            crate::session::clear_pending_two_factor_if_stale(&state);
            if let Some(reason) = due(&state, Instant::now()) {
                lock_now(&watchdog_handle, &reason).await;
            }
        }
    });

    let poller_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(SCREEN_POLL_PERIOD).await;
            let state = poller_handle.state::<AppState>();
            let armed = state.auto_lock.lock().trigger == AutoLockTrigger::ScreenLock
                && state.session.lock().is_some();
            if !armed {
                // Drop any countdown so re-arming later starts from the
                // *next* observed lock rather than from a stale one.
                *state.screen_locked_since.lock() = None;
                continue;
            }
            match crate::screen_lock::probe().await {
                // First tick that sees a locked screen starts the clock;
                // later ticks must not push it forward.
                Some(true) => {
                    let mut since = state.screen_locked_since.lock();
                    if since.is_none() {
                        *since = Some(Instant::now());
                        // Logged on transition only (never per tick): the
                        // one line that tells a user whether the probe
                        // sees their desktop at all, without them having
                        // to reason about D-Bus.
                        eprintln!("[clavix] desktop session locked — auto-lock countdown started");
                    }
                }
                Some(false) => {
                    let was_counting = state.screen_locked_since.lock().take().is_some();
                    if was_counting {
                        eprintln!("[clavix] desktop session unlocked — auto-lock countdown reset");
                    }
                }
                // Probe failed this tick (D-Bus hiccup, service restart).
                // Leave any running countdown alone: a transient failure
                // is not evidence the user came back.
                None => {}
            }
            if let Some(reason) = due(&state, Instant::now()) {
                lock_now(&poller_handle, &reason).await;
            }
        }
    });
}

/// Whether the vault is past its configured window, and the human-readable
/// reason to log if so. Pure over `AppState` — no I/O, no clock beyond the
/// `now` handed in, so tests can drive it with a synthetic `Instant`.
pub(crate) fn due(state: &AppState, now: Instant) -> Option<String> {
    let setting = *state.auto_lock.lock();
    // Reject anything `Duration::from_secs_f64` would panic on — NaN,
    // infinities, negatives — plus absurdly large windows, which mean
    // "never" in practice and would overflow the conversion.
    if !setting.minutes.is_finite() || !(0.0..=MAX_WINDOW_MINUTES).contains(&setting.minutes) {
        return None;
    }
    let window = Duration::from_secs_f64(setting.minutes * 60.0);
    let minutes = setting.minutes;

    match setting.trigger {
        AutoLockTrigger::Off => None,
        AutoLockTrigger::Idle => {
            // A zero-length idle window would lock the vault the instant
            // it opened; the UI encodes "never" as `Off`, so treat it as
            // a no-op rather than an aggressive lock.
            if setting.minutes <= 0.0 {
                return None;
            }
            let idle = now.saturating_duration_since(*state.last_activity.lock());
            (idle >= window).then(|| format!("{minutes} min idle"))
        }
        AutoLockTrigger::ScreenLock => {
            // No countdown running: screen unlocked, or the platform
            // can't report it. Either way there's nothing to expire.
            let since = (*state.screen_locked_since.lock())?;
            (now.saturating_duration_since(since) >= window)
                .then(|| format!("{minutes} min after the desktop session locked"))
        }
    }
}

/// Tears the session down and tells the renderer. Mirrors
/// `commands::tray::lock_session`, but from an async context — so the SSH
/// agent gets the async `stop()` rather than its blocking twin.
async fn lock_now(app: &AppHandle, reason: &str) {
    let state = app.state::<AppState>();
    let agent = state.ssh_agent.lock().take();
    if let Some(handle) = agent {
        handle.stop().await;
    }
    // Threshold reached: also drop any pending 2FA slot so the master key
    // never survives the lock.
    crate::session::clear_pending_two_factor(&state);
    let locked = {
        let mut session_guard = state.session.lock();
        if session_guard.is_some() {
            *session_guard = None;
            eprintln!("[clavix] session auto-locked: {reason}");
            true
        } else {
            false
        }
    };
    // Mirror the tray "Verrouiller maintenant" path: tell the WebView the
    // session is gone so it leaves the vault view at once. Without this
    // the backend drops the session silently and the UI keeps showing a
    // stale list until the next IPC call fails with `not_authenticated` —
    // which is exactly the "connexion perdue, plus rien ne marche"
    // dead-end users hit after a 10-min idle window.
    if locked {
        if let Err(e) = app.emit(crate::commands::tray::EVENT_SESSION_LOCKED, ()) {
            eprintln!("[clavix] emit session-locked after auto-lock failed (non-fatal): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AutoLockSetting;

    fn state_with(setting: AutoLockSetting) -> AppState {
        let state = AppState::default();
        *state.auto_lock.lock() = setting;
        state
    }

    fn minutes_ago(n: u64) -> Instant {
        Instant::now() - Duration::from_secs(n * 60)
    }

    #[test]
    fn off_never_fires_however_long_it_has_been() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::Off,
            minutes: 10.0,
        });
        *state.last_activity.lock() = minutes_ago(600);
        *state.screen_locked_since.lock() = Some(minutes_ago(600));
        assert!(due(&state, Instant::now()).is_none());
    }

    #[test]
    fn idle_fires_only_past_its_window() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::Idle,
            minutes: 10.0,
        });
        *state.last_activity.lock() = minutes_ago(9);
        assert!(due(&state, Instant::now()).is_none());
        *state.last_activity.lock() = minutes_ago(11);
        assert!(due(&state, Instant::now()).is_some());
    }

    #[test]
    fn idle_ignores_a_locked_screen() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::Idle,
            minutes: 10.0,
        });
        // Screen locked an hour ago, but the user has been active: the
        // idle trigger must not borrow the other trigger's signal.
        *state.screen_locked_since.lock() = Some(minutes_ago(60));
        *state.last_activity.lock() = Instant::now();
        assert!(due(&state, Instant::now()).is_none());
    }

    #[test]
    fn screen_lock_needs_an_observed_lock() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::ScreenLock,
            minutes: 60.0,
        });
        // Idle for days, but the screen is unlocked (or unprobeable) —
        // nothing to count from, so the vault stays up.
        *state.last_activity.lock() = minutes_ago(10_000);
        assert!(due(&state, Instant::now()).is_none());
    }

    #[test]
    fn screen_lock_fires_one_hour_after_the_screen_locked() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::ScreenLock,
            minutes: 60.0,
        });
        *state.screen_locked_since.lock() = Some(minutes_ago(59));
        assert!(due(&state, Instant::now()).is_none());
        *state.screen_locked_since.lock() = Some(minutes_ago(61));
        assert!(due(&state, Instant::now()).is_some());
    }

    #[test]
    fn screen_lock_with_zero_delay_fires_on_the_first_observation() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::ScreenLock,
            minutes: 0.0,
        });
        // "Immédiatement" is a real setting here, unlike for `Idle`
        // where 0 means the user picked "Jamais".
        *state.screen_locked_since.lock() = Some(Instant::now());
        assert!(due(&state, Instant::now()).is_some());
    }

    #[test]
    fn idle_with_zero_minutes_is_inert_not_instant() {
        let state = state_with(AutoLockSetting {
            trigger: AutoLockTrigger::Idle,
            minutes: 0.0,
        });
        *state.last_activity.lock() = minutes_ago(10_000);
        assert!(due(&state, Instant::now()).is_none());
    }

    #[test]
    fn a_nonsense_window_is_ignored_rather_than_locking_instantly() {
        for minutes in [f64::NAN, f64::INFINITY, -5.0] {
            let state = state_with(AutoLockSetting {
                trigger: AutoLockTrigger::ScreenLock,
                minutes,
            });
            *state.screen_locked_since.lock() = Some(minutes_ago(10_000));
            assert!(
                due(&state, Instant::now()).is_none(),
                "minutes = {minutes} should be rejected"
            );
        }
    }
}
