// Two-layer auto-lock setup, extracted from +page.svelte so the route
// stays focused on layout and wiring. Declares two Svelte 5 $effect
// blocks:
//
//   1. Mirror the user's configured idle window to the Rust watchdog
//      (`api.setAutoLockMinutes`). Best-effort — the front-end timer
//      is the primary guard, the backend watchdog a safety net for the
//      case where the WebView has frozen or a tab inspector disabled
//      the JS timers.
//   2. Client-side idle timer that listens for user activity and, when
//      the configured window elapses, calls `onLock`. Poll cadence is
//      adaptive: 15 s for typical 1–60 min windows, shrinks down to
//      ~250 ms when the window is sub-minute (used by the E2E suite)
//      so tests don't wait forever.
//
// Must be called from a component scope — the `$effect` calls will
// register against the current component's lifecycle and be torn down
// on unmount.
import { api } from "./api";

export type AutoLockConfig = {
  /** Current auto-lock window in minutes; 0 / ≤ 0 disables the timer. */
  getMinutes: () => number;
  /** Epoch ms of the last user activity, tracked by the caller. */
  getLastActivityAt: () => number;
  /** Called on any user activity event to refresh the idle window. */
  markActivity: () => void;
  /** `true` once the vault is unlocked — the timer is inert otherwise. */
  isLoggedIn: () => boolean;
  /** Invoked when the idle window elapses. Typically resets the vault. */
  onLock: () => Promise<void> | void;
};

export function setupAutoLock(cfg: AutoLockConfig): void {
  $effect(() => {
    const minutes = cfg.getMinutes();
    api.setAutoLockMinutes(minutes).catch((e) => {
      console.warn("[clavix] setAutoLockMinutes failed:", e);
    });
  });

  $effect(() => {
    if (!cfg.isLoggedIn()) return;
    const minutes = cfg.getMinutes();
    if (minutes <= 0) return;

    cfg.markActivity();
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "click"];
    const onActivity = () => cfg.markActivity();
    for (const evt of events) {
      window.addEventListener(evt, onActivity, { passive: true });
    }

    const lockMs = minutes * 60 * 1000;
    // Adaptive cadence: keep the cheap 15 s pass for production windows
    // and shrink only when the window is tiny (E2E seeds sub-minute
    // values). Worst-case overshoot stays around lockMs × 1.25.
    const pollMs = Math.min(15_000, Math.max(250, lockMs / 4));
    const interval = setInterval(async () => {
      if (Date.now() - cfg.getLastActivityAt() >= lockMs) {
        await cfg.onLock();
      }
    }, pollMs);

    return () => {
      clearInterval(interval);
      for (const evt of events) {
        window.removeEventListener(evt, onActivity);
      }
    };
  });
}
