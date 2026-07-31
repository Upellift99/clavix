// Periodic background sync, extracted from +page.svelte the same way
// auto-lock is. One $effect, one interval, no Rust counterpart: the
// vault can only sync while it is unlocked, and an unlocked vault means
// a live WebView — so there is nothing for a backend watchdog to do.
//
// The countdown is measured from the last sync that actually landed,
// not from a fixed tick, so hitting the toolbar's Sync button pushes
// the next automatic one a full window away instead of leaving a stray
// refresh a few seconds behind it.
//
// Must be called from a component scope — the `$effect` registers
// against the current component's lifecycle and is torn down on unmount.

export type AutoSyncConfig = {
  /** Minutes between two syncs. 0 (or less) disables the timer. */
  getMinutes: () => number;
  /** `true` once the vault is unlocked — the timer is inert otherwise. */
  isLoggedIn: () => boolean;
  /** Epoch ms of the last successful sync, or null when none landed. */
  getLastSyncAt: () => number | null;
  /**
   * `false` while a sync is already running or while something would be
   * disturbed by a vault refresh (the editor holding unsaved input).
   * The tick is skipped, not rescheduled: the next one re-asks.
   */
  canSync: () => boolean;
  /** Runs the sync. Must not throw — failures belong in the status dot. */
  onSync: () => void;
};

export function setupAutoSync(cfg: AutoSyncConfig): void {
  $effect(() => {
    if (!cfg.isLoggedIn()) return;
    const minutes = cfg.getMinutes();
    if (minutes <= 0) return;

    const windowMs = minutes * 60 * 1000;
    // Baseline for the first tick. Without it a session whose opening
    // sync failed (offline laptop, server down) would have a null
    // lastSyncAt forever and never retry; with it, the retry cadence is
    // the configured window.
    let lastAttemptAt = Date.now();
    // Same adaptive cadence as the auto-lock poll: cheap in production,
    // fine-grained enough that an E2E-seeded sub-minute window fires
    // without the suite waiting a quarter of an hour.
    const pollMs = Math.min(30_000, Math.max(250, windowMs / 4));

    const interval = setInterval(() => {
      const since = Math.max(lastAttemptAt, cfg.getLastSyncAt() ?? 0);
      if (Date.now() - since < windowMs) return;
      // Stamp the attempt even when we skip, so a long-open editor
      // doesn't queue a sync that fires the instant it closes.
      lastAttemptAt = Date.now();
      if (!cfg.canSync()) return;
      cfg.onSync();
    }, pollMs);

    return () => clearInterval(interval);
  });
}
