<script lang="ts">
  import { onDestroy } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import { formatExpiry, formatRelativeAgo, truncate } from "./format";
  import type { TokenSet } from "./types";

  type Props = {
    tokens: TokenSet;
    syncing: boolean;
    hasSync: boolean;
    lastSyncAt: number | null;
    lastSyncError: string | null;
    onSync: () => void;
    onLock: () => void;
    onSwitchAccount: () => void;
  };

  let {
    tokens,
    syncing,
    hasSync,
    lastSyncAt,
    lastSyncError,
    onSync,
    onLock,
    onSwitchAccount,
  }: Props = $props();

  // `now` ticks once a minute so the "il y a N min" text stays accurate
  // and the dot flips to "stale" without user interaction.
  let now = $state(Date.now());
  const tick = setInterval(() => (now = Date.now()), 60_000);
  onDestroy(() => clearInterval(tick));

  type Status = "syncing" | "fresh" | "stale" | "offline" | "unknown";

  const FRESH_MS = 10 * 60 * 1000;

  let status = $derived<Status>(
    syncing
      ? "syncing"
      : lastSyncError
        ? "offline"
        : lastSyncAt === null
          ? "unknown"
          : now - lastSyncAt < FRESH_MS
            ? "fresh"
            : "stale",
  );

  let agoText = $derived(
    lastSyncAt !== null ? formatRelativeAgo(lastSyncAt, now) : "",
  );

  let statusLabel = $derived.by(() => {
    switch (status) {
      case "syncing":
        return m.session_status_syncing();
      case "fresh":
        return m.session_status_fresh({ when: agoText });
      case "stale":
        return m.session_status_stale({ when: agoText });
      case "offline":
        return lastSyncAt === null
          ? m.session_status_offline_never()
          : m.session_status_offline({ when: agoText });
      case "unknown":
        return m.session_status_unknown();
    }
  });
</script>

<section class="session-bar">
  <span
    class="session-dot session-dot--{status}"
    class:pulse={status === "syncing"}
    aria-hidden="true"
  ></span>
  <span class="session-label" aria-live="polite">{statusLabel}</span>
  <code class="session-token">{truncate(tokens.access_token)}</code>
  <span class="session-expiry">{formatExpiry(tokens.expires_in)}</span>
  <div class="session-actions">
    <button type="button" class="secondary small" onclick={onSwitchAccount}>{m.action_logout()}</button>
    <button type="button" class="secondary small" onclick={onLock}>{m.action_lock()}</button>
    <button type="button" class="small" onclick={onSync} disabled={syncing}>
      {syncing ? m.action_syncing() : hasSync ? m.action_resync() : m.action_sync()}
    </button>
  </div>
</section>

<style>
  .session-bar {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.35rem 0.6rem;
    background: #fff;
    border: 1px solid #e5e5e5;
    border-radius: 6px;
    font-size: 0.82rem;
    flex: 0 0 auto;
  }

  .session-dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    flex: 0 0 auto;
    transition:
      background-color 150ms ease,
      box-shadow 150ms ease;
  }

  /* Fresh (< 10 min): vert vif, halo assorti — on est en confiance. */
  .session-dot--fresh {
    background: #22c55e;
    box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.2);
  }

  /* Syncing: ambre, animation pulse. */
  .session-dot--syncing {
    background: #f59e0b;
    box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
  }

  /* Stale (> 10 min, sync OK à la dernière tentative): ambre fixe. */
  .session-dot--stale {
    background: #f59e0b;
    box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
  }

  /* Offline: rouge — la dernière sync a raté. */
  .session-dot--offline {
    background: #ef4444;
    box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.2);
  }

  /* Unknown: gris neutre — session ouverte, pas encore synchronisée. */
  .session-dot--unknown {
    background: #9ca3af;
    box-shadow: 0 0 0 2px rgba(156, 163, 175, 0.2);
  }

  .pulse {
    animation: session-dot-pulse 1.2s ease-in-out infinite;
  }

  @keyframes session-dot-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .session-label {
    font-weight: 600;
    color: #444;
  }

  .session-token {
    font-family: var(--font-data);
    font-size: 0.78rem;
    background: #f3f4f6;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    color: #555;
  }

  .session-expiry {
    color: #4a4a4a;
    font-variant-numeric: tabular-nums;
  }

  .session-actions {
    margin-left: auto;
    display: flex;
    gap: 0.3rem;
  }

  @media (prefers-color-scheme: dark) {
    .session-bar { background: #232323; border-color: #333; }
    .session-label { color: #ccc; }
    .session-token { background: #2b2b2b; color: #aaa; }
    .session-expiry { color: #999; }
  }

  :global(:root.force-dark) .session-bar { background: #232323; border-color: #333; }
  :global(:root.force-dark) .session-label { color: #ccc; }
  :global(:root.force-dark) .session-token { background: #2b2b2b; color: #aaa; }
  :global(:root.force-dark) .session-expiry { color: #999; }
</style>
