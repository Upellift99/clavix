<script lang="ts">
  import { onDestroy } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import {
    computeSessionStatus,
    formatRelativeAgo,
    type SessionStatus,
  } from "./format";
  import Icon from "./Icon.svelte";

  type Props = {
    syncing: boolean;
    hasSync: boolean;
    lastSyncAt: number | null;
    lastSyncError: string | null;
    onSync: () => void;
    onLock: () => void;
    onSwitchAccount: () => void;
    onCreateItem: () => void;
    onOpenImport: () => void;
    onOpenExport: () => void;
    onOpenGenerator: () => void;
    onOpenAudit: () => void;
    onOpenStats: () => void;
  };

  let {
    syncing,
    hasSync,
    lastSyncAt,
    lastSyncError,
    onSync,
    onLock,
    onSwitchAccount,
    onCreateItem,
    onOpenImport,
    onOpenExport,
    onOpenGenerator,
    onOpenAudit,
    onOpenStats,
  }: Props = $props();

  // `now` ticks once a minute so the "il y a N min" text and the
  // session-status dot stay accurate without user interaction.
  let now = $state(Date.now());
  const tick = setInterval(() => (now = Date.now()), 60_000);
  onDestroy(() => clearInterval(tick));

  let status = $derived<SessionStatus>(
    computeSessionStatus({ syncing, lastSyncError, lastSyncAt, now }),
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

  let syncTitle = $derived(
    syncing ? m.action_syncing() : hasSync ? m.action_resync() : m.action_sync(),
  );
</script>

<nav class="toolbar" aria-label="Actions">
  <!-- Section: session -->
  <div class="tb-group">
    <button
      type="button"
      class="tb-btn"
      onclick={onSync}
      disabled={syncing}
      title={syncTitle}
      aria-label={syncTitle}
    >
      <Icon name="refresh" size={18} class={syncing ? "icon-spin" : ""} />
    </button>
    <button
      type="button"
      class="tb-btn"
      onclick={onLock}
      title={m.action_lock()}
      aria-label={m.action_lock()}
    >
      <Icon name="lock" size={18} />
    </button>
    <button
      type="button"
      class="tb-btn"
      onclick={onSwitchAccount}
      title={m.action_logout()}
      aria-label={m.action_logout()}
    >
      <Icon name="log-out" size={18} />
    </button>
  </div>

  <span class="tb-divider" aria-hidden="true"></span>

  <!-- Section: items -->
  <div class="tb-group">
    <button
      type="button"
      class="tb-btn"
      onclick={onCreateItem}
      title={m.action_new_item()}
      aria-label={m.action_new_item()}
    >
      <Icon name="plus" size={18} />
    </button>
    <button
      type="button"
      class="tb-btn"
      onclick={onOpenImport}
      title={m.import_label()}
      aria-label={m.import_label()}
    >
      <Icon name="download" size={18} />
    </button>
    <button
      type="button"
      class="tb-btn"
      onclick={onOpenExport}
      title={m.export_label()}
      aria-label={m.export_label()}
    >
      <Icon name="upload" size={18} />
    </button>
  </div>

  <span class="tb-divider" aria-hidden="true"></span>

  <!-- Section: tools -->
  <div class="tb-group">
    <button
      type="button"
      class="tb-btn"
      onclick={onOpenGenerator}
      title={m.generator_label()}
      aria-label={m.generator_label()}
    >
      <Icon name="dice" size={18} />
    </button>
    <button
      type="button"
      class="tb-btn"
      onclick={onOpenAudit}
      title={m.audit_label()}
      aria-label={m.audit_label()}
    >
      <Icon name="shield" size={18} />
    </button>
    <button
      type="button"
      class="tb-btn"
      onclick={onOpenStats}
      title={m.tree_infos_label()}
      aria-label={m.tree_infos_label()}
    >
      <Icon name="info" size={18} />
    </button>
  </div>

  <!-- Right-aligned session indicator -->
  <div class="tb-status" aria-live="polite">
    <span
      class="tb-dot tb-dot--{status}"
      class:pulse={status === "syncing"}
      aria-hidden="true"
    ></span>
    <span class="tb-status-label">{statusLabel}</span>
  </div>
</nav>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.3rem 0.5rem;
    background: #fff;
    border: 1px solid #d6e0ee;
    border-radius: 6px;
    flex: 0 0 auto;
  }

  .tb-group {
    display: flex;
    align-items: center;
    gap: 0.15rem;
  }

  .tb-divider {
    width: 1px;
    height: 1.4rem;
    background: #d6e0ee;
    margin: 0 0.2rem;
    flex: 0 0 auto;
  }

  .tb-btn {
    background: transparent;
    border: 1px solid transparent;
    color: inherit;
    width: 2rem;
    height: 2rem;
    padding: 0;
    border-radius: 4px;
    font-size: 1.05rem;
    line-height: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: background-color 100ms ease, border-color 100ms ease;
  }

  .tb-btn:hover:not(:disabled) {
    background: #dde9f8;
    border-color: #b6cdec;
    filter: none;
  }

  .tb-btn:active:not(:disabled) {
    background: #cfe0f5;
  }

  .tb-btn:disabled {
    opacity: 0.5;
    cursor: progress;
  }

  .tb-btn:focus-visible {
    outline: 2px solid #396cd8;
    outline-offset: 1px;
  }

  .tb-status {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.78rem;
    color: #555;
    padding-right: 0.2rem;
  }

  .tb-status-label {
    font-weight: 500;
  }

  .tb-dot {
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    flex: 0 0 auto;
    transition:
      background-color 150ms ease,
      box-shadow 150ms ease;
  }

  .tb-dot--fresh {
    background: #22c55e;
    box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.2);
  }
  .tb-dot--syncing {
    background: #f59e0b;
    box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
  }
  .tb-dot--stale {
    background: #f59e0b;
    box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
  }
  .tb-dot--offline {
    background: #ef4444;
    box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.2);
  }
  .tb-dot--unknown {
    background: #9ca3af;
    box-shadow: 0 0 0 2px rgba(156, 163, 175, 0.2);
  }

  .pulse {
    animation: tb-dot-pulse 1.2s ease-in-out infinite;
  }

  @keyframes tb-dot-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  @media (prefers-color-scheme: dark) {
    .toolbar {
      background: #232b3a;
      border-color: #2e3a52;
    }
    .tb-divider { background: #2e3a52; }
    .tb-btn:hover:not(:disabled) {
      background: #2c3a55;
      border-color: #3b4f72;
    }
    .tb-btn:active:not(:disabled) { background: #364871; }
    .tb-status { color: #aab; }
  }

  :global(:root.force-dark) .toolbar {
    background: #232b3a;
    border-color: #2e3a52;
  }
  :global(:root.force-dark) .tb-divider { background: #2e3a52; }
  :global(:root.force-dark) .tb-btn:hover:not(:disabled) {
    background: #2c3a55;
    border-color: #3b4f72;
  }
  :global(:root.force-dark) .tb-btn:active:not(:disabled) { background: #364871; }
  :global(:root.force-dark) .tb-status { color: #aab; }
</style>
