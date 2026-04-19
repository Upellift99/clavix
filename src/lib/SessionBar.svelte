<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { formatExpiry, truncate } from "./format";
  import type { TokenSet } from "./types";

  type Props = {
    tokens: TokenSet;
    syncing: boolean;
    hasSync: boolean;
    onSync: () => void;
    onLock: () => void;
    onSwitchAccount: () => void;
  };

  let { tokens, syncing, hasSync, onSync, onLock, onSwitchAccount }: Props = $props();
</script>

<section class="session-bar">
  <span class="session-dot" aria-hidden="true"></span>
  <span class="session-label">Session</span>
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
    background: #22c55e;
    box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.2);
    flex: 0 0 auto;
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
    color: #666;
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
