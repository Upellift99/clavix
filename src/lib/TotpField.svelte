<script lang="ts">
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "#lib/api.ts";
  import Icon from "./Icon.svelte";

  // The TOTP secret stays in Rust; we ask the backend for the current code
  // once a second. `id` is the cipher id.
  let { id, onCopy }: { id: string; onCopy: (code: string) => void } = $props();

  let code = $state<string>("");
  let remaining = $state<number>(30);
  let parseError = $state<string | null>(null);

  // Poll `totp_code` for the given item. Writes code/remaining but never reads
  // them, so it can't re-trigger itself; re-runs only when `id` changes.
  $effect(() => {
    const cipherId = id;
    code = "";
    parseError = null;

    let cancelled = false;
    async function tick() {
      try {
        const res = await api.totpCode(cipherId);
        if (!cancelled) {
          code = res.code;
          remaining = res.secondsRemaining;
        }
      } catch (e) {
        if (!cancelled) parseError = (e as Error).message ?? String(e);
      }
    }

    void tick();
    const timer = setInterval(() => void tick(), 1000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  function formatCode(value: string): string {
    if (value.length === 6) return `${value.slice(0, 3)} ${value.slice(3)}`;
    return value;
  }
</script>

<!-- Same order as every other detail field: the copy action sits in the
     fixed slot before the value, so it never moves as the code ticks. -->
<span class="field-actions">
  {#if code && !parseError}
    <button
      type="button"
      class="icon-btn"
      title={m.action_copy()}
      aria-label={m.action_copy()}
      onclick={() => onCopy(code)}
    >
      <Icon name="copy" size={14} />
    </button>
  {/if}
</span>
{#if parseError}
  <span class="totp-error">{parseError}</span>
{:else if code}
  <span class="totp">
    <span class="totp-code">{formatCode(code)}</span>
    <span class="totp-remaining" class:soon={remaining <= 5}>{remaining}s</span>
  </span>
{:else}
  <span class="totp-pending">…</span>
{/if}

<style>
  .totp {
    display: inline-flex;
    align-items: baseline;
    gap: 0.5rem;
    white-space: nowrap;
  }

  .totp-code {
    font-family: var(--font-data);
    font-variant-numeric: tabular-nums;
    font-size: 1.05rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    background: var(--accent-soft-bg);
    padding: 0.25rem 0.6rem;
    border-radius: 6px;
    color: var(--accent-text);
  }

  .totp-remaining {
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  .totp-remaining.soon {
    color: var(--warning-text);
    font-weight: 500;
  }

  .totp-error {
    color: var(--error-text);
    font-size: 0.85rem;
  }

  .totp-pending {
    color: var(--text-disabled);
  }
</style>
