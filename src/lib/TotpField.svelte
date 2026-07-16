<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "$lib/api";

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

{#if parseError}
  <span class="totp-error">{parseError}</span>
{:else if code}
  <span class="totp-code">{formatCode(code)}</span>
  <span class="totp-remaining" class:soon={remaining <= 5}>{remaining}s</span>
  <button type="button" class="secondary small" onclick={() => onCopy(code)}>
    {m.action_copy()}
  </button>
{:else}
  <span class="totp-pending">…</span>
{/if}

<style>
  .totp-code {
    font-family: ui-monospace, monospace;
    font-size: 1.1rem;
    font-weight: 600;
    letter-spacing: 0.15em;
    background: #eef3ff;
    padding: 0.25rem 0.6rem;
    border-radius: 6px;
    color: #163b8a;
  }

  .totp-remaining {
    font-variant-numeric: tabular-nums;
    color: #666;
    font-size: 0.85rem;
  }

  .totp-remaining.soon {
    color: #b8500e;
    font-weight: 500;
  }

  .totp-error {
    color: #7a1d1d;
    font-size: 0.85rem;
  }

  .totp-pending {
    color: #999;
  }

  button.small {
    padding: 0.2rem 0.5rem;
    font-size: 0.85rem;
  }
</style>
