<script lang="ts">
  import { onDestroy } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import { generateTotp, parseTotp, secondsRemaining, type TotpConfig } from "$lib/totp";

  let { source, onCopy }: { source: string; onCopy: (code: string) => void } = $props();

  let config = $state<TotpConfig | null>(null);
  let parseError = $state<string | null>(null);
  let code = $state<string>("");
  let remaining = $state<number>(30);

  let timer: ReturnType<typeof setInterval> | null = null;

  async function tick() {
    if (!config) return;
    const now = Math.floor(Date.now() / 1000);
    remaining = secondsRemaining(config.period, now);
    code = await generateTotp(config, now);
  }

  $effect(() => {
    parseError = null;
    config = null;
    code = "";
    try {
      config = parseTotp(source);
      void tick();
      if (timer) clearInterval(timer);
      timer = setInterval(tick, 1000);
    } catch (e) {
      parseError = (e as Error).message;
    }

    return () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  function formatCode(value: string): string {
    if (value.length === 6) return `${value.slice(0, 3)} ${value.slice(3)}`;
    return value;
  }
</script>

{#if parseError}
  <span class="totp-error">{parseError}</span>
{:else if config && code}
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
