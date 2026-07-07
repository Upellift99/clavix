<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { generateTotp, parseTotp, secondsRemaining, type TotpConfig } from "$lib/totp";

  let { source, onCopy }: { source: string; onCopy: (code: string) => void } = $props();

  // Derive config/error purely from `source`. No $state is both written and
  // read inside an effect, so there is no self-referential update loop.
  const parsed = $derived.by((): { config: TotpConfig | null; error: string | null } => {
    try {
      return { config: parseTotp(source), error: null };
    } catch (e) {
      return { config: null, error: (e as Error).message };
    }
  });
  const config = $derived(parsed.config);
  const parseError = $derived(parsed.error);

  let code = $state<string>("");
  let remaining = $state<number>(30);

  // Timer lives in its own effect that depends only on `config`. It writes
  // `code`/`remaining` but never reads them, so it cannot re-trigger itself.
  $effect(() => {
    const cfg = config;
    code = "";
    if (!cfg) return;

    let cancelled = false;
    async function tick(c: TotpConfig) {
      const now = Math.floor(Date.now() / 1000);
      remaining = secondsRemaining(c.period, now);
      const next = await generateTotp(c, now);
      if (!cancelled) code = next;
    }

    void tick(cfg);
    const timer = setInterval(() => void tick(cfg), 1000);

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
