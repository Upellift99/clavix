<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import type { ClipboardController } from "./clipboard.svelte";

  type Props = {
    clipboard: ClipboardController;
  };

  let { clipboard }: Props = $props();
</script>

{#if clipboard.secondsLeft !== null}
  <aside class="clipboard-toast variant-{clipboard.variant}" role="status">
    <span>
      {m.clipboard_toast({
        label: clipboard.label ?? "",
        seconds: String(clipboard.secondsLeft),
      })}
    </span>
    <button type="button" class="secondary small" onclick={() => clipboard.clearNow()}>
      {m.action_clear_now()}
    </button>
  </aside>
{/if}

<style>
  .clipboard-toast {
    /* Accent tints by copied kind (set via the variant-* classes). */
    --toast-accent: #1e3a8a;
    position: fixed;
    bottom: 1rem;
    left: 50%;
    transform: translateX(-50%);
    background: var(--toast-accent);
    color: #fff;
    padding: 0.6rem 1rem;
    border-radius: 8px;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    z-index: 1000;
  }

  .clipboard-toast.variant-password {
    --toast-accent: #1e3a8a;
  }
  .clipboard-toast.variant-username {
    --toast-accent: #0f766e;
  }
  .clipboard-toast.variant-totp {
    --toast-accent: #6d28d9;
  }
  .clipboard-toast.variant-default {
    --toast-accent: #334155;
  }

  .clipboard-toast button.secondary {
    background: #fff;
    color: var(--toast-accent);
    border-color: #fff;
    cursor: pointer;
    font: inherit;
    border-radius: 6px;
    padding: 0.4rem 0.75rem;
    font-size: 0.9rem;
  }
</style>
