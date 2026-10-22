<script lang="ts">
  import * as m from "#lib/paraglide/messages.js";
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
    /* Accent tints by copied kind (set via the variant-* classes). The
       toast is a solid dark pill in both themes, so these are not
       themed: each one already reads on a light or a dark page. */
    --toast-accent: #1e3a8a;
    position: fixed;
    bottom: 1rem;
    left: 50%;
    transform: translateX(-50%);
    background: var(--toast-accent);
    color: var(--on-primary);
    padding: 0.6rem 1rem;
    border-radius: 8px;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    box-shadow: var(--shadow-popover);
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
    background: var(--on-primary);
    color: var(--toast-accent);
    border-color: var(--on-primary);
    cursor: pointer;
    font: inherit;
    border-radius: 6px;
    padding: 0.4rem 0.75rem;
    font-size: 0.9rem;
  }
</style>
