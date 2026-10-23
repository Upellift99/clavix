<script lang="ts">
  import * as m from "#lib/paraglide/messages.js";
  import type { ClipboardController, ClipboardKind } from "./clipboard.svelte";

  type Props = {
    clipboard: ClipboardController;
  };

  let { clipboard }: Props = $props();

  function kindLabel(kind: ClipboardKind, label: string | null): string {
    switch (kind) {
      case "password":
        return m.clipboard_kind_password();
      case "username":
        return m.clipboard_kind_username();
      case "totp":
        return m.clipboard_kind_totp();
      case "url":
        return m.clipboard_kind_url();
      case "publicKey":
        return m.clipboard_kind_public_key();
      case "privateKey":
        return m.clipboard_kind_private_key();
      case "cardNumber":
        return m.clipboard_kind_card_number();
      case "securityCode":
        return m.clipboard_kind_security_code();
      case "command":
        return m.clipboard_kind_command();
      case "sshSock":
        return m.clipboard_kind_ssh_sock();
      case "field":
        return label ?? "";
    }
  }
</script>

{#if clipboard.secondsLeft !== null}
  <aside class="clipboard-toast variant-{clipboard.variant}" role="status">
    <span>
      {m.clipboard_toast({
        label: kindLabel(clipboard.kind, clipboard.label),
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
    --toast-accent: var(--toast-password);
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
    --toast-accent: var(--toast-password);
  }
  .clipboard-toast.variant-username {
    --toast-accent: var(--toast-username);
  }
  .clipboard-toast.variant-totp {
    --toast-accent: var(--toast-totp);
  }
  .clipboard-toast.variant-default {
    --toast-accent: var(--toast-default);
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
