<script lang="ts">
  import { tick } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import type { ConfirmRequest } from "./types";

  // Single in-app replacement for `window.confirm`. The native dialog
  // works, but it is a WebKit chrome box: system font, system buttons,
  // no way to mark the destructive action, and on Linux it renders
  // above the window with a title bar reading "localhost". Every
  // confirmation in the app goes through here instead.
  //
  // Usage: `bind:this` on the page that owns the dialog, then
  // `await confirmDialog.ask({...})` — resolves true only when the
  // user activates the confirm button.

  let dialog = $state<HTMLDialogElement | null>(null);
  let current = $state<ConfirmRequest | null>(null);
  let cancelButton = $state<HTMLButtonElement | null>(null);
  let resolver: ((ok: boolean) => void) | null = null;
  // Monotonic token rather than an identity check on `current`:
  // assigning a plain object to `$state` stores a proxy, so
  // `current !== request` is true even for the same request (Svelte's
  // `state_proxy_equality_mismatch`) and the open would never fire.
  let seq = 0;

  export function ask(request: ConfirmRequest): Promise<boolean> {
    // Only one prompt at a time. Nothing in the app opens two today,
    // but answering the older one "no" beats stranding its caller on a
    // promise that never settles.
    settle(false);
    const token = ++seq;
    current = request;
    const answer = new Promise<boolean>((resolve) => (resolver = resolve));
    // `showModal()` runs the focus algorithm once, at open time, and
    // Svelte flushes the `{#if current}` block on a microtask — opening
    // before the content is mounted would leave focus on the <dialog>
    // element itself, with Tab as the only way into the buttons.
    void tick().then(() => {
      if (seq !== token) return;
      dialog?.showModal();
      // Focus lands on Cancel, unlike `window.confirm`: everything that
      // reaches this dialog destroys something, so the answer an
      // in-flight Entrée picks must be the harmless one.
      cancelButton?.focus();
    });
    return answer;
  }

  function settle(ok: boolean) {
    const resolve = resolver;
    // Clear before closing: `close()` fires `onclose`, which would
    // otherwise settle the same request a second time.
    resolver = null;
    current = null;
    dialog?.close();
    resolve?.(ok);
  }
</script>

<dialog
  bind:this={dialog}
  class="confirm-dialog"
  onclose={() => {
    // Esc or the backdrop: an unanswered close means "no".
    if (resolver) settle(false);
  }}
>
  {#if current}
    <h2>{current.title}</h2>
    <p class="confirm-body">{current.body}</p>
    <div class="confirm-actions">
      <button bind:this={cancelButton} type="button" class="secondary" onclick={() => settle(false)}>
        {m.action_cancel()}
      </button>
      <button type="button" class:danger={current.danger} onclick={() => settle(true)}>
        {current.confirmLabel}
      </button>
    </div>
  {/if}
</dialog>

<style>
  .confirm-dialog {
    max-width: min(28rem, calc(100vw - 2rem));
    border: none;
    border-radius: 10px;
    padding: 1.25rem 1.4rem;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  }
  .confirm-dialog::backdrop {
    background: rgba(0, 0, 0, 0.45);
  }
  .confirm-dialog h2 {
    margin: 0 0 0.5rem;
    font-size: 1.15rem;
  }
  .confirm-body {
    margin: 0 0 1.1rem;
    color: #555;
    font-size: 0.9rem;
    /* Item and folder names are user data and can be long or
       unbroken; wrap them rather than widening the dialog. */
    overflow-wrap: anywhere;
  }
  .confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
  }
  .confirm-actions .danger {
    background: #b91c1c;
    border-color: #b91c1c;
    color: #fff;
  }
  .confirm-actions .danger:hover:not(:disabled) {
    filter: brightness(0.95);
  }

  @media (prefers-color-scheme: dark) {
    .confirm-body {
      color: #aaa;
    }
  }
  :global(:root.force-dark) .confirm-body {
    color: #aaa;
  }
</style>
