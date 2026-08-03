<script lang="ts">
  import { tick } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import { formatError } from "./format";

  // The master-password gate for items flagged with Bitwarden's
  // "reprompt". Verification is local (`verify_master_password` derives
  // the KDF and unwraps the stored user key) — no network, no session
  // change, so a wrong answer costs nothing but the retry.
  //
  // What this is worth: it stops someone who walks up to an unlocked
  // vault. It stops nothing at all against code running on the machine,
  // which can read the same decrypted vault the app is holding. The
  // editor says as much next to the checkbox.

  let dialog = $state<HTMLDialogElement | null>(null);
  let itemName = $state<string | null>(null);
  let password = $state("");
  let error = $state<string | null>(null);
  let checking = $state(false);
  let input = $state<HTMLInputElement | null>(null);
  let resolver: ((ok: boolean) => void) | null = null;
  let seq = 0;

  export function ask(name: string): Promise<boolean> {
    settle(false);
    const token = ++seq;
    itemName = name;
    password = "";
    error = null;
    checking = false;
    const answer = new Promise<boolean>((resolve) => (resolver = resolve));
    void tick().then(() => {
      if (seq !== token) return;
      dialog?.showModal();
      input?.focus();
    });
    return answer;
  }

  function settle(ok: boolean) {
    const resolve = resolver;
    resolver = null;
    itemName = null;
    // Never leave the typed master password in component state.
    password = "";
    dialog?.close();
    resolve?.(ok);
  }

  async function submit(event: Event) {
    event.preventDefault();
    if (checking || password.length === 0) return;
    checking = true;
    error = null;
    try {
      if (await api.verifyMasterPassword(password)) {
        settle(true);
      } else {
        error = m.reprompt_wrong();
        password = "";
        input?.focus();
      }
    } catch (e) {
      error = formatError(e);
    } finally {
      checking = false;
    }
  }
</script>

<dialog
  bind:this={dialog}
  class="reprompt-dialog"
  onclose={() => {
    if (resolver) settle(false);
  }}
>
  {#if itemName !== null}
    <h2>{m.reprompt_title()}</h2>
    <p class="reprompt-body">{m.reprompt_body({ name: itemName })}</p>
    <form onsubmit={submit}>
      <input
        bind:this={input}
        bind:value={password}
        type="password"
        autocomplete="current-password"
        placeholder={m.reprompt_placeholder()}
        aria-label={m.reprompt_placeholder()}
      />
      {#if error}
        <p class="reprompt-error">{error}</p>
      {/if}
      <div class="reprompt-actions">
        <button type="button" class="secondary" onclick={() => settle(false)}>
          {m.action_cancel()}
        </button>
        <button type="submit" disabled={checking || password.length === 0}>
          {m.reprompt_confirm()}
        </button>
      </div>
    </form>
  {/if}
</dialog>

<style>
  .reprompt-dialog {
    max-width: min(26rem, calc(100vw - 2rem));
    border: none;
    border-radius: 10px;
    padding: 1.25rem 1.4rem;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  }
  .reprompt-dialog::backdrop {
    background: rgba(0, 0, 0, 0.45);
  }
  .reprompt-dialog h2 {
    margin: 0 0 0.5rem;
    font-size: 1.15rem;
  }
  .reprompt-body {
    margin: 0 0 0.9rem;
    color: #555;
    font-size: 0.9rem;
    overflow-wrap: anywhere;
  }
  .reprompt-dialog input {
    width: 100%;
    font: inherit;
    padding: 0.4rem 0.5rem;
    box-sizing: border-box;
  }
  .reprompt-error {
    margin: 0.5rem 0 0;
    color: #b9301a;
    font-size: 0.85rem;
  }
  .reprompt-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
    margin-top: 1rem;
  }

  @media (prefers-color-scheme: dark) {
    .reprompt-body {
      color: #aaa;
    }
    .reprompt-error {
      color: #ffb4a8;
    }
  }
  :global(:root.force-dark) .reprompt-body {
    color: #aaa;
  }
  :global(:root.force-dark) .reprompt-error {
    color: #ffb4a8;
  }
</style>
