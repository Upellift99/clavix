<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { formatError } from "./format";

  /**
   * Emergency restore: open an encrypted export file with nothing but
   * its password.
   *
   * Deliberately collapsed behind a disclosure rather than shown as a
   * peer of "Unlock". This is the path for the day the server or the
   * account is gone — offering it with equal weight on every start
   * would invite people to browse a stale backup when their live vault
   * is one password away.
   */
  let { onOpen }: { onOpen: (bytes: Uint8Array, password: string) => Promise<void> } =
    $props();

  let expanded = $state(false);
  let file = $state<File | null>(null);
  let password = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);

  function pick(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    file = input.files?.[0] ?? null;
    error = null;
  }

  async function submit(event: Event) {
    event.preventDefault();
    if (!file || password.length === 0 || busy) return;
    busy = true;
    error = null;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      await onOpen(bytes, password);
    } catch (e) {
      error = formatError(e);
    } finally {
      // Cleared either way: on success the vault is open and this form
      // is gone, on failure the user retypes.
      password = "";
      busy = false;
    }
  }
</script>

<div class="standalone-open">
  {#if !expanded}
    <button type="button" class="link-button" onclick={() => (expanded = true)}>
      {m.standalone_open_file()}
    </button>
  {:else}
    <form onsubmit={submit}>
      <p class="hint">{m.standalone_open_file_hint()}</p>
      <input type="file" accept=".json,application/json" onchange={pick} disabled={busy} />
      <label for="standalone-file-password">{m.export_file_password()}</label>
      <input
        id="standalone-file-password"
        type="password"
        bind:value={password}
        autocomplete="off"
        disabled={busy}
      />
      {#if error}
        <p class="hint error-text">{error}</p>
      {/if}
      <div class="standalone-row">
        <button
          type="button"
          class="secondary small"
          onclick={() => (expanded = false)}
          disabled={busy}
        >
          {m.action_cancel()}
        </button>
        <button type="submit" class="small" disabled={busy || !file || password.length === 0}>
          {busy ? m.action_unlocking() : m.action_unlock()}
        </button>
      </div>
    </form>
  {/if}
</div>

<style>
  .standalone-open {
    margin-top: 0.8rem;
    font-size: 0.88rem;
  }

  .link-button {
    background: none;
    border: none;
    padding: 0;
    color: #396cd8;
    text-decoration: underline;
    cursor: pointer;
    font-size: 0.85rem;
  }

  .standalone-open label {
    font-size: 0.85rem;
    margin-top: 0.4rem;
  }

  .standalone-row {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }

  @media (prefers-color-scheme: dark) {
    .link-button {
      color: #8fb0ff;
    }
  }

  :where(:root.force-dark) .link-button {
    color: #8fb0ff;
  }
</style>
