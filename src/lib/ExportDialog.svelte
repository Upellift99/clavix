<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "$lib/api";
  import { serializeBitwardenCsv, type CsvExportRow } from "./csv";
  import type { CipherSummary, FolderSummary } from "./types";

  let {
    open,
    ciphers,
    folders,
    onCancel,
  }: {
    open: boolean;
    ciphers: CipherSummary[];
    folders: FolderSummary[];
    onCancel: () => void;
  } = $props();

  let exporting = $state(false);
  let progress = $state(0);
  let total = $state(0);
  let error = $state<string | null>(null);
  let includeLogins = $state(true);
  let includeNotes = $state(true);

  $effect(() => {
    if (open) {
      exporting = false;
      progress = 0;
      total = 0;
      error = null;
      includeLogins = true;
      includeNotes = true;
    }
  });

  function targetsFor(includeL: boolean, includeN: boolean): CipherSummary[] {
    return ciphers.filter((c) => {
      if (c.deletedDate) return false;
      if (c.kind === 1 && includeL) return true;
      if (c.kind === 2 && includeN) return true;
      return false;
    });
  }

  // Live-derived counts so the user knows what they're about to export
  // before they click. Updates as the type-filter checkboxes move.
  const targetCount = $derived(targetsFor(includeLogins, includeNotes).length);
  const loginCount = $derived(
    ciphers.filter((c) => !c.deletedDate && c.kind === 1).length,
  );
  const noteCount = $derived(
    ciphers.filter((c) => !c.deletedDate && c.kind === 2).length,
  );

  async function handleExport() {
    if (exporting) return;
    const targets = targetsFor(includeLogins, includeNotes);
    if (targets.length === 0) {
      error = m.export_nothing();
      return;
    }

    exporting = true;
    error = null;
    total = targets.length;
    progress = 0;

    const folderById = new Map(folders.map((f) => [f.id, f.name]));
    const rows: CsvExportRow[] = [];

    try {
      for (const c of targets) {
        const detail = await api.getCipher(c.id);
        const folder = c.folderId ? (folderById.get(c.folderId) ?? "") : "";
        if (detail.kind === 1) {
          rows.push({
            folder,
            favorite: detail.favorite,
            type: "login",
            name: detail.name,
            notes: detail.notes ?? "",
            loginUris: detail.login?.uris ?? [],
            loginUsername: detail.login?.username ?? "",
            loginPassword: detail.login?.password ?? "",
            loginTotp: detail.login?.totp ?? "",
          });
        } else if (detail.kind === 2) {
          rows.push({
            folder,
            favorite: detail.favorite,
            type: "note",
            name: detail.name,
            notes: detail.notes ?? "",
            loginUris: [],
            loginUsername: "",
            loginPassword: "",
            loginTotp: "",
          });
        }
        progress += 1;
      }

      const csv = serializeBitwardenCsv(rows);
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const stamp = new Date().toISOString().slice(0, 10);
      const a = document.createElement("a");
      a.href = url;
      a.download = `clavix-export-${stamp}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      onCancel();
    } catch (e) {
      error = (e as Error).message ?? String(e);
    } finally {
      exporting = false;
    }
  }
</script>

{#if open}
  <div
    class="import-backdrop"
    onclick={() => !exporting && onCancel()}
    onkeydown={(e) => !exporting && e.key === "Escape" && onCancel()}
    role="presentation"
  >
    <div
      class="import-panel"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="export-title"
      tabindex="-1"
    >
      <header class="import-header">
        <h2 id="export-title">{m.export_title()}</h2>
        <button
          type="button"
          class="secondary small"
          onclick={onCancel}
          disabled={exporting}
          aria-label={m.action_close()}
        >
          ✕
        </button>
      </header>

      <p class="export-warning">{m.export_warning()}</p>
      <p class="hint">{m.export_hint()}</p>

      <fieldset class="export-fieldset" disabled={exporting}>
        <legend class="visually-hidden">{m.export_filter_legend()}</legend>
        <label class="checkbox-row">
          <input type="checkbox" bind:checked={includeLogins} />
          <span>{m.export_include_logins({ count: String(loginCount) })}</span>
        </label>
        <label class="checkbox-row">
          <input type="checkbox" bind:checked={includeNotes} />
          <span>{m.export_include_notes({ count: String(noteCount) })}</span>
        </label>
      </fieldset>

      <p class="export-summary">
        {m.export_summary({ count: String(targetCount) })}
      </p>

      {#if exporting}
        <p class="import-progress">
          {m.export_progress({ done: String(progress), total: String(total) })}
        </p>
      {/if}

      {#if error}
        <p class="import-error">{error}</p>
      {/if}

      <div class="row">
        <button
          type="button"
          class="secondary"
          onclick={onCancel}
          disabled={exporting}
        >
          {m.action_cancel()}
        </button>
        <button
          type="button"
          onclick={handleExport}
          disabled={exporting || targetCount === 0}
        >
          {exporting ? m.export_running() : m.export_action()}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .export-warning {
    background: #fef3c7;
    color: #7a3b00;
    padding: 0.5rem 0.7rem;
    border-radius: 6px;
    margin: 0.4rem 0 0.6rem;
    font-size: 0.88rem;
  }

  .export-fieldset {
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 0.5rem 0.7rem;
    margin: 0.5rem 0;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  /* The label rows here were unstyled and inherited base.css
     `label { flex-direction: column }`, stacking the checkbox above
     its text. ImportDialog and CipherEditor define this class in
     their own scoped <style>; reuse the same one here to keep the
     two filter rows on a single line each. */
  .checkbox-row {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
    margin: 0.2rem 0;
    font-size: 0.9rem;
  }

  .export-summary {
    font-size: 0.88rem;
    margin: 0.4rem 0 0.6rem;
  }

  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  .row {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.6rem;
  }
</style>
