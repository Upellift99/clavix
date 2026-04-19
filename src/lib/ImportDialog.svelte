<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { parseKeepassCsv, type KeepassEntry } from "$lib/csv";
  import { api } from "$lib/api";
  import { EMPTY_EDITOR_INITIAL, type FolderSummary } from "$lib/types";

  let {
    open,
    folders,
    onCancel,
    onDone,
  }: {
    open: boolean;
    folders: FolderSummary[];
    onCancel: () => void;
    onDone: () => Promise<void> | void;
  } = $props();

  let entries = $state<KeepassEntry[]>([]);
  let parseError = $state<string | null>(null);
  let fileName = $state<string | null>(null);
  let importing = $state(false);
  let progress = $state(0);
  let createdCount = $state(0);
  let failedCount = $state(0);
  let lastError = $state<string | null>(null);
  let createFolders = $state(true);

  $effect(() => {
    if (open) {
      entries = [];
      parseError = null;
      fileName = null;
      importing = false;
      progress = 0;
      createdCount = 0;
      failedCount = 0;
      lastError = null;
    }
  });

  async function onFileChange(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    fileName = file.name;
    parseError = null;
    try {
      const text = await file.text();
      entries = parseKeepassCsv(text);
      if (entries.length === 0) {
        parseError = m.import_empty();
      }
    } catch (e) {
      parseError = (e as Error).message ?? String(e);
      entries = [];
    }
  }

  async function startImport() {
    if (entries.length === 0) return;
    importing = true;
    progress = 0;
    createdCount = 0;
    failedCount = 0;
    lastError = null;

    // Build a mutable folder name → id lookup so we only create each
    // missing KeePass group once per import.
    const folderByName = new Map<string, string>();
    for (const f of folders) folderByName.set(f.name, f.id);

    for (const entry of entries) {
      try {
        let folderId: string | null = null;
        if (entry.group && createFolders) {
          let existing = folderByName.get(entry.group);
          if (!existing) {
            try {
              existing = await api.createFolder(entry.group);
              folderByName.set(entry.group, existing);
            } catch (e) {
              console.warn("[clavix] import: folder create failed", e);
            }
          }
          folderId = existing ?? null;
        }

        await api.createCipher({
          ...EMPTY_EDITOR_INITIAL,
          cipherType: 1,
          name: entry.title || "(sans nom)",
          folderId,
          notes: entry.notes,
          username: entry.username,
          password: entry.password,
          uris: entry.url ? [entry.url] : [],
          totp: entry.totp,
        });
        createdCount += 1;
      } catch (e) {
        failedCount += 1;
        lastError = (e as Error).message ?? String(e);
      }
      progress += 1;
    }

    importing = false;
    await onDone();
  }
</script>

{#if open}
  <div
    class="import-backdrop"
    onclick={() => !importing && onCancel()}
    onkeydown={(e) => !importing && e.key === "Escape" && onCancel()}
    role="presentation"
  >
    <div
      class="import-panel"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-title"
      tabindex="-1"
    >
      <header class="import-header">
        <h2 id="import-title">{m.import_title()}</h2>
        <button
          type="button"
          class="secondary small"
          onclick={onCancel}
          disabled={importing}
          aria-label={m.action_close()}
        >
          ✕
        </button>
      </header>
      <p class="hint">{m.import_hint()}</p>

      <input type="file" accept=".csv,text/csv" onchange={onFileChange} disabled={importing} />

      {#if parseError}
        <p class="import-error">{parseError}</p>
      {/if}

      {#if entries.length > 0}
        <p class="import-summary">
          {m.import_summary({ count: String(entries.length), file: fileName ?? "?" })}
        </p>
        <label class="checkbox-row">
          <input type="checkbox" bind:checked={createFolders} disabled={importing} />
          <span>{m.import_create_folders()}</span>
        </label>

        <div class="import-preview">
          <table>
            <thead>
              <tr>
                <th>{m.editor_name()}</th>
                <th>{m.detail_field_username()}</th>
                <th>{m.detail_field_url_one()}</th>
                <th>{m.editor_folder()}</th>
              </tr>
            </thead>
            <tbody>
              {#each entries.slice(0, 15) as e, i (i)}
                <tr>
                  <td>{e.title}</td>
                  <td>{e.username}</td>
                  <td class="url-cell">{e.url}</td>
                  <td>{e.group}</td>
                </tr>
              {/each}
            </tbody>
          </table>
          {#if entries.length > 15}
            <p class="hint">{m.import_more({ count: String(entries.length - 15) })}</p>
          {/if}
        </div>
      {/if}

      {#if importing}
        <p class="import-progress">
          {m.import_progress({
            done: String(progress),
            total: String(entries.length),
          })}
        </p>
      {/if}

      {#if !importing && progress > 0}
        <p class="import-done">
          {m.import_done({
            created: String(createdCount),
            failed: String(failedCount),
          })}
        </p>
        {#if lastError}
          <p class="import-error">{lastError}</p>
        {/if}
      {/if}

      <div class="row">
        <button
          type="button"
          class="secondary"
          onclick={onCancel}
          disabled={importing}
        >
          {progress > 0 && !importing ? m.action_close() : m.action_cancel()}
        </button>
        <button
          type="button"
          onclick={startImport}
          disabled={importing || entries.length === 0 || progress > 0}
        >
          {importing ? m.import_running() : m.import_start()}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .import-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 150;
  }

  .import-panel {
    background: #fff;
    border-radius: 10px;
    padding: 1.1rem 1.4rem;
    width: min(640px, 96vw);
    max-height: 92vh;
    overflow-y: auto;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  }

  .import-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }

  .import-header h2 {
    margin: 0;
    font-size: 1.05rem;
  }

  .hint {
    color: #555;
    font-size: 0.85rem;
    margin: 0.2rem 0 0.6rem;
  }

  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0.4rem 0;
    font-size: 0.9rem;
  }

  .import-error {
    color: #7a1d1d;
    background: #fdecec;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    margin: 0.5rem 0;
    font-size: 0.85rem;
  }

  .import-summary {
    margin: 0.4rem 0;
    font-size: 0.9rem;
  }

  .import-preview {
    max-height: 280px;
    overflow-y: auto;
    border: 1px solid #e6e6e6;
    border-radius: 6px;
    margin: 0.4rem 0;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }

  th {
    position: sticky;
    top: 0;
    background: #f3f4f6;
    padding: 0.35rem 0.5rem;
    text-align: left;
    border-bottom: 1px solid #d0d0d0;
  }

  td {
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 180px;
  }

  .url-cell {
    color: #3f64a1;
  }

  .import-progress,
  .import-done {
    margin: 0.5rem 0;
    font-size: 0.9rem;
  }

  .row {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
    margin-top: 0.6rem;
  }

  button {
    cursor: pointer;
    background: #396cd8;
    color: #fff;
    border: 1px solid #396cd8;
    border-radius: 6px;
    padding: 0.45rem 0.9rem;
    font: inherit;
    font-weight: 500;
  }

  button.secondary {
    background: #fff;
    color: #333;
    border-color: #d0d0d0;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  button:hover:not(:disabled) {
    filter: brightness(0.95);
  }
</style>
