<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "$lib/api";
  import PasswordStrength from "./PasswordStrength.svelte";
  import { formatError } from "./format";
  import { serializeBitwardenCsv, type CsvExportRow } from "./csv";
  import type {
    CipherDetail,
    CipherSummary,
    FolderSummary,
    PasswordStrength as Strength,
  } from "./types";

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

  /**
   * Two formats, two jobs.
   *
   * `csv` is the Bitwarden dialect and exists for migrating to another
   * password manager. It is plaintext by definition and carries only
   * logins and notes — cards, identities and SSH keys have no place in
   * that schema.
   *
   * `encrypted` is the backup: every item type, sealed under a
   * password of the user's choosing.
   */
  type Format = "encrypted" | "csv";

  /** Below this the file password is not worth the file it protects. */
  const MIN_FILE_PASSWORD = 12;

  let format = $state<Format>("encrypted");
  let exporting = $state(false);
  let progress = $state(0);
  let total = $state(0);
  let error = $state<string | null>(null);
  let includeLogins = $state(true);
  let includeNotes = $state(true);
  let filePassword = $state("");
  let filePasswordConfirm = $state("");
  let showFilePassword = $state(false);
  let strength = $state<Strength | null>(null);
  let strengthSeq = 0;

  $effect(() => {
    if (open) {
      format = "encrypted";
      exporting = false;
      progress = 0;
      total = 0;
      error = null;
      includeLogins = true;
      includeNotes = true;
      filePassword = "";
      filePasswordConfirm = "";
      showFilePassword = false;
      strength = null;
    }
  });

  // Same debounced scoring as the item editor. This password matters
  // more than most: there is no server, no recovery and no reset
  // behind it — lose it and the backup is gone.
  $effect(() => {
    const current = filePassword;
    if (current.length === 0) {
      strength = null;
      return;
    }
    const seq = ++strengthSeq;
    const timer = setTimeout(() => {
      api
        .scorePassword(current, [])
        .then((result) => {
          if (seq === strengthSeq) strength = result;
        })
        .catch(() => {});
    }, 200);
    return () => clearTimeout(timer);
  });

  const passwordTooShort = $derived(
    filePassword.length > 0 && filePassword.length < MIN_FILE_PASSWORD,
  );
  const passwordsDiffer = $derived(
    filePasswordConfirm.length > 0 && filePassword !== filePasswordConfirm,
  );
  const encryptedReady = $derived(
    filePassword.length >= MIN_FILE_PASSWORD && filePassword === filePasswordConfirm,
  );

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

  /**
   * Custom fields for the export, hidden values included: `get_cipher`
   * withholds those, so each one is fetched the same way the password
   * is. An export that silently dropped them would be a lossy backup.
   */
  async function exportFields(
    detail: CipherDetail,
  ): Promise<{ name: string; value: string }[]> {
    const out: { name: string; value: string }[] = [];
    for (const [index, field] of detail.fields.entries()) {
      out.push({
        name: field.name ?? "",
        value: field.hidden
          ? ((await api.revealField(detail.id, `custom:${index}`)) ?? "")
          : (field.value ?? ""),
      });
    }
    return out;
  }

  /** Hand a finished file to the browser. Both formats end up here. */
  function download(bytes: BlobPart, mime: string, extension: string) {
    const blob = new Blob([bytes], { type: mime });
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().slice(0, 10);
    const a = document.createElement("a");
    a.href = url;
    a.download = `clavix-export-${stamp}.${extension}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function handleExport() {
    if (exporting) return;
    return format === "encrypted" ? exportEncrypted() : exportCsv();
  }

  /**
   * The encrypted path does almost nothing here on purpose: Rust
   * re-encrypts the vault under a fresh key, seals it, and hands back
   * ciphertext. No plaintext item ever reaches this component — unlike
   * the CSV path below, which has to decrypt every field to build its
   * rows.
   */
  async function exportEncrypted() {
    if (!encryptedReady) return;
    exporting = true;
    error = null;
    try {
      const bytes = await api.exportEncrypted(filePassword);
      download(bytes, "application/json", "json");
      onCancel();
    } catch (e) {
      error = formatError(e);
    } finally {
      exporting = false;
    }
  }

  async function exportCsv() {
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
          // The password and TOTP secret aren't in `detail` anymore; fetch the
          // raw values for export (a legitimate "get my secrets out" path).
          const loginPassword = detail.login?.hasPassword
            ? ((await api.revealField(c.id, "password")) ?? "")
            : "";
          const loginTotp = detail.login?.hasTotp
            ? ((await api.revealLoginTotp(c.id)) ?? "")
            : "";
          rows.push({
            folder,
            favorite: detail.favorite,
            type: "login",
            name: detail.name,
            notes: detail.notes ?? "",
            loginUris: detail.login?.uris ?? [],
            loginUsername: detail.login?.username ?? "",
            loginPassword,
            loginTotp,
            fields: await exportFields(detail),
            reprompt: detail.reprompt,
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
            fields: await exportFields(detail),
            reprompt: detail.reprompt,
          });
        }
        progress += 1;
      }

      download(serializeBitwardenCsv(rows), "text/csv;charset=utf-8", "csv");
      onCancel();
    } catch (e) {
      error = formatError(e);
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
      onkeydown={(e) => {
        // Escape must reach a handler on this element — without that,
        // stopPropagation prevented the backdrop's onkeydown from
        // closing the dialog when the user was focused on a checkbox
        // or button inside the panel.
        if (e.key === "Escape" && !exporting) onCancel();
        e.stopPropagation();
      }}
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

      <fieldset class="export-fieldset" disabled={exporting}>
        <legend class="export-legend">{m.export_format_legend()}</legend>
        <label class="checkbox-row">
          <input type="radio" bind:group={format} value="encrypted" />
          <span>{m.export_format_encrypted()}</span>
        </label>
        <p class="hint indented">{m.export_format_encrypted_hint()}</p>
        <label class="checkbox-row">
          <input type="radio" bind:group={format} value="csv" />
          <span>{m.export_format_csv()}</span>
        </label>
        <p class="hint indented">{m.export_format_csv_hint()}</p>
      </fieldset>

      {#if format === "encrypted"}
        <p class="export-warning">{m.export_encrypted_warning()}</p>
        <fieldset class="export-fieldset" disabled={exporting}>
          <legend class="export-legend">{m.export_file_password_legend()}</legend>
          <label class="export-password-label" for="export-file-password">
            {m.export_file_password()}
          </label>
          <div class="export-password-row">
            <input
              id="export-file-password"
              type={showFilePassword ? "text" : "password"}
              bind:value={filePassword}
              autocomplete="new-password"
            />
            <button
              type="button"
              class="secondary small"
              onclick={() => (showFilePassword = !showFilePassword)}
            >
              {showFilePassword ? m.action_hide() : m.action_show()}
            </button>
          </div>
          {#if filePassword.length > 0}
            <PasswordStrength
              score={strength?.score ?? null}
              warning={strength?.warning ?? null}
            />
          {/if}
          <label class="export-password-label" for="export-file-password-confirm">
            {m.export_file_password_confirm()}
          </label>
          <input
            id="export-file-password-confirm"
            type={showFilePassword ? "text" : "password"}
            bind:value={filePasswordConfirm}
            autocomplete="new-password"
          />
          {#if passwordTooShort}
            <p class="hint error-text">
              {m.export_file_password_too_short({ count: String(MIN_FILE_PASSWORD) })}
            </p>
          {/if}
          {#if passwordsDiffer}
            <p class="hint error-text">{m.export_file_password_mismatch()}</p>
          {/if}
          <p class="hint">{m.export_attachments_note()}</p>
        </fieldset>
      {:else}
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
      {/if}

      {#if exporting && format === "csv"}
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
          disabled={exporting ||
            (format === "encrypted" ? !encryptedReady : targetCount === 0)}
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

  .export-legend {
    font-size: 0.82rem;
    font-weight: 500;
    padding: 0 0.3rem;
  }

  /* Sits under its radio's label text, not under the radio itself. */
  .indented {
    margin: 0 0 0.4rem 1.5rem;
  }

  .export-password-label {
    font-size: 0.85rem;
    margin-top: 0.4rem;
  }

  .export-password-row {
    display: flex;
    gap: 0.4rem;
    align-items: center;
  }

  .export-password-row input {
    flex: 1;
    min-width: 0;
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
