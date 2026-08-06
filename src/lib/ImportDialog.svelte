<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { parseKeepassCsv, type KeepassEntry } from "$lib/csv";
  import { api } from "$lib/api";
  import { formatError } from "$lib/format";
  import { exceedsEncryptedLimit } from "$lib/limits";
  import { importIdentity } from "$lib/import";
  import {
    EMPTY_CARD_FIELDS,
    EMPTY_EDITOR_INITIAL,
    EMPTY_IDENTITY_FIELDS,
    EMPTY_SSH_FIELDS,
    type CipherSummary,
    type EditorPayload,
    type CollectionSummary,
    type FolderSummary,
    type ImportedItem,
    type OrganizationSummary,
  } from "$lib/types";

  let {
    open,
    folders,
    organizations,
    collections,
    existing,
    onCancel,
    onDone,
  }: {
    open: boolean;
    folders: FolderSummary[];
    organizations: OrganizationSummary[];
    collections: CollectionSummary[];
    /** Items already in the vault, used to skip re-importing them. */
    existing: CipherSummary[];
    onCancel: () => void;
    onDone: () => Promise<void> | void;
  } = $props();

  // Import destination: null = personal vault (KeePass groups become folders),
  // or an organization id (all items land in the chosen collection; groups are
  // ignored, since folders are a personal-vault concept in Bitwarden).
  let destOrgId = $state<string | null>(null);
  let destCollectionId = $state<string | null>(null);
  const orgCollections = $derived(
    destOrgId ? collections.filter((c) => c.organizationId === destOrgId) : [],
  );

  /**
   * A parsed row, whatever it came from.
   *
   * CSV and KDBX only ever describe logins, so those paths leave
   * `payload` unset and the import loop builds a login from the flat
   * fields. A Clavix encrypted export carries all five item types, and
   * flattening a card or an SSH key into `KeepassEntry` would silently
   * drop exactly what that format exists to preserve — so it supplies
   * a ready-made `payload` instead, and the flat fields are kept only
   * to feed the preview, the duplicate check and the size check, which
   * are format-agnostic.
   */
  type ImportEntry = KeepassEntry & { payload?: EditorPayload };

  let entries = $state<ImportEntry[]>([]);
  let parseError = $state<string | null>(null);
  let fileName = $state<string | null>(null);
  let importing = $state(false);
  let progress = $state(0);
  // How many items this run set out to create (the selected count captured at
  // start), so the progress line's denominator is the batch, not the file.
  let plannedCount = $state(0);
  let createdCount = $state(0);
  let failedCount = $state(0);
  let lastError = $state<string | null>(null);
  let createFolders = $state(true);
  // Which entries the server refused, and why. A bare failure *count*
  // used to be the only feedback, so an entry rejected for an oversized
  // note vanished with no way to tell which one it was.
  let failures = $state<{ title: string; username: string; message: string }[]>([]);
  let skippedCount = $state(0);
  // Set when the run stopped early because the server pushed back
  // (rate limit exhausted, or a proxy/WAF refusing us outright). The
  // remaining entries were never attempted — see `startImport`.
  let abortedReason = $state<"rate_limited" | "blocked" | null>(null);
  // KDBX path: we hold the picked file until the user types the
  // master password, then call `parse_kdbx` over IPC. The CSV path
  // ignores all of these.
  // Two formats need a password before they can be parsed at all: a
  // KDBX database and a Clavix encrypted export. Both are held here
  // until the user supplies one, then decrypted in Rust.
  let pendingFile = $state<File | null>(null);
  let pendingKind = $state<"kdbx" | "clavix" | null>(null);
  let filePassword = $state("");
  let fileParsing = $state(false);

  // An import is the one place Clavix issues hundreds of writes back to
  // back, and a self-hosted server usually sits behind something that
  // reacts to that. Left unthrottled, a 1100-item import tripped
  // Vaultwarden's own rate limiter, whose 429s then tripped the WAF in
  // front of it, which banned the client for an hour — and the loop kept
  // firing another 1100 requests into the ban.
  //
  // Hence: space the writes out, back off when told to, and stop rather
  // than hammer a server that is refusing us.
  // Starting spacing. 60ms was a guess, and it was wrong: against a
  // proxy capped at 5 r/s it still produced 6 r/s once latency was
  // accounted for, so the run kept earning 429s. 200ms targets 5 r/s,
  // which clears the common default — but the number below matters far
  // less than the fact that it adapts, since the client cannot know any
  // given deployment's limit.
  const INITIAL_THROTTLE_MS = 200;
  // Ceiling for the learned spacing: past this the import is so slow
  // that stopping and telling the user beats grinding on.
  const MAX_THROTTLE_MS = 2000;
  const MAX_RATE_LIMIT_RETRIES = 5;
  const BASE_BACKOFF_MS = 1000;

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  /** HTTP status behind a Tauri error, or null if it wasn't an HTTP one. */
  function httpStatusOf(e: unknown): number | null {
    const err = e as { code?: string; data?: { status?: unknown } };
    if (err?.code !== "http_status") return null;
    const status = Number(err.data?.status);
    return Number.isFinite(status) ? status : null;
  }

  const existingIds = $derived(
    new Set(existing.map((c) => importIdentity(c.name, c.username ?? ""))),
  );

  // The entries that will actually be created, in order. Vault duplicates and
  // within-file duplicates are dropped here exactly as `startImport` drops
  // them, so the preview shows precisely what the import will add — nothing it
  // will silently skip.
  const newEntries = $derived.by(() => {
    const seen = new Set(existingIds);
    const result: ImportEntry[] = [];
    for (const e of entries) {
      const id = importIdentity(e.title, e.username);
      if (seen.has(id)) continue;
      seen.add(id);
      result.push(e);
    }
    return result;
  });

  /** How many parsed entries are skipped as duplicates (vault or in-file). */
  const skippedPreview = $derived(entries.length - newEntries.length);

  // Rows the user has unchecked, keyed by import identity. Empty = everything
  // selected (the default). Only ever holds identities drawn from newEntries,
  // whose identities are unique, so `newEntries.length - excluded.size` is the
  // exact selected count. Reset whenever a new file is parsed.
  let excluded = $state<Set<string>>(new Set());

  const selectedEntries = $derived(
    newEntries.filter((e) => !excluded.has(importIdentity(e.title, e.username))),
  );
  const allSelected = $derived(newEntries.length > 0 && excluded.size === 0);

  function toggleEntry(id: string) {
    const next = new Set(excluded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    excluded = next;
  }

  function toggleAll() {
    excluded = allSelected
      ? new Set(newEntries.map((e) => importIdentity(e.title, e.username)))
      : new Set();
  }

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
      failures = [];
      skippedCount = 0;
      plannedCount = 0;
      abortedReason = null;
      excluded = new Set();
      pendingFile = null;
      filePassword = "";
      fileParsing = false;
      destOrgId = null;
      destCollectionId = null;
    }
  });

  // Default to the org's first collection when a destination org is picked, so
  // the import is never left targeting an org with no collection selected.
  function onDestOrgChange() {
    destCollectionId = orgCollections[0]?.id ?? null;
  }

  // Block the import when an org is chosen but no collection can receive the
  // items (org items must belong to at least one collection).
  const destInvalid = $derived(destOrgId !== null && destCollectionId === null);

  /** Which password-protected format this is, or null for plain CSV. */
  function encryptedKindOf(file: File): "kdbx" | "clavix" | null {
    const name = file.name.toLowerCase();
    if (name.endsWith(".kdbx")) return "kdbx";
    if (name.endsWith(".json")) return "clavix";
    return null;
  }

  async function onFileChange(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    fileName = file.name;
    parseError = null;
    entries = [];
    excluded = new Set();
    pendingFile = null;
    pendingKind = null;
    filePassword = "";

    const kind = encryptedKindOf(file);
    if (kind) {
      // Both formats derive a key from the password before anything can
      // be read, so the file waits here until `decryptPendingFile()`.
      pendingFile = file;
      pendingKind = kind;
      return;
    }

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

  /**
   * Turn the items out of a Clavix encrypted export into rows this
   * dialog can preview and import.
   *
   * The flat `KeepassEntry` fields are filled in for the preview, the
   * duplicate check and the note-size check — all of which only ever
   * look at a title, a username and a note. The `payload` alongside
   * them is what actually gets created, so a card, an identity or an
   * SSH key survives intact even though the preview row can only
   * describe it as a name.
   */
  function toImportEntries(items: ImportedItem[]): ImportEntry[] {
    return items.map(({ item, folderName }) => ({
      title: item.name,
      username: item.login?.username ?? "",
      password: item.login?.password ?? "",
      url: item.login?.uris?.[0] ?? "",
      notes: item.notes ?? "",
      totp: item.login?.totp ?? "",
      group: folderName,
      payload: {
        ...EMPTY_EDITOR_INITIAL,
        cipherType: (item.cipherType as EditorPayload["cipherType"]) ?? 1,
        name: item.name,
        favorite: item.favorite,
        notes: item.notes ?? "",
        username: item.login?.username ?? "",
        password: item.login?.password ?? "",
        uris: item.login?.uris ?? [],
        totp: item.login?.totp ?? "",
        card: { ...EMPTY_CARD_FIELDS, ...stripNulls(item.card) },
        identity: { ...EMPTY_IDENTITY_FIELDS, ...stripNulls(item.identity) },
        sshKey: { ...EMPTY_SSH_FIELDS, ...stripNulls(item.sshKey) },
        fields: (item.fields ?? []).map((f) => ({
          kind: f.kind ?? 0,
          name: f.name ?? "",
          value: f.value ?? "",
          linkedId: f.linkedId ?? null,
        })),
        reprompt: item.reprompt,
        // Destination is decided per-run in `startImport`, not here.
        folderId: null,
        organizationId: null,
        collectionIds: [],
      },
    }));
  }

  /**
   * Rust sends absent optional fields as `null`; the editor's field
   * types are plain strings. Spreading the nulls straight in would put
   * `null` where `""` is expected and render "null" in the editor, so
   * drop them and let the EMPTY_* defaults stand.
   */
  function stripNulls<T extends object>(
    source: T | null | undefined,
  ): Partial<{ [K in keyof T]: NonNullable<T[K]> }> {
    if (!source) return {};
    return Object.fromEntries(
      Object.entries(source).filter(([, v]) => v !== null && v !== undefined),
    ) as Partial<{ [K in keyof T]: NonNullable<T[K]> }>;
  }

  async function decryptPendingFile(event: Event) {
    event.preventDefault();
    if (!pendingFile || filePassword.length === 0 || fileParsing) return;
    fileParsing = true;
    parseError = null;
    try {
      const buffer = await pendingFile.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      // Both branches land in the same `entries` state, which is what
      // lets the preview, the duplicate check and the throttled import
      // loop stay ignorant of where a row came from.
      entries =
        pendingKind === "clavix"
          ? toImportEntries(await api.importEncrypted(bytes, filePassword))
          : await api.parseKdbx(bytes, filePassword);
      excluded = new Set();
      if (entries.length === 0) {
        parseError = m.import_empty();
      }
      pendingFile = null;
      pendingKind = null;
      filePassword = "";
    } catch (e) {
      parseError = formatError(e);
    } finally {
      fileParsing = false;
    }
  }

  // Entries the server will refuse outright: the encrypted note blows past
  // the 10 000-character cap on any single encrypted value. Flagged before
  // the import runs so the user knows what will not make it across — an
  // armored PGP key in a note is the usual culprit, and it is well under
  // any length the user can see, because the limit applies to the
  // *encrypted* value.
  const oversized = $derived(newEntries.filter((e) => exceedsEncryptedLimit(e.notes)));

  async function startImport() {
    // Snapshot the checked rows up front: `selectedEntries` already has vault
    // duplicates, in-file duplicates, and user-unchecked rows removed, so the
    // loop below just creates each one — no per-item skip logic needed.
    const toImport = selectedEntries;
    if (toImport.length === 0) return;
    importing = true;
    progress = 0;
    createdCount = 0;
    failedCount = 0;
    lastError = null;
    failures = [];
    // Must be cleared here too: without it a second run would break out
    // of the loop on its first iteration, importing nothing.
    abortedReason = null;
    // Each run relearns the pace from scratch. Carrying a widened value
    // over would make a retry of a once-throttled import needlessly slow
    // even against a server that is no longer limiting.
    let throttleMs = INITIAL_THROTTLE_MS;
    plannedCount = toImport.length;
    // Everything parsed but left out of this run: duplicates plus unchecked rows.
    skippedCount = entries.length - toImport.length;

    // Build a mutable folder name → id lookup so we only create each
    // missing KeePass group once per import.
    const folderByName = new Map<string, string>();
    for (const f of folders) folderByName.set(f.name, f.id);

    for (const entry of toImport) {
      try {
        // Folders are a personal-vault concept; when importing into an
        // organization every item goes to the chosen collection instead.
        let folderId: string | null = null;
        if (!destOrgId && entry.group && createFolders) {
          let known = folderByName.get(entry.group);
          if (!known) {
            try {
              known = await api.createFolder(entry.group);
              folderByName.set(entry.group, known);
            } catch (e) {
              console.warn("[clavix] import: folder create failed", e);
            }
          }
          folderId = known ?? null;
        }

        // Annotated because hoisting the literal out of the call site
        // loses the contextual typing that narrowed `cipherType` to
        // `CipherKind`.
        //
        // An encrypted export already supplies a complete payload, of
        // whatever item type; only the destination is decided here.
        // CSV and KDBX describe a login and nothing else, so that one
        // is built from the flat fields.
        const payload: EditorPayload = entry.payload
          ? {
              ...entry.payload,
              folderId,
              organizationId: destOrgId,
              collectionIds: destOrgId && destCollectionId ? [destCollectionId] : [],
            }
          : {
              ...EMPTY_EDITOR_INITIAL,
              cipherType: 1,
              name: entry.title || "(sans nom)",
              folderId,
              organizationId: destOrgId,
              collectionIds: destOrgId && destCollectionId ? [destCollectionId] : [],
              notes: entry.notes,
              username: entry.username,
              password: entry.password,
              uris: entry.url ? [entry.url] : [],
              totp: entry.totp,
            };

        // Retry only what retrying can fix. A 429 means "slow down", so
        // wait longer each time. A 403 means something in front of the
        // server has decided against us — retrying is what turns a
        // refusal into a ban, so stop immediately and say so.
        let attempt = 0;
        for (;;) {
          try {
            await api.createCipher(payload);
            createdCount += 1;
            break;
          } catch (e) {
            const status = httpStatusOf(e);
            if (status === 429 && attempt < MAX_RATE_LIMIT_RETRIES) {
              attempt += 1;
              // Slow the *rest of the run*, not just this retry. Backing
              // off only the retry leaves the base pace above the limit,
              // so the next items earn their own 429s — and a WAF that
              // counts 429s as bad behaviour bans the client long before
              // the import ends. Widening permanently converges under
              // whatever limit this deployment actually enforces.
              throttleMs = Math.min(throttleMs * 2, MAX_THROTTLE_MS);
              await sleep(BASE_BACKOFF_MS * 2 ** (attempt - 1));
              continue;
            }
            if (status === 429) {
              abortedReason = "rate_limited";
            } else if (status === 403) {
              abortedReason = "blocked";
            }
            throw e;
          }
        }
      } catch (e) {
        failedCount += 1;
        lastError = (e as Error).message ?? String(e);
        failures.push({
          title: entry.title || "(sans nom)",
          username: entry.username,
          message: formatError(e),
        });
      }
      progress += 1;

      // Leave the run half-done rather than push a server that is
      // already refusing us; the summary tells the user what remains.
      if (abortedReason) break;

      await sleep(throttleMs);
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
      onkeydown={(e) => {
        // Let Escape bubble to *us* so it closes the dialog when the
        // user is focused inside the file picker, KDBX-password input
        // or one of the import preview rows. stopPropagation alone
        // swallowed it before the backdrop's keydown handler ran.
        if (e.key === "Escape" && !importing) onCancel();
        e.stopPropagation();
      }}
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

      <input
        type="file"
        accept=".csv,text/csv,.kdbx,.json,application/json"
        onchange={onFileChange}
        disabled={importing || fileParsing}
      />

      {#if pendingFile}
        <form class="kdbx-password-row" onsubmit={decryptPendingFile}>
          <label class="kdbx-password-label" for="import-kdbx-password">
            {pendingKind === "clavix"
              ? m.import_clavix_password_label()
              : m.import_kdbx_password_label()}
          </label>
          <div class="kdbx-password-input-row">
            <!-- svelte-ignore a11y_autofocus -->
            <input
              id="import-kdbx-password"
              type="password"
              bind:value={filePassword}
              autofocus
              autocomplete="off"
              disabled={fileParsing}
            />
            <button type="submit" disabled={fileParsing || filePassword.length === 0}>
              {fileParsing ? m.import_kdbx_decrypting() : m.import_kdbx_decrypt()}
            </button>
          </div>
          <p class="hint">
            {pendingKind === "clavix"
              ? m.import_clavix_password_hint()
              : m.import_kdbx_password_hint()}
          </p>
        </form>
      {/if}

      {#if parseError}
        <p class="import-error">{parseError}</p>
      {/if}

      {#if entries.length > 0}
        <p class="import-summary">
          {m.import_summary({ count: String(newEntries.length), file: fileName ?? "?" })}
        </p>

        {#if organizations.length > 0}
          <label class="import-dest">
            {m.import_destination()}
            <select bind:value={destOrgId} onchange={onDestOrgChange} disabled={importing}>
              <option value={null}>{m.editor_owner_personal()}</option>
              {#each organizations as org (org.id)}
                <option value={org.id}>{org.name}</option>
              {/each}
            </select>
          </label>
          {#if destOrgId}
            <label class="import-dest">
              {m.editor_collection()}
              <select bind:value={destCollectionId} disabled={importing}>
                {#if orgCollections.length === 0}
                  <option value={null} disabled>{m.editor_no_collection()}</option>
                {:else}
                  {#each orgCollections as c (c.id)}
                    <option value={c.id}>{c.name}</option>
                  {/each}
                {/if}
              </select>
            </label>
          {/if}
        {/if}

        {#if !destOrgId}
          <label class="checkbox-row">
            <input type="checkbox" bind:checked={createFolders} disabled={importing} />
            <span>{m.import_create_folders()}</span>
          </label>
        {/if}

        {#if skippedPreview > 0}
          <p class="import-skip">
            {m.import_already_present({ count: String(skippedPreview) })}
          </p>
        {/if}

        {#if oversized.length > 0}
          <div class="import-warning">
            <p>{m.import_notes_too_long({ count: String(oversized.length) })}</p>
            <ul>
              {#each oversized.slice(0, 5) as e, i (i)}
                <li>{e.title || "(sans nom)"}{e.username ? ` — ${e.username}` : ""}</li>
              {/each}
            </ul>
            {#if oversized.length > 5}
              <p class="hint">{m.import_more({ count: String(oversized.length - 5) })}</p>
            {/if}
          </div>
        {/if}

        <div class="preview-toolbar">
          <label class="checkbox-row compact">
            <input
              type="checkbox"
              checked={allSelected}
              indeterminate={selectedEntries.length > 0 && !allSelected}
              onchange={toggleAll}
              disabled={importing}
            />
            <span>{m.import_select_all()}</span>
          </label>
          <span class="preview-count">
            {m.import_selected({
              selected: String(selectedEntries.length),
              total: String(newEntries.length),
            })}
          </span>
        </div>

        <div class="import-preview">
          <table>
            <thead>
              <tr>
                <th class="check-col"></th>
                <th>{m.editor_name()}</th>
                <th>{m.detail_field_username()}</th>
                <th>{m.detail_field_url_one()}</th>
                <th>{m.editor_folder()}</th>
              </tr>
            </thead>
            <tbody>
              {#each newEntries as e (importIdentity(e.title, e.username))}
                {@const id = importIdentity(e.title, e.username)}
                <tr class:deselected={excluded.has(id)}>
                  <td class="check-col">
                    <input
                      type="checkbox"
                      checked={!excluded.has(id)}
                      onchange={() => toggleEntry(id)}
                      disabled={importing}
                      aria-label={e.title || "(sans nom)"}
                    />
                  </td>
                  <td>{e.title}</td>
                  <td>{e.username}</td>
                  <td class="url-cell">{e.url}</td>
                  <td>{e.group}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}

      {#if importing}
        <p class="import-progress">
          {m.import_progress({
            done: String(progress),
            total: String(plannedCount),
          })}
        </p>
      {/if}

      {#if !importing && progress > 0}
        <p class="import-done">
          {m.import_done({
            created: String(createdCount),
            failed: String(failedCount),
          })}
          {#if skippedCount > 0}
            {" "}{m.import_skipped({ count: String(skippedCount) })}
          {/if}
        </p>
        {#if abortedReason}
          <!-- The remaining entries were never attempted, so say how many
               and why — a bare failure count would read as "these items
               are bad" rather than "the server stopped us". -->
          <p class="import-aborted">
            {abortedReason === "blocked"
              ? m.import_aborted_blocked({ remaining: String(plannedCount - progress) })
              : m.import_aborted_rate_limited({ remaining: String(plannedCount - progress) })}
          </p>
        {/if}
        {#if failures.length > 0}
          <div class="import-failures">
            <p>{m.import_failures_heading()}</p>
            <ul>
              {#each failures as f, i (i)}
                <li>
                  <strong>{f.title}</strong>{f.username ? ` — ${f.username}` : ""} — {f.message}
                </li>
              {/each}
            </ul>
          </div>
        {:else if lastError}
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
          disabled={importing || selectedEntries.length === 0 || progress > 0 || destInvalid}
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
    width: min(880px, 96vw);
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
    /* Override base.css `label { flex-direction: column }` so the
       checkbox sits to the left of the label, not stacked above it. */
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
    margin: 0.4rem 0;
    font-size: 0.9rem;
  }

  .import-dest {
    margin: 0.4rem 0;
    font-size: 0.9rem;
    gap: 0.25rem;
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

  .import-skip {
    margin: 0.5rem 0;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    background: #eef3ff;
    color: #163b8a;
    font-size: 0.85rem;
  }

  .import-warning {
    color: #7a4a0e;
    background: #fdf3e3;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    margin: 0.5rem 0;
    font-size: 0.85rem;
  }

  .import-failures {
    color: #7a1d1d;
    background: #fdecec;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    margin: 0.5rem 0;
    font-size: 0.85rem;
    max-height: 9rem;
    overflow-y: auto;
  }

  .import-warning ul,
  .import-failures ul {
    margin: 0.3rem 0 0;
    padding-left: 1.1rem;
  }

  .import-warning p,
  .import-failures p {
    margin: 0;
  }

  .preview-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    margin: 0.5rem 0 0.25rem;
  }

  .checkbox-row.compact {
    margin: 0;
    font-size: 0.85rem;
  }

  .preview-count {
    color: #555;
    font-size: 0.82rem;
  }

  .import-preview {
    max-height: 280px;
    overflow-y: auto;
    /* No horizontal scrollbar: cells already truncate with an ellipsis,
       and a bottom scrollbar overlapped the last row's checkbox, making
       it a fight to tick. */
    overflow-x: hidden;
    border: 1px solid #e6e6e6;
    border-radius: 6px;
    margin: 0 0 0.4rem;
  }

  .check-col {
    width: 1.75rem;
    text-align: center;
    padding-left: 0.4rem;
    padding-right: 0.2rem;
  }

  tr.deselected td:not(.check-col) {
    opacity: 0.45;
    text-decoration: line-through;
  }

  table {
    width: 100%;
    /* Fixed layout so columns share the container width and long values
       ellipsis-truncate instead of widening the table past its box (which
       forced a horizontal scrollbar over the last checkbox). */
    table-layout: fixed;
    /* `separate` (not `collapse`) so the sticky header keeps its own
       border while rows scroll under it — with `collapse` the shared
       border belongs to the cells and scrolls away, letting row text
       bleed over the header. */
    border-collapse: separate;
    border-spacing: 0;
    font-size: 0.82rem;
  }

  th {
    position: sticky;
    top: 0;
    /* Sit above the scrolling body so rows never paint over the header. */
    z-index: 2;
    background: #f3f4f6;
    padding: 0.35rem 0.5rem;
    text-align: left;
    /* box-shadow, not border-bottom: a sticky element's own border can
       still be overpainted by scrolling cells; an inset shadow can't. */
    box-shadow: inset 0 -1px 0 #d0d0d0;
  }

  td {
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .url-cell {
    color: #3f64a1;
  }

  .import-progress,
  .import-done {
    margin: 0.5rem 0;
    font-size: 0.9rem;
  }

  /* Amber, not the failures' red: the entries that remain aren't bad,
     they were never sent. */
  .import-aborted {
    color: #7a3b00;
    background: #fdf3e0;
    padding: 0.4rem 0.6rem;
    border-radius: 6px;
    margin: 0.5rem 0;
    font-size: 0.85rem;
  }

  .kdbx-password-row {
    margin: 0.6rem 0;
    padding: 0.7rem 0.9rem;
    background: #f7f8fa;
    border: 1px solid #e2e4e8;
    border-radius: 8px;
  }

  .kdbx-password-label {
    display: block;
    font-size: 0.85rem;
    margin-bottom: 0.4rem;
    font-weight: 500;
  }

  .kdbx-password-input-row {
    display: flex;
    gap: 0.5rem;
    align-items: stretch;
  }

  .kdbx-password-input-row input {
    flex: 1 1 auto;
    padding: 0.45rem 0.6rem;
    border: 1px solid #d0d0d0;
    border-radius: 6px;
    font: inherit;
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
