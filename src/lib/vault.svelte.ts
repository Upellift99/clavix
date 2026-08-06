import { api } from "./api";
import { applyVaultFilters } from "./filter";
import { formatError } from "./format";
import {
  buildCipherIndex,
  buildFolderTree,
  buildOrgTrees,
  collectAllKeys,
  folderPathFromKey,
} from "./tree";
import {
  EMPTY_EDITOR_INITIAL,
  type CipherDetail,
  type EditorField,
  type EditorInitial,
  type EditorPayload,
  type QuickFilter,
  type SortKey,
  type SyncSummary,
} from "./types";

const SEARCH_DEBOUNCE_MS = 150;
const SELECTED_KEY_STORAGE_KEY = "clavix.vault.selectedKey";
const QUICK_FILTER_STORAGE_KEY = "clavix.vault.quickFilter";

const QUICK_FILTER_FIXED: ReadonlySet<string> = new Set(["all", "favorites", "trash"]);
const QUICK_FILTER_TYPE_PATTERN = /^type:\d+$/;
function parseStoredQuickFilter(raw: string | null): QuickFilter | null {
  if (raw === null) return null;
  if (QUICK_FILTER_FIXED.has(raw)) return raw as QuickFilter;
  if (QUICK_FILTER_TYPE_PATTERN.test(raw)) return raw as QuickFilter;
  return null;
}

export class VaultController {
  summary = $state<SyncSummary | null>(null);
  syncing = $state(false);
  error = $state<string | null>(null);
  /** Epoch ms of the last successful sync. null when no sync has landed. */
  lastSyncAt = $state<number | null>(null);
  /**
   * Last sync failure message. Separate from `error` because `error` bleeds
   * from any failing command (openCipher, moveCipher, …), whereas the
   * session-bar indicator only wants "is the backend reachable?".
   */
  lastSyncError = $state<string | null>(null);

  search = $state("");
  searchDebounced = $state("");
  selectedKey = $state<string | null>(null);
  expanded = $state<Set<string>>(new Set());
  quickFilter = $state<QuickFilter>("all");
  sortKey = $state<SortKey>("name");
  sortAsc = $state(true);

  detail = $state<CipherDetail | null>(null);
  detailLoading = $state(false);

  editorOpen = $state(false);
  editorMode = $state<"create" | "edit">("create");
  editorInitial = $state<EditorInitial>(EMPTY_EDITOR_INITIAL);

  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private effectCleanup: (() => void) | null = null;

  cipherIndex = $derived.by(() => buildCipherIndex(this.summary?.ciphers));
  folderTree = $derived.by(() =>
    this.summary ? buildFolderTree(this.summary.folders, this.cipherIndex.byFolder) : null,
  );
  orgTrees = $derived.by(() =>
    this.summary
      ? buildOrgTrees(
          this.summary.organizations,
          this.summary.collections,
          this.cipherIndex.byOrg,
          this.cipherIndex.byCollection,
        )
      : [],
  );
  allTrees = $derived.by(() => {
    const list = [];
    if (this.folderTree) list.push(this.folderTree);
    list.push(...this.orgTrees);
    return list;
  });
  filteredCiphers = $derived.by(() =>
    this.summary
      ? applyVaultFilters(this.summary.ciphers, {
          quickFilter: this.quickFilter,
          selectedKey: this.selectedKey,
          trees: this.allTrees,
          search: this.searchDebounced,
          sortKey: this.sortKey,
          sortAsc: this.sortAsc,
        })
      : [],
  );
  hasNarrowing = $derived(this.searchDebounced.trim() !== "" || this.selectedKey !== null);
  detailSummaryEntry = $derived(
    this.detail ? (this.summary?.ciphers.find((c) => c.id === this.detail!.id) ?? null) : null,
  );

  constructor() {
    // Restore last vault selection from localStorage so the user lands
    // back on whatever folder / quick-filter they last opened, instead
    // of being dumped into "Tous les éléments" every launch.
    // selectedKey is opaque to us (folder UUID or org:cipher path) — we
    // don't validate it here; if the underlying entry no longer exists
    // after sync, the renderer's filter naturally falls back to empty.
    try {
      const savedFilter = parseStoredQuickFilter(localStorage.getItem(QUICK_FILTER_STORAGE_KEY));
      if (savedFilter) this.quickFilter = savedFilter;
      const savedKey = localStorage.getItem(SELECTED_KEY_STORAGE_KEY);
      if (savedKey) this.selectedKey = savedKey;
    } catch {
      // ignore: localStorage may be unavailable in tests
    }

    this.effectCleanup = $effect.root(() => {
      $effect(() => {
        const current = this.search;
        if (this.debounceTimer !== null) clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
          this.searchDebounced = current;
        }, SEARCH_DEBOUNCE_MS);
        return () => {
          if (this.debounceTimer !== null) clearTimeout(this.debounceTimer);
        };
      });

      // Persist selection on every change once a vault is loaded.
      // localStorage writes are cheap and the user toggles selection
      // at human speed, so no debounce needed. The `summary != null`
      // gate matters because `reset()` wipes both selection AND
      // summary on lock — without the gate, locking would erase the
      // stored selection and the next session would start blank.
      $effect(() => {
        const key = this.selectedKey;
        const filter = this.quickFilter;
        if (this.summary === null) return;
        try {
          if (key) {
            localStorage.setItem(SELECTED_KEY_STORAGE_KEY, key);
          } else {
            localStorage.removeItem(SELECTED_KEY_STORAGE_KEY);
          }
          if (filter !== "all") {
            localStorage.setItem(QUICK_FILTER_STORAGE_KEY, filter);
          } else {
            localStorage.removeItem(QUICK_FILTER_STORAGE_KEY);
          }
        } catch {
          // best-effort
        }
      });
    });
  }

  dispose() {
    if (this.effectCleanup) {
      this.effectCleanup();
      this.effectCleanup = null;
    }
    if (this.debounceTimer !== null) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }

  /** Resets state on lock/logout. */
  reset() {
    this.summary = null;
    this.detail = null;
    this.editorOpen = false;
    this.error = null;
    this.lastSyncAt = null;
    this.lastSyncError = null;
    this.search = "";
    this.searchDebounced = "";
    this.selectedKey = null;
    this.quickFilter = "all";
  }

  async loadCached() {
    try {
      const cached = await api.loadCachedVault();
      if (cached) this.summary = cached;
    } catch (e) {
      console.warn("[clavix] cached vault load failed:", e);
    }
  }

  /**
   * Build the item list for a vault opened from an export file.
   *
   * Unlike `loadCached`, a failure here is fatal to the screen rather
   * than a degraded start: there is no cache to fall back on and no
   * sync coming to fill the gap, so an empty list would be
   * indistinguishable from an empty backup.
   */
  async loadStandalone() {
    this.error = null;
    try {
      this.summary = await api.standaloneSummary();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  /**
   * `quiet` keeps a failure out of the big red error box and reports it
   * only through the status indicator. It is for syncs the user did not
   * ask for — the periodic one — where a dropped Wi-Fi connection should
   * dim the dot, not plaster an error across a vault the user is reading.
   */
  async sync(opts: { quiet?: boolean } = {}) {
    const quiet = opts.quiet === true;
    const priorSyncError = this.lastSyncError;
    this.syncing = true;
    if (!quiet) this.error = null;
    this.lastSyncError = null;
    try {
      this.summary = await api.sync();
      this.lastSyncAt = Date.now();
      // A silent sync that succeeds retires the box a *previous* sync
      // failure put on screen — but only that one. `error` is a shared
      // bucket (openCipher, moves, …), and a background refresh has no
      // business erasing a message the user hasn't read yet.
      if (quiet && this.error !== null && this.error === priorSyncError) {
        this.error = null;
      }
    } catch (e) {
      const msg = formatError(e);
      if (!quiet) this.error = msg;
      this.lastSyncError = msg;
    } finally {
      this.syncing = false;
    }
  }

  /**
   * Fire-and-forget sync. Meant for post-login auto-refresh: the UI has
   * already painted from `loadCached()`, and this call updates the state
   * in the background without blocking the event handler that triggered
   * it. Errors land in `lastSyncError` / `error` like a normal sync —
   * nothing is thrown.
   */
  syncInBackground(opts: { quiet?: boolean } = {}) {
    void this.sync(opts);
  }

  // Navigation keeps the search box intact: the query narrows *within*
  // whatever folder / quick filter is active, so browsing around while
  // hunting for an item no longer means retyping the query at every
  // click. When the combination matches nothing, the list's empty state
  // offers "Effacer la recherche" as the way out.
  selectQuickFilter(f: QuickFilter) {
    this.quickFilter = f;
    this.selectedKey = null;
  }

  selectNode(key: string) {
    this.selectedKey = this.selectedKey === key ? null : key;
  }

  toggleSort(key: SortKey) {
    if (this.sortKey === key) {
      this.sortAsc = !this.sortAsc;
    } else {
      this.sortKey = key;
      this.sortAsc = true;
    }
  }

  toggleExpanded(key: string) {
    const next = new Set(this.expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    this.expanded = next;
  }

  expandAllNodes() {
    const next = new Set<string>();
    if (this.folderTree) collectAllKeys(this.folderTree, next);
    for (const t of this.orgTrees) collectAllKeys(t, next);
    this.expanded = next;
  }

  collapseAllNodes() {
    this.expanded = new Set();
  }

  /**
   * Load `id` into the detail panel. Idempotent on purpose: it used to
   * toggle the panel shut when called with the item already open, which
   * made a double-click on a row read as open-then-close before the
   * dblclick handler ever ran (and quietly closed the panel after every
   * save, since `submitEditor` re-opens the item it just wrote). The
   * panel is closed from its own ✕ button.
   */
  async openCipher(id: string) {
    this.detailLoading = true;
    this.error = null;
    try {
      this.detail = await api.getCipher(id);
    } catch (e) {
      this.error = formatError(e);
      this.detail = null;
    } finally {
      this.detailLoading = false;
    }
  }

  closeDetail() {
    this.detail = null;
  }

  async restoreCipher(id: string) {
    try {
      await api.restoreCipher(id);
      if (this.summary) {
        const c = this.summary.ciphers.find((c) => c.id === id);
        if (c) c.deletedDate = null;
      }
    } catch (e) {
      this.error = formatError(e);
    }
  }

  // Both delete paths assume the caller already got a yes: confirmation
  // is a UI concern and lives in `ConfirmDialog` (see routes/+page.svelte),
  // which the store cannot reach and unit tests should not have to stub.
  async softDeleteCipher(id: string) {
    try {
      await api.softDeleteCipher(id);
      if (this.summary) {
        const c = this.summary.ciphers.find((c) => c.id === id);
        // Optimistic: any non-null deletedDate moves the row into the
        // trash bucket of every filter helper. The next sync rewrites
        // it with the server's authoritative ISO 8601 timestamp.
        if (c) c.deletedDate = "pending-sync";
      }
      if (this.detail?.id === id) this.closeDetail();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  async deleteCipherForever(id: string) {
    try {
      await api.deleteCipher(id);
      if (this.summary) {
        this.summary.ciphers = this.summary.ciphers.filter((c) => c.id !== id);
      }
      if (this.detail?.id === id) this.closeDetail();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  /**
   * Copy an item. The whole operation runs in Rust — decrypt, rename,
   * re-encrypt, create — so no secret passes through here. A sync
   * follows because the new cipher only exists server-side and in the
   * Rust vault; the summary this store paints from is rebuilt from it.
   */
  async duplicateCipher(id: string, nameSuffix: string) {
    try {
      await api.duplicateCipher(id, nameSuffix);
      await this.sync();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  /**
   * Bulk operations, run one item at a time.
   *
   * Sequential rather than `Promise.all`: each call is a write against
   * the same vault, and Vaultwarden is a single server that a hundred
   * parallel PUTs would simply queue anyway — worse, a partial failure
   * mid-flight would leave the local optimistic state unrecoverable.
   * The count of failures is returned so the caller can say so instead
   * of showing one error per item.
   */
  async bulkSoftDelete(ids: string[]): Promise<number> {
    let failed = 0;
    for (const id of ids) {
      try {
        await api.softDeleteCipher(id);
        const c = this.summary?.ciphers.find((c) => c.id === id);
        if (c) c.deletedDate = "pending-sync";
        if (this.detail?.id === id) this.closeDetail();
      } catch {
        failed += 1;
      }
    }
    return failed;
  }

  async bulkDeleteForever(ids: string[]): Promise<number> {
    let failed = 0;
    const removed = new Set<string>();
    for (const id of ids) {
      try {
        await api.deleteCipher(id);
        removed.add(id);
        if (this.detail?.id === id) this.closeDetail();
      } catch {
        failed += 1;
      }
    }
    if (this.summary && removed.size > 0) {
      this.summary.ciphers = this.summary.ciphers.filter((c) => !removed.has(c.id));
    }
    return failed;
  }

  async bulkRestore(ids: string[]): Promise<number> {
    let failed = 0;
    for (const id of ids) {
      try {
        await api.restoreCipher(id);
        const c = this.summary?.ciphers.find((c) => c.id === id);
        if (c) c.deletedDate = null;
      } catch {
        failed += 1;
      }
    }
    return failed;
  }

  async bulkMoveToFolder(ids: string[], folderId: string | null): Promise<number> {
    let failed = 0;
    for (const id of ids) {
      const cipher = this.summary?.ciphers.find((c) => c.id === id);
      // Org items live in collections, not folders; skip them silently
      // rather than counting a failure the server never saw.
      if (!cipher || cipher.organizationId) continue;
      if (cipher.folderId === folderId) continue;
      const previous = cipher.folderId;
      cipher.folderId = folderId;
      try {
        await api.moveCipherToFolder(id, folderId);
      } catch {
        cipher.folderId = previous;
        failed += 1;
      }
    }
    return failed;
  }

  openCreateEditor() {
    const presetFolder = this.selectedKey ? folderPathFromKey(this.selectedKey) : null;
    const folderMatch = presetFolder
      ? this.summary?.folders.find((f) => f.name === presetFolder)
      : null;
    // If the user picked an org/collection node in the tree, preselect that
    // destination so creation lands in the right place.
    let presetOrg: string | null = null;
    let presetCollection: string[] = [];
    if (this.selectedKey) {
      const stack = [...(this.orgTrees ?? [])];
      while (stack.length > 0) {
        const node = stack.pop()!;
        if (node.key === this.selectedKey) {
          presetOrg = node.organizationId;
          if (node.collectionId) presetCollection = [node.collectionId];
          break;
        }
        for (const c of node.children) stack.push(c);
      }
    }
    this.editorInitial = {
      ...EMPTY_EDITOR_INITIAL,
      folderId: presetOrg ? null : (folderMatch?.id ?? null),
      organizationId: presetOrg,
      collectionIds: presetCollection,
    };
    this.editorMode = "create";
    this.editorOpen = true;
  }

  async openEditEditor() {
    if (!this.detail) return;
    // Secrets are no longer in `detail`; fetch the ones the editor edits so
    // saving them back doesn't wipe them.
    let sshPrivateKey = "";
    let totpSecret = "";
    let password = "";
    let cardNumber = "";
    let cardCode = "";
    let ssn = "";
    // Hidden custom fields follow the same rule as every other secret:
    // `get_cipher` withholds the value, so the editor has to ask for it
    // or saving would write the field back empty.
    const fields: EditorField[] = [];
    try {
      const id = this.detail.id;
      for (const [index, field] of this.detail.fields.entries()) {
        fields.push({
          kind: field.kind,
          name: field.name ?? "",
          value: field.hidden
            ? ((await api.revealField(id, `custom:${index}`)) ?? "")
            : (field.value ?? ""),
          linkedId: null,
        });
      }
      if (this.detail.login?.hasPassword) {
        password = (await api.revealField(id, "password")) ?? "";
      }
      if (this.detail.card?.hasNumber) {
        cardNumber = (await api.revealField(id, "cardNumber")) ?? "";
      }
      if (this.detail.card?.hasCode) {
        cardCode = (await api.revealField(id, "cardCode")) ?? "";
      }
      if (this.detail.identity?.hasSsn) {
        ssn = (await api.revealField(id, "ssn")) ?? "";
      }
      if (this.detail.sshKey?.hasPrivateKey) {
        sshPrivateKey = (await api.revealField(id, "sshPrivateKey")) ?? "";
      }
      if (this.detail.login?.hasTotp) {
        totpSecret = (await api.revealLoginTotp(id)) ?? "";
      }
    } catch (e) {
      this.error = formatError(e);
    }
    if (!this.detail) return;
    const currentCipher = this.summary?.ciphers.find((c) => c.id === this.detail!.id);
    const kind = (this.detail.kind as 1 | 2 | 3 | 4 | 5) ?? 1;
    this.editorInitial = {
      ...EMPTY_EDITOR_INITIAL,
      id: this.detail.id,
      cipherType: kind,
      name: currentCipher?.name ?? "",
      folderId: currentCipher?.folderId ?? null,
      favorite: currentCipher?.favorite ?? false,
      notes: this.detail.notes ?? "",
      username: this.detail.login?.username ?? "",
      password,
      uris: this.detail.login?.uris ?? [],
      totp: totpSecret,
      card: {
        cardholderName: this.detail.card?.cardholderName ?? "",
        brand: this.detail.card?.brand ?? "",
        number: cardNumber,
        expMonth: this.detail.card?.expMonth ?? "",
        expYear: this.detail.card?.expYear ?? "",
        code: cardCode,
      },
      identity: {
        title: this.detail.identity?.title ?? "",
        firstName: this.detail.identity?.firstName ?? "",
        middleName: this.detail.identity?.middleName ?? "",
        lastName: this.detail.identity?.lastName ?? "",
        address1: this.detail.identity?.address1 ?? "",
        address2: this.detail.identity?.address2 ?? "",
        address3: this.detail.identity?.address3 ?? "",
        city: this.detail.identity?.city ?? "",
        state: this.detail.identity?.state ?? "",
        postalCode: this.detail.identity?.postalCode ?? "",
        country: this.detail.identity?.country ?? "",
        company: this.detail.identity?.company ?? "",
        email: this.detail.identity?.email ?? "",
        phone: this.detail.identity?.phone ?? "",
        ssn,
        username: this.detail.identity?.username ?? "",
        passportNumber: this.detail.identity?.passportNumber ?? "",
        licenseNumber: this.detail.identity?.licenseNumber ?? "",
      },
      sshKey: {
        privateKey: sshPrivateKey,
        publicKey: this.detail.sshKey?.publicKey ?? "",
        keyFingerprint: this.detail.sshKey?.keyFingerprint ?? "",
      },
      organizationId: currentCipher?.organizationId ?? null,
      collectionIds: currentCipher?.collectionIds ?? [],
      fields,
      reprompt: this.detail.reprompt,
    };
    this.editorMode = "edit";
    this.editorOpen = true;
  }

  /**
   * Open the editor straight on `id` — the double-click path from the
   * list, which doesn't go through the detail panel's "Modifier" button.
   * `openEditEditor` reads `this.detail`, so the item has to be loaded
   * first. Items in the trash aren't editable (the detail panel offers
   * restore/delete instead), so they only get shown.
   */
  async openEditorFor(id: string, gate?: (detail: CipherDetail) => Promise<boolean>) {
    await this.openCipher(id);
    if (this.detail?.id !== id) return;
    const entry = this.summary?.ciphers.find((c) => c.id === id);
    if (entry?.deletedDate) return;
    // The editor reveals every secret the item holds, so an item asking
    // for the master password has to ask here too. The check runs after
    // the load because only the detail knows about the flag.
    if (gate && !(await gate(this.detail))) return;
    await this.openEditEditor();
  }

  closeEditor() {
    this.editorOpen = false;
  }

  async submitEditor(input: EditorPayload) {
    try {
      if (this.editorMode === "create") {
        const newId = await api.createCipher(input);
        await this.sync();
        await this.openCipher(newId);
      } else if (this.editorInitial.id) {
        await api.updateCipher(this.editorInitial.id, input);
        await this.sync();
        await this.openCipher(this.editorInitial.id);
      }
      this.editorOpen = false;
    } catch (e) {
      throw new Error(formatError(e));
    }
  }

  async moveCipherToFolder(cipherId: string, targetFolderId: string | null) {
    if (!this.summary) return;
    const cipher = this.summary.ciphers.find((c) => c.id === cipherId);
    if (!cipher) return;
    const previousFolderId = cipher.folderId;
    if (previousFolderId === targetFolderId) return;
    cipher.folderId = targetFolderId;
    try {
      await api.moveCipherToFolder(cipherId, targetFolderId);
    } catch (e) {
      cipher.folderId = previousFolderId;
      this.error = formatError(e);
    }
  }

  async moveCipherToCollection(cipherId: string, targetCollectionId: string) {
    if (!this.summary) return;
    const cipher = this.summary.ciphers.find((c) => c.id === cipherId);
    if (!cipher) return;
    const targetCollection = this.summary.collections.find((c) => c.id === targetCollectionId);
    if (!targetCollection) return;

    if (cipher.organizationId === targetCollection.organizationId) {
      const previousCollectionIds = [...cipher.collectionIds];
      if (previousCollectionIds.length === 1 && previousCollectionIds[0] === targetCollectionId) {
        return;
      }
      cipher.collectionIds = [targetCollectionId];
      try {
        await api.moveCipherToCollection(cipherId, targetCollectionId);
      } catch (e) {
        cipher.collectionIds = previousCollectionIds;
        this.error = formatError(e);
      }
      return;
    }

    try {
      await api.shareCipherToCollection(cipherId, targetCollectionId);
      this.summary = await api.sync();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  async performFolderMove(sourcePath: string, targetParentPath: string | null) {
    try {
      await api.moveFolderPath(sourcePath, targetParentPath);
      this.summary = await api.sync();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  async deleteFolder(folderIds: string[]) {
    // Vaultwarden's web UI doesn't let users delete folders at all;
    // this command is the only path. Sync after the call so detached
    // ciphers (Bitwarden semantics: items move to "no folder" rather
    // than being deleted) and the dropped folder both surface.
    //
    // Multiple ids cover the cascade case: Bitwarden folders are flat
    // with `/` in the name, so the sidebar synthesises parents like
    // `work` from a real `work/projects`. Deleting the visual `work`
    // group means deleting every real folder whose path falls under
    // it; the caller collects the ids and we delete them serially so
    // partial failures still surface a sensible vault state on the
    // next sync.
    try {
      for (const id of folderIds) {
        await api.deleteFolder(id);
      }
      this.summary = await api.sync();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  async renameFolder(folderId: string, name: string) {
    const trimmed = name.trim();
    if (trimmed.length === 0) return;
    try {
      await api.renameFolder(folderId, trimmed);
      this.summary = await api.sync();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  async renameFolderPath(sourcePath: string, newPath: string) {
    // Path-based rename so the sidebar can rename a synthetic parent
    // (`work` showing only because `work/projects` exists) the same
    // way it renames a real folder. The Rust side reuses
    // `plan_folder_renames`, so descendants get re-prefixed in the
    // same batch.
    const source = sourcePath.trim();
    const next = newPath.trim();
    if (source.length === 0 || next.length === 0 || source === next) return;
    try {
      await api.renameFolderPath(source, next);
      this.summary = await api.sync();
    } catch (e) {
      this.error = formatError(e);
    }
  }

  async jumpToCipher(id: string) {
    if (this.detail?.id !== id) {
      await this.openCipher(id);
    }
  }
}
