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
  type EditorInitial,
  type EditorPayload,
  type QuickFilter,
  type SortKey,
  type SyncSummary,
} from "./types";

const SEARCH_DEBOUNCE_MS = 150;

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

  async sync() {
    this.syncing = true;
    this.error = null;
    this.lastSyncError = null;
    try {
      this.summary = await api.sync();
      this.lastSyncAt = Date.now();
    } catch (e) {
      const msg = formatError(e);
      this.error = msg;
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
  syncInBackground() {
    void this.sync();
  }

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

  async openCipher(id: string) {
    if (this.detail?.id === id) {
      this.detail = null;
      return;
    }
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

  async deleteCipherForever(id: string, confirm: string) {
    if (!window.confirm(confirm)) return;
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

  openEditEditor() {
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
      password: this.detail.login?.password ?? "",
      uris: this.detail.login?.uris ?? [],
      totp: this.detail.login?.totp ?? "",
      card: {
        cardholderName: this.detail.card?.cardholderName ?? "",
        brand: this.detail.card?.brand ?? "",
        number: this.detail.card?.number ?? "",
        expMonth: this.detail.card?.expMonth ?? "",
        expYear: this.detail.card?.expYear ?? "",
        code: this.detail.card?.code ?? "",
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
        ssn: this.detail.identity?.ssn ?? "",
        username: this.detail.identity?.username ?? "",
        passportNumber: this.detail.identity?.passportNumber ?? "",
        licenseNumber: this.detail.identity?.licenseNumber ?? "",
      },
      sshKey: {
        privateKey: this.detail.sshKey?.privateKey ?? "",
        publicKey: this.detail.sshKey?.publicKey ?? "",
        keyFingerprint: this.detail.sshKey?.keyFingerprint ?? "",
      },
      organizationId: currentCipher?.organizationId ?? null,
      collectionIds: currentCipher?.collectionIds ?? [],
    };
    this.editorMode = "edit";
    this.editorOpen = true;
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
