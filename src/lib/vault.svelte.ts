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
    try {
      this.summary = await api.sync();
    } catch (e) {
      this.error = formatError(e);
    } finally {
      this.syncing = false;
    }
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
    this.editorInitial = {
      ...EMPTY_EDITOR_INITIAL,
      folderId: folderMatch?.id ?? null,
    };
    this.editorMode = "create";
    this.editorOpen = true;
  }

  openEditEditor() {
    if (!this.detail || !this.detail.login) return;
    const currentCipher = this.summary?.ciphers.find((c) => c.id === this.detail!.id);
    this.editorInitial = {
      id: this.detail.id,
      name: currentCipher?.name ?? "",
      folderId: currentCipher?.folderId ?? null,
      favorite: currentCipher?.favorite ?? false,
      notes: "",
      username: this.detail.login.username ?? "",
      password: this.detail.login.password ?? "",
      uris: this.detail.login.uris ?? [],
      totp: this.detail.login.totp ?? "",
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
        const newId = await api.createLoginCipher(input);
        await this.sync();
        await this.openCipher(newId);
      } else if (this.editorInitial.id) {
        await api.updateLoginCipher(this.editorInitial.id, input);
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

  async jumpToCipher(id: string) {
    if (this.detail?.id !== id) {
      await this.openCipher(id);
    }
  }
}
