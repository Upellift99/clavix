<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { clear as clearClipboard, writeText } from "@tauri-apps/plugin-clipboard-manager";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { onDestroy, onMount } from "svelte";

  type TokenSet = {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    token_type: string;
    key: string | null;
    privateKey: string | null;
    kdf: 0 | 1 | null;
    kdfIterations: number | null;
  };

  type LoginResult =
    | { type: "success"; data: TokenSet }
    | { type: "twoFactorRequired"; data: { providers: number[] } };

  type TypeCounts = {
    login: number;
    secureNote: number;
    card: number;
    identity: number;
    sshKey: number;
  };

  type FolderSummary = { id: string; name: string };
  type OrganizationSummary = { id: string; name: string };
  type CollectionSummary = { id: string; organizationId: string; name: string };

  type CipherSummary = {
    id: string;
    kind: number;
    name: string;
    folderId: string | null;
    organizationId: string | null;
    collectionIds: string[];
    favorite: boolean;
    primaryUri: string | null;
  };

  type SyncSummary = {
    email: string;
    name: string | null;
    itemCount: number;
    folderCount: number;
    collectionCount: number;
    organizationCount: number;
    typeCounts: TypeCounts;
    folders: FolderSummary[];
    organizations: OrganizationSummary[];
    collections: CollectionSummary[];
    ciphers: CipherSummary[];
  };

  type LoginDetail = {
    username: string | null;
    password: string | null;
    uris: string[];
    totp: string | null;
  };

  type CardDetail = {
    cardholderName: string | null;
    brand: string | null;
    number: string | null;
    expMonth: string | null;
    expYear: string | null;
    code: string | null;
  };

  type IdentityDetail = {
    title: string | null;
    firstName: string | null;
    middleName: string | null;
    lastName: string | null;
    address1: string | null;
    address2: string | null;
    address3: string | null;
    city: string | null;
    state: string | null;
    postalCode: string | null;
    country: string | null;
    company: string | null;
    email: string | null;
    phone: string | null;
    ssn: string | null;
    username: string | null;
    passportNumber: string | null;
    licenseNumber: string | null;
  };

  type SshKeyDetail = {
    privateKey: string | null;
    publicKey: string | null;
    keyFingerprint: string | null;
  };

  type CipherDetail = {
    id: string;
    kind: number;
    name: string;
    notes: string | null;
    organizationId: string | null;
    folderId: string | null;
    collectionIds: string[];
    revisionDate: string | null;
    favorite: boolean;
    login: LoginDetail | null;
    card: CardDetail | null;
    identity: IdentityDetail | null;
    sshKey: SshKeyDetail | null;
  };

  type Phase =
    | "init"
    | "idle"
    | "authenticating"
    | "twoFactor"
    | "unlock"
    | "loggedIn"
    | "error";

  type StoredAccount = { serverUrl: string; email: string };

  type TauriError = { code: string; message: string; data?: Record<string, unknown> };

  function formatError(e: unknown): string {
    if (e && typeof e === "object" && "message" in e) {
      const m = (e as { message?: unknown }).message;
      if (typeof m === "string") return m;
    }
    return String(e);
  }

  const TOTP_PATTERN = "[0-9]{6}";

  let serverUrl = $state("https://vault.example.com");
  let email = $state("");
  let password = $state("");
  let totpCode = $state("");
  let phase = $state<Phase>("init");
  let errorMsg = $state<string | null>(null);
  let tokens = $state<TokenSet | null>(null);
  let pendingProviders = $state<number[]>([]);
  let syncSummary = $state<SyncSummary | null>(null);
  let syncing = $state(false);
  let storedAccount = $state<StoredAccount | null>(null);
  let search = $state("");
  let searchDebounced = $state("");
  let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  $effect(() => {
    const current = search;
    if (searchDebounceTimer !== null) clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      searchDebounced = current;
    }, 150);
    return () => {
      if (searchDebounceTimer !== null) clearTimeout(searchDebounceTimer);
    };
  });
  let selectedKey = $state<string | null>(null);
  let expanded = $state<Set<string>>(new Set());
  let detail = $state<CipherDetail | null>(null);
  let detailLoading = $state(false);
  let showPassword = $state(false);
  let showCardNumber = $state(false);
  let showCardCode = $state(false);
  let showSsn = $state(false);
  let showSshPrivate = $state(false);
  let draggingCipherId = $state<string | null>(null);
  let draggingFolderPath = $state<string | null>(null);
  let dragOverKey = $state<string | null>(null);
  let statsDialog = $state<HTMLDialogElement | null>(null);
  let searchInput = $state<HTMLInputElement | null>(null);

  const TREE_WIDTH_MIN = 180;
  const TREE_WIDTH_MAX = 560;
  const TREE_WIDTH_STORAGE_KEY = "clavix.treeWidth";
  let treeWidth = $state(260);

  const AUTO_LOCK_STORAGE_KEY = "clavix.autoLockMinutes";
  const AUTO_LOCK_DEFAULT_MINUTES = 10;
  let autoLockMinutes = $state<number>(AUTO_LOCK_DEFAULT_MINUTES);
  let lastActivityAt = $state<number>(Date.now());

  function onUserActivity() {
    lastActivityAt = Date.now();
  }

  function onSplitterMouseDown(event: MouseEvent) {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = treeWidth;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    let pendingX: number | null = null;
    let rafId: number | null = null;

    const applyPending = () => {
      rafId = null;
      if (pendingX === null) return;
      const delta = pendingX - startX;
      pendingX = null;
      treeWidth = Math.max(TREE_WIDTH_MIN, Math.min(TREE_WIDTH_MAX, startWidth + delta));
    };

    const onMove = (e: MouseEvent) => {
      pendingX = e.clientX;
      if (rafId === null) {
        rafId = requestAnimationFrame(applyPending);
      }
    };

    const onUp = () => {
      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }
      applyPending();
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      try {
        localStorage.setItem(TREE_WIDTH_STORAGE_KEY, String(treeWidth));
      } catch {
        // ignore quota / storage disabled
      }
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }

  function openStats() {
    statsDialog?.showModal();
  }

  function closeStats() {
    statsDialog?.close();
  }

  const FOLDERS_ROOT_PREFIX = "folders/";

  function folderPathFromKey(key: string): string | null {
    if (!key.startsWith(FOLDERS_ROOT_PREFIX)) return null;
    return key.slice(FOLDERS_ROOT_PREFIX.length);
  }
  let clipboardSecondsLeft = $state<number | null>(null);
  let clipboardLabel = $state<string | null>(null);
  let clipboardTimeout: ReturnType<typeof setTimeout> | null = null;
  let clipboardInterval: ReturnType<typeof setInterval> | null = null;

  const CLIPBOARD_CLEAR_SECONDS = 30;

  type TreeNode = {
    key: string;
    label: string;
    kind: "folder" | "organization" | "collection";
    folderId: string | null;
    organizationId: string | null;
    collectionId: string | null;
    children: TreeNode[];
    itemCount: number;
  };

  // Pré-calcule : folderId -> count, collectionId -> count, orgId -> count.
  // Évite de retraverser les 1688 ciphers à chaque calcul de compteur de nœud.
  const cipherIndex = $derived.by(() => {
    const byFolder = new Map<string, number>();
    const byCollection = new Map<string, number>();
    const byOrg = new Map<string, number>();
    if (!syncSummary) return { byFolder, byCollection, byOrg };
    for (const c of syncSummary.ciphers) {
      if (c.folderId) byFolder.set(c.folderId, (byFolder.get(c.folderId) ?? 0) + 1);
      if (c.organizationId) byOrg.set(c.organizationId, (byOrg.get(c.organizationId) ?? 0) + 1);
      for (const cid of c.collectionIds) {
        byCollection.set(cid, (byCollection.get(cid) ?? 0) + 1);
      }
    }
    return { byFolder, byCollection, byOrg };
  });

  const folderTree = $derived.by<TreeNode | null>(() => {
    if (!syncSummary) return null;
    const root: TreeNode = {
      key: "folders",
      label: "Folders",
      kind: "folder",
      folderId: null,
      organizationId: null,
      collectionId: null,
      children: [],
      itemCount: 0,
    };
    for (const f of syncSummary.folders) {
      const segments = splitPath(f.name);
      if (segments.length === 0) continue;
      insertIntoTree(root, segments, { folderId: f.id, kind: "folder" });
    }
    computeFolderCounts(root, cipherIndex.byFolder);
    sortTree(root);
    return root;
  });

  const orgTrees = $derived.by<TreeNode[]>(() => {
    if (!syncSummary) return [];
    return syncSummary.organizations.map((org) => {
      const root: TreeNode = {
        key: `org/${org.id}`,
        label: org.name,
        kind: "organization",
        folderId: null,
        organizationId: org.id,
        collectionId: null,
        children: [],
        itemCount: cipherIndex.byOrg.get(org.id) ?? 0,
      };
      for (const c of syncSummary!.collections) {
        if (c.organizationId !== org.id) continue;
        const segments = splitPath(c.name);
        if (segments.length === 0) continue;
        insertIntoTree(root, segments, {
          collectionId: c.id,
          organizationId: org.id,
          kind: "collection",
        });
      }
      computeCollectionCounts(root, cipherIndex.byCollection);
      sortTree(root);
      return root;
    });
  });

  function splitPath(name: string): string[] {
    return name.split("/").map((s) => s.trim()).filter((s) => s.length > 0);
  }

  function insertIntoTree(
    root: TreeNode,
    segments: string[],
    leaf: { folderId?: string; collectionId?: string; organizationId?: string; kind: "folder" | "collection" },
  ) {
    let current = root;
    let acc = root.key;
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      acc = `${acc}/${seg}`;
      let child = current.children.find((c) => c.label === seg);
      if (!child) {
        child = {
          key: acc,
          label: seg,
          kind: leaf.kind,
          folderId: null,
          organizationId: leaf.organizationId ?? null,
          collectionId: null,
          children: [],
          itemCount: 0,
        };
        current.children.push(child);
      }
      if (i === segments.length - 1) {
        if (leaf.folderId) child.folderId = leaf.folderId;
        if (leaf.collectionId) child.collectionId = leaf.collectionId;
      }
      current = child;
    }
  }

  function computeFolderCounts(node: TreeNode, byFolder: Map<string, number>): number {
    const direct = node.folderId ? (byFolder.get(node.folderId) ?? 0) : 0;
    let total = direct;
    for (const child of node.children) {
      total += computeFolderCounts(child, byFolder);
    }
    node.itemCount = total;
    return total;
  }

  function computeCollectionCounts(node: TreeNode, byCollection: Map<string, number>): number {
    const direct = node.collectionId ? (byCollection.get(node.collectionId) ?? 0) : 0;
    let total = direct;
    for (const child of node.children) {
      total += computeCollectionCounts(child, byCollection);
    }
    // For organization root, keep the pre-computed total (all items of the org)
    if (node.kind !== "organization") {
      node.itemCount = total;
    }
    return total;
  }

  function sortTree(node: TreeNode) {
    node.children.sort((a, b) => a.label.localeCompare(b.label, "fr"));
    for (const child of node.children) sortTree(child);
  }

  function findNodeInTrees(key: string): TreeNode | null {
    const search = (node: TreeNode): TreeNode | null => {
      if (node.key === key) return node;
      for (const c of node.children) {
        const found = search(c);
        if (found) return found;
      }
      return null;
    };
    if (folderTree) {
      const hit = search(folderTree);
      if (hit) return hit;
    }
    for (const t of orgTrees) {
      const hit = search(t);
      if (hit) return hit;
    }
    return null;
  }

  function collectFolderIds(node: TreeNode, ids: Set<string>) {
    if (node.folderId) ids.add(node.folderId);
    for (const c of node.children) collectFolderIds(c, ids);
  }

  function collectCollectionIds(node: TreeNode, ids: Set<string>) {
    if (node.collectionId) ids.add(node.collectionId);
    for (const c of node.children) collectCollectionIds(c, ids);
  }

  const filteredCiphers = $derived.by(() => {
    if (!syncSummary) return [];
    const q = searchDebounced.trim().toLowerCase();
    let items = syncSummary.ciphers;

    if (selectedKey) {
      const node = findNodeInTrees(selectedKey);
      if (node) {
        if (node.kind === "folder") {
          const ids = new Set<string>();
          collectFolderIds(node, ids);
          items = items.filter((c) => c.folderId !== null && ids.has(c.folderId));
        } else if (node.kind === "organization") {
          items = items.filter((c) => c.organizationId === node.organizationId);
        } else {
          const ids = new Set<string>();
          collectCollectionIds(node, ids);
          items = items.filter((c) => c.collectionIds.some((cid) => ids.has(cid)));
        }
      }
    }

    if (q) {
      items = items.filter((c) => c.name.toLowerCase().includes(q));
    }
    return items;
  });

  const ROW_HEIGHT = 36;
  const OVERSCAN = 6;
  let listScrollEl = $state<HTMLElement | null>(null);
  let listScrollTop = $state(0);
  let listViewportHeight = $state(600);

  function onListScroll(event: Event) {
    listScrollTop = (event.currentTarget as HTMLElement).scrollTop;
  }

  $effect(() => {
    if (!listScrollEl) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        listViewportHeight = entry.contentRect.height;
      }
    });
    observer.observe(listScrollEl);
    listViewportHeight = listScrollEl.clientHeight;
    return () => observer.disconnect();
  });

  const virtualWindow = $derived.by(() => {
    const total = filteredCiphers.length;
    const start = Math.max(0, Math.floor(listScrollTop / ROW_HEIGHT) - OVERSCAN);
    const end = Math.min(
      total,
      Math.ceil((listScrollTop + listViewportHeight) / ROW_HEIGHT) + OVERSCAN,
    );
    return {
      total,
      start,
      end,
      items: filteredCiphers.slice(start, end),
      offsetY: start * ROW_HEIGHT,
      totalHeight: total * ROW_HEIGHT,
    };
  });

  function toggleExpanded(key: string) {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    expanded = next;
  }

  function collectAllKeys(node: TreeNode, into: Set<string>) {
    if (node.children.length === 0) return;
    into.add(node.key);
    for (const child of node.children) collectAllKeys(child, into);
  }

  function expandAllNodes() {
    const next = new Set<string>();
    if (folderTree) collectAllKeys(folderTree, next);
    for (const t of orgTrees) collectAllKeys(t, next);
    expanded = next;
  }

  function collapseAllNodes() {
    expanded = new Set();
  }

  function selectNode(key: string) {
    selectedKey = selectedKey === key ? null : key;
  }

  function resetDetailReveals() {
    showPassword = false;
    showCardNumber = false;
    showCardCode = false;
    showSsn = false;
    showSshPrivate = false;
  }

  async function openCipher(id: string) {
    if (detail?.id === id) {
      detail = null;
      resetDetailReveals();
      return;
    }
    detailLoading = true;
    errorMsg = null;
    resetDetailReveals();
    try {
      detail = await invoke<CipherDetail>("get_cipher", { id });
    } catch (e) {
      errorMsg = formatError(e);
      detail = null;
    } finally {
      detailLoading = false;
    }
  }

  function closeDetail() {
    detail = null;
    resetDetailReveals();
  }

  function mask(value: string, length: number = 12): string {
    return "•".repeat(Math.min(value.length, length));
  }

  async function copyToClipboard(value: string, label: string) {
    try {
      await writeText(value);
      scheduleClipboardClear(label);
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  function scheduleClipboardClear(label: string) {
    clearClipboardTimers();
    clipboardLabel = label;
    clipboardSecondsLeft = CLIPBOARD_CLEAR_SECONDS;
    clipboardInterval = setInterval(() => {
      if (clipboardSecondsLeft !== null && clipboardSecondsLeft > 0) {
        clipboardSecondsLeft -= 1;
      }
    }, 1000);
    clipboardTimeout = setTimeout(async () => {
      try {
        await clearClipboard();
      } catch {
        // ignore
      }
      clipboardSecondsLeft = null;
      clipboardLabel = null;
      clearClipboardTimers();
    }, CLIPBOARD_CLEAR_SECONDS * 1000);
  }

  function clearClipboardTimers() {
    if (clipboardTimeout !== null) {
      clearTimeout(clipboardTimeout);
      clipboardTimeout = null;
    }
    if (clipboardInterval !== null) {
      clearInterval(clipboardInterval);
      clipboardInterval = null;
    }
  }

  async function clearClipboardNow() {
    clearClipboardTimers();
    try {
      await clearClipboard();
    } catch {
      // ignore
    }
    clipboardSecondsLeft = null;
    clipboardLabel = null;
  }

  onDestroy(() => {
    clearClipboardTimers();
  });

  $effect(() => {
    if (phase !== "loggedIn") return;
    if (autoLockMinutes <= 0) return;

    lastActivityAt = Date.now();
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "click"];
    for (const evt of events) {
      window.addEventListener(evt, onUserActivity, { passive: true });
    }

    const lockMs = autoLockMinutes * 60 * 1000;
    const check = async () => {
      if (Date.now() - lastActivityAt >= lockMs) {
        await onLock();
      }
    };
    const interval = setInterval(check, 15000);

    return () => {
      clearInterval(interval);
      for (const evt of events) {
        window.removeEventListener(evt, onUserActivity);
      }
    };
  });

  function persistAutoLockSetting(minutes: number) {
    autoLockMinutes = minutes;
    try {
      localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(minutes));
    } catch {
      // ignore
    }
  }

  function isTypingContext(): boolean {
    const a = document.activeElement as HTMLElement | null;
    if (!a) return false;
    const tag = a.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || a.isContentEditable;
  }

  async function handleGlobalKeydown(event: KeyboardEvent) {
    if (phase === "loggedIn") {
      if (event.key === "Escape" && detail) {
        event.preventDefault();
        closeDetail();
        return;
      }

      if (event.key === "/" && !isTypingContext()) {
        event.preventDefault();
        searchInput?.focus();
        searchInput?.select();
        return;
      }

      if (event.ctrlKey || event.metaKey) {
        const key = event.key.toLowerCase();

        if (key === "f") {
          event.preventDefault();
          searchInput?.focus();
          searchInput?.select();
          return;
        }

        if (key === "l") {
          event.preventDefault();
          await onLock();
          return;
        }

        if (isTypingContext()) return;

        const selectionLength = window.getSelection()?.toString().length ?? 0;
        if (!detail || selectionLength > 0) return;

        if (key === "c" && detail.login?.password) {
          event.preventDefault();
          await copyToClipboard(detail.login.password, "mot de passe");
          return;
        }

        if (key === "b" && detail.login?.username) {
          event.preventDefault();
          await copyToClipboard(detail.login.username, "identifiant");
          return;
        }

        if (key === "u" && detail.login?.uris?.[0]) {
          event.preventDefault();
          try {
            await openUrl(detail.login.uris[0]);
          } catch (e) {
            errorMsg = formatError(e);
          }
          return;
        }
      }
    }
  }

  function onCipherDragStart(event: DragEvent, cipherId: string) {
    draggingCipherId = cipherId;
    draggingFolderPath = null;
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", cipherId);
    }
  }

  function onCipherDragEnd() {
    draggingCipherId = null;
    dragOverKey = null;
  }

  function onFolderDragStart(event: DragEvent, node: TreeNode) {
    const path = folderPathFromKey(node.key);
    if (!path) {
      event.preventDefault();
      return;
    }
    draggingFolderPath = path;
    draggingCipherId = null;
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", `folder:${path}`);
    }
    event.stopPropagation();
  }

  function onFolderDragEnd() {
    draggingFolderPath = null;
    dragOverKey = null;
  }

  function canDropFolderOn(targetPath: string | null): boolean {
    if (!draggingFolderPath) return false;
    if (targetPath === null) return true;
    if (targetPath === draggingFolderPath) return false;
    if (targetPath.startsWith(`${draggingFolderPath}/`)) return false;
    return true;
  }

  function isCipherDroppable(node: TreeNode): boolean {
    return (
      (node.kind === "folder" && node.folderId !== null) ||
      (node.kind === "collection" && node.collectionId !== null)
    );
  }

  function isFolderDropTarget(node: TreeNode): boolean {
    if (draggingFolderPath === null) return false;
    if (node.kind !== "folder") return false;
    const path = folderPathFromKey(node.key);
    return canDropFolderOn(path);
  }

  function onNodeDragOver(event: DragEvent, key: string) {
    if (!draggingCipherId && !draggingFolderPath) return;
    if (draggingFolderPath) {
      const path = key === "__all__" ? null : folderPathFromKey(key);
      if (!canDropFolderOn(path)) return;
    }
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
    dragOverKey = key;
  }

  function onNodeDragLeave(key: string) {
    if (dragOverKey === key) dragOverKey = null;
  }

  async function onDropOnFolderRoot(event: DragEvent): Promise<void> {
    event.preventDefault();
    dragOverKey = null;
    if (draggingCipherId) {
      await onDropOnFolder(event, null);
      return;
    }
    if (draggingFolderPath) {
      const source = draggingFolderPath;
      draggingFolderPath = null;
      await performFolderMove(source, null);
    }
  }

  async function onDropOnFolderNode(event: DragEvent, node: TreeNode): Promise<void> {
    event.preventDefault();
    dragOverKey = null;
    if (draggingCipherId) {
      if (node.folderId) {
        await onDropOnFolder(event, node.folderId);
      }
      return;
    }
    if (draggingFolderPath) {
      const source = draggingFolderPath;
      const target = folderPathFromKey(node.key);
      const allowed = target !== null && canDropFolderOn(target);
      draggingFolderPath = null;
      if (!allowed || target === null) return;
      await performFolderMove(source, target);
    }
  }

  async function performFolderMove(sourcePath: string, targetParentPath: string | null) {
    try {
      await invoke("move_folder_path", {
        sourcePath,
        targetParentPath,
      });
      // Refresh vault from backend to get encrypted names
      syncSummary = await invoke<SyncSummary>("sync");
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  async function onDropOnFolder(
    event: DragEvent,
    targetFolderId: string | null,
  ): Promise<void> {
    event.preventDefault();
    dragOverKey = null;
    const cipherId = draggingCipherId ?? event.dataTransfer?.getData("text/plain") ?? null;
    draggingCipherId = null;
    if (!cipherId || !syncSummary) return;

    const cipher = syncSummary.ciphers.find((c) => c.id === cipherId);
    if (!cipher) return;

    const previousFolderId = cipher.folderId;
    if (previousFolderId === targetFolderId) return;

    cipher.folderId = targetFolderId;

    try {
      await invoke("move_cipher_to_folder", {
        cipherId,
        folderId: targetFolderId,
      });
    } catch (e) {
      cipher.folderId = previousFolderId;
      errorMsg = formatError(e);
    }
  }

  async function onDropOnCollection(event: DragEvent, targetCollectionId: string): Promise<void> {
    event.preventDefault();
    dragOverKey = null;
    const cipherId = draggingCipherId ?? event.dataTransfer?.getData("text/plain") ?? null;
    draggingCipherId = null;
    if (!cipherId || !syncSummary) return;

    const cipher = syncSummary.ciphers.find((c) => c.id === cipherId);
    if (!cipher) return;

    const targetCollection = syncSummary.collections.find((c) => c.id === targetCollectionId);
    if (!targetCollection) return;

    // Cas 1 : même orga -> juste change de collection
    if (cipher.organizationId === targetCollection.organizationId) {
      const previousCollectionIds = [...cipher.collectionIds];
      if (previousCollectionIds.length === 1 && previousCollectionIds[0] === targetCollectionId) {
        return;
      }
      cipher.collectionIds = [targetCollectionId];
      try {
        await invoke("move_cipher_to_collection", {
          cipherId,
          collectionId: targetCollectionId,
        });
      } catch (e) {
        cipher.collectionIds = previousCollectionIds;
        errorMsg = formatError(e);
      }
      return;
    }

    // Cas 2 : cipher perso -> partage ou cipher d'une autre orga -> cross-org transfert.
    // Dans les deux cas, le backend re-chiffre avec la clé de l'orga cible.
    try {
      await invoke("share_cipher_to_collection", {
        cipherId,
        collectionId: targetCollectionId,
      });
      syncSummary = await invoke<SyncSummary>("sync");
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  onMount(async () => {
    try {
      const saved = localStorage.getItem(TREE_WIDTH_STORAGE_KEY);
      if (saved) {
        const parsed = parseInt(saved, 10);
        if (Number.isFinite(parsed)) {
          treeWidth = Math.max(TREE_WIDTH_MIN, Math.min(TREE_WIDTH_MAX, parsed));
        }
      }
      const savedLock = localStorage.getItem(AUTO_LOCK_STORAGE_KEY);
      if (savedLock) {
        const parsed = parseInt(savedLock, 10);
        if (Number.isFinite(parsed) && parsed >= 0) {
          autoLockMinutes = parsed;
        }
      }
    } catch {
      // ignore
    }

    try {
      const account = await invoke<StoredAccount | null>("stored_account");
      if (account) {
        storedAccount = account;
        serverUrl = account.serverUrl;
        email = account.email;
        phase = "unlock";
      } else {
        phase = "idle";
      }
    } catch (e) {
      errorMsg = formatError(e);
      phase = "idle";
    }
  });

  async function onLoginSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<LoginResult>("login", { serverUrl, email, password });
      if (result.type === "success") {
        tokens = result.data;
        storedAccount = { serverUrl, email };
        password = "";
        phase = "loggedIn";
        await loadCachedVault();
      } else {
        pendingProviders = result.data.providers;
        phase = "twoFactor";
      }
    } catch (e) {
      errorMsg = formatError(e);
      phase = "error";
    }
  }

  async function onTwoFactorSubmit(event: Event) {
    event.preventDefault();
    const codeSnapshot = totpCode;
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<TokenSet>("login_with_two_factor", {
        serverUrl,
        email,
        password,
        code: codeSnapshot,
        provider: 0,
      });
      tokens = result;
      storedAccount = { serverUrl, email };
      password = "";
      totpCode = "";
      phase = "loggedIn";
      await loadCachedVault();
    } catch (e) {
      errorMsg = formatError(e);
      phase = "twoFactor";
    }
  }

  async function onUnlockSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      tokens = await invoke<TokenSet>("unlock", { password });
      password = "";
      phase = "loggedIn";
      await loadCachedVault();
    } catch (e) {
      errorMsg = formatError(e);
      phase = "unlock";
    }
  }

  async function loadCachedVault() {
    try {
      const cached = await invoke<SyncSummary | null>("load_cached_vault");
      if (cached) {
        syncSummary = cached;
      }
    } catch (e) {
      // Cache corrompu ou absent : silencieux, l'utilisateur peut cliquer Synchroniser
      console.warn("[clavix] cached vault load failed:", e);
    }
  }

  async function onLock() {
    try {
      await invoke("lock");
    } catch {
      // best-effort
    }
    password = "";
    totpCode = "";
    tokens = null;
    syncSummary = null;
    pendingProviders = [];
    errorMsg = null;
    phase = storedAccount ? "unlock" : "idle";
  }

  async function switchAccount() {
    try {
      await invoke("logout");
    } catch {
      // best-effort
    }
    storedAccount = null;
    password = "";
    totpCode = "";
    tokens = null;
    syncSummary = null;
    pendingProviders = [];
    errorMsg = null;
    phase = "idle";
  }

  async function onSync() {
    syncing = true;
    errorMsg = null;
    try {
      syncSummary = await invoke<SyncSummary>("sync");
    } catch (e) {
      errorMsg = formatError(e);
    } finally {
      syncing = false;
    }
  }

  function reset() {
    phase = storedAccount ? "unlock" : "idle";
    errorMsg = null;
    totpCode = "";
    tokens = null;
    pendingProviders = [];
    password = "";
    syncSummary = null;
  }

  function truncate(s: string, n: number = 24): string {
    return s.length > n ? `${s.slice(0, n)}…` : s;
  }

  function formatExpiry(seconds: number): string {
    const minutes = Math.round(seconds / 60);
    if (minutes >= 60) return `${(minutes / 60).toFixed(1)} h`;
    return `${minutes} min`;
  }

  const providerLabel = (p: number): string => {
    switch (p) {
      case 0: return "TOTP (Authenticator)";
      case 1: return "Email";
      case 2: return "Duo";
      case 3: return "YubiKey OTP";
      case 7: return "WebAuthn / FIDO2";
      default: return `Provider #${p}`;
    }
  };

  const cipherTypeLabel = (k: number): string => {
    switch (k) {
      case 1: return "Login";
      case 2: return "Note";
      case 3: return "Carte";
      case 4: return "Identité";
      case 5: return "Clé SSH";
      default: return `Type ${k}`;
    }
  };

  const cipherTypeIcon = (k: number): string => {
    switch (k) {
      case 1: return "🔐";
      case 2: return "📝";
      case 3: return "💳";
      case 4: return "🪪";
      case 5: return "🔑";
      default: return "❔";
    }
  };

  function extractDomain(uri: string): string | null {
    try {
      const url = new URL(uri.startsWith("http") ? uri : `https://${uri}`);
      return url.hostname;
    } catch {
      return null;
    }
  }

  function faviconUrl(cipher: CipherSummary): string | null {
    if (cipher.kind !== 1 || !cipher.primaryUri || !storedAccount) return null;
    const domain = extractDomain(cipher.primaryUri);
    if (!domain) return null;
    const base = storedAccount.serverUrl.replace(/\/$/, "");
    return `${base}/icons/${domain}/icon.png`;
  }
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<main class="container" class:wide={phase === "loggedIn" && syncSummary !== null}>
  <h1>Clavix</h1>

  {#if phase === "init"}
    <p class="subtitle">Chargement…</p>
  {/if}

  {#if phase === "idle" || (phase === "authenticating" && !storedAccount) || phase === "error"}
    <form onsubmit={onLoginSubmit}>
      <label>
        Serveur Vaultwarden
        <input type="url" bind:value={serverUrl} required disabled={phase === "authenticating"} />
      </label>
      <label>
        Email
        <input type="email" bind:value={email} placeholder="toi@exemple.fr" required disabled={phase === "authenticating"} />
      </label>
      <label>
        Mot de passe maître
        <input type="password" bind:value={password} required disabled={phase === "authenticating"} />
      </label>
      <button type="submit" disabled={phase === "authenticating"}>
        {phase === "authenticating" ? "Connexion…" : "Connexion"}
      </button>
    </form>
  {/if}

  {#if phase === "unlock" || (phase === "authenticating" && storedAccount)}
    <section class="box">
      <h2>Déverrouiller</h2>
      <p class="hint">
        {storedAccount?.email} sur {storedAccount?.serverUrl}
      </p>
      <form onsubmit={onUnlockSubmit}>
        <label>
          Mot de passe maître
          <input type="password" bind:value={password} required disabled={phase === "authenticating"} />
        </label>
        <div class="row">
          <button type="button" class="secondary" onclick={switchAccount}>Changer de compte</button>
          <button type="submit" disabled={phase === "authenticating"}>
            {phase === "authenticating" ? "Déverrouillage…" : "Déverrouiller"}
          </button>
        </div>
      </form>
    </section>
  {/if}

  {#if phase === "twoFactor"}
    <section class="box">
      <h2>Double authentification</h2>
      <p class="hint">
        Providers annoncés : {pendingProviders.map(providerLabel).join(", ")}
      </p>
      <form onsubmit={onTwoFactorSubmit}>
        <label>
          Code TOTP (6 chiffres)
          <input
            type="text"
            bind:value={totpCode}
            inputmode="numeric"
            pattern={TOTP_PATTERN}
            maxlength="6"
            autocomplete="one-time-code"
            required
          />
        </label>
        <div class="row">
          <button type="button" class="secondary" onclick={reset}>Annuler</button>
          <button type="submit">Valider</button>
        </div>
      </form>
    </section>
  {/if}

  {#if phase === "loggedIn" && tokens}
    <section class="box">
      <h2>Session active</h2>
      <dl>
        <dt>access_token</dt>
        <dd><code>{truncate(tokens.access_token)}</code></dd>
        <dt>expires_in</dt>
        <dd>{formatExpiry(tokens.expires_in)}</dd>
      </dl>
      <div class="row">
        <button type="button" class="secondary" onclick={switchAccount}>Se déconnecter</button>
        <button type="button" class="secondary" onclick={onLock}>Verrouiller</button>
        <button type="button" onclick={onSync} disabled={syncing}>
          {syncing ? "Synchronisation…" : (syncSummary ? "Resynchroniser" : "Synchroniser")}
        </button>
      </div>
    </section>

    {#if syncSummary}
      <section class="vault-section">
        {#if syncSummary.ciphers.length > 0}
          <div class="vault-layout" style="--tree-width: {treeWidth}px;">
            <aside class="tree-pane">
              <button
                type="button"
                class="tree-all"
                class:selected={selectedKey === null}
                class:drop-over={dragOverKey === "__all__"}
                onclick={() => (selectedKey = null)}
                ondragover={(e) => onNodeDragOver(e, "__all__")}
                ondragleave={() => onNodeDragLeave("__all__")}
                ondrop={onDropOnFolderRoot}
              >
                <span>Tous les items</span>
                <span class="tree-count">{syncSummary.itemCount.toLocaleString("fr-FR")}</span>
              </button>
              {#if (folderTree && folderTree.children.length > 0) || orgTrees.length > 0}
                <div class="tree-toolbar">
                  <button type="button" class="secondary small" onclick={expandAllNodes}>
                    Tout déplier
                  </button>
                  <button type="button" class="secondary small" onclick={collapseAllNodes}>
                    Tout replier
                  </button>
                  <button
                    type="button"
                    class="secondary small info-button"
                    onclick={openStats}
                    title="Infos du coffre"
                    aria-label="Infos du coffre"
                  >
                    ⓘ
                  </button>
                </div>
              {/if}
              {#if folderTree && folderTree.children.length > 0}
                <ul class="tree-root">
                  {#each folderTree.children as node (node.key)}
                    {@render treeNode(node)}
                  {/each}
                </ul>
              {/if}
              {#if orgTrees.length > 0}
                <h4>Organisations</h4>
                <ul class="tree-root">
                  {#each orgTrees as orgRoot (orgRoot.key)}
                    {@render orgRootNode(orgRoot)}
                  {/each}
                </ul>
              {/if}
            </aside>

            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <div
              class="splitter"
              role="separator"
              aria-orientation="vertical"
              aria-label="Redimensionner le panneau"
              onmousedown={onSplitterMouseDown}
            ></div>

            <section class="list-pane">
              <h3>
                Items
                <small>
                  ({filteredCiphers.length.toLocaleString("fr-FR")}
                  {#if search.trim() || selectedKey}/{syncSummary.ciphers.length.toLocaleString("fr-FR")}{/if})
                </small>
              </h3>
              <div class="search-row">
                <input
                  type="search"
                  bind:value={search}
                  bind:this={searchInput}
                  placeholder="Rechercher un item… (/ ou Ctrl+F)"
                  class="search"
                />
                {#if search.trim()}
                  <button type="button" class="secondary small" onclick={() => (search = "")}>
                    Effacer
                  </button>
                {/if}
              </div>
              {#if filteredCiphers.length === 0}
                <p class="hint">
                  {#if search.trim()}
                    Aucun item ne correspond à « {search} ».
                  {:else}
                    Aucun item dans ce dossier.
                  {/if}
                </p>
              {:else}
                <div
                  class="cipher-scroll"
                  bind:this={listScrollEl}
                  onscroll={onListScroll}
                >
                  <div class="cipher-spacer" style:height="{virtualWindow.totalHeight}px">
                    <ul
                      class="enc-list cipher-list"
                      style:transform="translateY({virtualWindow.offsetY}px)"
                    >
                      {#each virtualWindow.items as c (c.id)}
                        {@const fav = faviconUrl(c)}
                        <li style:height="{ROW_HEIGHT}px">
                          <button
                            type="button"
                            class="cipher-row"
                            class:selected={detail?.id === c.id}
                            class:dragging={draggingCipherId === c.id}
                            onclick={() => openCipher(c.id)}
                            draggable="true"
                            ondragstart={(e) => onCipherDragStart(e, c.id)}
                            ondragend={onCipherDragEnd}
                          >
                            <span class="cipher-icon" title={cipherTypeLabel(c.kind)}>
                              {#if fav}
                                <img
                                  src={fav}
                                  alt=""
                                  loading="lazy"
                                  onerror={(e) => {
                                    const img = e.currentTarget as HTMLImageElement;
                                    img.style.display = "none";
                                    const fallback = img.nextElementSibling as HTMLElement | null;
                                    if (fallback) fallback.style.display = "inline";
                                  }}
                                />
                                <span class="emoji-fallback" style:display="none">
                                  {cipherTypeIcon(c.kind)}
                                </span>
                              {:else}
                                <span class="emoji-fallback">{cipherTypeIcon(c.kind)}</span>
                              {/if}
                            </span>
                            <span class="name">{c.name}</span>
                            {#if c.favorite}<span class="star" title="Favori">★</span>{/if}
                          </button>
                        </li>
                      {/each}
                    </ul>
                  </div>
                </div>
              {/if}
            </section>
          </div>

          {#if detailLoading}
            <section class="box">
              <p class="hint">Déchiffrement de l'item…</p>
            </section>
          {/if}

          {#if detail}
            <section class="box cipher-detail">
              <header class="detail-header">
                <div>
                  <span class="badge">{cipherTypeLabel(detail.kind)}</span>
                  <h2>{detail.name}</h2>
                </div>
                <button type="button" class="secondary small" onclick={closeDetail}>Fermer</button>
              </header>

              {#if detail.login}
                {#if detail.login.username}
                  <dl class="detail-field">
                    <dt>Identifiant</dt>
                    <dd>
                      <code>{detail.login.username}</code>
                      <button
                        type="button"
                        class="secondary small"
                        onclick={() => copyToClipboard(detail!.login!.username!, "identifiant")}
                      >
                        Copier
                      </button>
                    </dd>
                  </dl>
                {/if}

                {#if detail.login.password}
                  <dl class="detail-field">
                    <dt>Mot de passe</dt>
                    <dd>
                      <code class="password">
                        {showPassword ? detail.login.password : "•".repeat(Math.min(detail.login.password.length, 16))}
                      </code>
                      <button
                        type="button"
                        class="secondary small"
                        onclick={() => (showPassword = !showPassword)}
                      >
                        {showPassword ? "Masquer" : "Afficher"}
                      </button>
                      <button
                        type="button"
                        class="small"
                        onclick={() => copyToClipboard(detail!.login!.password!, "mot de passe")}
                      >
                        Copier
                      </button>
                    </dd>
                  </dl>
                {/if}

                {#if detail.login.uris.length > 0}
                  <dl class="detail-field">
                    <dt>URL{detail.login.uris.length > 1 ? "s" : ""}</dt>
                    <dd>
                      <ul class="uri-list">
                        {#each detail.login.uris as u}
                          <li><code>{u}</code></li>
                        {/each}
                      </ul>
                    </dd>
                  </dl>
                {/if}

                {#if detail.login.totp}
                  <dl class="detail-field">
                    <dt>TOTP</dt>
                    <dd><code>{detail.login.totp}</code> <small>(génération de code à venir)</small></dd>
                  </dl>
                {/if}
              {/if}

              {#if detail.card}
                {#if detail.card.cardholderName}
                  <dl class="detail-field">
                    <dt>Titulaire</dt>
                    <dd>
                      <code>{detail.card.cardholderName}</code>
                      <button type="button" class="secondary small"
                        onclick={() => copyToClipboard(detail!.card!.cardholderName!, "titulaire")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
                {#if detail.card.brand}
                  <dl class="detail-field">
                    <dt>Réseau</dt>
                    <dd>{detail.card.brand}</dd>
                  </dl>
                {/if}
                {#if detail.card.number}
                  <dl class="detail-field">
                    <dt>Numéro</dt>
                    <dd>
                      <code>{showCardNumber ? detail.card.number : mask(detail.card.number, 16)}</code>
                      <button type="button" class="secondary small"
                        onclick={() => (showCardNumber = !showCardNumber)}>
                        {showCardNumber ? "Masquer" : "Afficher"}
                      </button>
                      <button type="button" class="small"
                        onclick={() => copyToClipboard(detail!.card!.number!, "numéro de carte")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
                {#if detail.card.expMonth || detail.card.expYear}
                  <dl class="detail-field">
                    <dt>Expiration</dt>
                    <dd>
                      {detail.card.expMonth ?? "?"} / {detail.card.expYear ?? "?"}
                    </dd>
                  </dl>
                {/if}
                {#if detail.card.code}
                  <dl class="detail-field">
                    <dt>CVV</dt>
                    <dd>
                      <code>{showCardCode ? detail.card.code : mask(detail.card.code, 3)}</code>
                      <button type="button" class="secondary small"
                        onclick={() => (showCardCode = !showCardCode)}>
                        {showCardCode ? "Masquer" : "Afficher"}
                      </button>
                      <button type="button" class="small"
                        onclick={() => copyToClipboard(detail!.card!.code!, "CVV")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
              {/if}

              {#if detail.identity}
                {@const identityFields = [
                  ["Titre", detail.identity.title],
                  ["Prénom", detail.identity.firstName],
                  ["Deuxième prénom", detail.identity.middleName],
                  ["Nom", detail.identity.lastName],
                  ["Entreprise", detail.identity.company],
                  ["Adresse 1", detail.identity.address1],
                  ["Adresse 2", detail.identity.address2],
                  ["Adresse 3", detail.identity.address3],
                  ["Ville", detail.identity.city],
                  ["Département/État", detail.identity.state],
                  ["Code postal", detail.identity.postalCode],
                  ["Pays", detail.identity.country],
                  ["Email", detail.identity.email],
                  ["Téléphone", detail.identity.phone],
                  ["Identifiant", detail.identity.username],
                  ["N° passeport", detail.identity.passportNumber],
                  ["N° permis", detail.identity.licenseNumber],
                ] as Array<[string, string | null]>}
                {#each identityFields as [label, value]}
                  {#if value}
                    <dl class="detail-field">
                      <dt>{label}</dt>
                      <dd>
                        <code>{value}</code>
                        <button type="button" class="secondary small"
                          onclick={() => copyToClipboard(value, label.toLowerCase())}>Copier</button>
                      </dd>
                    </dl>
                  {/if}
                {/each}
                {#if detail.identity.ssn}
                  <dl class="detail-field">
                    <dt>NIR / SSN</dt>
                    <dd>
                      <code>{showSsn ? detail.identity.ssn : mask(detail.identity.ssn, 11)}</code>
                      <button type="button" class="secondary small"
                        onclick={() => (showSsn = !showSsn)}>
                        {showSsn ? "Masquer" : "Afficher"}
                      </button>
                      <button type="button" class="small"
                        onclick={() => copyToClipboard(detail!.identity!.ssn!, "NIR")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
              {/if}

              {#if detail.sshKey}
                {#if detail.sshKey.keyFingerprint}
                  <dl class="detail-field">
                    <dt>Empreinte</dt>
                    <dd>
                      <code>{detail.sshKey.keyFingerprint}</code>
                      <button type="button" class="secondary small"
                        onclick={() => copyToClipboard(detail!.sshKey!.keyFingerprint!, "empreinte")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
                {#if detail.sshKey.publicKey}
                  <dl class="detail-field">
                    <dt>Clé publique</dt>
                    <dd>
                      <code class="ssh-key">{detail.sshKey.publicKey}</code>
                      <button type="button" class="secondary small"
                        onclick={() => copyToClipboard(detail!.sshKey!.publicKey!, "clé publique")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
                {#if detail.sshKey.privateKey}
                  <dl class="detail-field">
                    <dt>Clé privée</dt>
                    <dd>
                      {#if showSshPrivate}
                        <code class="ssh-key">{detail.sshKey.privateKey}</code>
                      {:else}
                        <code>••••••• (masquée)</code>
                      {/if}
                      <button type="button" class="secondary small"
                        onclick={() => (showSshPrivate = !showSshPrivate)}>
                        {showSshPrivate ? "Masquer" : "Afficher"}
                      </button>
                      <button type="button" class="small"
                        onclick={() => copyToClipboard(detail!.sshKey!.privateKey!, "clé privée")}>Copier</button>
                    </dd>
                  </dl>
                {/if}
              {/if}

              {#if detail.notes}
                <dl class="detail-field">
                  <dt>Notes</dt>
                  <dd class="notes">{detail.notes}</dd>
                </dl>
              {/if}

              <p class="hint detail-footer">
                Item #{detail.id.slice(0, 8)}
                {#if detail.organizationId}
                  · Organisation : {syncSummary?.organizations.find((o) => o.id === detail!.organizationId)?.name ?? "?"}
                {/if}
              </p>
            </section>
          {/if}
        {/if}

        {#snippet treeNode(node: TreeNode)}
          <li>
            <div
              class="tree-row"
              class:selected={selectedKey === node.key}
              class:drop-over={dragOverKey === node.key}
              class:droppable={
                (draggingCipherId !== null && isCipherDroppable(node)) ||
                isFolderDropTarget(node)
              }
            >
              {#if node.children.length > 0}
                <button
                  type="button"
                  class="tree-toggle"
                  onclick={() => toggleExpanded(node.key)}
                  aria-label={expanded.has(node.key) ? "Réduire" : "Déplier"}
                >
                  {expanded.has(node.key) ? "▼" : "▶"}
                </button>
              {:else}
                <span class="tree-spacer"></span>
              {/if}
              <button
                type="button"
                class="tree-label"
                draggable={node.kind === "folder"}
                onclick={() => selectNode(node.key)}
                ondragstart={node.kind === "folder"
                  ? (e) => onFolderDragStart(e, node)
                  : undefined}
                ondragend={node.kind === "folder" ? onFolderDragEnd : undefined}
                ondragover={(e) => onNodeDragOver(e, node.key)}
                ondragleave={() => onNodeDragLeave(node.key)}
                ondrop={node.kind === "folder"
                  ? (e) => onDropOnFolderNode(e, node)
                  : node.kind === "collection" && node.collectionId !== null
                    ? (e) => onDropOnCollection(e, node.collectionId!)
                    : undefined}
              >
                <span class="tree-label-text">{node.label}</span>
                <span class="tree-count">{node.itemCount}</span>
              </button>
            </div>
            {#if expanded.has(node.key) && node.children.length > 0}
              <ul class="tree-children">
                {#each node.children as child (child.key)}
                  {@render treeNode(child)}
                {/each}
              </ul>
            {/if}
          </li>
        {/snippet}

        {#snippet orgRootNode(node: TreeNode)}
          <li>
            <div class="tree-row org-root" class:selected={selectedKey === node.key}>
              {#if node.children.length > 0}
                <button
                  type="button"
                  class="tree-toggle"
                  onclick={() => toggleExpanded(node.key)}
                  aria-label={expanded.has(node.key) ? "Réduire" : "Déplier"}
                >
                  {expanded.has(node.key) ? "▼" : "▶"}
                </button>
              {:else}
                <span class="tree-spacer"></span>
              {/if}
              <button
                type="button"
                class="tree-label"
                onclick={() => selectNode(node.key)}
              >
                <span class="tree-label-text">{node.label}</span>
                <span class="tree-count">{node.itemCount}</span>
              </button>
            </div>
            {#if expanded.has(node.key) && node.children.length > 0}
              <ul class="tree-children">
                {#each node.children as child (child.key)}
                  {@render treeNode(child)}
                {/each}
              </ul>
            {/if}
          </li>
        {/snippet}
      </section>
    {/if}
  {/if}

  {#if errorMsg}
    <section class="box error">
      <h2>Erreur</h2>
      <pre>{errorMsg}</pre>
    </section>
  {/if}
</main>

{#if clipboardSecondsLeft !== null}
  <aside class="clipboard-toast" role="status">
    <span>
      Presse-papier ({clipboardLabel}) effacé dans {clipboardSecondsLeft}s
    </span>
    <button type="button" class="secondary small" onclick={clearClipboardNow}>Effacer maintenant</button>
  </aside>
{/if}

<dialog bind:this={statsDialog} class="stats-dialog">
  {#if syncSummary}
    <header class="stats-header">
      <h2>Coffre synchronisé</h2>
      <button type="button" class="secondary small" onclick={closeStats} aria-label="Fermer">
        ✕
      </button>
    </header>
    <dl>
      <dt>Compte</dt>
      <dd>{syncSummary.name ?? syncSummary.email}</dd>
      <dt>Items</dt>
      <dd>{syncSummary.itemCount}</dd>
      <dt>Folders</dt>
      <dd>{syncSummary.folderCount}</dd>
      <dt>Collections</dt>
      <dd>{syncSummary.collectionCount}</dd>
      <dt>Organisations</dt>
      <dd>{syncSummary.organizationCount}</dd>
      <dt>Verrouillage auto</dt>
      <dd>
        <select
          value={autoLockMinutes}
          onchange={(e) => persistAutoLockSetting(parseInt((e.currentTarget as HTMLSelectElement).value, 10))}
        >
          <option value={0}>Jamais</option>
          <option value={1}>1 min</option>
          <option value={5}>5 min</option>
          <option value={10}>10 min</option>
          <option value={15}>15 min</option>
          <option value={30}>30 min</option>
          <option value={60}>1 h</option>
        </select>
      </dd>
    </dl>

    <h3>Répartition par type</h3>
    <dl>
      <dt>Logins</dt>
      <dd>{syncSummary.typeCounts.login}</dd>
      <dt>Notes</dt>
      <dd>{syncSummary.typeCounts.secureNote}</dd>
      <dt>Cartes</dt>
      <dd>{syncSummary.typeCounts.card}</dd>
      <dt>Identités</dt>
      <dd>{syncSummary.typeCounts.identity}</dd>
      {#if syncSummary.typeCounts.sshKey > 0}
        <dt>Clés SSH</dt>
        <dd>{syncSummary.typeCounts.sshKey}</dd>
      {/if}
    </dl>
  {/if}
</dialog>

<style>
  :root {
    font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
    font-size: 15px;
    line-height: 1.5;
    color: #0f0f0f;
    background-color: #f6f6f6;
  }

  .container {
    max-width: 620px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }

  .container.wide {
    max-width: none;
    margin: 0;
    padding: 1rem 1.5rem;
    height: 100vh;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .container.wide h1 {
    flex: 0 0 auto;
  }

  .container.wide > .box {
    flex: 0 0 auto;
  }

  .container.wide .vault-section {
    flex: 1 1 auto;
    min-height: 0;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .vault-section {
    margin-top: 1rem;
  }

  h1 {
    margin: 0 0 0.25rem;
  }

  h2 {
    margin: 0 0 0.75rem;
    font-size: 1rem;
  }

  h3 {
    margin: 1rem 0 0.5rem;
    font-size: 0.9rem;
    color: #444;
  }

  h3 small {
    color: #888;
    font-weight: 400;
  }

  .subtitle {
    margin: 0 0 2rem;
    color: #555;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
    background: #fff;
    padding: 1.25rem;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.9rem;
    color: #333;
  }

  input,
  button {
    font: inherit;
    padding: 0.55rem 0.8rem;
    border-radius: 6px;
    border: 1px solid #d0d0d0;
    background: #fff;
  }

  input:focus {
    outline: none;
    border-color: #396cd8;
    box-shadow: 0 0 0 2px rgba(57, 108, 216, 0.15);
  }

  button {
    cursor: pointer;
    background: #396cd8;
    color: #fff;
    border-color: #396cd8;
    font-weight: 500;
  }

  button.secondary {
    background: #fff;
    color: #333;
    border-color: #d0d0d0;
  }

  button:hover:not(:disabled) {
    filter: brightness(0.95);
  }

  button:disabled {
    opacity: 0.6;
    cursor: progress;
  }

  .row {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }

  .box {
    margin-top: 1.5rem;
    padding: 1rem 1.25rem;
    border-radius: 10px;
    background: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  }

  .box.error {
    border-left: 4px solid #d63a3a;
  }

  .box.error pre {
    color: #7a1d1d;
    white-space: pre-wrap;
    margin: 0;
  }

  .hint {
    margin: 0.5rem 0 0;
    font-size: 0.85rem;
    color: #555;
  }

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.35rem 1rem;
    margin: 0 0 0.5rem;
  }

  dt {
    font-weight: 600;
    color: #444;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  pre {
    font-size: 0.8rem;
    background: #f1f1f1;
    padding: 0.5rem;
    border-radius: 6px;
    overflow-x: auto;
  }

  code {
    background: #eee;
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    font-size: 0.85em;
    word-break: break-all;
  }

  .enc-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .enc-list li {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
  }

  .badge {
    display: inline-block;
    padding: 0.05rem 0.4rem;
    background: #eef2ff;
    color: #3751c4;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 500;
    min-width: 3.5rem;
    text-align: center;
  }

  .name {
    overflow-wrap: anywhere;
    flex: 1;
  }

  .star {
    color: #f0a500;
  }

  .search-row {
    display: flex;
    gap: 0.5rem;
    margin: 0.5rem 0 0.75rem;
  }

  .search {
    flex: 1;
  }

  button.small {
    padding: 0.4rem 0.75rem;
    font-size: 0.9rem;
  }

  button.info-button {
    margin-left: auto;
    width: 2rem;
    min-width: 2rem;
    padding: 0.2rem 0;
    font-size: 1.1rem;
    line-height: 1;
  }

  .stats-dialog {
    border: none;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    min-width: 320px;
    max-width: 480px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  }

  .stats-dialog::backdrop {
    background: rgba(0, 0, 0, 0.35);
  }

  .stats-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }

  .stats-header h2 {
    margin: 0;
    font-size: 1.05rem;
  }

  @media (prefers-color-scheme: dark) {
    .stats-dialog {
      background: #2b2b2b;
      color: #f6f6f6;
    }
  }

  .vault-layout {
    display: grid;
    grid-template-columns: var(--tree-width, 260px) 6px 1fr;
    gap: 0;
    align-items: stretch;
    min-height: 0;
  }

  .container.wide .vault-layout {
    flex: 1 1 auto;
  }

  .splitter {
    cursor: col-resize;
    background: transparent;
    transition: background-color 0.1s;
    user-select: none;
  }

  .splitter::before {
    content: "";
    display: block;
    width: 1px;
    height: 100%;
    margin-left: 2.5px;
    background: #e5e5e5;
  }

  .splitter:hover {
    background: #dbeafe;
  }

  .splitter:hover::before {
    background: #3b82f6;
  }

  .tree-pane {
    background: #fff;
    border-radius: 10px;
    padding: 0.75rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
    overflow: auto;
    max-height: 70vh;
    margin-right: 0.5rem;
  }

  .list-pane {
    margin-left: 0.5rem;
  }

  .container.wide .tree-pane {
    max-height: none;
    min-height: 0;
  }

  .list-pane {
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .list-pane h3 {
    flex: 0 0 auto;
  }

  .list-pane .search-row {
    flex: 0 0 auto;
  }

  .list-pane .cipher-scroll {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    contain: strict;
  }

  .cipher-spacer {
    position: relative;
    width: 100%;
  }

  .list-pane .enc-list.cipher-list {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    will-change: transform;
    margin: 0;
  }

  .cipher-list li {
    display: flex;
    align-items: center;
  }

  .tree-pane h4 {
    margin: 0.75rem 0 0.3rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #888;
  }

  .tree-toolbar {
    display: flex;
    gap: 0.35rem;
    margin: 0.75rem 0 0.5rem;
  }

  .tree-root,
  .tree-children {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .tree-children {
    padding-left: 0.9rem;
    margin-left: 0.5rem;
    border-left: 1px solid #e5e5e5;
  }

  .tree-row {
    display: flex;
    align-items: center;
    gap: 0.15rem;
    min-width: 0;
  }

  .tree-toggle,
  .tree-spacer {
    width: 1.3rem;
    min-width: 1.3rem;
    height: 1.3rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .tree-toggle {
    background: transparent;
    border: none;
    cursor: pointer;
    font-size: 0.6rem;
    color: #777;
    padding: 0;
  }

  .tree-label {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.4rem;
    padding: 0.2rem 0.4rem;
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    color: inherit;
    font: inherit;
    text-align: left;
  }

  .tree-label-text {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tree-label:hover {
    background: #f0f0f0;
  }

  .tree-row.selected > .tree-label {
    background: #e3ecff;
    color: #1e3a8a;
    font-weight: 500;
  }

  .tree-count {
    font-size: 0.72rem;
    color: #888;
    background: #f1f1f1;
    padding: 0.05rem 0.4rem;
    border-radius: 10px;
    min-width: 1.5rem;
    text-align: center;
  }

  .tree-row.selected > .tree-label .tree-count {
    background: #c5d6ff;
    color: #1e3a8a;
  }

  .tree-all {
    display: flex;
    width: 100%;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0.6rem;
    border: none;
    background: transparent;
    border-radius: 6px;
    cursor: pointer;
    color: inherit;
    font: inherit;
    font-weight: 500;
  }

  .tree-all:hover {
    background: #f0f0f0;
  }

  .tree-all.selected {
    background: #e3ecff;
    color: #1e3a8a;
  }

  .tree-row.org-root > .tree-label {
    font-weight: 500;
  }

  .cipher-list {
    max-height: 60vh;
    overflow-y: auto;
  }

  .cipher-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    padding: 0.35rem 0.5rem;
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    color: inherit;
    font: inherit;
    text-align: left;
  }

  .cipher-row:hover {
    background: #f0f0f0;
  }

  .cipher-row.selected {
    background: #e3ecff;
    color: #1e3a8a;
  }

  .cipher-row.dragging {
    opacity: 0.5;
  }

  .cipher-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.4rem;
    height: 1.4rem;
    min-width: 1.4rem;
    font-size: 1rem;
    line-height: 1;
  }

  .cipher-icon img {
    width: 1.2rem;
    height: 1.2rem;
    object-fit: contain;
    border-radius: 3px;
  }

  .tree-row.droppable > .tree-label {
    outline: 1px dashed transparent;
    transition: outline-color 0.1s;
  }

  .tree-row.droppable:not(.drop-over) > .tree-label {
    outline-color: #c5d6ff;
  }

  .tree-row.drop-over > .tree-label,
  .tree-all.drop-over {
    background: #fde68a !important;
    color: #78350f !important;
    outline: 2px solid #f59e0b;
  }

  .cipher-detail {
    margin-top: 1rem;
  }

  .detail-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }

  .detail-header h2 {
    margin: 0.3rem 0 0;
    font-size: 1.15rem;
  }

  .detail-field {
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 0.5rem 1rem;
    align-items: center;
    margin: 0 0 0.6rem;
  }

  .detail-field dt {
    font-weight: 600;
    color: #555;
    font-size: 0.85rem;
  }

  .detail-field dd {
    margin: 0;
    display: flex;
    align-items: center;
    gap: 0.4rem;
    flex-wrap: wrap;
  }

  .password {
    font-family: ui-monospace, monospace;
    letter-spacing: 0.1em;
  }

  .uri-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    flex: 1;
  }

  .uri-list code {
    overflow-wrap: anywhere;
  }

  .notes {
    white-space: pre-wrap;
    font-size: 0.9rem;
  }

  .ssh-key {
    display: block;
    max-width: 100%;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 10rem;
    overflow-y: auto;
  }

  .detail-footer {
    margin-top: 0.75rem;
    font-size: 0.8rem;
  }

  .clipboard-toast {
    position: fixed;
    bottom: 1rem;
    left: 50%;
    transform: translateX(-50%);
    background: #1e3a8a;
    color: #fff;
    padding: 0.6rem 1rem;
    border-radius: 8px;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    z-index: 1000;
  }

  .clipboard-toast button.secondary {
    background: #fff;
    color: #1e3a8a;
    border-color: #fff;
  }

  @media (prefers-color-scheme: dark) {
    .cipher-row:hover { background: #333; }
    .cipher-row.selected { background: #1f2a54; color: #aabaff; }
    .detail-field dt { color: #aaa; }
  }

  @media (max-width: 760px) {
    .vault-layout {
      grid-template-columns: 1fr;
    }
    .tree-pane {
      max-height: 40vh;
    }
  }

  @media (prefers-color-scheme: dark) {
    .tree-pane {
      background: #2b2b2b;
      box-shadow: none;
    }
    .tree-pane h4 { color: #aaa; }
    .tree-label:hover, .tree-all:hover { background: #333; }
    .tree-row.selected > .tree-label,
    .tree-all.selected {
      background: #1f2a54;
      color: #aabaff;
    }
    .tree-count {
      background: #333;
      color: #aaa;
    }
    .tree-row.selected > .tree-label .tree-count {
      background: #2a3870;
      color: #aabaff;
    }
    .tree-children { border-left-color: #444; }
    .splitter::before { background: #3a3a3a; }
    .splitter:hover { background: #1e3a8a; }
    .splitter:hover::before { background: #60a5fa; }
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f6f6f6;
      background-color: #1e1e1e;
    }
    .subtitle, h3 small, .hint { color: #aaa; }
    h3 { color: #ccc; }
    form, .box { background: #2b2b2b; box-shadow: none; }
    label { color: #ccc; }
    input, button { background: #1e1e1e; color: #f6f6f6; border-color: #3a3a3a; }
    button { background: #396cd8; border-color: #396cd8; }
    button.secondary { background: #2b2b2b; color: #ddd; border-color: #3a3a3a; }
    dt { color: #ccc; }
    .box.error pre { color: #ff8a8a; }
    pre { background: #181818; }
    code { background: #333; }
    .badge { background: #1f2a54; color: #aabaff; }
  }
</style>
