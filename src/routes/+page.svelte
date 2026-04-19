<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { clear as clearClipboard, writeText } from "@tauri-apps/plugin-clipboard-manager";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { onDestroy, onMount } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import { getLocale, setLocale } from "$lib/paraglide/runtime";
  import Onboarding from "$lib/Onboarding.svelte";
  import TotpField from "$lib/TotpField.svelte";
  import LoginEditor from "$lib/LoginEditor.svelte";

  type Locale = "fr" | "en";
  const LOCALE_STORAGE_KEY = "clavix.locale";
  let currentLocale = $state<Locale>("fr");

  function applyLocale(loc: Locale, opts: { reload?: boolean } = {}) {
    currentLocale = loc;
    try {
      localStorage.setItem(LOCALE_STORAGE_KEY, loc);
    } catch {
      // ignore
    }
    setLocale(loc, { reload: opts.reload === true });
  }

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
    username: string | null;
    revisionDate: string | null;
    deletedDate: string | null;
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
    | "onboarding"
    | "idle"
    | "authenticating"
    | "twoFactor"
    | "unlock"
    | "loggedIn"
    | "error";

  type StoredAccount = { serverUrl: string; email: string };

  type TauriError = { code: string; message: string; data?: Record<string, unknown> };

  function formatError(e: unknown): string {
    if (!e || typeof e !== "object") return String(e);
    const err = e as { code?: string; message?: string; data?: Record<string, unknown> };
    const data = err.data ?? {};
    const str = (v: unknown) => (v === null || v === undefined ? "" : String(v));

    switch (err.code) {
      case "invalid_url":
        return m.err_invalid_url({ url: str(data.url) });
      case "network_error":
        return m.err_network({ cause: str(data.cause) });
      case "invalid_response":
        return m.err_invalid_response({ reason: str(data.reason) });
      case "http_status":
        return m.err_http_status({ status: str(data.status), message: str(data.message) });
      case "auth_failed":
        return m.err_auth_failed({ message: str(data.message) });
      case "crypto_error":
        return m.err_crypto({ reason: str(data.reason) });
      case "two_factor_provider_unsupported":
        return m.err_two_factor_provider_unsupported({ provider: str(data.provider) });
      case "not_authenticated":
        return m.err_not_authenticated();
      case "storage_error":
        return m.err_storage({ reason: str(data.reason) });
      default:
        return err.message ?? String(e);
    }
  }

  const TOTP_PATTERN = "[0-9]{6}";

  let serverUrl = $state("https://vault.example.com");
  let email = $state("");
  let password = $state("");
  let totpCode = $state("");
  let yubikeyOtp = $state("");
  let selectedProvider = $state(0);
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
  let generatorDialog = $state<HTMLDialogElement | null>(null);
  let auditDialog = $state<HTMLDialogElement | null>(null);

  type AuditEntry = { cipherId: string; name: string; count: number };
  type ReusedGroup = { cipherIds: string[]; names: string[] };
  type WeakEntry = { cipherId: string; name: string; score: number };
  type AuditResult = {
    checked: number;
    pwned: AuditEntry[];
    reused: ReusedGroup[];
    weak: WeakEntry[];
  };
  let auditLoading = $state(false);
  let auditResult = $state<AuditResult | null>(null);
  let auditError = $state<string | null>(null);

  type EditorInitial = {
    id: string | null;
    name: string;
    folderId: string | null;
    favorite: boolean;
    notes: string;
    username: string;
    password: string;
    uris: string[];
    totp: string;
  };
  const EMPTY_EDITOR_INITIAL: EditorInitial = {
    id: null,
    name: "",
    folderId: null,
    favorite: false,
    notes: "",
    username: "",
    password: "",
    uris: [],
    totp: "",
  };
  let editorOpen = $state(false);
  let editorMode = $state<"create" | "edit">("create");
  let editorInitial = $state<EditorInitial>(EMPTY_EDITOR_INITIAL);

  type SshAgentStatus = {
    running: boolean;
    socketPath: string | null;
    keyCount: number;
    skippedCount: number;
  };
  let sshAgent = $state<SshAgentStatus>({
    running: false,
    socketPath: null,
    keyCount: 0,
    skippedCount: 0,
  });
  let sshAgentBusy = $state(false);
  let sshAgentError = $state<string | null>(null);

  async function refreshSshAgentStatus() {
    try {
      sshAgent = await invoke<SshAgentStatus>("ssh_agent_status");
    } catch (e) {
      console.warn("[clavix] ssh_agent_status failed:", e);
    }
  }

  async function toggleSshAgent() {
    sshAgentBusy = true;
    sshAgentError = null;
    try {
      if (sshAgent.running) {
        await invoke("stop_ssh_agent");
      } else {
        sshAgent = await invoke<SshAgentStatus>("start_ssh_agent");
        sshAgentBusy = false;
        return;
      }
      await refreshSshAgentStatus();
    } catch (e) {
      sshAgentError = formatError(e);
    } finally {
      sshAgentBusy = false;
    }
  }

  async function copySshAgentPath() {
    if (sshAgent.socketPath) {
      await copyToClipboard(`export SSH_AUTH_SOCK=${sshAgent.socketPath}`, "SSH_AUTH_SOCK");
    }
  }
  let searchInput = $state<HTMLInputElement | null>(null);

  const GEN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const GEN_LOWER = "abcdefghijklmnopqrstuvwxyz";
  const GEN_DIGITS = "0123456789";
  const GEN_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";
  const GEN_AMBIGUOUS = /[O0Il1|`']/g;

  let genLength = $state(20);
  let genUpper = $state(true);
  let genLower = $state(true);
  let genDigits = $state(true);
  let genSymbols = $state(true);
  let genAvoidAmbiguous = $state(true);
  let genOutput = $state("");
  let genError = $state<string | null>(null);

  function regeneratePassword() {
    let charset = "";
    if (genUpper) charset += GEN_UPPER;
    if (genLower) charset += GEN_LOWER;
    if (genDigits) charset += GEN_DIGITS;
    if (genSymbols) charset += GEN_SYMBOLS;
    if (genAvoidAmbiguous) charset = charset.replace(GEN_AMBIGUOUS, "");
    if (charset.length === 0) {
      genOutput = "";
      genError = m.generator_empty_charset();
      return;
    }
    genError = null;
    const chars = Array.from(charset);
    const out: string[] = [];
    const rng = new Uint32Array(genLength);
    crypto.getRandomValues(rng);
    for (let i = 0; i < genLength; i++) {
      out.push(chars[rng[i] % chars.length]);
    }
    genOutput = out.join("");
  }

  function openGenerator() {
    if (!genOutput) regeneratePassword();
    generatorDialog?.showModal();
  }

  function closeGenerator() {
    generatorDialog?.close();
  }

  const TREE_WIDTH_MIN = 180;
  const TREE_WIDTH_MAX = 560;
  const TREE_WIDTH_STORAGE_KEY = "clavix.treeWidth";
  let treeWidth = $state(260);

  const ONBOARDED_STORAGE_KEY = "clavix.onboarded";
  const THEME_STORAGE_KEY = "clavix.theme";
  type ThemePref = "auto" | "dark";
  let themePref = $state<ThemePref>("auto");

  function applyTheme(next: ThemePref) {
    themePref = next;
    try {
      if (typeof document !== "undefined") {
        document.documentElement.classList.toggle("force-dark", next === "dark");
      }
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // best-effort — no SSR, no storage, we just render with the fallback
    }
  }

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
    void refreshSshAgentStatus();
  }

  function closeStats() {
    statsDialog?.close();
  }

  async function openAudit() {
    auditDialog?.showModal();
    auditError = null;
    auditResult = null;
    auditLoading = true;
    try {
      auditResult = await invoke<AuditResult>("audit_vault_passwords");
    } catch (e) {
      auditError = formatError(e);
    } finally {
      auditLoading = false;
    }
  }

  function closeAudit() {
    auditDialog?.close();
  }

  async function jumpToCipher(id: string) {
    auditDialog?.close();
    if (detail?.id !== id) {
      await openCipher(id);
    }
  }

  function openCreateEditor() {
    const presetFolder = folderPathFromKey(selectedKey ?? "");
    const folderMatch = presetFolder
      ? syncSummary?.folders.find((f) => f.name === presetFolder)
      : null;
    editorInitial = {
      ...EMPTY_EDITOR_INITIAL,
      folderId: folderMatch?.id ?? null,
    };
    editorMode = "create";
    editorOpen = true;
  }

  function openEditEditor() {
    if (!detail || !detail.login) return;
    const currentCipher = syncSummary?.ciphers.find((c) => c.id === detail!.id);
    editorInitial = {
      id: detail.id,
      name: currentCipher?.name ?? "",
      folderId: currentCipher?.folderId ?? null,
      favorite: currentCipher?.favorite ?? false,
      notes: "",
      username: detail.login.username ?? "",
      password: detail.login.password ?? "",
      uris: detail.login.uris ?? [],
      totp: detail.login.totp ?? "",
    };
    editorMode = "edit";
    editorOpen = true;
  }

  async function submitEditor(input: {
    name: string;
    folderId: string | null;
    favorite: boolean;
    notes: string;
    username: string;
    password: string;
    uris: string[];
    totp: string;
  }) {
    const payload = {
      name: input.name,
      folderId: input.folderId,
      favorite: input.favorite,
      notes: input.notes || null,
      login: {
        username: input.username || null,
        password: input.password || null,
        uris: input.uris,
        totp: input.totp || null,
      },
    };
    try {
      if (editorMode === "create") {
        const newId = await invoke<string>("create_login_cipher", { input: payload });
        await onSync();
        await openCipher(newId);
      } else if (editorInitial.id) {
        await invoke("update_login_cipher", {
          cipherId: editorInitial.id,
          input: payload,
        });
        await onSync();
        await openCipher(editorInitial.id);
      }
      editorOpen = false;
    } catch (e) {
      throw new Error(formatError(e));
    }
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
    let favorites = 0;
    let trash = 0;
    const byType = new Map<number, number>();
    if (!syncSummary) return { byFolder, byCollection, byOrg, favorites, trash, byType };
    for (const c of syncSummary.ciphers) {
      if (c.deletedDate !== null) {
        trash += 1;
        continue;
      }
      if (c.favorite) favorites += 1;
      byType.set(c.kind, (byType.get(c.kind) ?? 0) + 1);
      if (c.folderId) byFolder.set(c.folderId, (byFolder.get(c.folderId) ?? 0) + 1);
      if (c.organizationId) byOrg.set(c.organizationId, (byOrg.get(c.organizationId) ?? 0) + 1);
      for (const cid of c.collectionIds) {
        byCollection.set(cid, (byCollection.get(cid) ?? 0) + 1);
      }
    }
    return { byFolder, byCollection, byOrg, favorites, trash, byType };
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

  type SortKey = "name" | "username" | "uri";
  let sortKey = $state<SortKey>("name");
  let sortAsc = $state<boolean>(true);

  type QuickFilter = "all" | "favorites" | "trash" | `type:${number}`;
  let quickFilter = $state<QuickFilter>("all");

  function selectQuickFilter(f: QuickFilter) {
    quickFilter = f;
    selectedKey = null;
  }

  function matchesQuickFilter(c: CipherSummary): boolean {
    if (quickFilter === "trash") return c.deletedDate !== null;
    if (c.deletedDate !== null) return false;
    if (quickFilter === "favorites") return c.favorite;
    if (quickFilter.startsWith("type:")) {
      const k = parseInt(quickFilter.slice(5), 10);
      return c.kind === k;
    }
    return true;
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      sortAsc = true;
    }
  }

  function compareBy(a: string | null | undefined, b: string | null | undefined): number {
    const av = (a ?? "").toLowerCase();
    const bv = (b ?? "").toLowerCase();
    if (av === bv) return 0;
    if (av === "") return 1;
    if (bv === "") return -1;
    return av.localeCompare(bv, "fr");
  }

  const filteredCiphers = $derived.by(() => {
    if (!syncSummary) return [];
    const q = searchDebounced.trim().toLowerCase();
    let items = syncSummary.ciphers.filter(matchesQuickFilter);

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
      items = items.filter(
        (c) =>
          c.name.toLowerCase().includes(q) ||
          (c.username?.toLowerCase().includes(q) ?? false) ||
          (c.primaryUri?.toLowerCase().includes(q) ?? false),
      );
    }

    const sorted = [...items].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "name") cmp = compareBy(a.name, b.name);
      else if (sortKey === "username") cmp = compareBy(a.username, b.username);
      else cmp = compareBy(a.primaryUri, b.primaryUri);
      return sortAsc ? cmp : -cmp;
    });

    return sorted;
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

  async function restoreCipher(id: string) {
    try {
      await invoke("restore_cipher", { cipherId: id });
      if (syncSummary) {
        const c = syncSummary.ciphers.find((c) => c.id === id);
        if (c) c.deletedDate = null;
      }
      if (detail?.id === id) detail.id = detail.id;
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  async function deleteCipherForever(id: string) {
    if (!confirm(m.action_confirm_delete())) return;
    try {
      await invoke("delete_cipher", { cipherId: id });
      if (syncSummary) {
        syncSummary.ciphers = syncSummary.ciphers.filter((c) => c.id !== id);
      }
      if (detail?.id === id) closeDetail();
    } catch (e) {
      errorMsg = formatError(e);
    }
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
      const saved = localStorage.getItem(THEME_STORAGE_KEY) as ThemePref | null;
      applyTheme(saved === "dark" ? "dark" : "auto");
    } catch {
      applyTheme("auto");
    }

    try {
      const savedLocale = localStorage.getItem(LOCALE_STORAGE_KEY) as Locale | null;
      if (savedLocale === "fr" || savedLocale === "en") {
        applyLocale(savedLocale);
      } else {
        const browser = (navigator.language || "fr").toLowerCase();
        applyLocale(browser.startsWith("en") ? "en" : "fr");
      }
    } catch {
      applyLocale("fr");
    }

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
        let onboarded = false;
        try {
          onboarded = localStorage.getItem(ONBOARDED_STORAGE_KEY) === "1";
        } catch {
          onboarded = false;
        }
        phase = onboarded ? "idle" : "onboarding";
      }
    } catch (e) {
      errorMsg = formatError(e);
      phase = "idle";
    }
  });

  function completeOnboarding() {
    try {
      localStorage.setItem(ONBOARDED_STORAGE_KEY, "1");
    } catch {
      // best-effort : si localStorage indisponible, on continue sans persister
    }
    phase = "idle";
  }

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
        const supported = pendingProviders.find((p) => p === 0 || p === 3);
        selectedProvider = supported ?? pendingProviders[0] ?? 0;
        totpCode = "";
        yubikeyOtp = "";
        phase = "twoFactor";
      }
    } catch (e) {
      errorMsg = formatError(e);
      phase = "error";
    }
  }

  async function onTwoFactorSubmit(event: Event) {
    event.preventDefault();
    const codeSnapshot =
      selectedProvider === 3 ? yubikeyOtp.trim() : totpCode.trim();
    if (!codeSnapshot) return;
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<TokenSet>("login_with_two_factor", {
        serverUrl,
        email,
        password,
        code: codeSnapshot,
        provider: selectedProvider,
      });
      tokens = result;
      storedAccount = { serverUrl, email };
      password = "";
      totpCode = "";
      yubikeyOtp = "";
      phase = "loggedIn";
      await loadCachedVault();
    } catch (e) {
      errorMsg = formatError(e);
      phase = "twoFactor";
    }
  }

  const YUBIKEY_OTP_LENGTH = 44;

  function onYubikeyInput(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const value = input.value.trim().toLowerCase();
    yubikeyOtp = value;
    if (value.length === YUBIKEY_OTP_LENGTH) {
      input.form?.requestSubmit();
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
  {#key currentLocale}
  <h1>{m.app_name()}</h1>

  {#if phase === "init"}
    <p class="subtitle">{m.loading()}</p>
  {/if}

  {#if phase === "onboarding"}
    <Onboarding onComplete={completeOnboarding} />
  {/if}

  {#if phase === "idle" || (phase === "authenticating" && !storedAccount) || phase === "error"}
    <form onsubmit={onLoginSubmit}>
      <label>
        {m.form_server()}
        <input type="url" bind:value={serverUrl} required disabled={phase === "authenticating"} />
      </label>
      <label>
        {m.form_email()}
        <input type="email" bind:value={email} placeholder={m.form_email_placeholder()} required disabled={phase === "authenticating"} />
      </label>
      <label>
        {m.form_master_password()}
        <input type="password" bind:value={password} required disabled={phase === "authenticating"} />
      </label>
      <button type="submit" disabled={phase === "authenticating"}>
        {phase === "authenticating" ? m.action_signing_in() : m.action_sign_in()}
      </button>
    </form>
  {/if}

  {#if phase === "unlock" || (phase === "authenticating" && storedAccount)}
    <section class="box">
      <h2>{m.unlock_title()}</h2>
      <p class="hint">
        {storedAccount?.email} — {storedAccount?.serverUrl}
      </p>
      <form onsubmit={onUnlockSubmit}>
        <label>
          {m.form_master_password()}
          <input type="password" bind:value={password} required disabled={phase === "authenticating"} />
        </label>
        <div class="row">
          <button type="button" class="secondary" onclick={switchAccount}>{m.action_logout()}</button>
          <button type="submit" disabled={phase === "authenticating"}>
            {phase === "authenticating" ? m.action_unlocking() : m.action_unlock()}
          </button>
        </div>
      </form>
    </section>
  {/if}

  {#if phase === "twoFactor"}
    <section class="box">
      <h2>{m.two_factor_title()}</h2>
      <p class="hint">
        {m.two_factor_providers({ providers: pendingProviders.map(providerLabel).join(", ") })}
      </p>
      <form onsubmit={onTwoFactorSubmit}>
        {#if pendingProviders.filter((p) => p === 0 || p === 3).length > 1}
          <label>
            {m.two_factor_method_label()}
            <select bind:value={selectedProvider}>
              {#each pendingProviders.filter((p) => p === 0 || p === 3) as p}
                <option value={p}>{providerLabel(p)}</option>
              {/each}
            </select>
          </label>
        {/if}

        {#if selectedProvider === 0}
          <label>
            {m.two_factor_code_label()}
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
        {:else if selectedProvider === 3}
          <label>
            {m.two_factor_yubikey_label()}
            <input
              type="text"
              value={yubikeyOtp}
              oninput={onYubikeyInput}
              inputmode="text"
              maxlength={YUBIKEY_OTP_LENGTH}
              autocomplete="off"
              spellcheck="false"
              required
            />
          </label>
          <p class="hint">{m.two_factor_yubikey_help()}</p>
        {:else}
          <p class="hint">
            {m.two_factor_unsupported({ provider: providerLabel(selectedProvider) })}
          </p>
        {/if}

        <div class="row">
          <button type="button" class="secondary" onclick={reset}>{m.action_cancel()}</button>
          <button type="submit" disabled={selectedProvider !== 0 && selectedProvider !== 3}>
            {m.action_submit()}
          </button>
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
        <button type="button" class="secondary" onclick={switchAccount}>{m.action_logout()}</button>
        <button type="button" class="secondary" onclick={onLock}>{m.action_lock()}</button>
        <button type="button" onclick={onSync} disabled={syncing}>
          {syncing ? m.action_syncing() : syncSummary ? m.action_resync() : m.action_sync()}
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
                class:selected={selectedKey === null && quickFilter === "all"}
                class:drop-over={dragOverKey === "__all__"}
                onclick={() => selectQuickFilter("all")}
                ondragover={(e) => onNodeDragOver(e, "__all__")}
                ondragleave={() => onNodeDragLeave("__all__")}
                ondrop={onDropOnFolderRoot}
              >
                <span>{m.tree_all_items()}</span>
                <span class="tree-count">{(syncSummary.itemCount - cipherIndex.trash).toLocaleString(currentLocale === "fr" ? "fr-FR" : "en-US")}</span>
              </button>
              <button
                type="button"
                class="tree-all"
                class:selected={quickFilter === "favorites"}
                onclick={() => selectQuickFilter("favorites")}
              >
                <span>★ {m.tree_favorites()}</span>
                <span class="tree-count">{cipherIndex.favorites}</span>
              </button>
              <button
                type="button"
                class="tree-all"
                class:selected={quickFilter === "trash"}
                onclick={() => selectQuickFilter("trash")}
              >
                <span>🗑 {m.tree_trash()}</span>
                <span class="tree-count">{cipherIndex.trash}</span>
              </button>
              <details class="tree-types">
                <summary>{m.tree_types()}</summary>
                {#each [
                  [1, "🔐", m.type_login()],
                  [2, "📝", m.type_note()],
                  [3, "💳", m.type_card()],
                  [4, "🪪", m.type_identity()],
                  [5, "🔑", m.type_ssh_key()],
                ] as [k, icon, label]}
                  <button
                    type="button"
                    class="tree-all tree-type-btn"
                    class:selected={quickFilter === `type:${k}`}
                    onclick={() => selectQuickFilter(`type:${k}` as QuickFilter)}
                  >
                    <span>{icon} {label}</span>
                    <span class="tree-count">{cipherIndex.byType.get(k as number) ?? 0}</span>
                  </button>
                {/each}
              </details>
              {#if (folderTree && folderTree.children.length > 0) || orgTrees.length > 0}
                <div class="tree-toolbar">
                  <button type="button" class="secondary small" onclick={expandAllNodes}>
                    {m.tree_expand_all()}
                  </button>
                  <button type="button" class="secondary small" onclick={collapseAllNodes}>
                    {m.tree_collapse_all()}
                  </button>
                  <button
                    type="button"
                    class="secondary small info-button"
                    onclick={openCreateEditor}
                    title={m.action_new_item()}
                    aria-label={m.action_new_item()}
                  >
                    ＋
                  </button>
                  <button
                    type="button"
                    class="secondary small info-button"
                    onclick={openGenerator}
                    title={m.generator_label()}
                    aria-label={m.generator_label()}
                  >
                    🎲
                  </button>
                  <button
                    type="button"
                    class="secondary small info-button"
                    onclick={openAudit}
                    title={m.audit_label()}
                    aria-label={m.audit_label()}
                  >
                    🛡
                  </button>
                  <button
                    type="button"
                    class="secondary small info-button"
                    onclick={openStats}
                    title={m.tree_infos_label()}
                    aria-label={m.tree_infos_label()}
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
                <h4>{m.tree_organizations()}</h4>
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
                  placeholder={m.items_search_placeholder()}
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
                <div class="cipher-headers cipher-columns" role="row">
                  <span></span>
                  <button
                    type="button"
                    class="cipher-header"
                    class:active={sortKey === "name"}
                    onclick={() => toggleSort("name")}
                  >
                    {m.col_name()}
                    {#if sortKey === "name"}<span class="sort-arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
                  </button>
                  <button
                    type="button"
                    class="cipher-header"
                    class:active={sortKey === "username"}
                    onclick={() => toggleSort("username")}
                  >
                    {m.col_username()}
                    {#if sortKey === "username"}<span class="sort-arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
                  </button>
                  <button
                    type="button"
                    class="cipher-header"
                    class:active={sortKey === "uri"}
                    onclick={() => toggleSort("uri")}
                  >
                    {m.col_url()}
                    {#if sortKey === "uri"}<span class="sort-arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
                  </button>
                </div>
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
                            class="cipher-row cipher-columns"
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
                            <span class="col-name">
                              {c.name}
                              {#if c.favorite}<span class="star" title="Favori">★</span>{/if}
                            </span>
                            <span class="col-username" title={c.username ?? ""}>
                              {c.username ?? ""}
                            </span>
                            <span class="col-uri" title={c.primaryUri ?? ""}>
                              {c.primaryUri ?? ""}
                            </span>
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
                <div class="row">
                  {#if syncSummary?.ciphers.find((c) => c.id === detail?.id)?.deletedDate}
                    <button type="button" class="secondary small" onclick={() => restoreCipher(detail!.id)}>
                      {m.action_restore()}
                    </button>
                    <button type="button" class="small" onclick={() => deleteCipherForever(detail!.id)}>
                      {m.action_delete_forever()}
                    </button>
                  {:else if detail.kind === 1}
                    <button type="button" class="secondary small" onclick={openEditEditor}>
                      {m.action_edit()}
                    </button>
                  {/if}
                  <button type="button" class="secondary small" onclick={closeDetail}>{m.action_close()}</button>
                </div>
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
                    <dt>{m.detail_field_totp()}</dt>
                    <dd>
                      <TotpField
                        source={detail.login.totp}
                        onCopy={(code) => copyToClipboard(code, m.detail_field_totp())}
                      />
                    </dd>
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
      <h2>{m.error()}</h2>
      <pre>{errorMsg}</pre>
    </section>
  {/if}
  {/key}
</main>

{#if clipboardSecondsLeft !== null}
  <aside class="clipboard-toast" role="status">
    <span>
      Presse-papier ({clipboardLabel}) effacé dans {clipboardSecondsLeft}s
    </span>
    <button type="button" class="secondary small" onclick={clearClipboardNow}>Effacer maintenant</button>
  </aside>
{/if}

<dialog bind:this={generatorDialog} class="stats-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>{m.generator_title()}</h2>
      <button type="button" class="secondary small" onclick={closeGenerator} aria-label={m.action_close()}>
        ✕
      </button>
    </header>

    <div class="generator-output">
      <code>{genOutput || "—"}</code>
    </div>
    {#if genError}
      <p class="hint error-text">{genError}</p>
    {/if}

    <label class="generator-slider">
      {m.generator_length({ count: String(genLength) })}
      <input
        type="range"
        min="6"
        max="64"
        bind:value={genLength}
        oninput={regeneratePassword}
      />
    </label>

    <label class="generator-check">
      <input type="checkbox" bind:checked={genUpper} onchange={regeneratePassword} />
      {m.generator_upper()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={genLower} onchange={regeneratePassword} />
      {m.generator_lower()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={genDigits} onchange={regeneratePassword} />
      {m.generator_numbers()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={genSymbols} onchange={regeneratePassword} />
      {m.generator_symbols()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={genAvoidAmbiguous} onchange={regeneratePassword} />
      {m.generator_avoid_ambiguous()}
    </label>

    <div class="row" style:margin-top="0.75rem">
      <button type="button" class="secondary" onclick={regeneratePassword}>
        {m.generator_regenerate()}
      </button>
      <button
        type="button"
        onclick={() => genOutput && copyToClipboard(genOutput, m.detail_field_password())}
        disabled={!genOutput}
      >
        {m.action_copy()}
      </button>
    </div>
  {/key}
</dialog>

<dialog bind:this={statsDialog} class="stats-dialog">
  {#key currentLocale}
  {#if syncSummary}
    <header class="stats-header">
      <h2>{m.stats_title()}</h2>
      <button type="button" class="secondary small" onclick={closeStats} aria-label={m.action_close()}>
        ✕
      </button>
    </header>
    <dl>
      <dt>{m.stats_account()}</dt>
      <dd>{syncSummary.name ?? syncSummary.email}</dd>
      <dt>{m.stats_items()}</dt>
      <dd>{syncSummary.itemCount}</dd>
      <dt>{m.stats_folders()}</dt>
      <dd>{syncSummary.folderCount}</dd>
      <dt>{m.stats_collections()}</dt>
      <dd>{syncSummary.collectionCount}</dd>
      <dt>{m.stats_organizations()}</dt>
      <dd>{syncSummary.organizationCount}</dd>
    </dl>

    <h3>{m.settings_title()}</h3>
    <dl>
      <dt>{m.settings_language()}</dt>
      <dd>
        <select
          value={currentLocale}
          onchange={(e) => applyLocale((e.currentTarget as HTMLSelectElement).value as Locale, { reload: true })}
        >
          <option value="fr">Français</option>
          <option value="en">English</option>
        </select>
      </dd>
      <dt>{m.settings_theme()}</dt>
      <dd>
        <select
          value={themePref}
          onchange={(e) => applyTheme((e.currentTarget as HTMLSelectElement).value as ThemePref)}
        >
          <option value="auto">{m.settings_theme_auto()}</option>
          <option value="dark">{m.settings_theme_dark()}</option>
        </select>
      </dd>
      <dt>{m.stats_auto_lock()}</dt>
      <dd>
        <select
          value={autoLockMinutes}
          onchange={(e) => persistAutoLockSetting(parseInt((e.currentTarget as HTMLSelectElement).value, 10))}
        >
          <option value={0}>{m.stats_auto_lock_never()}</option>
          <option value={1}>{m.stats_auto_lock_minutes({ count: "1" })}</option>
          <option value={5}>{m.stats_auto_lock_minutes({ count: "5" })}</option>
          <option value={10}>{m.stats_auto_lock_minutes({ count: "10" })}</option>
          <option value={15}>{m.stats_auto_lock_minutes({ count: "15" })}</option>
          <option value={30}>{m.stats_auto_lock_minutes({ count: "30" })}</option>
          <option value={60}>{m.stats_auto_lock_hour()}</option>
        </select>
      </dd>
    </dl>

    <h3>{m.ssh_agent_title()}</h3>
    <p class="hint ssh-agent-hint">{m.ssh_agent_hint()}</p>
    <div class="ssh-agent-row">
      <button type="button" onclick={toggleSshAgent} disabled={sshAgentBusy}>
        {sshAgent.running ? m.ssh_agent_stop() : m.ssh_agent_start()}
      </button>
      <span class="ssh-agent-state" class:on={sshAgent.running}>
        {sshAgent.running
          ? m.ssh_agent_running({ count: String(sshAgent.keyCount) })
          : m.ssh_agent_stopped()}
      </span>
    </div>
    {#if sshAgent.running && sshAgent.socketPath}
      <div class="ssh-agent-sock">
        <code>{sshAgent.socketPath}</code>
        <button type="button" class="secondary small" onclick={copySshAgentPath}>
          {m.ssh_agent_copy_export()}
        </button>
      </div>
    {/if}
    {#if sshAgent.skippedCount > 0}
      <p class="hint">{m.ssh_agent_skipped({ count: String(sshAgent.skippedCount) })}</p>
    {/if}
    {#if sshAgentError}
      <p class="audit-error">{sshAgentError}</p>
    {/if}

    <h3>{m.stats_breakdown()}</h3>
    <dl>
      <dt>{m.stats_logins()}</dt>
      <dd>{syncSummary.typeCounts.login}</dd>
      <dt>{m.stats_notes()}</dt>
      <dd>{syncSummary.typeCounts.secureNote}</dd>
      <dt>{m.stats_cards()}</dt>
      <dd>{syncSummary.typeCounts.card}</dd>
      <dt>{m.stats_identities()}</dt>
      <dd>{syncSummary.typeCounts.identity}</dd>
      {#if syncSummary.typeCounts.sshKey > 0}
        <dt>{m.stats_ssh_keys()}</dt>
        <dd>{syncSummary.typeCounts.sshKey}</dd>
      {/if}
    </dl>
  {/if}
  {/key}
</dialog>

<dialog bind:this={auditDialog} class="stats-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>🛡 {m.audit_title()}</h2>
      <button type="button" class="secondary small" onclick={closeAudit} aria-label={m.action_close()}>
        ✕
      </button>
    </header>
    <p class="hint audit-privacy">{m.audit_privacy_note()}</p>

    {#if auditLoading}
      <p>{m.audit_running()}</p>
    {:else if auditError}
      <p class="audit-error">{auditError}</p>
      <div class="row">
        <button type="button" onclick={openAudit}>{m.action_retry()}</button>
      </div>
    {:else if auditResult}
      <p>{m.audit_checked({ count: String(auditResult.checked) })}</p>

      <h3 class="audit-h3">{m.audit_section_pwned()}</h3>
      {#if auditResult.pwned.length === 0}
        <p class="audit-success">✔ {m.audit_no_pwned()}</p>
      {:else}
        <p class="audit-warning">⚠ {m.audit_pwned_count({ count: String(auditResult.pwned.length) })}</p>
        <ul class="audit-list">
          {#each auditResult.pwned as entry (entry.cipherId)}
            <li>
              <button type="button" class="link-button" onclick={() => jumpToCipher(entry.cipherId)}>
                {entry.name}
              </button>
              <span class="audit-count">{m.audit_seen_n_times({ count: entry.count.toLocaleString(currentLocale === "fr" ? "fr-FR" : "en-US") })}</span>
            </li>
          {/each}
        </ul>
      {/if}

      <h3 class="audit-h3">{m.audit_section_reused()}</h3>
      {#if auditResult.reused.length === 0}
        <p class="audit-success">✔ {m.audit_no_reused()}</p>
      {:else}
        <p class="audit-warning">⚠ {m.audit_reused_count({ count: String(auditResult.reused.length) })}</p>
        <ul class="audit-list">
          {#each auditResult.reused as group, i (i)}
            <li class="audit-group">
              <span class="audit-count">{m.audit_reused_shared({ count: String(group.cipherIds.length) })}</span>
              <span class="audit-group-items">
                {#each group.cipherIds as cid, j (cid)}
                  <button type="button" class="link-button" onclick={() => jumpToCipher(cid)}>
                    {group.names[j]}
                  </button>{#if j < group.cipherIds.length - 1}, {/if}
                {/each}
              </span>
            </li>
          {/each}
        </ul>
      {/if}

      <h3 class="audit-h3">{m.audit_section_weak()}</h3>
      {#if auditResult.weak.length === 0}
        <p class="audit-success">✔ {m.audit_no_weak()}</p>
      {:else}
        <p class="audit-warning">⚠ {m.audit_weak_count({ count: String(auditResult.weak.length) })}</p>
        <ul class="audit-list">
          {#each auditResult.weak as entry (entry.cipherId)}
            <li>
              <button type="button" class="link-button" onclick={() => jumpToCipher(entry.cipherId)}>
                {entry.name}
              </button>
              <span class="audit-count">{m.audit_weak_score({ score: String(entry.score) })}</span>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  {/key}
</dialog>

{#key currentLocale}
  <LoginEditor
    open={editorOpen}
    mode={editorMode}
    initial={editorInitial}
    folders={syncSummary?.folders ?? []}
    onCancel={() => (editorOpen = false)}
    onSubmit={submitEditor}
  />
{/key}

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

  .audit-privacy {
    font-size: 0.82rem;
    margin-bottom: 0.75rem;
  }

  .ssh-agent-hint {
    font-size: 0.82rem;
    margin: 0.25rem 0 0.5rem;
  }

  .ssh-agent-row {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin: 0.3rem 0 0.5rem;
  }

  .ssh-agent-state {
    font-size: 0.88rem;
    color: #666;
  }

  .ssh-agent-state.on {
    color: #18683a;
    font-weight: 500;
  }

  .ssh-agent-sock {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
  }

  .ssh-agent-sock code {
    background: #f3f4f6;
    padding: 0.2rem 0.4rem;
    border-radius: 4px;
    font-size: 0.82rem;
    overflow-wrap: anywhere;
  }

  .audit-error {
    color: #7a1d1d;
    background: #fdecec;
    padding: 0.5rem 0.7rem;
    border-radius: 6px;
  }

  .audit-success {
    color: #18683a;
    font-weight: 500;
  }

  .audit-warning {
    color: #7a3b00;
    font-weight: 500;
    margin-top: 0.25rem;
  }

  .audit-list {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0;
    max-height: 320px;
    overflow-y: auto;
  }

  .audit-list li {
    display: flex;
    justify-content: space-between;
    gap: 0.5rem;
    padding: 0.35rem 0;
    border-bottom: 1px solid #eee;
  }

  .audit-list li:last-child {
    border-bottom: none;
  }

  .audit-h3 {
    margin-top: 1rem;
    margin-bottom: 0.3rem;
  }

  .audit-group {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2rem;
  }

  .audit-group-items {
    font-size: 0.9rem;
  }

  .audit-count {
    font-variant-numeric: tabular-nums;
    color: #7a3b00;
    font-size: 0.85rem;
    white-space: nowrap;
  }

  .link-button {
    background: none;
    border: none;
    padding: 0;
    color: #1f4db0;
    text-decoration: underline;
    cursor: pointer;
    font: inherit;
    text-align: left;
  }

  .link-button:hover {
    color: #0f307a;
  }

  .generator-output {
    background: #f3f4f6;
    padding: 0.6rem 0.8rem;
    border-radius: 6px;
    font-family: ui-monospace, monospace;
    font-size: 1rem;
    margin-bottom: 0.75rem;
    overflow-wrap: anywhere;
    min-height: 2.2rem;
  }

  .generator-slider {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin-bottom: 0.75rem;
    font-size: 0.9rem;
  }

  .generator-check {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.3rem;
    font-size: 0.9rem;
    cursor: pointer;
  }

  .error-text {
    color: #b91c1c;
  }

  @media (prefers-color-scheme: dark) {
    .generator-output { background: #1e1e1e; }
    .error-text { color: #ff8a8a; }
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

  .tree-types {
    margin-top: 0.25rem;
  }

  .tree-types summary {
    padding: 0.3rem 0.6rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #888;
    cursor: pointer;
    list-style: none;
  }

  .tree-types summary::-webkit-details-marker {
    display: none;
  }

  .tree-types .tree-type-btn {
    padding-left: 1.25rem;
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

  .cipher-columns {
    display: grid;
    grid-template-columns: 1.6rem minmax(0, 2fr) minmax(0, 1.4fr) minmax(0, 2fr);
    gap: 0.75rem;
  }

  .cipher-headers {
    padding: 0.25rem 0.5rem;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: #666;
    border-bottom: 1px solid #e5e5e5;
  }

  .cipher-header {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    background: transparent;
    border: none;
    padding: 0.2rem 0;
    cursor: pointer;
    color: inherit;
    font: inherit;
    text-align: left;
  }

  .cipher-header:hover {
    color: #1e3a8a;
  }

  .cipher-header.active {
    color: #1e3a8a;
    font-weight: 600;
  }

  .sort-arrow {
    font-size: 0.7rem;
  }

  @media (prefers-color-scheme: dark) {
    .cipher-headers { color: #aaa; border-bottom-color: #3a3a3a; }
    .cipher-header:hover, .cipher-header.active { color: #aabaff; }
  }

  .col-name,
  .col-username,
  .col-uri {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .col-name {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }

  .col-username,
  .col-uri {
    color: #666;
    font-size: 0.9em;
  }

  @media (prefers-color-scheme: dark) {
    .col-username, .col-uri { color: #aaa; }
  }

  @media (max-width: 900px) {
    .cipher-row.cipher-columns {
      grid-template-columns: 1.6rem minmax(0, 2fr) minmax(0, 1.4fr);
    }
    .col-uri { display: none; }
  }

  @media (max-width: 680px) {
    .cipher-row.cipher-columns {
      grid-template-columns: 1.6rem minmax(0, 1fr);
    }
    .col-username, .col-uri { display: none; }
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

  /* Force-dark override — duplicates the prefers-color-scheme: dark rules
     so that users can opt into dark mode even on a light system. */
  :global(:root.force-dark) {
    color: #f6f6f6;
    background-color: #1e1e1e;
  }
  :global(:root.force-dark) .generator-output { background: #1e1e1e; }
  :global(:root.force-dark) .error-text { color: #ff8a8a; }
  :global(:root.force-dark) .stats-dialog { background: #2b2b2b; color: #f6f6f6; }
  :global(:root.force-dark) .cipher-headers { color: #aaa; border-bottom-color: #3a3a3a; }
  :global(:root.force-dark) .cipher-header:hover,
  :global(:root.force-dark) .cipher-header.active { color: #aabaff; }
  :global(:root.force-dark) .col-username,
  :global(:root.force-dark) .col-uri { color: #aaa; }
  :global(:root.force-dark) .cipher-row:hover { background: #333; }
  :global(:root.force-dark) .cipher-row.selected { background: #1f2a54; color: #aabaff; }
  :global(:root.force-dark) .detail-field dt { color: #aaa; }
  :global(:root.force-dark) .tree-pane { background: #2b2b2b; box-shadow: none; }
  :global(:root.force-dark) .tree-pane h4 { color: #aaa; }
  :global(:root.force-dark) .tree-label:hover,
  :global(:root.force-dark) .tree-all:hover { background: #333; }
  :global(:root.force-dark) .tree-row.selected > .tree-label,
  :global(:root.force-dark) .tree-all.selected { background: #1f2a54; color: #aabaff; }
  :global(:root.force-dark) .tree-count { background: #333; color: #aaa; }
  :global(:root.force-dark) .tree-row.selected > .tree-label .tree-count {
    background: #2a3870;
    color: #aabaff;
  }
  :global(:root.force-dark) .tree-children { border-left-color: #444; }
  :global(:root.force-dark) .splitter::before { background: #3a3a3a; }
  :global(:root.force-dark) .splitter:hover { background: #1e3a8a; }
  :global(:root.force-dark) .splitter:hover::before { background: #60a5fa; }
  :global(:root.force-dark) .subtitle,
  :global(:root.force-dark) h3 small,
  :global(:root.force-dark) .hint { color: #aaa; }
  :global(:root.force-dark) h3 { color: #ccc; }
  :global(:root.force-dark) form,
  :global(:root.force-dark) .box { background: #2b2b2b; box-shadow: none; }
  :global(:root.force-dark) label { color: #ccc; }
  :global(:root.force-dark) input,
  :global(:root.force-dark) button { background: #1e1e1e; color: #f6f6f6; border-color: #3a3a3a; }
  :global(:root.force-dark) button { background: #396cd8; border-color: #396cd8; }
  :global(:root.force-dark) button.secondary { background: #2b2b2b; color: #ddd; border-color: #3a3a3a; }
  :global(:root.force-dark) dt { color: #ccc; }
  :global(:root.force-dark) .box.error pre { color: #ff8a8a; }
  :global(:root.force-dark) pre { background: #181818; }
  :global(:root.force-dark) code { background: #333; }
  :global(:root.force-dark) .badge { background: #1f2a54; color: #aabaff; }
</style>
