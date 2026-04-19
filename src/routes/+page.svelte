<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { onDestroy, onMount } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import { getLocale, setLocale } from "$lib/paraglide/runtime";
  import Onboarding from "$lib/Onboarding.svelte";
  import LoginEditor from "$lib/LoginEditor.svelte";
  import AuthLoginForm from "$lib/AuthLoginForm.svelte";
  import UnlockForm from "$lib/UnlockForm.svelte";
  import TwoFactorForm from "$lib/TwoFactorForm.svelte";
  import SessionBar from "$lib/SessionBar.svelte";
  import VaultSidebar from "$lib/VaultSidebar.svelte";
  import CipherList from "$lib/CipherList.svelte";
  import CipherDetail from "$lib/CipherDetail.svelte";
  import ClipboardToast from "$lib/ClipboardToast.svelte";
  import GeneratorDialog from "$lib/GeneratorDialog.svelte";
  import StatsDialog from "$lib/StatsDialog.svelte";
  import AuditDialog from "$lib/AuditDialog.svelte";
  import { ClipboardController } from "$lib/clipboard.svelte";
  import { DragController } from "$lib/drag.svelte";
  import { api } from "$lib/api";
  import { formatError } from "$lib/format";
  import { applyVaultFilters } from "$lib/filter";
  import {
    buildCipherIndex,
    buildFolderTree,
    buildOrgTrees,
    collectAllKeys,
    folderPathFromKey,
  } from "$lib/tree";
  import {
    EMPTY_EDITOR_INITIAL,
    type CipherDetail as CipherDetailType,
    type EditorInitial,
    type EditorPayload,
    type Locale,
    type LoginResult,
    type Phase,
    type QuickFilter,
    type SortKey,
    type StoredAccount,
    type SyncSummary,
    type ThemePref,
    type TokenSet,
  } from "$lib/types";

  const LOCALE_STORAGE_KEY = "clavix.locale";
  const TREE_WIDTH_STORAGE_KEY = "clavix.treeWidth";
  const TREE_WIDTH_MIN = 180;
  const TREE_WIDTH_MAX = 560;
  const ONBOARDED_STORAGE_KEY = "clavix.onboarded";
  const THEME_STORAGE_KEY = "clavix.theme";
  const AUTO_LOCK_STORAGE_KEY = "clavix.autoLockMinutes";
  const AUTO_LOCK_DEFAULT_MINUTES = 10;

  let currentLocale = $state<Locale>("fr");
  let themePref = $state<ThemePref>("auto");
  let treeWidth = $state(260);
  let autoLockMinutes = $state<number>(AUTO_LOCK_DEFAULT_MINUTES);
  let lastActivityAt = $state<number>(Date.now());

  function applyLocale(loc: Locale, opts: { reload?: boolean } = {}) {
    currentLocale = loc;
    try {
      localStorage.setItem(LOCALE_STORAGE_KEY, loc);
    } catch {
      // ignore
    }
    setLocale(loc, { reload: opts.reload === true });
  }

  function applyTheme(next: ThemePref) {
    themePref = next;
    try {
      if (typeof document !== "undefined") {
        document.documentElement.classList.toggle("force-dark", next === "dark");
      }
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // best-effort
    }
  }

  function persistAutoLockSetting(minutes: number) {
    autoLockMinutes = minutes;
    try {
      localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(minutes));
    } catch {
      // ignore
    }
  }

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
  let detail = $state<CipherDetailType | null>(null);
  let detailLoading = $state(false);

  let sortKey = $state<SortKey>("name");
  let sortAsc = $state<boolean>(true);
  let quickFilter = $state<QuickFilter>("all");

  let editorOpen = $state(false);
  let editorMode = $state<"create" | "edit">("create");
  let editorInitial = $state<EditorInitial>(EMPTY_EDITOR_INITIAL);

  let searchInput: HTMLInputElement | null = null;
  let statsDialog = $state<{ open: () => Promise<void> } | null>(null);
  let auditDialog = $state<{ open: () => Promise<void> } | null>(null);
  let generatorDialog = $state<{ open: () => void } | null>(null);

  const clipboard = new ClipboardController();
  const drag = new DragController();

  async function copyToClipboard(value: string, label: string) {
    try {
      await clipboard.copy(value, label);
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  onDestroy(() => {
    clipboard.dispose();
  });

  const cipherIndex = $derived.by(() => buildCipherIndex(syncSummary?.ciphers));
  const folderTree = $derived.by(() =>
    syncSummary ? buildFolderTree(syncSummary.folders, cipherIndex.byFolder) : null,
  );
  const orgTrees = $derived.by(() =>
    syncSummary
      ? buildOrgTrees(
          syncSummary.organizations,
          syncSummary.collections,
          cipherIndex.byOrg,
          cipherIndex.byCollection,
        )
      : [],
  );
  const allTrees = $derived.by(() => {
    const list: typeof orgTrees = [];
    if (folderTree) list.push(folderTree);
    list.push(...orgTrees);
    return list;
  });

  const filteredCiphers = $derived.by(() =>
    syncSummary
      ? applyVaultFilters(syncSummary.ciphers, {
          quickFilter,
          selectedKey,
          trees: allTrees,
          search: searchDebounced,
          sortKey,
          sortAsc,
        })
      : [],
  );

  function selectQuickFilter(f: QuickFilter) {
    quickFilter = f;
    selectedKey = null;
  }

  function selectNode(key: string) {
    selectedKey = selectedKey === key ? null : key;
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      sortAsc = true;
    }
  }

  function toggleExpanded(key: string) {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    expanded = next;
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

  function openCreateEditor() {
    const presetFolder = selectedKey ? folderPathFromKey(selectedKey) : null;
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

  async function submitEditor(input: EditorPayload) {
    try {
      if (editorMode === "create") {
        const newId = await api.createLoginCipher(input);
        await onSync();
        await openCipher(newId);
      } else if (editorInitial.id) {
        await api.updateLoginCipher(editorInitial.id, input);
        await onSync();
        await openCipher(editorInitial.id);
      }
      editorOpen = false;
    } catch (e) {
      throw new Error(formatError(e));
    }
  }

  async function openCipher(id: string) {
    if (detail?.id === id) {
      detail = null;
      return;
    }
    detailLoading = true;
    errorMsg = null;
    try {
      detail = await api.getCipher(id);
    } catch (e) {
      errorMsg = formatError(e);
      detail = null;
    } finally {
      detailLoading = false;
    }
  }

  function closeDetail() {
    detail = null;
  }

  async function restoreCipher(id: string) {
    try {
      await api.restoreCipher(id);
      if (syncSummary) {
        const c = syncSummary.ciphers.find((c) => c.id === id);
        if (c) c.deletedDate = null;
      }
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  async function deleteCipherForever(id: string) {
    if (!confirm(m.action_confirm_delete())) return;
    try {
      await api.deleteCipher(id);
      if (syncSummary) {
        syncSummary.ciphers = syncSummary.ciphers.filter((c) => c.id !== id);
      }
      if (detail?.id === id) closeDetail();
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  async function moveCipherToFolder(cipherId: string, targetFolderId: string | null) {
    if (!syncSummary) return;
    const cipher = syncSummary.ciphers.find((c) => c.id === cipherId);
    if (!cipher) return;
    const previousFolderId = cipher.folderId;
    if (previousFolderId === targetFolderId) return;
    cipher.folderId = targetFolderId;
    try {
      await api.moveCipherToFolder(cipherId, targetFolderId);
    } catch (e) {
      cipher.folderId = previousFolderId;
      errorMsg = formatError(e);
    }
  }

  async function moveCipherToCollection(cipherId: string, targetCollectionId: string) {
    if (!syncSummary) return;
    const cipher = syncSummary.ciphers.find((c) => c.id === cipherId);
    if (!cipher) return;
    const targetCollection = syncSummary.collections.find((c) => c.id === targetCollectionId);
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
        errorMsg = formatError(e);
      }
      return;
    }

    try {
      await api.shareCipherToCollection(cipherId, targetCollectionId);
      syncSummary = await api.sync();
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  async function performFolderMove(sourcePath: string, targetParentPath: string | null) {
    try {
      await api.moveFolderPath(sourcePath, targetParentPath);
      syncSummary = await api.sync();
    } catch (e) {
      errorMsg = formatError(e);
    }
  }

  async function copySshAgentSocket(socketPath: string) {
    await copyToClipboard(`export SSH_AUTH_SOCK=${socketPath}`, "SSH_AUTH_SOCK");
  }

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
        // ignore
      }
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }

  function isTypingContext(): boolean {
    const a = document.activeElement as HTMLElement | null;
    if (!a) return false;
    const tag = a.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || a.isContentEditable;
  }

  async function handleGlobalKeydown(event: KeyboardEvent) {
    if (phase !== "loggedIn") return;
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

    if (!event.ctrlKey && !event.metaKey) return;
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
    }
  }

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
      applyLocale(getLocale() === "en" ? "en" : "fr");
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
      const account = await api.storedAccount();
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
      // best-effort
    }
    phase = "idle";
  }

  async function onLoginSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      const result: LoginResult = await api.login(serverUrl, email, password);
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
    const codeSnapshot = selectedProvider === 3 ? yubikeyOtp.trim() : totpCode.trim();
    if (!codeSnapshot) return;
    phase = "authenticating";
    errorMsg = null;
    try {
      tokens = await api.loginWithTwoFactor(
        serverUrl,
        email,
        password,
        codeSnapshot,
        selectedProvider,
      );
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

  async function onUnlockSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      tokens = await api.unlock(password);
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
      const cached = await api.loadCachedVault();
      if (cached) {
        syncSummary = cached;
      }
    } catch (e) {
      console.warn("[clavix] cached vault load failed:", e);
    }
  }

  async function onLock() {
    try {
      await api.lock();
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
      await api.logout();
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
      syncSummary = await api.sync();
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

  async function jumpToCipher(id: string) {
    if (detail?.id !== id) {
      await openCipher(id);
    }
  }

  const detailSummaryEntry = $derived(
    detail ? (syncSummary?.ciphers.find((c) => c.id === detail!.id) ?? null) : null,
  );
  const hasNarrowing = $derived(searchDebounced.trim() !== "" || selectedKey !== null);
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
      <AuthLoginForm
        bind:serverUrl
        bind:email
        bind:password
        disabled={phase === "authenticating"}
        onSubmit={onLoginSubmit}
      />
    {/if}

    {#if phase === "unlock" || (phase === "authenticating" && storedAccount)}
      <UnlockForm
        account={storedAccount}
        bind:password
        disabled={phase === "authenticating"}
        onSubmit={onUnlockSubmit}
        onSwitchAccount={switchAccount}
      />
    {/if}

    {#if phase === "twoFactor"}
      <TwoFactorForm
        providers={pendingProviders}
        bind:selectedProvider
        bind:totpCode
        bind:yubikeyOtp
        onSubmit={onTwoFactorSubmit}
        onCancel={reset}
      />
    {/if}

    {#if phase === "loggedIn" && tokens}
      <SessionBar
        {tokens}
        {syncing}
        hasSync={syncSummary !== null}
        onSync={onSync}
        onLock={onLock}
        onSwitchAccount={switchAccount}
      />

      {#if syncSummary}
        <section class="vault-section">
          {#if syncSummary.ciphers.length > 0}
            <div class="vault-layout" style="--tree-width: {treeWidth}px;">
              <VaultSidebar
                summary={syncSummary}
                {folderTree}
                {orgTrees}
                {cipherIndex}
                {expanded}
                {selectedKey}
                {quickFilter}
                {currentLocale}
                {drag}
                onSelectQuickFilter={selectQuickFilter}
                onSelectNode={selectNode}
                onToggleExpanded={toggleExpanded}
                onExpandAll={expandAllNodes}
                onCollapseAll={collapseAllNodes}
                onMoveCipherToFolder={moveCipherToFolder}
                onMoveCipherToCollection={moveCipherToCollection}
                onMoveFolderPath={performFolderMove}
                onCreateItem={openCreateEditor}
                onOpenGenerator={() => generatorDialog?.open()}
                onOpenAudit={() => auditDialog?.open()}
                onOpenStats={() => statsDialog?.open()}
              />

              <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
              <div
                class="splitter"
                role="separator"
                aria-orientation="vertical"
                aria-label="Redimensionner le panneau"
                onmousedown={onSplitterMouseDown}
              ></div>

              <CipherList
                items={filteredCiphers}
                totalCount={syncSummary.ciphers.length}
                {hasNarrowing}
                selectedId={detail?.id ?? null}
                {sortKey}
                {sortAsc}
                {storedAccount}
                {drag}
                onOpenCipher={openCipher}
                onToggleSort={toggleSort}
                onSearchInputRef={(el) => (searchInput = el)}
                bind:search
              />
            </div>

            {#if detailLoading}
              <section class="box">
                <p class="hint">Déchiffrement de l'item…</p>
              </section>
            {/if}

            {#if detail}
              <CipherDetail
                {detail}
                summaryEntry={detailSummaryEntry}
                organizations={syncSummary.organizations}
                onCopy={copyToClipboard}
                onClose={closeDetail}
                onEdit={openEditEditor}
                onRestore={restoreCipher}
                onDeleteForever={deleteCipherForever}
              />
            {/if}
          {/if}
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

<ClipboardToast {clipboard} />

<GeneratorDialog
  bind:this={generatorDialog}
  {currentLocale}
  onCopy={(value) => copyToClipboard(value, m.detail_field_password())}
/>

{#if syncSummary}
  <StatsDialog
    bind:this={statsDialog}
    summary={syncSummary}
    {currentLocale}
    {themePref}
    {autoLockMinutes}
    onApplyLocale={(loc) => applyLocale(loc, { reload: true })}
    onApplyTheme={applyTheme}
    onApplyAutoLock={persistAutoLockSetting}
    onCopySocketPath={copySshAgentSocket}
  />
{/if}

<AuditDialog
  bind:this={auditDialog}
  {currentLocale}
  onJumpToCipher={jumpToCipher}
/>

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

