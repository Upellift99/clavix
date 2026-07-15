<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import * as m from "$lib/paraglide/messages";
  import CipherEditor from "$lib/CipherEditor.svelte";
  import ImportDialog from "$lib/ImportDialog.svelte";
  import ExportDialog from "$lib/ExportDialog.svelte";
  import AuthGate from "$lib/AuthGate.svelte";
  import Toolbar from "$lib/Toolbar.svelte";
  import VaultSidebar from "$lib/VaultSidebar.svelte";
  import CipherList from "$lib/CipherList.svelte";
  import CipherDetail from "$lib/CipherDetail.svelte";
  import ClipboardToast from "$lib/ClipboardToast.svelte";
  import GeneratorDialog from "$lib/GeneratorDialog.svelte";
  import StatsDialog from "$lib/StatsDialog.svelte";
  import AuditDialog from "$lib/AuditDialog.svelte";
  import { ClipboardController } from "$lib/clipboard.svelte";
  import { DragController } from "$lib/drag.svelte";
  import { AuthController } from "$lib/auth.svelte";
  import { VaultController } from "$lib/vault.svelte";
  import {
    DETAIL_HEIGHT_MAX,
    DETAIL_HEIGHT_MIN,
    PrefsController,
    TREE_WIDTH_MAX,
    TREE_WIDTH_MIN,
  } from "$lib/prefs.svelte";
  import { api } from "$lib/api";
  import { setupAutoLock } from "$lib/auto-lock.svelte";
  import { formatError } from "$lib/format";
  import { startSplitterDrag } from "$lib/splitter";
  import { makeVaultKeyHandler } from "$lib/keyboard";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import type { CipherDetail as CipherDetailData, CipherSummary } from "$lib/types";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";

  const prefs = new PrefsController();
  const drag = new DragController();
  const clipboard = new ClipboardController();
  const auth = new AuthController();
  const vault = new VaultController();

  let searchInput: HTMLInputElement | null = null;
  let statsDialog = $state<{ open: () => Promise<void> } | null>(null);
  let auditDialog = $state<{ open: () => Promise<void> } | null>(null);
  let generatorDialog = $state<{ open: () => void } | null>(null);
  let importOpen = $state(false);
  let exportOpen = $state(false);

  // "Show all items" is a per-session escape hatch from the gate: it lasts
  // until the vault is locked, and does not touch the stored preference.
  let showAllOnce = $state(false);
  const listGated = $derived(
    prefs.requireNarrowing &&
      !showAllOnce &&
      !vault.hasNarrowing &&
      vault.quickFilter === "all",
  );

  auth.on(async (event) => {
    if (event === "loggedIn") {
      // Paint the UI immediately from the encrypted local cache, then
      // reconcile against the server in the background. On a fresh
      // profile loadCached finds nothing and syncInBackground fills the
      // vault once the network roundtrip lands — no more empty screen
      // until the user hits "Sync" manually.
      await vault.loadCached();
      vault.syncInBackground();
    }
  });

  async function copyToClipboard(value: string, label: string) {
    try {
      await clipboard.copy(value, label);
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  // Right-click context menu over a list row. Mirrors the KeePassXC entry
  // menu: open, copy username (Ctrl+B), copy password (Ctrl+C), copy the
  // current TOTP (Ctrl+T), open the URL (Ctrl+U). Username/URL come straight
  // from the summary so the menu paints instantly; password/TOTP need the
  // decrypted detail, which we fetch in the background — those two rows only
  // appear once we actually know the item carries them.
  let menuCipher = $state<CipherSummary | null>(null);
  let menuDetail = $state<CipherDetailData | null>(null);
  let menuX = $state(0);
  let menuY = $state(0);
  let menuEl = $state<HTMLDivElement | null>(null);

  function openRowMenu(event: MouseEvent, cipher: CipherSummary) {
    event.preventDefault();
    menuCipher = cipher;
    menuDetail = vault.detail?.id === cipher.id ? vault.detail : null;
    menuX = event.clientX;
    menuY = event.clientY;
    // Only login items can carry a password/TOTP worth decrypting for.
    if (!menuDetail && cipher.kind === 1) {
      void loadMenuDetail(cipher.id);
    }
  }

  async function loadMenuDetail(id: string) {
    try {
      const detail = await api.getCipher(id);
      // Guard against a stale response: the menu may have closed or moved
      // to another row while the decrypt was in flight.
      if (menuCipher?.id === id) menuDetail = detail;
    } catch {
      // The menu simply won't gain the decrypt-only actions; opening the
      // item surfaces the real error through the normal path.
    }
  }

  function closeRowMenu() {
    menuCipher = null;
    menuDetail = null;
  }

  // Tug the menu back inside the viewport once laid out, so a right-click
  // near the right/bottom edge doesn't clip its actions.
  $effect(() => {
    if (menuCipher === null || menuEl === null) return;
    const rect = menuEl.getBoundingClientRect();
    const overflowX = rect.right - window.innerWidth;
    const overflowY = rect.bottom - window.innerHeight;
    if (overflowX > 0) menuX = Math.max(8, menuX - overflowX - 8);
    if (overflowY > 0) menuY = Math.max(8, menuY - overflowY - 8);
  });

  function openMenuCipher() {
    const id = menuCipher?.id;
    closeRowMenu();
    // openCipher toggles, so calling it on the already-open item would
    // close the panel — guard so "Ouvrir" never hides what it opens.
    if (id && vault.detail?.id !== id) vault.openCipher(id);
  }

  async function copyMenuUsername() {
    const username = menuDetail?.login?.username ?? menuCipher?.username;
    closeRowMenu();
    if (username) await copyToClipboard(username, "identifiant");
  }

  async function copyMenuPassword() {
    const id = menuCipher?.id;
    const hasPassword = menuDetail?.login?.hasPassword;
    closeRowMenu();
    if (!id || !hasPassword) return;
    try {
      const password = await api.revealField(id, "password");
      if (password) await copyToClipboard(password, "mot de passe");
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  async function copyMenuTotp() {
    const id = menuCipher?.id;
    const hasTotp = menuDetail?.login?.hasTotp;
    closeRowMenu();
    if (!id || !hasTotp) return;
    try {
      const { code } = await api.totpCode(id);
      await copyToClipboard(code, "code TOTP");
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  async function openMenuUri() {
    const uri = menuCipher?.primaryUri;
    closeRowMenu();
    if (!uri) return;
    try {
      await openUrl(uri);
    } catch (e) {
      vault.error = formatError(e);
    }
  }

  async function copySshAgentSocket(socketPath: string) {
    await copyToClipboard(`export SSH_AUTH_SOCK=${socketPath}`, "SSH_AUTH_SOCK");
  }

  async function lockAndReset() {
    await auth.lock();
    vault.reset();
    showAllOnce = false;
    closeRowMenu();
  }

  async function switchAccountAndReset() {
    await auth.switchAccount();
    vault.reset();
  }

  function onSplitterMouseDown(event: MouseEvent) {
    startSplitterDrag(event, {
      axis: "x",
      min: TREE_WIDTH_MIN,
      max: TREE_WIDTH_MAX,
      startSize: prefs.treeWidth,
      onChange: (w) => (prefs.treeWidth = w),
      onCommit: () => prefs.persistTreeWidth(),
    });
  }

  function onDetailSplitterMouseDown(event: MouseEvent) {
    startSplitterDrag(event, {
      axis: "y",
      invert: true,
      min: DETAIL_HEIGHT_MIN,
      max: DETAIL_HEIGHT_MAX,
      startSize: prefs.detailHeight,
      onChange: (h) => (prefs.detailHeight = h),
      onCommit: () => prefs.persistDetailHeight(),
    });
  }

  const handleGlobalKeydown = makeVaultKeyHandler({
    isLoggedIn: () => auth.phase === "loggedIn",
    getDetail: () => vault.detail,
    getSearchInput: () => searchInput,
    closeDetail: () => vault.closeDetail(),
    lock: () => lockAndReset(),
    copy: copyToClipboard,
    getPassword: async (id) => (await api.revealField(id, "password")) ?? "",
    getTotpCode: async (id) => (await api.totpCode(id)).code,
    onError: (e) => (vault.error = formatError(e)),
  });

  // Suppress the WebKitGTK native context menu (Reload / Back / Forward
  // / Inspect Element) everywhere except inside text-editable surfaces,
  // so users keep Paste / Copy / Spell-check on inputs, textareas and
  // contenteditable nodes. The folder-tree right-click in VaultSidebar
  // already calls preventDefault on its own; this handler covers every
  // other surface (cipher list, detail, dialogs, toolbar, empty space)
  // where the default debug menu would otherwise leak through.
  function suppressNativeContextMenu(event: MouseEvent) {
    const t = event.target;
    if (
      t instanceof HTMLInputElement ||
      t instanceof HTMLTextAreaElement ||
      (t instanceof HTMLElement && t.isContentEditable)
    ) {
      return;
    }
    event.preventDefault();
  }

  setupAutoLock({
    getMinutes: () => prefs.autoLockMinutes,
    getLastActivityAt: () => prefs.lastActivityAt,
    markActivity: () => prefs.markActivity(),
    isLoggedIn: () => auth.phase === "loggedIn",
    onLock: lockAndReset,
  });

  // Mirror the close-to-tray preference into Rust whenever it
  // changes (and once on bootstrap, after `prefs.bootstrap()` lands
  // the localStorage value). The window-event handler reads from
  // an AtomicBool on AppState, so this keeps the X button's
  // behaviour in lockstep with the dialog toggle.
  $effect(() => {
    api.setCloseToTray(prefs.closeToTray).catch((e) => {
      console.warn("[clavix] setCloseToTray failed:", e);
    });
  });
  $effect(() => {
    api.setMinimizeToTray(prefs.minimizeToTray).catch((e) => {
      console.warn("[clavix] setMinimizeToTray failed:", e);
    });
  });
  $effect(() => {
    api.setHideDockOnTray(prefs.hideDockOnTray).catch((e) => {
      console.warn("[clavix] setHideDockOnTray failed:", e);
    });
  });
  // Hand the user's locale to the tray menu builder so the
  // Ouvrir / Verrouiller / Quitter strings switch with the
  // language toggle. Native menus don't go through Paraglide,
  // hence the dedicated IPC.
  $effect(() => {
    api.setTrayLocale(prefs.currentLocale).catch((e) => {
      console.warn("[clavix] setTrayLocale failed:", e);
    });
  });

  let unlistenSessionLocked: UnlistenFn | null = null;

  onMount(async () => {
    prefs.bootstrap();
    await auth.bootstrap({ onboarded: prefs.isOnboarded() });
    // Tray menu "Verrouiller maintenant" clears the Rust session
    // out-of-band — without this listener the UI would stay on the
    // vault view until the next IPC call hits a session check.
    unlistenSessionLocked = await listen("clavix:session-locked", () => {
      lockAndReset();
    });
  });

  onDestroy(() => {
    clipboard.dispose();
    vault.dispose();
    unlistenSessionLocked?.();
  });

  function completeOnboarding() {
    prefs.markOnboarded();
    auth.phase = "idle";
  }

  const errorMsg = $derived(auth.error ?? vault.error);
  const wide = $derived(auth.phase === "loggedIn" && vault.summary !== null);
</script>

<svelte:window
  onkeydown={(e) => {
    if (e.key === "Escape" && menuCipher) {
      e.preventDefault();
      closeRowMenu();
      return;
    }
    handleGlobalKeydown(e);
  }}
  oncontextmenu={suppressNativeContextMenu}
/>

<main class="container" class:wide>
  {#key prefs.currentLocale}
    {#if auth.phase !== "loggedIn"}
      <div class="auth-screen">
        <AuthGate {auth} onOnboardingComplete={completeOnboarding} />
      </div>
    {:else}
      <AuthGate {auth} onOnboardingComplete={completeOnboarding} />
    {/if}

    {#if auth.phase === "loggedIn"}
      <Toolbar
        syncing={vault.syncing}
        hasSync={vault.summary !== null}
        lastSyncAt={vault.lastSyncAt}
        lastSyncError={vault.lastSyncError}
        onSync={() => vault.sync()}
        onLock={lockAndReset}
        onSwitchAccount={switchAccountAndReset}
        onCreateItem={() => vault.openCreateEditor()}
        onOpenImport={() => (importOpen = true)}
        onOpenExport={() => (exportOpen = true)}
        onOpenGenerator={() => generatorDialog?.open()}
        onOpenAudit={() => auditDialog?.open()}
        onOpenStats={() => statsDialog?.open()}
      />

      {#if vault.summary}
        <section class="vault-section">
          {#if vault.summary.ciphers.length > 0}
            <div class="vault-layout" style="--tree-width: {prefs.treeWidth}px;">
              <VaultSidebar
                summary={vault.summary}
                folderTree={vault.folderTree}
                orgTrees={vault.orgTrees}
                cipherIndex={vault.cipherIndex}
                expanded={vault.expanded}
                selectedKey={vault.selectedKey}
                quickFilter={vault.quickFilter}
                currentLocale={prefs.currentLocale}
                {drag}
                onSelectQuickFilter={(f) => vault.selectQuickFilter(f)}
                onSelectNode={(k) => vault.selectNode(k)}
                onToggleExpanded={(k) => vault.toggleExpanded(k)}
                onExpandAll={() => vault.expandAllNodes()}
                onCollapseAll={() => vault.collapseAllNodes()}
                onMoveCipherToFolder={(id, fid) => vault.moveCipherToFolder(id, fid)}
                onMoveCipherToCollection={(id, cid) => vault.moveCipherToCollection(id, cid)}
                onMoveFolderPath={(s, t) => vault.performFolderMove(s, t)}
                onDeleteFolder={(ids) => vault.deleteFolder(ids)}
                onRenameFolder={(src, dst) => vault.renameFolderPath(src, dst)}
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
                items={vault.filteredCiphers}
                totalCount={vault.summary.ciphers.length}
                hasNarrowing={vault.hasNarrowing}
                gated={listGated}
                onShowAll={() => (showAllOnce = true)}
                selectedId={vault.detail?.id ?? null}
                sortKey={vault.sortKey}
                sortAsc={vault.sortAsc}
                storedAccount={auth.storedAccount}
                visibleColumns={prefs.visibleColumns}
                {drag}
                onOpenCipher={(id) => vault.openCipher(id)}
                onRowContextMenu={openRowMenu}
                onToggleSort={(k) => vault.toggleSort(k)}
                onToggleColumn={(k, v) => prefs.setVisibleColumn(k, v)}
                onSearchInputRef={(el) => (searchInput = el)}
                bind:search={vault.search}
              />
            </div>

            {#if vault.detailLoading}
              <section class="box">
                <p class="hint">Déchiffrement de l'item…</p>
              </section>
            {/if}

            {#if vault.detail}
              <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
              <div
                class="detail-splitter"
                role="separator"
                aria-orientation="horizontal"
                aria-label="Redimensionner le panneau de détail"
                onmousedown={onDetailSplitterMouseDown}
              ></div>
              <div class="detail-pane" style="height: {prefs.detailHeight}px;">
                <CipherDetail
                  detail={vault.detail}
                  summaryEntry={vault.detailSummaryEntry}
                  organizations={vault.summary.organizations}
                  onCopy={copyToClipboard}
                  onClose={() => vault.closeDetail()}
                  onEdit={() => vault.openEditEditor()}
                  onRestore={(id) => vault.restoreCipher(id)}
                  onSoftDelete={(id) => vault.softDeleteCipher(id)}
                  onDeleteForever={(id) =>
                    vault.deleteCipherForever(id, m.action_confirm_delete())}
                />
              </div>
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

{#if menuCipher}
  <!-- Click-anywhere-else dismisses; right-clicking elsewhere is swallowed so
       the native WebKit menu never leaks through. Keyboard reaches the items
       via tab order, Escape closes it (handled on the window). -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div
    class="ctx-menu-backdrop"
    onclick={closeRowMenu}
    oncontextmenu={(e) => {
      e.preventDefault();
      closeRowMenu();
    }}
  ></div>
  <div
    bind:this={menuEl}
    class="ctx-menu"
    role="menu"
    style="left: {menuX}px; top: {menuY}px;"
  >
    <button type="button" role="menuitem" onclick={openMenuCipher}>
      <span class="ctx-label">{m.ctx_open()}</span>
    </button>
    {#if menuCipher.username}
      <button type="button" role="menuitem" onclick={copyMenuUsername}>
        <span class="ctx-label">{m.ctx_copy_username()}</span>
        <kbd class="ctx-shortcut">Ctrl+B</kbd>
      </button>
    {/if}
    {#if menuDetail?.login?.hasPassword}
      <button type="button" role="menuitem" onclick={copyMenuPassword}>
        <span class="ctx-label">{m.ctx_copy_password()}</span>
        <kbd class="ctx-shortcut">Ctrl+C</kbd>
      </button>
    {/if}
    {#if menuDetail?.login?.hasTotp}
      <button type="button" role="menuitem" onclick={copyMenuTotp}>
        <span class="ctx-label">{m.ctx_copy_totp()}</span>
        <kbd class="ctx-shortcut">Ctrl+T</kbd>
      </button>
    {/if}
    {#if menuCipher.primaryUri}
      <button type="button" role="menuitem" onclick={openMenuUri}>
        <span class="ctx-label">{m.ctx_open_url()}</span>
        <kbd class="ctx-shortcut">Ctrl+U</kbd>
      </button>
    {/if}
  </div>
{/if}

<GeneratorDialog
  bind:this={generatorDialog}
  currentLocale={prefs.currentLocale}
  onCopy={(value) => copyToClipboard(value, m.detail_field_password())}
/>

{#if vault.summary}
  <StatsDialog
    bind:this={statsDialog}
    summary={vault.summary}
    currentLocale={prefs.currentLocale}
    themePref={prefs.themePref}
    autoLockMinutes={prefs.autoLockMinutes}
    closeToTray={prefs.closeToTray}
    minimizeToTray={prefs.minimizeToTray}
    hideDockOnTray={prefs.hideDockOnTray}
    requireNarrowing={prefs.requireNarrowing}
    onApplyLocale={(loc) => prefs.applyLocale(loc, { reload: true })}
    onApplyTheme={(t) => prefs.applyTheme(t)}
    onApplyAutoLock={(min) => prefs.setAutoLockMinutes(min)}
    onApplyCloseToTray={(v) => prefs.setCloseToTray(v)}
    onApplyMinimizeToTray={(v) => prefs.setMinimizeToTray(v)}
    onApplyHideDockOnTray={(v) => prefs.setHideDockOnTray(v)}
    onApplyRequireNarrowing={(v) => prefs.setRequireNarrowing(v)}
    onCopySocketPath={copySshAgentSocket}
  />
{/if}

<AuditDialog
  bind:this={auditDialog}
  currentLocale={prefs.currentLocale}
  onJumpToCipher={(id) => vault.jumpToCipher(id)}
/>

{#key prefs.currentLocale}
  <CipherEditor
    open={vault.editorOpen}
    mode={vault.editorMode}
    initial={vault.editorInitial}
    folders={vault.summary?.folders ?? []}
    organizations={vault.summary?.organizations ?? []}
    collections={vault.summary?.collections ?? []}
    onCancel={() => vault.closeEditor()}
    onSubmit={(input) => vault.submitEditor(input)}
  />
  <ImportDialog
    open={importOpen}
    folders={vault.summary?.folders ?? []}
    existing={vault.summary?.ciphers ?? []}
    onCancel={() => (importOpen = false)}
    onDone={async () => {
      importOpen = false;
      await vault.sync();
    }}
  />
  <ExportDialog
    open={exportOpen}
    ciphers={vault.summary?.ciphers ?? []}
    folders={vault.summary?.folders ?? []}
    onCancel={() => (exportOpen = false)}
  />
{/key}
