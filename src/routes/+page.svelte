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

  async function copySshAgentSocket(socketPath: string) {
    await copyToClipboard(`export SSH_AUTH_SOCK=${socketPath}`, "SSH_AUTH_SOCK");
  }

  async function lockAndReset() {
    await auth.lock();
    vault.reset();
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
    onError: (e) => (vault.error = formatError(e)),
  });

  setupAutoLock({
    getMinutes: () => prefs.autoLockMinutes,
    getLastActivityAt: () => prefs.lastActivityAt,
    markActivity: () => prefs.markActivity(),
    isLoggedIn: () => auth.phase === "loggedIn",
    onLock: lockAndReset,
  });

  onMount(async () => {
    prefs.bootstrap();
    await auth.bootstrap({ onboarded: prefs.isOnboarded() });
  });

  onDestroy(() => {
    clipboard.dispose();
    vault.dispose();
  });

  function completeOnboarding() {
    prefs.markOnboarded();
    auth.phase = "idle";
  }

  const errorMsg = $derived(auth.error ?? vault.error);
  const wide = $derived(auth.phase === "loggedIn" && vault.summary !== null);
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<main class="container" class:wide>
  {#key prefs.currentLocale}
    <AuthGate {auth} onOnboardingComplete={completeOnboarding} />

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
                onDeleteFolder={(id) => vault.deleteFolder(id)}
                onRenameFolder={(id, name) => vault.renameFolder(id, name)}
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
                selectedId={vault.detail?.id ?? null}
                sortKey={vault.sortKey}
                sortAsc={vault.sortAsc}
                storedAccount={auth.storedAccount}
                visibleColumns={prefs.visibleColumns}
                {drag}
                onOpenCipher={(id) => vault.openCipher(id)}
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
    onApplyLocale={(loc) => prefs.applyLocale(loc, { reload: true })}
    onApplyTheme={(t) => prefs.applyTheme(t)}
    onApplyAutoLock={(min) => prefs.setAutoLockMinutes(min)}
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
