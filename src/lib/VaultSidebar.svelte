<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import Icon, { type IconName } from "./Icon.svelte";
  import { canDropFolderOn, isCipherDroppable, isFolderDropTarget } from "./drag";
  import type { DragController } from "./drag.svelte";
  import { folderPathFromKey } from "./tree";
  import type { CipherIndex } from "./tree";
  import type { Locale, QuickFilter, SyncSummary, TreeNode } from "./types";

  type Props = {
    summary: SyncSummary;
    folderTree: TreeNode | null;
    orgTrees: TreeNode[];
    cipherIndex: CipherIndex;
    expanded: Set<string>;
    selectedKey: string | null;
    quickFilter: QuickFilter;
    currentLocale: Locale;
    drag: DragController;
    onSelectQuickFilter: (f: QuickFilter) => void;
    onSelectNode: (key: string) => void;
    onToggleExpanded: (key: string) => void;
    onExpandAll: () => void;
    onCollapseAll: () => void;
    onMoveCipherToFolder: (cipherId: string, folderId: string | null) => Promise<void>;
    onMoveCipherToCollection: (cipherId: string, collectionId: string) => Promise<void>;
    onMoveFolderPath: (source: string, targetParent: string | null) => Promise<void>;
    onDeleteFolder: (folderId: string) => Promise<void>;
    onRenameFolder: (folderId: string, name: string) => Promise<void>;
  };

  let {
    summary,
    folderTree,
    orgTrees,
    cipherIndex,
    expanded,
    selectedKey,
    quickFilter,
    currentLocale,
    drag,
    onSelectQuickFilter,
    onSelectNode,
    onToggleExpanded,
    onExpandAll,
    onCollapseAll,
    onMoveCipherToFolder,
    onMoveCipherToCollection,
    onMoveFolderPath,
    onDeleteFolder,
    onRenameFolder,
  }: Props = $props();

  // Right-click context menu state. `node` is the folder leaf the
  // menu was opened against; `x`/`y` are viewport coordinates of the
  // contextmenu event so the menu pops up where the cursor was.
  // Native fields rather than a dedicated component because we have
  // no other context-menu surface in the app yet — keeps the footprint
  // small.
  let menuNode = $state<TreeNode | null>(null);
  let menuX = $state(0);
  let menuY = $state(0);
  let renamingNode = $state<TreeNode | null>(null);
  let renameValue = $state("");

  function openContextMenu(event: MouseEvent, node: TreeNode) {
    if (!node.folderId) return;
    event.preventDefault();
    menuNode = node;
    menuX = event.clientX;
    menuY = event.clientY;
  }

  function closeContextMenu() {
    menuNode = null;
  }

  async function confirmDelete() {
    const node = menuNode;
    if (!node?.folderId) return;
    closeContextMenu();
    const ok = window.confirm(
      m.folder_delete_confirm({ name: node.label, count: String(node.itemCount) }),
    );
    if (!ok) return;
    await onDeleteFolder(node.folderId);
  }

  function startRename() {
    if (!menuNode?.folderId) return;
    renamingNode = menuNode;
    renameValue = menuNode.label;
    closeContextMenu();
  }

  async function commitRename(event: Event) {
    event.preventDefault();
    const node = renamingNode;
    if (!node?.folderId) return;
    const next = renameValue.trim();
    renamingNode = null;
    if (next.length === 0 || next === node.label) return;
    await onRenameFolder(node.folderId, next);
  }

  function cancelRename() {
    renamingNode = null;
  }

  function onFolderDragStart(event: DragEvent, node: TreeNode) {
    const path = folderPathFromKey(node.key);
    if (!path) {
      event.preventDefault();
      return;
    }
    drag.startFolder(path);
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", `folder:${path}`);
    }
    event.stopPropagation();
  }

  function onFolderDragEnd() {
    drag.resetFolder();
  }

  function onNodeDragOver(event: DragEvent, key: string) {
    if (!drag.cipherId && !drag.folderPath) return;
    if (drag.folderPath) {
      const path = key === "__all__" ? null : folderPathFromKey(key);
      if (!canDropFolderOn(drag.folderPath, path)) return;
    }
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
    drag.overKey = key;
  }

  function onNodeDragLeave(key: string) {
    if (drag.overKey === key) drag.overKey = null;
  }

  async function onDropOnFolderRoot(event: DragEvent): Promise<void> {
    event.preventDefault();
    drag.overKey = null;
    if (drag.cipherId) {
      const cipherId = drag.cipherId;
      drag.cipherId = null;
      await onMoveCipherToFolder(cipherId, null);
      return;
    }
    if (drag.folderPath) {
      const source = drag.folderPath;
      drag.folderPath = null;
      await onMoveFolderPath(source, null);
    }
  }

  async function onDropOnFolderNode(event: DragEvent, node: TreeNode): Promise<void> {
    event.preventDefault();
    drag.overKey = null;
    if (drag.cipherId) {
      if (node.folderId) {
        const cipherId = drag.cipherId;
        drag.cipherId = null;
        await onMoveCipherToFolder(cipherId, node.folderId);
      }
      return;
    }
    if (drag.folderPath) {
      const source = drag.folderPath;
      const target = folderPathFromKey(node.key);
      const allowed = target !== null && canDropFolderOn(drag.folderPath, target);
      drag.folderPath = null;
      if (!allowed || target === null) return;
      await onMoveFolderPath(source, target);
    }
  }

  async function onDropOnCollection(event: DragEvent, collectionId: string): Promise<void> {
    event.preventDefault();
    drag.overKey = null;
    if (!drag.cipherId) return;
    const cipherId = drag.cipherId;
    drag.cipherId = null;
    await onMoveCipherToCollection(cipherId, collectionId);
  }

  const numberLocale = $derived(currentLocale === "fr" ? "fr-FR" : "en-US");

  // The cipher-type filter rows under the "Types" disclosure. Kept
  // here rather than inline in the template so the per-row icon name
  // gets typed as `IconName` and not as the union of every literal in
  // the table.
  const typeRows: Array<{ kind: number; icon: IconName; label: string }> = $derived(
    [
      { kind: 1, icon: "key", label: m.type_login() },
      { kind: 2, icon: "note", label: m.type_note() },
      { kind: 3, icon: "card", label: m.type_card() },
      { kind: 4, icon: "id-card", label: m.type_identity() },
      { kind: 5, icon: "terminal", label: m.type_ssh_key() },
    ],
  );
</script>

<aside class="tree-pane">
  <button
    type="button"
    class="tree-all"
    class:selected={selectedKey === null && quickFilter === "all"}
    class:drop-over={drag.overKey === "__all__"}
    onclick={() => onSelectQuickFilter("all")}
    ondragover={(e) => onNodeDragOver(e, "__all__")}
    ondragleave={() => onNodeDragLeave("__all__")}
    ondrop={onDropOnFolderRoot}
  >
    <span>{m.tree_all_items()}</span>
    <span class="tree-count">
      {(summary.itemCount - cipherIndex.trash).toLocaleString(numberLocale)}
    </span>
  </button>
  <button
    type="button"
    class="tree-all"
    class:selected={quickFilter === "favorites"}
    onclick={() => onSelectQuickFilter("favorites")}
  >
    <span class="tree-all-label"><Icon name="star" size={14} />{m.tree_favorites()}</span>
    <span class="tree-count">{cipherIndex.favorites}</span>
  </button>
  <button
    type="button"
    class="tree-all"
    class:selected={quickFilter === "trash"}
    onclick={() => onSelectQuickFilter("trash")}
  >
    <span class="tree-all-label"><Icon name="trash" size={14} />{m.tree_trash()}</span>
    <span class="tree-count">{cipherIndex.trash}</span>
  </button>
  <details class="tree-types">
    <summary>{m.tree_types()}</summary>
    {#each typeRows as row (row.kind)}
      <button
        type="button"
        class="tree-all tree-type-btn"
        class:selected={quickFilter === `type:${row.kind}`}
        onclick={() => onSelectQuickFilter(`type:${row.kind}` as QuickFilter)}
      >
        <span class="tree-all-label">
          <Icon name={row.icon} size={14} />{row.label}
        </span>
        <span class="tree-count">{cipherIndex.byType.get(row.kind) ?? 0}</span>
      </button>
    {/each}
  </details>
  {#if (folderTree && folderTree.children.length > 0) || orgTrees.length > 0}
    <div class="tree-toolbar">
      <button type="button" class="secondary small" onclick={onExpandAll}>
        {m.tree_expand_all()}
      </button>
      <button type="button" class="secondary small" onclick={onCollapseAll}>
        {m.tree_collapse_all()}
      </button>
    </div>
  {/if}
  {#if folderTree && folderTree.children.length > 0}
    <h4>{m.tree_my_vault()}</h4>
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

{#if menuNode}
  <!-- Click-anywhere-else dismisses; right-clicking on another folder
       repositions the same menu. The svelte-ignore is fine here:
       this is a transient dismiss layer, the keyboard reaches the
       menu items beneath it via tab order. -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="tree-menu-backdrop" onclick={closeContextMenu} oncontextmenu={(e) => e.preventDefault()}></div>
  <div
    class="tree-menu"
    role="menu"
    style="left: {menuX}px; top: {menuY}px;"
  >
    <button type="button" role="menuitem" onclick={startRename}>
      {m.folder_action_rename()}
    </button>
    <button type="button" role="menuitem" class="danger" onclick={confirmDelete}>
      {m.folder_action_delete()}
    </button>
  </div>
{/if}

{#snippet treeNode(node: TreeNode)}
  <li>
    <div
      class="tree-row"
      class:selected={selectedKey === node.key}
      class:drop-over={drag.overKey === node.key}
      class:droppable={
        (drag.cipherId !== null && isCipherDroppable(node)) ||
        isFolderDropTarget(node, drag.folderPath)
      }
    >
      {#if node.children.length > 0}
        <button
          type="button"
          class="tree-toggle"
          onclick={() => onToggleExpanded(node.key)}
          aria-label={expanded.has(node.key) ? "Réduire" : "Déplier"}
        >
          <Icon name={expanded.has(node.key) ? "chevron-down" : "chevron-right"} size={12} />
        </button>
      {:else}
        <span class="tree-spacer"></span>
      {/if}
      {#if renamingNode?.key === node.key}
        <form class="tree-rename" onsubmit={commitRename}>
          <!-- svelte-ignore a11y_autofocus -->
          <input
            type="text"
            bind:value={renameValue}
            autofocus
            onkeydown={(e) => {
              if (e.key === "Escape") {
                e.preventDefault();
                cancelRename();
              }
            }}
            onblur={cancelRename}
          />
        </form>
      {:else}
        <button
          type="button"
          class="tree-label"
          draggable={node.kind === "folder"}
          onclick={() => onSelectNode(node.key)}
          oncontextmenu={(e) =>
            node.kind === "folder" && node.folderId ? openContextMenu(e, node) : undefined}
          ondragstart={node.kind === "folder" ? (e) => onFolderDragStart(e, node) : undefined}
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
      {/if}
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
          onclick={() => onToggleExpanded(node.key)}
          aria-label={expanded.has(node.key) ? "Réduire" : "Déplier"}
        >
          <Icon name={expanded.has(node.key) ? "chevron-down" : "chevron-right"} size={12} />
        </button>
      {:else}
        <span class="tree-spacer"></span>
      {/if}
      <button type="button" class="tree-label" onclick={() => onSelectNode(node.key)}>
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
