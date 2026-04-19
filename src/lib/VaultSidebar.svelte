<script lang="ts">
  import * as m from "$lib/paraglide/messages";
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
    onCreateItem: () => void;
    onOpenImport: () => void;
    onOpenGenerator: () => void;
    onOpenAudit: () => void;
    onOpenStats: () => void;
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
    onCreateItem,
    onOpenImport,
    onOpenGenerator,
    onOpenAudit,
    onOpenStats,
  }: Props = $props();

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
    <span>★ {m.tree_favorites()}</span>
    <span class="tree-count">{cipherIndex.favorites}</span>
  </button>
  <button
    type="button"
    class="tree-all"
    class:selected={quickFilter === "trash"}
    onclick={() => onSelectQuickFilter("trash")}
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
        onclick={() => onSelectQuickFilter(`type:${k}` as QuickFilter)}
      >
        <span>{icon} {label}</span>
        <span class="tree-count">{cipherIndex.byType.get(k as number) ?? 0}</span>
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
      <button
        type="button"
        class="secondary small info-button"
        onclick={onCreateItem}
        title={m.action_new_item()}
        aria-label={m.action_new_item()}
      >
        ＋
      </button>
      <button
        type="button"
        class="secondary small info-button"
        onclick={onOpenImport}
        title={m.import_label()}
        aria-label={m.import_label()}
      >
        📥
      </button>
      <button
        type="button"
        class="secondary small info-button"
        onclick={onOpenGenerator}
        title={m.generator_label()}
        aria-label={m.generator_label()}
      >
        🎲
      </button>
      <button
        type="button"
        class="secondary small info-button"
        onclick={onOpenAudit}
        title={m.audit_label()}
        aria-label={m.audit_label()}
      >
        🛡
      </button>
      <button
        type="button"
        class="secondary small info-button"
        onclick={onOpenStats}
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
          {expanded.has(node.key) ? "▼" : "▶"}
        </button>
      {:else}
        <span class="tree-spacer"></span>
      {/if}
      <button
        type="button"
        class="tree-label"
        draggable={node.kind === "folder"}
        onclick={() => onSelectNode(node.key)}
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
          {expanded.has(node.key) ? "▼" : "▶"}
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
