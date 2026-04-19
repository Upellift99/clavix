import type { CipherSummary, QuickFilter, SortKey, TreeNode } from "./types";
import { collectCollectionIds, collectFolderIds, findNode } from "./tree";

export function matchesQuickFilter(c: CipherSummary, filter: QuickFilter): boolean {
  if (filter === "trash") return c.deletedDate !== null;
  if (c.deletedDate !== null) return false;
  if (filter === "favorites") return c.favorite;
  if (filter.startsWith("type:")) {
    const k = parseInt(filter.slice(5), 10);
    return c.kind === k;
  }
  return true;
}

export function compareBy(a: string | null | undefined, b: string | null | undefined): number {
  const av = (a ?? "").toLowerCase();
  const bv = (b ?? "").toLowerCase();
  if (av === bv) return 0;
  if (av === "") return 1;
  if (bv === "") return -1;
  return av.localeCompare(bv, "fr");
}

export function matchesSearch(c: CipherSummary, q: string): boolean {
  if (!q) return true;
  return (
    c.name.toLowerCase().includes(q) ||
    (c.username?.toLowerCase().includes(q) ?? false) ||
    (c.primaryUri?.toLowerCase().includes(q) ?? false)
  );
}

export function filterByTreeNode(
  items: CipherSummary[],
  node: TreeNode,
): CipherSummary[] {
  if (node.kind === "folder") {
    const ids = new Set<string>();
    collectFolderIds(node, ids);
    return items.filter((c) => c.folderId !== null && ids.has(c.folderId));
  }
  if (node.kind === "organization") {
    return items.filter((c) => c.organizationId === node.organizationId);
  }
  const ids = new Set<string>();
  collectCollectionIds(node, ids);
  return items.filter((c) => c.collectionIds.some((cid) => ids.has(cid)));
}

export function sortCiphers(
  items: CipherSummary[],
  sortKey: SortKey,
  sortAsc: boolean,
): CipherSummary[] {
  return [...items].sort((a, b) => {
    let cmp = 0;
    if (sortKey === "name") cmp = compareBy(a.name, b.name);
    else if (sortKey === "username") cmp = compareBy(a.username, b.username);
    else cmp = compareBy(a.primaryUri, b.primaryUri);
    return sortAsc ? cmp : -cmp;
  });
}

export function applyVaultFilters(
  ciphers: CipherSummary[],
  options: {
    quickFilter: QuickFilter;
    selectedKey: string | null;
    trees: TreeNode[];
    search: string;
    sortKey: SortKey;
    sortAsc: boolean;
  },
): CipherSummary[] {
  const q = options.search.trim().toLowerCase();
  let items = ciphers.filter((c) => matchesQuickFilter(c, options.quickFilter));

  if (options.selectedKey) {
    const node = findNode(options.trees, options.selectedKey);
    if (node) {
      items = filterByTreeNode(items, node);
    }
  }

  if (q) {
    items = items.filter((c) => matchesSearch(c, q));
  }

  return sortCiphers(items, options.sortKey, options.sortAsc);
}
