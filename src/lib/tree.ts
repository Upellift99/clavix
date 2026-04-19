import type {
  CipherSummary,
  CollectionSummary,
  FolderSummary,
  OrganizationSummary,
  TreeNode,
} from "./types";

export const FOLDERS_ROOT_PREFIX = "folders/";

export function folderPathFromKey(key: string): string | null {
  if (!key.startsWith(FOLDERS_ROOT_PREFIX)) return null;
  return key.slice(FOLDERS_ROOT_PREFIX.length);
}

export function splitPath(name: string): string[] {
  return name.split("/").map((s) => s.trim()).filter((s) => s.length > 0);
}

export function insertIntoTree(
  root: TreeNode,
  segments: string[],
  leaf: {
    folderId?: string;
    collectionId?: string;
    organizationId?: string;
    kind: "folder" | "collection";
  },
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

export function computeFolderCounts(node: TreeNode, byFolder: Map<string, number>): number {
  const direct = node.folderId ? (byFolder.get(node.folderId) ?? 0) : 0;
  let total = direct;
  for (const child of node.children) {
    total += computeFolderCounts(child, byFolder);
  }
  node.itemCount = total;
  return total;
}

export function computeCollectionCounts(node: TreeNode, byCollection: Map<string, number>): number {
  const direct = node.collectionId ? (byCollection.get(node.collectionId) ?? 0) : 0;
  let total = direct;
  for (const child of node.children) {
    total += computeCollectionCounts(child, byCollection);
  }
  if (node.kind !== "organization") {
    node.itemCount = total;
  }
  return total;
}

export function sortTree(node: TreeNode) {
  node.children.sort((a, b) => a.label.localeCompare(b.label, "fr"));
  for (const child of node.children) sortTree(child);
}

export function findNode(roots: TreeNode[], key: string): TreeNode | null {
  const visit = (node: TreeNode): TreeNode | null => {
    if (node.key === key) return node;
    for (const c of node.children) {
      const found = visit(c);
      if (found) return found;
    }
    return null;
  };
  for (const r of roots) {
    const hit = visit(r);
    if (hit) return hit;
  }
  return null;
}

export function collectFolderIds(node: TreeNode, ids: Set<string>) {
  if (node.folderId) ids.add(node.folderId);
  for (const c of node.children) collectFolderIds(c, ids);
}

export function collectCollectionIds(node: TreeNode, ids: Set<string>) {
  if (node.collectionId) ids.add(node.collectionId);
  for (const c of node.children) collectCollectionIds(c, ids);
}

export function collectAllKeys(node: TreeNode, into: Set<string>) {
  if (node.children.length === 0) return;
  into.add(node.key);
  for (const child of node.children) collectAllKeys(child, into);
}

export type CipherIndex = {
  byFolder: Map<string, number>;
  byCollection: Map<string, number>;
  byOrg: Map<string, number>;
  byType: Map<number, number>;
  favorites: number;
  trash: number;
};

export function buildCipherIndex(ciphers: CipherSummary[] | undefined): CipherIndex {
  const byFolder = new Map<string, number>();
  const byCollection = new Map<string, number>();
  const byOrg = new Map<string, number>();
  const byType = new Map<number, number>();
  let favorites = 0;
  let trash = 0;
  if (!ciphers) return { byFolder, byCollection, byOrg, byType, favorites, trash };
  for (const c of ciphers) {
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
  return { byFolder, byCollection, byOrg, byType, favorites, trash };
}

export function buildFolderTree(
  folders: FolderSummary[],
  byFolder: Map<string, number>,
): TreeNode | null {
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
  for (const f of folders) {
    const segments = splitPath(f.name);
    if (segments.length === 0) continue;
    insertIntoTree(root, segments, { folderId: f.id, kind: "folder" });
  }
  computeFolderCounts(root, byFolder);
  sortTree(root);
  return root;
}

export function buildOrgTrees(
  organizations: OrganizationSummary[],
  collections: CollectionSummary[],
  byOrg: Map<string, number>,
  byCollection: Map<string, number>,
): TreeNode[] {
  return organizations.map((org) => {
    const root: TreeNode = {
      key: `org/${org.id}`,
      label: org.name,
      kind: "organization",
      folderId: null,
      organizationId: org.id,
      collectionId: null,
      children: [],
      itemCount: byOrg.get(org.id) ?? 0,
    };
    for (const c of collections) {
      if (c.organizationId !== org.id) continue;
      const segments = splitPath(c.name);
      if (segments.length === 0) continue;
      insertIntoTree(root, segments, {
        collectionId: c.id,
        organizationId: org.id,
        kind: "collection",
      });
    }
    computeCollectionCounts(root, byCollection);
    sortTree(root);
    return root;
  });
}
