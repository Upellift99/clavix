import { describe, expect, it } from "vitest";
import type { CipherSummary, TreeNode } from "./types";
import {
  FOLDERS_ROOT_PREFIX,
  buildCipherIndex,
  buildFolderTree,
  buildOrgTrees,
  collectAllKeys,
  collectCollectionIds,
  collectFolderIds,
  computeCollectionCounts,
  computeFolderCounts,
  findNode,
  folderPathFromKey,
  insertIntoTree,
  sortTree,
  splitPath,
} from "./tree";

function rootFolderNode(): TreeNode {
  return {
    key: "folders",
    label: "Folders",
    kind: "folder",
    folderId: null,
    organizationId: null,
    collectionId: null,
    children: [],
    itemCount: 0,
  };
}

function cipher(partial: Partial<CipherSummary>): CipherSummary {
  return {
    id: partial.id ?? "c",
    kind: partial.kind ?? 1,
    name: partial.name ?? "item",
    folderId: partial.folderId ?? null,
    organizationId: partial.organizationId ?? null,
    collectionIds: partial.collectionIds ?? [],
    favorite: partial.favorite ?? false,
    primaryUri: partial.primaryUri ?? null,
    username: partial.username ?? null,
    revisionDate: partial.revisionDate ?? null,
    deletedDate: partial.deletedDate ?? null,
  };
}

describe("splitPath", () => {
  it("splits on '/' and trims segments", () => {
    expect(splitPath(" work / projects /")).toEqual(["work", "projects"]);
  });

  it("drops empty segments", () => {
    expect(splitPath("a///b")).toEqual(["a", "b"]);
  });

  it("returns empty array for empty name", () => {
    expect(splitPath("")).toEqual([]);
    expect(splitPath("  ")).toEqual([]);
  });
});

describe("folderPathFromKey", () => {
  it("strips the folders/ prefix", () => {
    expect(folderPathFromKey(`${FOLDERS_ROOT_PREFIX}work/projects`)).toBe("work/projects");
  });

  it("returns null for keys without the prefix", () => {
    expect(folderPathFromKey("org/abc")).toBeNull();
  });

  it("strips the #id disambiguator that duplicates carry", () => {
    // Path-based operations (drag-drop reparenting, move_folder_path)
    // only understand names — collapsing the suffix back to the bare
    // path keeps them working when the user has two folders with the
    // same path. Their right-click delete/rename uses folderId so
    // duplicates stay individually addressable for the actions that
    // matter.
    expect(folderPathFromKey(`${FOLDERS_ROOT_PREFIX}Finance#abc-123`)).toBe("Finance");
    expect(folderPathFromKey(`${FOLDERS_ROOT_PREFIX}work/projects#xyz`)).toBe("work/projects");
  });
});

describe("insertIntoTree + computeFolderCounts", () => {
  it("inserts nested segments once", () => {
    const root = rootFolderNode();
    insertIntoTree(root, ["work", "projects"], { folderId: "f1", kind: "folder" });
    insertIntoTree(root, ["work", "notes"], { folderId: "f2", kind: "folder" });

    expect(root.children).toHaveLength(1);
    const work = root.children[0];
    expect(work.label).toBe("work");
    expect(work.children.map((c) => c.label).sort()).toEqual(["notes", "projects"]);
  });

  it("two folders with the same path produce two distinct leaves", () => {
    // Regression: pre-fix the second insert silently rewrote the
    // first leaf's folderId, so the user saw one "Finance" entry in
    // the sidebar even though Vaultwarden held two — and items
    // belonging to the rewritten folder lost their tree node.
    const root = rootFolderNode();
    insertIntoTree(root, ["Finance"], { folderId: "f-aaa", kind: "folder" });
    insertIntoTree(root, ["Finance"], { folderId: "f-bbb", kind: "folder" });

    expect(root.children).toHaveLength(2);
    const ids = root.children.map((c) => c.folderId).sort();
    expect(ids).toEqual(["f-aaa", "f-bbb"]);
    // Keys must be unique even though the labels collide.
    const keys = root.children.map((c) => c.key);
    expect(new Set(keys).size).toBe(2);
    // The first occurrence keeps the natural path key so existing
    // path-based selection (and `findNode("folders/Finance")`)
    // continues to work for the common single-folder case.
    expect(keys).toContain("folders/Finance");
  });

  it("a child of a duplicated parent still nests under the first occurrence", () => {
    // Document the behaviour the implementation actually delivers:
    // when two folders share a path AND one of them has a sub-path,
    // the sub-path attaches to whichever ancestor was inserted
    // first. There is no unambiguous answer here without a server-
    // side parent reference (Bitwarden folders are flat); we settle
    // for "consistent with insertion order" rather than guessing.
    const root = rootFolderNode();
    insertIntoTree(root, ["Finance"], { folderId: "f-aaa", kind: "folder" });
    insertIntoTree(root, ["Finance", "Reports"], { folderId: "f-rep", kind: "folder" });
    insertIntoTree(root, ["Finance"], { folderId: "f-bbb", kind: "folder" });

    expect(root.children).toHaveLength(2);
    const aaa = root.children.find((c) => c.folderId === "f-aaa")!;
    const bbb = root.children.find((c) => c.folderId === "f-bbb")!;
    expect(aaa.children.map((c) => c.folderId)).toEqual(["f-rep"]);
    expect(bbb.children).toEqual([]);
  });

  it("computes cumulative item counts", () => {
    const root = rootFolderNode();
    insertIntoTree(root, ["work"], { folderId: "f-work", kind: "folder" });
    insertIntoTree(root, ["work", "projects"], { folderId: "f-proj", kind: "folder" });
    const byFolder = new Map<string, number>([
      ["f-work", 2],
      ["f-proj", 3],
    ]);
    computeFolderCounts(root, byFolder);
    expect(root.children[0].itemCount).toBe(5);
    expect(root.children[0].children[0].itemCount).toBe(3);
  });
});

describe("sortTree", () => {
  it("sorts children alphabetically at every level", () => {
    const root = rootFolderNode();
    insertIntoTree(root, ["zeta"], { folderId: "z", kind: "folder" });
    insertIntoTree(root, ["alpha"], { folderId: "a", kind: "folder" });
    insertIntoTree(root, ["alpha", "gamma"], { folderId: "g", kind: "folder" });
    insertIntoTree(root, ["alpha", "beta"], { folderId: "b", kind: "folder" });

    sortTree(root);
    expect(root.children.map((c) => c.label)).toEqual(["alpha", "zeta"]);
    expect(root.children[0].children.map((c) => c.label)).toEqual(["beta", "gamma"]);
  });
});

describe("findNode", () => {
  it("locates a node by key across multiple trees", () => {
    const a = rootFolderNode();
    insertIntoTree(a, ["work"], { folderId: "w", kind: "folder" });
    const b: TreeNode = {
      ...rootFolderNode(),
      key: "org/x",
      label: "Org",
      kind: "organization",
      organizationId: "x",
    };
    insertIntoTree(b, ["Shared"], { collectionId: "c1", organizationId: "x", kind: "collection" });

    expect(findNode([a, b], "folders/work")?.folderId).toBe("w");
    expect(findNode([a, b], "org/x/Shared")?.collectionId).toBe("c1");
    expect(findNode([a, b], "unknown")).toBeNull();
  });
});

describe("collectFolderIds / collectCollectionIds / collectAllKeys", () => {
  it("aggregates folder ids recursively", () => {
    const root = rootFolderNode();
    insertIntoTree(root, ["a"], { folderId: "fa", kind: "folder" });
    insertIntoTree(root, ["a", "b"], { folderId: "fb", kind: "folder" });
    const ids = new Set<string>();
    collectFolderIds(root, ids);
    expect(ids).toEqual(new Set(["fa", "fb"]));
  });

  it("aggregates collection ids recursively", () => {
    const org: TreeNode = {
      ...rootFolderNode(),
      key: "org/1",
      kind: "organization",
      organizationId: "1",
    };
    insertIntoTree(org, ["Team"], { collectionId: "t", organizationId: "1", kind: "collection" });
    insertIntoTree(org, ["Team", "Dev"], { collectionId: "d", organizationId: "1", kind: "collection" });
    const ids = new Set<string>();
    collectCollectionIds(org, ids);
    expect(ids).toEqual(new Set(["t", "d"]));
  });

  it("collectAllKeys skips leaves but includes nodes with children", () => {
    const root = rootFolderNode();
    insertIntoTree(root, ["a"], { folderId: "a", kind: "folder" });
    insertIntoTree(root, ["a", "b"], { folderId: "b", kind: "folder" });
    const keys = new Set<string>();
    collectAllKeys(root, keys);
    expect(keys.has("folders")).toBe(true);
    expect(keys.has("folders/a")).toBe(true);
    expect(keys.has("folders/a/b")).toBe(false);
  });
});

describe("buildCipherIndex", () => {
  it("counts by folder, collection, org, type, favorites and trash", () => {
    const ciphers = [
      cipher({ id: "1", kind: 1, folderId: "f1", favorite: true }),
      cipher({ id: "2", kind: 1, folderId: "f1" }),
      cipher({ id: "3", kind: 2, organizationId: "o1", collectionIds: ["c1"] }),
      cipher({ id: "4", deletedDate: "2026-01-01" }),
      cipher({ id: "5", kind: 1, favorite: true, deletedDate: "2026-01-02" }),
    ];
    const idx = buildCipherIndex(ciphers);
    expect(idx.favorites).toBe(1); // deletedDate excludes #5 from the count
    expect(idx.trash).toBe(2);
    expect(idx.byFolder.get("f1")).toBe(2);
    expect(idx.byCollection.get("c1")).toBe(1);
    expect(idx.byOrg.get("o1")).toBe(1);
    expect(idx.byType.get(1)).toBe(2);
    expect(idx.byType.get(2)).toBe(1);
  });

  it("returns zeros when ciphers are undefined", () => {
    const idx = buildCipherIndex(undefined);
    expect(idx.favorites).toBe(0);
    expect(idx.trash).toBe(0);
    expect(idx.byFolder.size).toBe(0);
  });
});

describe("buildFolderTree + buildOrgTrees", () => {
  it("builds a folder tree and computes counts", () => {
    const tree = buildFolderTree(
      [
        { id: "w", name: "work" },
        { id: "p", name: "work/projects" },
      ],
      new Map([
        ["w", 1],
        ["p", 3],
      ]),
    );
    expect(tree?.children[0].label).toBe("work");
    expect(tree?.children[0].itemCount).toBe(4);
    expect(tree?.children[0].children[0].itemCount).toBe(3);
  });

  it("builds org trees with organization root counts", () => {
    const trees = buildOrgTrees(
      [{ id: "o1", name: "Acme" }],
      [
        { id: "c1", organizationId: "o1", name: "Team/Dev" },
        { id: "c2", organizationId: "o2", name: "Other" },
      ],
      new Map([["o1", 10]]),
      new Map([["c1", 3]]),
    );
    expect(trees).toHaveLength(1);
    expect(trees[0].label).toBe("Acme");
    expect(trees[0].itemCount).toBe(10);
    expect(trees[0].children[0].label).toBe("Team");
    expect(trees[0].children[0].children[0].label).toBe("Dev");
  });
});

describe("computeCollectionCounts", () => {
  it("preserves the organization root count but recomputes collection subtrees", () => {
    const org: TreeNode = {
      ...rootFolderNode(),
      key: "org/1",
      kind: "organization",
      organizationId: "1",
      itemCount: 42,
    };
    insertIntoTree(org, ["A"], { collectionId: "a", organizationId: "1", kind: "collection" });
    insertIntoTree(org, ["A", "B"], { collectionId: "b", organizationId: "1", kind: "collection" });
    computeCollectionCounts(
      org,
      new Map([
        ["a", 1],
        ["b", 2],
      ]),
    );
    expect(org.itemCount).toBe(42); // org root untouched
    expect(org.children[0].itemCount).toBe(3);
  });
});
