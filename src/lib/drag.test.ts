import { describe, expect, it } from "vitest";
import { canDropFolderOn, isCipherDroppable, isFolderDropTarget } from "./drag";
import type { TreeNode } from "./types";

function folderNode(path: string, folderId: string | null = null): TreeNode {
  return {
    key: `folders/${path}`,
    label: path.split("/").pop() ?? path,
    kind: "folder",
    folderId,
    organizationId: null,
    collectionId: null,
    children: [],
    itemCount: 0,
  };
}

function collectionNode(id: string | null): TreeNode {
  return {
    key: "org/x/Name",
    label: "Name",
    kind: "collection",
    folderId: null,
    organizationId: "x",
    collectionId: id,
    children: [],
    itemCount: 0,
  };
}

describe("canDropFolderOn", () => {
  it("requires an active folder drag", () => {
    expect(canDropFolderOn(null, "anywhere")).toBe(false);
  });

  it("allows drop at the root (null target)", () => {
    expect(canDropFolderOn("work", null)).toBe(true);
  });

  it("rejects dropping onto itself", () => {
    expect(canDropFolderOn("work", "work")).toBe(false);
  });

  it("rejects dropping onto a descendant", () => {
    expect(canDropFolderOn("work", "work/projects")).toBe(false);
  });

  it("allows dropping onto a sibling / unrelated path", () => {
    expect(canDropFolderOn("work", "personal")).toBe(true);
    expect(canDropFolderOn("work", "personal/bills")).toBe(true);
  });
});

describe("isCipherDroppable", () => {
  it("accepts folders with an id and collections with an id", () => {
    expect(isCipherDroppable(folderNode("work", "f1"))).toBe(true);
    expect(isCipherDroppable(collectionNode("c1"))).toBe(true);
  });

  it("rejects folders without a real folder id (virtual nodes)", () => {
    expect(isCipherDroppable(folderNode("work", null))).toBe(false);
  });

  it("rejects organization roots", () => {
    const orgRoot: TreeNode = {
      key: "org/x",
      label: "Org",
      kind: "organization",
      folderId: null,
      organizationId: "x",
      collectionId: null,
      children: [],
      itemCount: 0,
    };
    expect(isCipherDroppable(orgRoot)).toBe(false);
  });
});

describe("isFolderDropTarget", () => {
  it("returns false without an active folder drag", () => {
    expect(isFolderDropTarget(folderNode("work"), null)).toBe(false);
  });

  it("returns false for non-folder nodes", () => {
    expect(isFolderDropTarget(collectionNode("c1"), "something")).toBe(false);
  });

  it("rejects drops on self or descendants", () => {
    expect(isFolderDropTarget(folderNode("work"), "work")).toBe(false);
    expect(isFolderDropTarget(folderNode("work/projects"), "work")).toBe(false);
  });

  it("accepts drops on unrelated folders", () => {
    expect(isFolderDropTarget(folderNode("personal"), "work")).toBe(true);
  });
});
