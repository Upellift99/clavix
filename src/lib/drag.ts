import type { TreeNode } from "./types";
import { folderPathFromKey } from "./tree";

export function canDropFolderOn(
  draggingFolderPath: string | null,
  targetPath: string | null,
): boolean {
  if (!draggingFolderPath) return false;
  if (targetPath === null) return true;
  if (targetPath === draggingFolderPath) return false;
  if (targetPath.startsWith(`${draggingFolderPath}/`)) return false;
  return true;
}

export function isCipherDroppable(node: TreeNode): boolean {
  return (
    (node.kind === "folder" && node.folderId !== null) ||
    (node.kind === "collection" && node.collectionId !== null)
  );
}

export function isFolderDropTarget(
  node: TreeNode,
  draggingFolderPath: string | null,
): boolean {
  if (draggingFolderPath === null) return false;
  if (node.kind !== "folder") return false;
  const path = folderPathFromKey(node.key);
  return canDropFolderOn(draggingFolderPath, path);
}
