/**
 * Svelte action: promote a floating element (context menu) to the
 * browser's top layer as a manual popover.
 *
 * `position: fixed` plus a z-index is not enough under WebKitGTK: the
 * GTK overlay scrollbar of a scrolling pane (the folder tree) is
 * painted above every page layer, so it drew a stripe through the
 * menu whenever the menu crossed the pane's right edge. The top layer
 * sits above all of that. Engines without the Popover API keep the
 * plain fixed positioning, which is what the CSS already describes.
 */
export function topLayer(node: HTMLElement) {
  if (typeof node.showPopover !== "function") return;
  node.popover = "manual";
  node.showPopover();
}
