/**
 * Svelte action: promote a floating element (context menu) to the
 * browser's top layer as a manual popover, so no stacking context or
 * z-index elsewhere on the page can cover it.
 *
 * It does not keep WebKitGTK's native overlay scrollbars off the menu:
 * those are painted above the top layer too. The styled scrollbars in
 * styles/base.css handle that. Engines without the Popover API keep
 * the plain fixed positioning, which is what the CSS already describes.
 */
export function topLayer(node: HTMLElement) {
  if (typeof node.showPopover !== "function") return;
  node.popover = "manual";
  node.showPopover();
}
