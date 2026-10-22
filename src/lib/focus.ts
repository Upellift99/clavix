import { tick } from "svelte";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), ' +
  'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function isVisible(el: HTMLElement): boolean {
  return el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0;
}

export function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(isVisible);
}

/**
 * Svelte action: move focus into `node` once it is mounted.
 *
 * Programmatic rather than the `autofocus` attribute so the a11y lint
 * stays quiet and the target can be a wrapper component's inner input.
 * Focus is deferred one tick so the element exists in the DOM.
 */
export function focusOnMount(node: HTMLElement) {
  void tick().then(() => node.focus());
}

export type TrapOptions = {
  /** Element (or selector within the trap) that takes focus on open. */
  initial?: HTMLElement | string | null;
};

/**
 * Svelte action: keep Tab / Shift+Tab inside `node` while it is mounted,
 * focus `initial` (or the first focusable control) on open, and give
 * focus back to the element that had it when the trap is destroyed.
 *
 * Meant for the hand-rolled `div[role="dialog"]` surfaces (editor,
 * import, export, QR scanner). The native `<dialog>` surfaces already
 * get this from `showModal()`.
 */
export function trapFocus(node: HTMLElement, options: TrapOptions = {}) {
  const previous = document.activeElement as HTMLElement | null;

  function resolveInitial(opts: TrapOptions): HTMLElement | null {
    const { initial } = opts;
    if (initial instanceof HTMLElement) return initial;
    if (typeof initial === "string") return node.querySelector<HTMLElement>(initial);
    return null;
  }

  function focusInitial(opts: TrapOptions) {
    void tick().then(() => {
      if (!node.isConnected) return;
      const target = resolveInitial(opts) ?? focusableWithin(node)[0] ?? node;
      target.focus();
    });
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key !== "Tab") return;
    const items = focusableWithin(node);
    if (items.length === 0) {
      event.preventDefault();
      node.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (event.shiftKey) {
      if (active === first || !node.contains(active)) {
        event.preventDefault();
        last.focus();
      }
    } else if (active === last || !node.contains(active)) {
      event.preventDefault();
      first.focus();
    }
  }

  node.addEventListener("keydown", onKeydown);
  focusInitial(options);

  return {
    update(next: TrapOptions) {
      options = next;
    },
    destroy() {
      node.removeEventListener("keydown", onKeydown);
      if (previous?.isConnected) previous.focus();
    },
  };
}
