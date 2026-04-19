export type SplitterOptions = {
  min: number;
  max: number;
  startWidth: number;
  onChange: (width: number) => void;
  onCommit: (width: number) => void;
};

/** Attaches mousemove/mouseup listeners to drive a horizontal splitter from a
 *  mousedown event. RAF-throttled to keep resize smooth. */
export function startSplitterDrag(event: MouseEvent, opts: SplitterOptions): void {
  event.preventDefault();
  const startX = event.clientX;
  document.body.style.cursor = "col-resize";
  document.body.style.userSelect = "none";

  let pendingX: number | null = null;
  let rafId: number | null = null;
  let lastWidth = opts.startWidth;

  const applyPending = () => {
    rafId = null;
    if (pendingX === null) return;
    const delta = pendingX - startX;
    pendingX = null;
    lastWidth = Math.max(opts.min, Math.min(opts.max, opts.startWidth + delta));
    opts.onChange(lastWidth);
  };

  const onMove = (e: MouseEvent) => {
    pendingX = e.clientX;
    if (rafId === null) {
      rafId = requestAnimationFrame(applyPending);
    }
  };

  const onUp = () => {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    applyPending();
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    window.removeEventListener("mousemove", onMove);
    window.removeEventListener("mouseup", onUp);
    opts.onCommit(lastWidth);
  };

  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);
}
