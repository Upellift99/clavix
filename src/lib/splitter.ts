export type SplitterOptions = {
  axis?: "x" | "y";
  /** Si true, un déplacement positif (droite/bas) diminue la taille
   *  — utile quand le splitter est au bord opposé du panneau redimensionné. */
  invert?: boolean;
  min: number;
  max: number;
  startSize: number;
  onChange: (size: number) => void;
  onCommit: (size: number) => void;
};

/** Attaches mousemove/mouseup listeners to drive a splitter from a mousedown
 *  event. RAF-throttled to keep resize smooth. Supports horizontal (x) and
 *  vertical (y) axes, with optional inversion. */
export function startSplitterDrag(event: MouseEvent, opts: SplitterOptions): void {
  event.preventDefault();
  const axis = opts.axis ?? "x";
  const sign = opts.invert ? -1 : 1;
  const startCoord = axis === "x" ? event.clientX : event.clientY;
  document.body.style.cursor = axis === "x" ? "col-resize" : "row-resize";
  document.body.style.userSelect = "none";

  let pendingCoord: number | null = null;
  let rafId: number | null = null;
  let lastSize = opts.startSize;

  const applyPending = () => {
    rafId = null;
    if (pendingCoord === null) return;
    const delta = (pendingCoord - startCoord) * sign;
    pendingCoord = null;
    lastSize = Math.max(opts.min, Math.min(opts.max, opts.startSize + delta));
    opts.onChange(lastSize);
  };

  const onMove = (e: MouseEvent) => {
    pendingCoord = axis === "x" ? e.clientX : e.clientY;
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
    opts.onCommit(lastSize);
  };

  window.addEventListener("mousemove", onMove);
  window.addEventListener("mouseup", onUp);
}
