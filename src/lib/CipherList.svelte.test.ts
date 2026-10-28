// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

import CipherList from "./CipherList.svelte";
import { DragController } from "./drag.svelte";
import type { CipherSummary } from "./types";

// jsdom has no ResizeObserver; the list only uses it to size its window.
beforeEach(() => {
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    disconnect() {}
  };
});

afterEach(() => {
  cleanup();
});

function item(id: string, name: string): CipherSummary {
  return {
    id,
    kind: 1,
    name,
    folderId: null,
    organizationId: null,
    collectionIds: [],
    favorite: false,
    primaryUri: null,
    username: null,
    revisionDate: null,
    deletedDate: null,
    archivedDate: null,
  };
}

const ITEMS = [item("a", "Alpha"), item("b", "Bravo"), item("c", "Charlie")];

async function flush() {
  for (let i = 0; i < 3; i++) await tick();
}

function mount(overrides: Record<string, unknown> = {}) {
  const onOpenCipher = vi.fn();
  const onClearSelection = vi.fn();
  const onCreateItem = vi.fn();
  const onOpenImport = vi.fn();
  const { container } = render(CipherList, {
    props: {
      items: ITEMS,
      totalCount: ITEMS.length,
      hasNarrowing: false,
      gated: false,
      onShowAll: vi.fn(),
      selectedId: null,
      currentLocale: "fr" as const,
      sortKey: "name" as const,
      sortAsc: true,
      storedAccount: null,
      visibleColumns: { username: true, uri: true },
      drag: new DragController(),
      onOpenCipher,
      onEditCipher: vi.fn(),
      onRowContextMenu: vi.fn(),
      onToggleSort: vi.fn(),
      onToggleColumn: vi.fn(),
      onSearchInputRef: vi.fn(),
      search: "",
      selectedIds: new Set<string>(),
      onToggleSelection: vi.fn(),
      onSetSelection: vi.fn(),
      onClearSelection,
      folders: [],
      trashView: false,
      onBulkMove: vi.fn(),
      onBulkDelete: vi.fn(),
      onBulkRestore: vi.fn(),
      onCreateItem,
      onOpenImport,
      ...overrides,
    },
  });
  const search = container.querySelector("input[type='search']") as HTMLInputElement;
  const rows = () => Array.from(container.querySelectorAll<HTMLButtonElement>(".cipher-row"));
  return { container, search, rows, onOpenCipher, onClearSelection, onCreateItem, onOpenImport };
}

function key(target: Element, k: string) {
  const event = new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}

describe("CipherList keyboard flow", () => {
  it("focuses the search box on mount", async () => {
    const { search } = mount();
    await flush();
    expect(document.activeElement).toBe(search);
  });

  it("exposes exactly one row to the Tab order", async () => {
    const { rows } = mount();
    await flush();
    const stops = rows().filter((r) => r.tabIndex === 0);
    expect(stops.map((r) => r.dataset.id)).toEqual(["a"]);
  });

  it("makes the open item the Tab stop", async () => {
    const { rows } = mount({ selectedId: "b" });
    await flush();
    expect(rows().filter((r) => r.tabIndex === 0).map((r) => r.dataset.id)).toEqual(["b"]);
  });

  it("ArrowDown from the search box lands on the first row", async () => {
    const { search, rows } = mount();
    await flush();
    const event = key(search, "ArrowDown");
    await flush();
    expect(event.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(rows()[0]);
  });

  it("arrows move between rows, Home and End jump", async () => {
    const { search, rows } = mount();
    await flush();
    key(search, "ArrowDown");
    await flush();
    key(rows()[0], "ArrowDown");
    await flush();
    expect(document.activeElement?.getAttribute("data-id")).toBe("b");
    key(rows()[1], "End");
    await flush();
    expect(document.activeElement?.getAttribute("data-id")).toBe("c");
    key(rows()[2], "Home");
    await flush();
    expect(document.activeElement?.getAttribute("data-id")).toBe("a");
  });

  it("ArrowUp on the first row returns to the search box", async () => {
    const { search, rows } = mount();
    await flush();
    key(search, "ArrowDown");
    await flush();
    key(rows()[0], "ArrowUp");
    await flush();
    expect(document.activeElement).toBe(search);
  });

  it("Enter in the search box opens the first match and focuses its row", async () => {
    const { search, rows, onOpenCipher } = mount();
    await flush();
    key(search, "Enter");
    await flush();
    expect(onOpenCipher).toHaveBeenCalledWith("a");
    expect(document.activeElement).toBe(rows()[0]);
  });

  it("Enter in the search box does nothing while the list is gated", async () => {
    const { search, onOpenCipher } = mount({ gated: true });
    await flush();
    key(search, "Enter");
    await flush();
    expect(onOpenCipher).not.toHaveBeenCalled();
  });

  it("offers import and create on a brand-new vault", async () => {
    const { container, onCreateItem, onOpenImport } = mount({ items: [], totalCount: 0 });
    await flush();
    const buttons = Array.from(container.querySelectorAll<HTMLButtonElement>(".empty-actions button"));
    expect(buttons).toHaveLength(2);
    buttons[0].click();
    buttons[1].click();
    expect(onOpenImport).toHaveBeenCalledTimes(1);
    expect(onCreateItem).toHaveBeenCalledTimes(1);
  });

  it("hides the first-run actions when the vault is read-only", async () => {
    const { container } = mount({ items: [], totalCount: 0, readOnly: true });
    await flush();
    expect(container.querySelector(".empty-actions")).toBeNull();
    expect(container.querySelector(".empty-title")?.textContent).toContain("vide");
  });

  it("names every row so truncated titles still read in full", async () => {
    const { container } = mount();
    await flush();
    const name = container.querySelector(".cipher-row .col-name") as HTMLElement;
    expect(name.getAttribute("title")).toBe("Alpha");
  });
});
