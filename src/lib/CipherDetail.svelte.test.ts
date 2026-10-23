// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// The panel scores the password over IPC on mount; no Tauri backend here.
vi.mock("./api", () => ({
  api: {
    scoreCipherPassword: vi.fn().mockResolvedValue(null),
  },
}));

import CipherDetail from "./CipherDetail.svelte";
import type { CipherDetail as Detail } from "./types";

afterEach(() => {
  cleanup();
});

function detail(p: Partial<Detail>): Detail {
  return {
    id: "00000000-aaaa",
    kind: 1,
    name: "Same name",
    notes: null,
    organizationId: null,
    folderId: null,
    collectionIds: [],
    revisionDate: null,
    favorite: false,
    login: null,
    card: null,
    identity: null,
    sshKey: null,
    fields: [],
    passwordHistoryCount: 0,
    attachments: [],
    reprompt: false,
    ...p,
  };
}

function location(p: Partial<Detail>): string[] {
  const noop = () => {};
  const { container } = render(CipherDetail, {
    props: {
      detail: detail(p),
      summaryEntry: null,
      folders: [
        { id: "f1", name: "Work/Sites/Client A" },
        { id: "f2", name: "Work/Sites/Client B" },
      ],
      organizations: [{ id: "o1", name: "Acme" }],
      collections: [{ id: "c1", organizationId: "o1", name: "Infra/Prod" }],
      onCopy: noop,
      onClose: noop,
      onEdit: noop,
      onRestore: noop,
      onSoftDelete: noop,
      onDeleteForever: noop,
      onDuplicate: noop,
      onReprompt: async () => true,
      confirm: async () => true,
      onError: noop,
      onRefresh: noop,
    },
  });
  const items = container.querySelectorAll(".detail-header .detail-location li");
  return [...items].map((li) => li.textContent?.trim() ?? "");
}

describe("CipherDetail location", () => {
  it("shows the full folder path under the name", () => {
    expect(location({ folderId: "f1" })).toEqual(["Work › Sites › Client A"]);
  });

  it("tells two same-named items apart", () => {
    const a = location({ folderId: "f1" });
    cleanup();
    expect(location({ folderId: "f2" })).not.toEqual(a);
  });

  it("shows the organization and collection of a shared item", () => {
    expect(location({ organizationId: "o1", collectionIds: ["c1"] })).toEqual([
      "Acme › Infra › Prod",
    ]);
  });

  it("says so when the item is unfiled", () => {
    expect(location({})).toHaveLength(1);
    expect(location({})[0]).not.toBe("");
  });
});

describe("CipherDetail notes", () => {
  function mountNotes(over: Record<string, unknown> = {}) {
    const onReprompt = vi.fn().mockResolvedValue(true);
    const { container } = render(CipherDetail, {
      props: {
        detail: detail({ notes: "Codes de secours : 1111-2222" }),
        summaryEntry: null,
        folders: [],
        organizations: [],
        collections: [],
        onCopy: () => {},
        onClose: () => {},
        onEdit: () => {},
        onRestore: () => {},
        onSoftDelete: () => {},
        onDeleteForever: () => {},
        onDuplicate: () => {},
        onReprompt,
        confirm: async () => true,
        onError: () => {},
        onRefresh: () => {},
        ...over,
      },
    });
    return { container, onReprompt };
  }

  const flush = async () => {
    for (let i = 0; i < 4; i++) await tick();
  };

  it("blurs notes by default and keeps them out of the accessibility tree", async () => {
    const { container } = mountNotes();
    const blurred = container.querySelector(".notes-blurred");
    expect(blurred).not.toBeNull();
    expect(blurred?.querySelector('[aria-hidden="true"]')?.textContent).toContain("1111-2222");
    expect(container.querySelector("p.notes")).toBeNull();
  });

  it("reveals on click, through the reprompt gate", async () => {
    const { container, onReprompt } = mountNotes();
    (container.querySelector(".notes-blurred") as HTMLButtonElement).click();
    await flush();
    expect(onReprompt).toHaveBeenCalledTimes(1);
    expect(container.querySelector("p.notes")?.textContent).toContain("1111-2222");
  });

  it("stays blurred when the reprompt is refused", async () => {
    const { container } = mountNotes({ onReprompt: vi.fn().mockResolvedValue(false) });
    (container.querySelector(".notes-blurred") as HTMLButtonElement).click();
    await flush();
    expect(container.querySelector(".notes-blurred")).not.toBeNull();
    expect(container.querySelector("p.notes")).toBeNull();
  });

  it("shows notes plainly when the preference is off", async () => {
    const { container } = mountNotes({ blurNotes: false });
    expect(container.querySelector(".notes-blurred")).toBeNull();
    expect(container.querySelector("p.notes")?.textContent).toContain("1111-2222");
  });
});
