// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";

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
