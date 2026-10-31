import { describe, expect, it } from "vitest";
import {
  applyVaultFilters,
  compareBy,
  matchesQuickFilter,
  matchesSearch,
  sortCiphers,
} from "./filter";
import { buildFolderTree, buildOrgTrees } from "./tree";
import type { CipherSummary } from "./types";

function cipher(p: Partial<CipherSummary>): CipherSummary {
  return {
    id: p.id ?? "c",
    kind: p.kind ?? 1,
    name: p.name ?? "item",
    folderId: p.folderId ?? null,
    organizationId: p.organizationId ?? null,
    collectionIds: p.collectionIds ?? [],
    favorite: p.favorite ?? false,
    primaryUri: p.primaryUri ?? null,
    username: p.username ?? null,
    revisionDate: null,
    deletedDate: p.deletedDate ?? null,
    archivedDate: p.archivedDate ?? null,
    notes: p.notes ?? null,
  };
}

describe("matchesSearch", () => {
  it("finds a term that only appears in the notes", () => {
    const c = cipher({ name: "Box", notes: "recovery code: 1234-5678" });
    expect(matchesSearch(c, "recovery")).toBe(true);
    expect(matchesSearch(c, "1234")).toBe(true);
  });

  it("matches terms spread across the notes and another field", () => {
    const c = cipher({ name: "Box", username: "admin", notes: "rack 3, shelf B" });
    expect(matchesSearch(c, "admin rack")).toBe(true);
  });

  it("ignores diacritics in the notes like everywhere else", () => {
    const c = cipher({ notes: "Téléphonie du bureau" });
    expect(matchesSearch(c, "telephonie")).toBe(true);
  });

  // The summary carries no notes for a reprompt item, or when the
  // preference is off: nothing to match, whatever the query.
  it("matches nothing in the notes when the summary carries none", () => {
    const c = cipher({ name: "Box", notes: null });
    expect(matchesSearch(c, "recovery")).toBe(false);
    expect(matchesSearch(c, "box")).toBe(true);
  });
});

describe("matchesQuickFilter", () => {
  it("keeps only trashed items under 'trash'", () => {
    const a = cipher({ id: "a" });
    const b = cipher({ id: "b", deletedDate: "2026-01-01" });
    expect(matchesQuickFilter(a, "trash")).toBe(false);
    expect(matchesQuickFilter(b, "trash")).toBe(true);
  });

  it("hides deleted items on non-trash filters", () => {
    const trashed = cipher({ id: "x", deletedDate: "2026-01-01", favorite: true });
    expect(matchesQuickFilter(trashed, "favorites")).toBe(false);
    expect(matchesQuickFilter(trashed, "all")).toBe(false);
    expect(matchesQuickFilter(trashed, "type:1")).toBe(false);
  });

  it("keeps only archived items under 'archive'", () => {
    const live = cipher({ id: "a" });
    const archived = cipher({ id: "b", archivedDate: "2026-10-01T09:30:00.000000Z" });
    expect(matchesQuickFilter(live, "archive")).toBe(false);
    expect(matchesQuickFilter(archived, "archive")).toBe(true);
  });

  it("hides archived items on every other filter", () => {
    const archived = cipher({ archivedDate: "2026-10-01", favorite: true });
    expect(matchesQuickFilter(archived, "all")).toBe(false);
    expect(matchesQuickFilter(archived, "favorites")).toBe(false);
    expect(matchesQuickFilter(archived, "type:1")).toBe(false);
    expect(matchesQuickFilter(archived, "trash")).toBe(false);
  });

  it("lets the trash win over the archive", () => {
    const both = cipher({ archivedDate: "2026-10-01", deletedDate: "2026-10-02" });
    expect(matchesQuickFilter(both, "trash")).toBe(true);
    expect(matchesQuickFilter(both, "archive")).toBe(false);
  });

  it("keeps only favorites under 'favorites'", () => {
    const fav = cipher({ favorite: true });
    const notFav = cipher({ favorite: false });
    expect(matchesQuickFilter(fav, "favorites")).toBe(true);
    expect(matchesQuickFilter(notFav, "favorites")).toBe(false);
  });

  it("filters by type code", () => {
    expect(matchesQuickFilter(cipher({ kind: 1 }), "type:1")).toBe(true);
    expect(matchesQuickFilter(cipher({ kind: 2 }), "type:1")).toBe(false);
  });
});

describe("compareBy", () => {
  it("pushes empty values to the end", () => {
    expect(compareBy("", "abc")).toBeGreaterThan(0);
    expect(compareBy("abc", "")).toBeLessThan(0);
  });

  it("compares case-insensitively with fr locale", () => {
    expect(compareBy("éclair", "evade")).toBeLessThan(0);
  });

  it("treats null/undefined as empty", () => {
    expect(compareBy(null, "a")).toBeGreaterThan(0);
    expect(compareBy("a", undefined)).toBeLessThan(0);
  });
});

describe("matchesSearch", () => {
  it("matches name, username and primaryUri case-insensitively", () => {
    const c = cipher({
      name: "GitHub",
      username: "alice@example.com",
      primaryUri: "https://github.com",
    });
    expect(matchesSearch(c, "github")).toBe(true);
    expect(matchesSearch(c, "alice")).toBe(true);
    expect(matchesSearch(c, "example.com")).toBe(true);
    expect(matchesSearch(c, "gitlab")).toBe(false);
  });

  it("returns true on empty query", () => {
    expect(matchesSearch(cipher({}), "")).toBe(true);
  });

  it("requires every term, letting them land in different fields", () => {
    const c = cipher({
      name: "Clicface",
      username: "claudeai9358@alias.clicface.fr",
      primaryUri: "https://clicface.fr",
    });
    // The whole point: no single field contains "claude clicface".
    expect(matchesSearch(c, "claude clicface")).toBe(true);
    expect(matchesSearch(c, "clicface claude")).toBe(true);
    // A term that matches nothing still rules the item out.
    expect(matchesSearch(c, "claude github")).toBe(false);
  });

  it("spreads terms across name and username", () => {
    const c = cipher({ name: "Omada - TP-Link Cloud", username: "omada@example.com" });
    expect(matchesSearch(c, "omada cloud")).toBe(true);
    expect(matchesSearch(c, "tp-link example.com")).toBe(true);
  });

  it("ignores accents in both the query and the item", () => {
    const c = cipher({ name: "Téléphonie", username: "hé@x.fr" });
    expect(matchesSearch(c, "telephonie")).toBe(true);
    expect(matchesSearch(c, "Téléphonie")).toBe(true);
  });

  it("ignores surrounding and repeated whitespace", () => {
    const c = cipher({ name: "GitHub", username: "alice@example.com" });
    expect(matchesSearch(c, "  github   alice ")).toBe(true);
    expect(matchesSearch(c, "   ")).toBe(true);
  });

  it("does not let a term straddle two fields", () => {
    const c = cipher({ name: "alpha", username: "beta" });
    expect(matchesSearch(c, "alphabeta")).toBe(false);
  });
});

describe("sortCiphers", () => {
  const items = [
    cipher({ id: "1", name: "Bravo", username: "b@x", primaryUri: "https://b.example" }),
    cipher({ id: "2", name: "alpha", username: "a@x", primaryUri: "https://a.example" }),
    cipher({ id: "3", name: "Charlie", username: null, primaryUri: null }),
  ];

  it("sorts by name ascending", () => {
    expect(sortCiphers(items, "name", true).map((c) => c.id)).toEqual(["2", "1", "3"]);
  });

  it("reverses on descending", () => {
    expect(sortCiphers(items, "name", false).map((c) => c.id)).toEqual(["3", "1", "2"]);
  });

  it("pushes missing username/uri to the end on asc", () => {
    expect(sortCiphers(items, "username", true).map((c) => c.id)).toEqual(["2", "1", "3"]);
    expect(sortCiphers(items, "uri", true).map((c) => c.id)).toEqual(["2", "1", "3"]);
  });
});

describe("applyVaultFilters", () => {
  const folders = [{ id: "f-work", name: "work" }];
  const orgs = [{ id: "o1", name: "Acme" }];
  const collections = [{ id: "c1", organizationId: "o1", name: "Dev" }];

  const items = [
    cipher({ id: "1", name: "GitHub", folderId: "f-work", primaryUri: "https://github.com" }),
    cipher({ id: "2", name: "GitLab", folderId: null, primaryUri: "https://gitlab.com" }),
    cipher({ id: "3", name: "Org Secret", organizationId: "o1", collectionIds: ["c1"] }),
    cipher({ id: "4", name: "Deleted", deletedDate: "2026-01-01" }),
  ];

  const trees = [
    buildFolderTree(
      folders,
      new Map([["f-work", 1]]),
    )!,
    ...buildOrgTrees(
      orgs,
      collections,
      new Map([["o1", 1]]),
      new Map([["c1", 1]]),
    ),
  ];

  it("narrows by folder selection", () => {
    const r = applyVaultFilters(items, {
      quickFilter: "all",
      selectedKey: "folders/work",
      trees,
      search: "",
      sortKey: "name",
      sortAsc: true,
    });
    expect(r.map((c) => c.id)).toEqual(["1"]);
  });

  it("narrows by organization root", () => {
    const r = applyVaultFilters(items, {
      quickFilter: "all",
      selectedKey: "org/o1",
      trees,
      search: "",
      sortKey: "name",
      sortAsc: true,
    });
    expect(r.map((c) => c.id)).toEqual(["3"]);
  });

  it("narrows by collection", () => {
    const r = applyVaultFilters(items, {
      quickFilter: "all",
      selectedKey: "org/o1/Dev",
      trees,
      search: "",
      sortKey: "name",
      sortAsc: true,
    });
    expect(r.map((c) => c.id)).toEqual(["3"]);
  });

  it("applies quick filter + search + sort", () => {
    const r = applyVaultFilters(items, {
      quickFilter: "all",
      selectedKey: null,
      trees,
      search: "Git",
      sortKey: "name",
      sortAsc: false,
    });
    expect(r.map((c) => c.id)).toEqual(["2", "1"]);
  });

  it("shows only trashed items on trash filter", () => {
    const r = applyVaultFilters(items, {
      quickFilter: "trash",
      selectedKey: null,
      trees,
      search: "",
      sortKey: "name",
      sortAsc: true,
    });
    expect(r.map((c) => c.id)).toEqual(["4"]);
  });
});
