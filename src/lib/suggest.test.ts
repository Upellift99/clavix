import { describe, expect, it } from "vitest";
import { matchSuggestions, usernameSuggestions } from "./suggest";
import type { CipherSummary } from "./types";

function cipher(p: Partial<CipherSummary>): CipherSummary {
  return {
    id: p.id ?? "c",
    kind: p.kind ?? 1,
    name: p.name ?? "item",
    folderId: null,
    organizationId: null,
    collectionIds: [],
    favorite: false,
    primaryUri: null,
    username: p.username ?? null,
    revisionDate: null,
    deletedDate: p.deletedDate ?? null,
    archivedDate: p.archivedDate ?? null,
    notes: null,
  };
}

describe("usernameSuggestions", () => {
  it("returns nothing without a vault", () => {
    expect(usernameSuggestions(undefined)).toEqual([]);
    expect(usernameSuggestions([])).toEqual([]);
  });

  it("puts the most used username first", () => {
    const list = usernameSuggestions([
      cipher({ username: "rare" }),
      cipher({ username: "me@example.com" }),
      cipher({ username: "me@example.com" }),
    ]);
    expect(list).toEqual(["me@example.com", "rare"]);
  });

  it("breaks ties alphabetically, ignoring case", () => {
    const list = usernameSuggestions([
      cipher({ username: "zed" }),
      cipher({ username: "Bob" }),
      cipher({ username: "alice" }),
    ]);
    expect(list).toEqual(["alice", "Bob", "zed"]);
  });

  it("trims values and drops empty or missing ones", () => {
    const list = usernameSuggestions([
      cipher({ username: "  admin " }),
      cipher({ username: "admin" }),
      cipher({ username: "   " }),
      cipher({ username: null }),
    ]);
    expect(list).toEqual(["admin"]);
  });

  it("skips the trash but keeps the archive", () => {
    const list = usernameSuggestions([
      cipher({ username: "trashed", deletedDate: "2026-01-01T00:00:00Z" }),
      cipher({ username: "archived", archivedDate: "2026-01-01T00:00:00Z" }),
    ]);
    expect(list).toEqual(["archived"]);
  });

  it("ignores kinds other than logins", () => {
    const list = usernameSuggestions([
      cipher({ kind: 2, username: "note" }),
      cipher({ kind: 4, username: "identity" }),
      cipher({ kind: 1, username: "login" }),
    ]);
    expect(list).toEqual(["login"]);
  });
});

describe("matchSuggestions", () => {
  const all = ["root", "raoul@example.com", "admin", "Robert", "bar"];

  it("puts prefix matches before substring matches, keeping order", () => {
    expect(matchSuggestions(all, "r")).toEqual(["root", "raoul@example.com", "Robert", "bar"]);
  });

  it("ignores case and surrounding spaces", () => {
    expect(matchSuggestions(all, "  ROB ")).toEqual(["Robert"]);
  });

  it("drops an entry equal to the text", () => {
    expect(matchSuggestions(all, "admin")).toEqual([]);
  });

  it("caps the list", () => {
    expect(matchSuggestions(all, "", 2)).toEqual(["root", "raoul@example.com"]);
  });
});
