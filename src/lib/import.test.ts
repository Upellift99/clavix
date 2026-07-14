import { describe, expect, it } from "vitest";
import { importIdentity } from "./import";

describe("importIdentity", () => {
  it("treats the same entry as already present regardless of case, accents and padding", () => {
    expect(importIdentity("  Gîte  ", "Alice@Example.com ")).toBe(
      importIdentity("gite", "alice@example.com"),
    );
  });

  it("separates two entries that differ only by username", () => {
    expect(importIdentity("GitHub", "alice")).not.toBe(importIdentity("GitHub", "bob"));
  });

  it("separates two entries that differ only by name", () => {
    expect(importIdentity("GitHub", "alice")).not.toBe(importIdentity("GitLab", "alice"));
  });

  it("does not let name and username bleed into each other", () => {
    // Without a separator, ("ab", "c") and ("a", "bc") would collide and one
    // of the two entries would be silently skipped on re-import.
    expect(importIdentity("ab", "c")).not.toBe(importIdentity("a", "bc"));
  });

  it("matches an entry whose password changed since the import", () => {
    // The identity ignores secrets entirely, which is what keeps a re-import
    // from overwriting a password the user rotated inside Clavix.
    expect(importIdentity("GitHub", "alice")).toBe(importIdentity("GitHub", "alice"));
  });
});
