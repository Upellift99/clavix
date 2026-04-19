import { describe, expect, it } from "vitest";
import {
  cipherTypeIcon,
  cipherTypeLabel,
  extractDomain,
  faviconUrl,
  formatExpiry,
  mask,
  providerLabel,
  truncate,
} from "./format";
import type { CipherSummary, StoredAccount } from "./types";

function cipher(p: Partial<CipherSummary>): CipherSummary {
  return {
    id: p.id ?? "c",
    kind: p.kind ?? 1,
    name: p.name ?? "n",
    folderId: null,
    organizationId: null,
    collectionIds: [],
    favorite: false,
    primaryUri: p.primaryUri ?? null,
    username: null,
    revisionDate: null,
    deletedDate: null,
  };
}

describe("truncate", () => {
  it("adds ellipsis past the limit", () => {
    expect(truncate("abcdefghij", 5)).toBe("abcde…");
  });
  it("returns the string untouched under the limit", () => {
    expect(truncate("abc", 5)).toBe("abc");
  });
});

describe("formatExpiry", () => {
  it("uses minutes under an hour", () => {
    expect(formatExpiry(30 * 60)).toBe("30 min");
  });
  it("switches to hours with one decimal at or past 60 min", () => {
    expect(formatExpiry(60 * 60)).toBe("1.0 h");
    expect(formatExpiry(90 * 60)).toBe("1.5 h");
  });
});

describe("mask", () => {
  it("defaults to 12 masked bullets max", () => {
    expect(mask("abcdefghijklmnop")).toBe("•".repeat(12));
  });
  it("caps to the string length", () => {
    expect(mask("ab", 16)).toBe("••");
  });
});

describe("extractDomain", () => {
  it("extracts hostname from a bare domain", () => {
    expect(extractDomain("example.com")).toBe("example.com");
  });
  it("preserves scheme when present", () => {
    expect(extractDomain("https://foo.bar/path")).toBe("foo.bar");
  });
  it("returns null on malformed input", () => {
    expect(extractDomain("::::")).toBeNull();
  });
});

describe("faviconUrl", () => {
  const account: StoredAccount = { serverUrl: "https://vault.example.com/", email: "a@b" };
  it("builds an icon URL for login ciphers with a URI", () => {
    const url = faviconUrl(cipher({ primaryUri: "https://github.com" }), account);
    expect(url).toBe("https://vault.example.com/icons/github.com/icon.png");
  });
  it("returns null for non-login kinds", () => {
    expect(faviconUrl(cipher({ kind: 2, primaryUri: "https://x.y" }), account)).toBeNull();
  });
  it("returns null without a URI or account", () => {
    expect(faviconUrl(cipher({ primaryUri: null }), account)).toBeNull();
    expect(faviconUrl(cipher({ primaryUri: "https://x" }), null)).toBeNull();
  });
});

describe("providerLabel", () => {
  it("maps known provider numbers to labels", () => {
    expect(providerLabel(0)).toMatch(/TOTP/);
    expect(providerLabel(3)).toMatch(/YubiKey/);
    expect(providerLabel(7)).toMatch(/WebAuthn/);
  });
  it("falls back to a generic marker for unknown providers", () => {
    expect(providerLabel(99)).toBe("Provider #99");
  });
});

describe("cipherTypeLabel / cipherTypeIcon", () => {
  it("maps known kinds", () => {
    expect(cipherTypeLabel(1)).toBe("Login");
    expect(cipherTypeIcon(5)).toBe("🔑");
  });
  it("falls back for unknown kinds", () => {
    expect(cipherTypeLabel(42)).toBe("Type 42");
    expect(cipherTypeIcon(42)).toBe("❔");
  });
});
