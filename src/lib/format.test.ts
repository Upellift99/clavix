import { describe, expect, it } from "vitest";
import {
  cipherTypeIcon,
  cipherTypeLabel,
  computeSessionStatus,
  extractDomain,
  faviconUrl,
  mask,
  providerLabel,
  SESSION_FRESH_MS,
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

describe("computeSessionStatus", () => {
  const now = 1_000_000;
  const base = {
    syncing: false,
    lastSyncError: null,
    lastSyncAt: null as number | null,
    now,
  };

  it("is syncing when a sync is in flight, even if the last one failed", () => {
    // Priority: syncing dominates every other signal — while a sync is
    // running the UI should show progress, not the stale error state.
    expect(
      computeSessionStatus({
        ...base,
        syncing: true,
        lastSyncError: "boom",
        lastSyncAt: now - 60_000,
      }),
    ).toBe("syncing");
  });

  it("is offline when the last sync errored out", () => {
    expect(
      computeSessionStatus({
        ...base,
        lastSyncError: "network down",
        lastSyncAt: now - 60_000,
      }),
    ).toBe("offline");
  });

  it("is unknown when no sync has ever landed", () => {
    expect(computeSessionStatus({ ...base })).toBe("unknown");
  });

  it("is fresh when the last sync is within the freshness window", () => {
    expect(
      computeSessionStatus({ ...base, lastSyncAt: now - (SESSION_FRESH_MS - 1) }),
    ).toBe("fresh");
  });

  it("is stale once the freshness window has elapsed", () => {
    // Boundary check: exactly at the threshold counts as stale so the
    // amber dot shows up the moment the user crosses the line instead
    // of requiring an extra millisecond.
    expect(
      computeSessionStatus({ ...base, lastSyncAt: now - SESSION_FRESH_MS }),
    ).toBe("stale");
  });

  it("lets a sync-in-progress mask a previous offline state", () => {
    // Common UX sequence: network came back, the user hit Sync, we're
    // waiting on the round-trip. Should read "syncing", not "offline".
    expect(
      computeSessionStatus({
        ...base,
        syncing: true,
        lastSyncError: "previous failure",
      }),
    ).toBe("syncing");
  });

  it("honours a custom freshness window", () => {
    expect(
      computeSessionStatus({
        ...base,
        lastSyncAt: now - 30_000,
        freshMs: 60_000,
      }),
    ).toBe("fresh");
    expect(
      computeSessionStatus({
        ...base,
        lastSyncAt: now - 60_001,
        freshMs: 60_000,
      }),
    ).toBe("stale");
  });
});
