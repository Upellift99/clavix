import { describe, expect, it } from "vitest";
import {
  MAX_ENCRYPTED_VALUE_LENGTH,
  encryptedLength,
  exceedsEncryptedLimit,
} from "./limits";

describe("encryptedLength", () => {
  // Cross-checked against a real AES-256-CBC + HMAC-SHA256 EncString:
  // "2.<iv b64>|<ciphertext b64>|<mac b64>".
  it.each([
    [0, 96],
    [15, 96],
    [16, 116],
    [100, 224],
  ])("matches the EncString length for a %i-char plaintext", (n, expected) => {
    expect(encryptedLength("a".repeat(n))).toBe(expected);
  });

  it("counts UTF-8 bytes, not code points", () => {
    // "é" is two bytes, so 8 of them fill a block a 8-char ASCII string would not.
    expect(encryptedLength("é".repeat(8))).toBeGreaterThan(encryptedLength("a".repeat(8)));
  });
});

describe("exceedsEncryptedLimit", () => {
  it("accepts the longest plaintext that still fits", () => {
    expect(encryptedLength("a".repeat(7439))).toBeLessThanOrEqual(MAX_ENCRYPTED_VALUE_LENGTH);
    expect(exceedsEncryptedLimit("a".repeat(7439))).toBe(false);
  });

  it("rejects one character past the ceiling", () => {
    expect(exceedsEncryptedLimit("a".repeat(7440))).toBe(true);
  });

  it("rejects an armored PGP key block, the case that broke the import", () => {
    const pgp = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${"AbCd".repeat(2500)}\n-----END PGP PRIVATE KEY BLOCK-----`;
    expect(exceedsEncryptedLimit(pgp)).toBe(true);
  });

  it("never flags an empty value", () => {
    expect(exceedsEncryptedLimit("")).toBe(false);
  });
});
