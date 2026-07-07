import { describe, expect, it } from "vitest";
import { generateTotp, parseTotp, secondsRemaining, type TotpConfig } from "./totp";

const ascii = (s: string) => new TextEncoder().encode(s);

// RFC 6238 Appendix B seeds (ASCII), one per hash size.
const SEED_SHA1 = ascii("12345678901234567890");
const SEED_SHA256 = ascii("12345678901234567890123456789012");
const SEED_SHA512 = ascii("1234567890123456789012345678901234567890123456789012345678901234");

function cfg(secret: Uint8Array, algorithm: TotpConfig["algorithm"]): TotpConfig {
  return { secret, algorithm, period: 30, digits: 8 };
}

describe("generateTotp — RFC 6238 test vectors", () => {
  // [time (s), algorithm, expected 8-digit TOTP] from RFC 6238 Appendix B.
  const vectors: Array<[number, TotpConfig, string]> = [
    [59, cfg(SEED_SHA1, "SHA-1"), "94287082"],
    [59, cfg(SEED_SHA256, "SHA-256"), "46119246"],
    [59, cfg(SEED_SHA512, "SHA-512"), "90693936"],
    [1111111109, cfg(SEED_SHA1, "SHA-1"), "07081804"],
    [1111111111, cfg(SEED_SHA1, "SHA-1"), "14050471"],
    [1234567890, cfg(SEED_SHA1, "SHA-1"), "89005924"],
    [2000000000, cfg(SEED_SHA1, "SHA-1"), "69279037"],
    [20000000000, cfg(SEED_SHA1, "SHA-1"), "65353130"],
  ];

  for (const [time, config, expected] of vectors) {
    it(`${config.algorithm} @ t=${time} -> ${expected}`, async () => {
      expect(await generateTotp(config, time)).toBe(expected);
    });
  }

  it("zero-pads short codes to the requested number of digits", async () => {
    const code = await generateTotp(cfg(SEED_SHA1, "SHA-1"), 1111111109);
    expect(code).toHaveLength(8);
    expect(code).toMatch(/^\d{8}$/);
  });
});

describe("parseTotp — otpauth parsing", () => {
  it("parses a bare base32 secret with SHA-1 defaults", () => {
    const c = parseTotp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(c.algorithm).toBe("SHA-1");
    expect(c.period).toBe(30);
    expect(c.digits).toBe(6);
    expect(Array.from(c.secret)).toEqual(Array.from(SEED_SHA1));
  });

  it("parses algorithm SHA256 / SHA512", () => {
    const base = "otpauth://totp/Acme:alice?secret=GEZDGNBVGY3TQOJQ";
    expect(parseTotp(`${base}&algorithm=SHA256`).algorithm).toBe("SHA-256");
    expect(parseTotp(`${base}&algorithm=SHA512`).algorithm).toBe("SHA-512");
    expect(parseTotp(`${base}&algorithm=SHA1`).algorithm).toBe("SHA-1");
    expect(parseTotp(base).algorithm).toBe("SHA-1"); // default
  });

  it("parses custom period and digits", () => {
    const c = parseTotp("otpauth://totp/Acme:alice?secret=GEZDGNBVGY3TQOJQ&period=60&digits=8");
    expect(c.period).toBe(60);
    expect(c.digits).toBe(8);
  });

  it("throws when the secret is missing", () => {
    expect(() => parseTotp("otpauth://totp/Acme:alice?issuer=Acme")).toThrow(/secret/);
  });

  it("throws on invalid base32", () => {
    expect(() => parseTotp("not base32!!!")).toThrow(/base32/);
  });
});

describe("parseTotp — bounds aberrant parameters", () => {
  const secret = "secret=GEZDGNBVGY3TQOJQ";

  it("clamps an absurd digits value to the 4..10 range", () => {
    expect(parseTotp(`otpauth://totp/A?${secret}&digits=100000`).digits).toBe(10);
    expect(parseTotp(`otpauth://totp/A?${secret}&digits=1`).digits).toBe(4);
  });

  it("clamps an absurd period value to the 1..3600 range", () => {
    expect(parseTotp(`otpauth://totp/A?${secret}&period=999999`).period).toBe(3600);
    expect(parseTotp(`otpauth://totp/A?${secret}&period=0`).period).toBe(30); // fallback
  });

  it("falls back on non-numeric parameters", () => {
    const c = parseTotp(`otpauth://totp/A?${secret}&digits=abc&period=xyz`);
    expect(c.digits).toBe(6);
    expect(c.period).toBe(30);
  });

  it("does not blow up generating a code with clamped digits", async () => {
    const c = parseTotp(`otpauth://totp/A?${secret}&digits=100000`);
    const code = await generateTotp(c, 59);
    expect(code).toHaveLength(10);
  });
});

describe("secondsRemaining", () => {
  it("counts down within the period window", () => {
    expect(secondsRemaining(30, 0)).toBe(30);
    expect(secondsRemaining(30, 1)).toBe(29);
    expect(secondsRemaining(30, 29)).toBe(1);
    expect(secondsRemaining(30, 30)).toBe(30);
  });
});
