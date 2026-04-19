import { describe, expect, it } from "vitest";
import {
  buildCharset,
  GEN_AMBIGUOUS,
  GEN_DIGITS,
  GEN_LOWER,
  GEN_SYMBOLS,
  GEN_UPPER,
  generatePassword,
} from "./generator";

describe("buildCharset", () => {
  it("combines all four pools when everything is enabled", () => {
    const cs = buildCharset({
      upper: true,
      lower: true,
      digits: true,
      symbols: true,
      avoidAmbiguous: false,
    });
    expect(cs).toContain(GEN_UPPER);
    expect(cs).toContain(GEN_LOWER);
    expect(cs).toContain(GEN_DIGITS);
    expect(cs).toContain(GEN_SYMBOLS);
  });

  it("returns an empty string when no pool is selected", () => {
    expect(
      buildCharset({
        upper: false,
        lower: false,
        digits: false,
        symbols: false,
        avoidAmbiguous: false,
      }),
    ).toBe("");
  });

  it("strips ambiguous characters when asked", () => {
    const cs = buildCharset({
      upper: true,
      lower: true,
      digits: true,
      symbols: true,
      avoidAmbiguous: true,
    });
    expect(cs).not.toMatch(GEN_AMBIGUOUS);
    // Control: without avoidAmbiguous, ambiguous characters are present
    expect(
      buildCharset({
        upper: true,
        lower: false,
        digits: false,
        symbols: false,
        avoidAmbiguous: false,
      }),
    ).toContain("O");
  });
});

describe("generatePassword", () => {
  it("returns an empty string when the charset is empty", () => {
    expect(
      generatePassword({
        length: 12,
        upper: false,
        lower: false,
        digits: false,
        symbols: false,
        avoidAmbiguous: false,
      }),
    ).toBe("");
  });

  it("produces a password of the requested length", () => {
    const pw = generatePassword({
      length: 24,
      upper: true,
      lower: true,
      digits: true,
      symbols: false,
      avoidAmbiguous: false,
    });
    expect(pw).toHaveLength(24);
  });

  it("only uses characters from the active pools", () => {
    const pw = generatePassword({
      length: 64,
      upper: false,
      lower: false,
      digits: true,
      symbols: false,
      avoidAmbiguous: false,
    });
    expect(pw).toMatch(/^[0-9]+$/);
  });
});
