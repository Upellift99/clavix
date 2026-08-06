import { describe, expect, it } from "vitest";
import {
  BANDS,
  bandForBits,
  bandForScore,
  bandIndex,
  entropyBits,
} from "./strength";
import { GEN_LOWER, GEN_UPPER, type GeneratorOptions } from "./generator";

const ALL: GeneratorOptions = {
  length: 20,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

describe("entropyBits", () => {
  it("matches length × log2(charset) for a known alphabet", () => {
    // Lowercase only: 26 symbols, 10 characters.
    const bits = entropyBits({ ...ALL, length: 10, upper: false, digits: false, symbols: false });
    expect(bits).toBeCloseTo(10 * Math.log2(26), 6);
  });

  it("drops when a character class is turned off", () => {
    const withSymbols = entropyBits(ALL);
    const without = entropyBits({ ...ALL, symbols: false });
    expect(without).toBeLessThan(withSymbols);
  });

  it("drops when ambiguous characters are excluded", () => {
    // Fewer symbols to draw from means less entropy per character — the
    // trade the checkbox makes, and the reason the generator shows bits
    // rather than a zxcvbn score that would sit pinned at "very strong".
    expect(entropyBits({ ...ALL, avoidAmbiguous: true })).toBeLessThan(entropyBits(ALL));
  });

  it("scales linearly with length", () => {
    expect(entropyBits({ ...ALL, length: 40 })).toBeCloseTo(entropyBits({ ...ALL, length: 20 }) * 2, 6);
  });

  it("returns 0 rather than NaN for an empty charset", () => {
    const bits = entropyBits({
      ...ALL,
      upper: false,
      lower: false,
      digits: false,
      symbols: false,
    });
    expect(bits).toBe(0);
  });

  it("returns 0 for a zero length", () => {
    expect(entropyBits({ ...ALL, length: 0 })).toBe(0);
  });

  it("counts the full alphabet when both letter cases are on", () => {
    const size = new Set([...GEN_UPPER, ...GEN_LOWER]).size;
    const bits = entropyBits({ ...ALL, length: 1, digits: false, symbols: false });
    expect(bits).toBeCloseTo(Math.log2(size), 6);
  });
});

describe("bandForBits", () => {
  it("calls a short generated password weak", () => {
    // 6 lowercase characters ≈ 28 bits.
    expect(bandForBits(28)).toBe("weak");
  });

  it("calls the default 20-character password strong", () => {
    expect(bandForBits(entropyBits(ALL))).toBe("strong");
  });

  it("reports empty for zero bits", () => {
    expect(bandForBits(0)).toBe("empty");
  });

  it("increases monotonically", () => {
    const samples = [10, 44, 45, 74, 75, 99, 100, 200];
    const indices = samples.map((b) => bandIndex(bandForBits(b)));
    for (const pair of indices.slice(1).map((v, i) => [indices[i], v])) {
      expect(pair[0]).toBeLessThanOrEqual(pair[1]);
    }
  });
});

describe("bandForScore", () => {
  it("treats zxcvbn score <= 2 as not good, matching the audit's cut-off", () => {
    // strength::WEAK_SCORE_MAX is 2 in Rust; anything at or below it
    // must stay out of the "good"/"strong" bands or the editor would
    // bless a password the audit lists as weak.
    for (const score of [0, 1, 2]) {
      expect(["weak", "fair"]).toContain(bandForScore(score));
    }
    expect(bandForScore(3)).toBe("good");
    expect(bandForScore(4)).toBe("strong");
  });

  it("never returns a band outside the shared list", () => {
    for (const score of [0, 1, 2, 3, 4]) {
      expect(BANDS).toContain(bandForScore(score));
    }
  });
});
