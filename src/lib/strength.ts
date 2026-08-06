import { buildCharset, type GeneratorOptions } from "./generator";

/**
 * Two scales live here, and they must not be conflated.
 *
 * - **Entropy in bits** applies to a password we generated ourselves.
 *   We know the alphabet and the draw is uniform, so `length ×
 *   log2(|charset|)` is not an estimate — it is the exact strength.
 * - **zxcvbn's 0-4 score** applies to a password a human chose. It
 *   estimates guessability against dictionaries and patterns, which is
 *   the only sensible question for a human-picked string and the wrong
 *   question for a random one (it saturates at 4 from roughly twelve
 *   characters and stops discriminating).
 *
 * Hence two separate threshold tables below. Sharing one would mean
 * pretending 60 bits and "score 3" are the same claim; they aren't.
 */

/** Visual band, shared by both scales so the bar looks consistent. */
export type StrengthBand = "empty" | "weak" | "fair" | "good" | "strong";

/** Order matters: it drives the filled-segment count in the meter. */
export const BANDS: StrengthBand[] = ["empty", "weak", "fair", "good", "strong"];

export function bandIndex(band: StrengthBand): number {
  return BANDS.indexOf(band);
}

/**
 * Exact entropy of a uniform draw over the generator's alphabet.
 *
 * Returns 0 for an empty charset — the generator already refuses that
 * case, but a caller shouldn't get a NaN out of `log2(0)` if it ever
 * slips through.
 */
export function entropyBits(opts: GeneratorOptions): number {
  const charset = buildCharset(opts);
  const size = Array.from(charset).length;
  if (size <= 1 || opts.length <= 0) return 0;
  return opts.length * Math.log2(size);
}

/**
 * Bands for generated passwords.
 *
 * The boundaries are deliberately stricter than the folklore "40 bits
 * is fine": these are vault passwords, assumed to be under offline
 * attack against a leaked hash, where a GPU farm covers 60 bits in
 * reach. 75 bits is the first level that is comfortable for decades,
 * and 100 is where the number stops being the weakest link.
 */
export function bandForBits(bits: number): StrengthBand {
  if (bits <= 0) return "empty";
  if (bits < 45) return "weak";
  if (bits < 75) return "fair";
  if (bits < 100) return "good";
  return "strong";
}

/**
 * Bands for zxcvbn's score. Mirrors the audit's own cut-off: score <= 2
 * is what `strength::WEAK_SCORE_MAX` flags as weak in Rust, so the
 * editor's red/amber bar and the audit's "weak passwords" list always
 * agree about the same password.
 */
export function bandForScore(score: number): StrengthBand {
  if (score <= 1) return "weak";
  if (score === 2) return "fair";
  if (score === 3) return "good";
  return "strong";
}
