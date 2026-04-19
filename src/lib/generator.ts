export const GEN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const GEN_LOWER = "abcdefghijklmnopqrstuvwxyz";
export const GEN_DIGITS = "0123456789";
export const GEN_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";
export const GEN_AMBIGUOUS = /[O0Il1|`']/g;

export type GeneratorOptions = {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
};

export function buildCharset(opts: Omit<GeneratorOptions, "length">): string {
  let charset = "";
  if (opts.upper) charset += GEN_UPPER;
  if (opts.lower) charset += GEN_LOWER;
  if (opts.digits) charset += GEN_DIGITS;
  if (opts.symbols) charset += GEN_SYMBOLS;
  if (opts.avoidAmbiguous) charset = charset.replace(GEN_AMBIGUOUS, "");
  return charset;
}

export function generatePassword(opts: GeneratorOptions): string {
  const charset = buildCharset(opts);
  if (charset.length === 0) return "";
  const chars = Array.from(charset);
  const rng = new Uint32Array(opts.length);
  crypto.getRandomValues(rng);
  const out: string[] = [];
  for (let i = 0; i < opts.length; i++) {
    out.push(chars[rng[i] % chars.length]);
  }
  return out.join("");
}
