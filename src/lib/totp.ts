export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

export type TotpConfig = {
  secret: Uint8Array;
  period: number;
  digits: number;
  algorithm: TotpAlgorithm;
};

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function decodeBase32(input: string): Uint8Array {
  const cleaned = input.replace(/=+$/g, "").replace(/\s+/g, "").toUpperCase();
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base32 char: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

// Clamp an untrusted numeric parameter to a sane range, falling back when the
// value is missing, non-finite, or non-positive. Prevents an aberrant `digits`
// (e.g. from a hostile otpauth URI) from triggering a huge padStart allocation.
function clampParam(raw: string | null, min: number, max: number, fallback: number): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

export function parseTotp(source: string): TotpConfig {
  const trimmed = source.trim();
  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    const url = new URL(trimmed);
    const secretRaw = url.searchParams.get("secret");
    if (!secretRaw) throw new Error("otpauth URI missing secret");
    const algoParam = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
    const algorithm: TotpAlgorithm =
      algoParam === "SHA256" || algoParam === "SHA-256"
        ? "SHA-256"
        : algoParam === "SHA512" || algoParam === "SHA-512"
          ? "SHA-512"
          : "SHA-1";
    return {
      secret: decodeBase32(secretRaw),
      period: clampParam(url.searchParams.get("period"), 1, 3600, 30),
      digits: clampParam(url.searchParams.get("digits"), 4, 10, 6),
      algorithm,
    };
  }
  return {
    secret: decodeBase32(trimmed),
    period: 30,
    digits: 6,
    algorithm: "SHA-1",
  };
}

export async function generateTotp(config: TotpConfig, nowSeconds: number): Promise<string> {
  const counter = Math.floor(nowSeconds / config.period);
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const key = await crypto.subtle.importKey(
    "raw",
    config.secret,
    { name: "HMAC", hash: config.algorithm },
    false,
    ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, counterBytes);
  const sig = new Uint8Array(sigBuf);
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const code = binary % 10 ** config.digits;
  return code.toString().padStart(config.digits, "0");
}

export function secondsRemaining(period: number, nowSeconds: number): number {
  return period - (nowSeconds % period);
}
