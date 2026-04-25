// RFC 6238 / RFC 4226 TOTP code computation, in pure Node.
//
// Used by login-totp.spec.mjs to drive the second-factor login
// against the seeded `e2e-2fa@clavix.test` fixture. The TOTP secret
// is stamped deterministically into Vaultwarden by `e2e_seed.rs`
// (`TWO_FA_SECRET_BASE32`) so the spec can recompute a valid code
// at runtime without scraping seed stdout.
//
// We deliberately avoid pulling in an `otplib` / `notp` npm
// dependency — Node's built-in `crypto.createHmac` covers the
// arithmetic, the helper is ~25 lines, and skipping a transitive
// dep keeps Dependabot quieter.

import crypto from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Base32 → bytes, RFC 4648 alphabet. Tolerant of `=` padding. */
function base32Decode(input) {
  const cleaned = input.toUpperCase().replace(/[\s=]/g, "");
  let bits = "";
  for (const ch of cleaned) {
    const v = ALPHABET.indexOf(ch);
    if (v === -1) {
      throw new Error(`base32: invalid character ${JSON.stringify(ch)}`);
    }
    bits += v.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/**
 * Compute the current 6-digit TOTP code for a Bitwarden-style
 * base32 secret. Defaults match what Vaultwarden / Authy / Google
 * Authenticator use: 30-second window, SHA-1 HMAC, 6 digits.
 */
export function totpCode(secretBase32, options = {}) {
  const period = options.period ?? 30;
  const digits = options.digits ?? 6;
  const timestamp = options.timestamp ?? Date.now();

  const secret = base32Decode(secretBase32);
  const counter = Math.floor(timestamp / 1000 / period);

  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));

  const sig = crypto.createHmac("sha1", secret).update(buf).digest();
  const offset = sig[sig.length - 1] & 0x0f;
  const truncated =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);

  return (truncated % 10 ** digits).toString().padStart(digits, "0");
}
