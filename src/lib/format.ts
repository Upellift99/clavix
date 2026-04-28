import * as m from "$lib/paraglide/messages";
import type { CipherSummary, StoredAccount } from "./types";

export function formatError(e: unknown): string {
  if (!e || typeof e !== "object") return String(e);
  const err = e as { code?: string; message?: string; data?: Record<string, unknown> };
  const data = err.data ?? {};
  const str = (v: unknown) => (v === null || v === undefined ? "" : String(v));

  switch (err.code) {
    case "invalid_url":
      return m.err_invalid_url({ url: str(data.url) });
    case "network_error":
      return m.err_network({ cause: str(data.cause) });
    case "invalid_response":
      return m.err_invalid_response({ reason: str(data.reason) });
    case "http_status":
      return m.err_http_status({ status: str(data.status), message: str(data.message) });
    case "auth_failed": {
      // The Rust side classifies known Vaultwarden patterns into a
      // stable `reason` code (see `error::classify_auth_message`).
      // When present, surface a localised string; otherwise fall
      // back to the raw server message verbatim — same behaviour as
      // before this dispatch existed, so an unknown server message
      // is never lost.
      const reason = str(data.reason);
      switch (reason) {
        case "invalid_credentials":
          return m.err_auth_invalid_credentials();
        case "two_factor_invalid":
          return m.err_auth_two_factor_invalid();
        case "refresh_expired":
          return m.err_auth_refresh_expired();
        case "captcha_required":
          return m.err_auth_captcha_required();
        case "user_not_found":
          return m.err_auth_user_not_found();
        default:
          return m.err_auth_failed({ message: str(data.message) });
      }
    }
    case "crypto_error":
      return m.err_crypto({ reason: str(data.reason) });
    case "two_factor_provider_unsupported":
      return m.err_two_factor_provider_unsupported({ provider: str(data.provider) });
    case "not_authenticated":
      return m.err_not_authenticated();
    case "storage_error":
      return m.err_storage({ reason: str(data.reason) });
    default:
      return err.message ?? String(e);
  }
}

export type SessionStatus = "syncing" | "fresh" | "stale" | "offline" | "unknown";

/** Ciphers-staleness threshold: the session dot flips amber after this. */
export const SESSION_FRESH_MS = 10 * 60 * 1000;

/**
 * Derive the 5-state session status used by the toolbar indicator.
 * Split out of the Svelte component so it can be covered by vitest
 * (without needing a DOM) and reused if another surface wants to show
 * the same signal — e.g. a menu badge or a tray icon.
 */
export function computeSessionStatus(input: {
  syncing: boolean;
  lastSyncError: string | null;
  lastSyncAt: number | null;
  now: number;
  freshMs?: number;
}): SessionStatus {
  const { syncing, lastSyncError, lastSyncAt, now, freshMs = SESSION_FRESH_MS } =
    input;
  if (syncing) return "syncing";
  if (lastSyncError) return "offline";
  if (lastSyncAt === null) return "unknown";
  return now - lastSyncAt < freshMs ? "fresh" : "stale";
}

/**
 * Human-friendly "il y a X" string for a past epoch (ms) relative to `nowMs`.
 * Buckets are chosen to match the session-bar freshness palette:
 *   < 45 s  → "à l'instant"
 *   < 1 h   → "il y a N min"
 *   < 24 h  → "il y a N h"
 *   else    → "il y a N j"
 *
 * Returns a paraglide-translated string so it reads in the user's locale.
 */
export function formatRelativeAgo(pastMs: number, nowMs: number = Date.now()): string {
  const deltaSec = Math.max(0, Math.round((nowMs - pastMs) / 1000));
  if (deltaSec < 45) return m.time_ago_now();
  const deltaMin = Math.round(deltaSec / 60);
  if (deltaMin < 60) return m.time_ago_minutes({ n: String(deltaMin) });
  const deltaHour = Math.round(deltaMin / 60);
  if (deltaHour < 24) return m.time_ago_hours({ n: String(deltaHour) });
  const deltaDay = Math.round(deltaHour / 24);
  return m.time_ago_days({ n: String(deltaDay) });
}

export function mask(value: string, length: number = 12): string {
  return "•".repeat(Math.min(value.length, length));
}

export function extractDomain(uri: string): string | null {
  try {
    const url = new URL(uri.startsWith("http") ? uri : `https://${uri}`);
    return url.hostname;
  } catch {
    return null;
  }
}

export function faviconUrl(
  cipher: CipherSummary,
  storedAccount: StoredAccount | null,
): string | null {
  if (cipher.kind !== 1 || !cipher.primaryUri || !storedAccount) return null;
  const domain = extractDomain(cipher.primaryUri);
  if (!domain) return null;
  const base = storedAccount.serverUrl.replace(/\/$/, "");
  return `${base}/icons/${domain}/icon.png`;
}

export function providerLabel(p: number): string {
  switch (p) {
    case 0: return "TOTP (Authenticator)";
    case 1: return "Email";
    case 2: return "Duo";
    case 3: return "YubiKey OTP";
    case 7: return "WebAuthn / FIDO2";
    default: return `Provider #${p}`;
  }
}

export function cipherTypeLabel(k: number): string {
  switch (k) {
    case 1: return "Login";
    case 2: return "Note";
    case 3: return "Carte";
    case 4: return "Identité";
    case 5: return "Clé SSH";
    default: return `Type ${k}`;
  }
}

/** Maps a Bitwarden cipher kind to the right SVG `Icon` name. The
 *  emojis we used to render here looked OK on macOS but rendered as
 *  multicolour bitmap glyphs on most Linux GTK builds, fighting the
 *  rest of the monochrome UI. Returning a name + letting the
 *  consumer do `<Icon name={...}/>` keeps everything inheriting
 *  `currentColor`. */
export function cipherTypeIconName(
  k: number,
): "key" | "note" | "card" | "id-card" | "terminal" | "info" {
  switch (k) {
    case 1: return "key";
    case 2: return "note";
    case 3: return "card";
    case 4: return "id-card";
    case 5: return "terminal";
    default: return "info";
  }
}
