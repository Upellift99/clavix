import { api } from "./api";

export const CLIPBOARD_CLEAR_SECONDS = 30;

/**
 * What was copied. The toast names it (through a message key, so it
 * follows the locale) and tints itself from it. `field` is the generic
 * case, for a custom field or an identity row: the caller hands over
 * the already-localised label it shows on screen.
 */
export type ClipboardKind =
  | "password"
  | "username"
  | "totp"
  | "url"
  | "publicKey"
  | "privateKey"
  | "cardNumber"
  | "securityCode"
  | "command"
  | "sshSock"
  | "field";

/** Toast tint, derived from the kind. */
export type ClipboardVariant = "password" | "username" | "totp" | "default";

export function clipboardVariant(kind: ClipboardKind): ClipboardVariant {
  switch (kind) {
    case "password":
    case "privateKey":
    case "cardNumber":
    case "securityCode":
      return "password";
    case "username":
      return "username";
    case "totp":
      return "totp";
    default:
      return "default";
  }
}

export class ClipboardController {
  secondsLeft = $state<number | null>(null);
  kind = $state<ClipboardKind>("field");
  /** Localised label, only meaningful when `kind` is `field`. */
  label = $state<string | null>(null);
  variant = $state<ClipboardVariant>("default");
  private timeout: ReturnType<typeof setTimeout> | null = null;
  private interval: ReturnType<typeof setInterval> | null = null;

  async copy(value: string, kind: ClipboardKind, label?: string): Promise<void> {
    await api.clipboardWrite(value);
    this.scheduleClear(kind, label);
  }

  scheduleClear(kind: ClipboardKind, label?: string) {
    this.clearTimers();
    this.kind = kind;
    this.label = label ?? null;
    this.variant = clipboardVariant(kind);
    this.secondsLeft = CLIPBOARD_CLEAR_SECONDS;
    this.interval = setInterval(() => {
      if (this.secondsLeft !== null && this.secondsLeft > 0) {
        this.secondsLeft -= 1;
      }
    }, 1000);
    // Only clears while the clipboard still holds what was copied here:
    // anything the user copied since, in Clavix or elsewhere, stays.
    this.timeout = setTimeout(async () => {
      try {
        await api.clipboardClearIfOurs();
      } catch {
        // best-effort
      }
      this.reset();
      this.clearTimers();
    }, CLIPBOARD_CLEAR_SECONDS * 1000);
  }

  async clearNow(): Promise<void> {
    this.clearTimers();
    try {
      await api.clipboardClearIfOurs();
    } catch {
      // best-effort
    }
    this.reset();
  }

  dispose() {
    this.clearTimers();
  }

  private reset() {
    this.secondsLeft = null;
    this.kind = "field";
    this.label = null;
    this.variant = "default";
  }

  private clearTimers() {
    if (this.timeout !== null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }
    if (this.interval !== null) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }
}
