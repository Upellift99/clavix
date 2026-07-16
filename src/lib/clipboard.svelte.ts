import { clear as clearClipboard, writeText } from "@tauri-apps/plugin-clipboard-manager";

export const CLIPBOARD_CLEAR_SECONDS = 30;

/** Copied-value kind, used to tint the clipboard toast. */
export type ClipboardVariant = "password" | "username" | "totp" | "default";

export class ClipboardController {
  secondsLeft = $state<number | null>(null);
  label = $state<string | null>(null);
  variant = $state<ClipboardVariant>("default");
  private timeout: ReturnType<typeof setTimeout> | null = null;
  private interval: ReturnType<typeof setInterval> | null = null;

  async copy(value: string, label: string, variant: ClipboardVariant = "default"): Promise<void> {
    await writeText(value);
    this.scheduleClear(label, variant);
  }

  scheduleClear(label: string, variant: ClipboardVariant = "default") {
    this.clearTimers();
    this.label = label;
    this.variant = variant;
    this.secondsLeft = CLIPBOARD_CLEAR_SECONDS;
    this.interval = setInterval(() => {
      if (this.secondsLeft !== null && this.secondsLeft > 0) {
        this.secondsLeft -= 1;
      }
    }, 1000);
    this.timeout = setTimeout(async () => {
      try {
        await clearClipboard();
      } catch {
        // best-effort
      }
      this.secondsLeft = null;
      this.label = null;
      this.variant = "default";
      this.clearTimers();
    }, CLIPBOARD_CLEAR_SECONDS * 1000);
  }

  async clearNow(): Promise<void> {
    this.clearTimers();
    try {
      await clearClipboard();
    } catch {
      // best-effort
    }
    this.secondsLeft = null;
    this.label = null;
    this.variant = "default";
  }

  dispose() {
    this.clearTimers();
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
