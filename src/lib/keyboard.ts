import { openUrl } from "@tauri-apps/plugin-opener";
import type { ClipboardKind } from "./clipboard.svelte";
import type { CipherDetail, CipherSummary } from "./types";

function isTypingContext(): boolean {
  const a = document.activeElement as HTMLElement | null;
  if (!a) return false;
  const tag = a.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || a.isContentEditable;
}

/** Id of the list row that currently holds keyboard focus, if any. */
export function focusedRowId(): string | null {
  const a = document.activeElement as HTMLElement | null;
  return a?.closest<HTMLElement>(".cipher-row")?.dataset.id ?? null;
}

/**
 * Ctrl+Q (Cmd+Q on macOS) quits the app from any screen. Alt rules it
 * out because some layouts report AltGr as Ctrl+Alt.
 */
export function isQuitShortcut(event: KeyboardEvent): boolean {
  return (event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === "q";
}

export type VaultKeyDeps = {
  isLoggedIn: () => boolean;
  getDetail: () => CipherDetail | null;
  /** Summary for a row id, so the shortcuts work on the focused row
   *  before the detail panel is open. */
  getSummary: (id: string) => CipherSummary | null;
  getSearchInput: () => HTMLInputElement | null;
  closeDetail: () => void;
  lock: () => Promise<void> | void;
  copy: (value: string, kind: ClipboardKind) => Promise<void> | void;
  /** Reveal the password for a cipher id on demand (kept out of `detail`).
   *  Resolves to "" when the item has none or the reprompt was refused. */
  getPassword: (cipherId: string) => Promise<string>;
  /** Current TOTP code for a cipher id (computed in Rust); "" when none. */
  getTotpCode: (cipherId: string) => Promise<string>;
  onError: (e: unknown) => void;
};

type ShortcutTarget = {
  id: string;
  username: string | null;
  uri: string | null;
  /** False only when known to be absent; a summary cannot tell. */
  mayHavePassword: boolean;
  mayHaveTotp: boolean;
};

function fromDetail(detail: CipherDetail): ShortcutTarget {
  return {
    id: detail.id,
    username: detail.login?.username ?? null,
    uri: detail.login?.uris?.[0] ?? null,
    mayHavePassword: detail.login?.hasPassword ?? false,
    mayHaveTotp: detail.login?.hasTotp ?? false,
  };
}

function fromSummary(summary: CipherSummary): ShortcutTarget {
  const isLogin = summary.kind === 1;
  return {
    id: summary.id,
    username: summary.username,
    uri: summary.primaryUri,
    mayHavePassword: isLogin,
    mayHaveTotp: isLogin,
  };
}

/**
 * Builds the global keydown handler for the vault view (Esc, /, Ctrl+F/L/C/B/T/U).
 *
 * Ctrl+C/B/T/U act on the item the detail panel shows; with the panel
 * closed they act on the list row that has keyboard focus, so the
 * keyboard path is type, Enter or Down, Ctrl+C.
 */
export function makeVaultKeyHandler(deps: VaultKeyDeps) {
  return async function handle(event: KeyboardEvent) {
    if (!deps.isLoggedIn()) return;
    // A modal dialog owns the keyboard while it is up. Without this,
    // Escape on a delete confirmation both answered the dialog and
    // collapsed the detail panel behind it, and Ctrl+C over a
    // confirmation copied the password of the item underneath.
    if (document.querySelector("dialog[open]")) return;
    const detail = deps.getDetail();

    if (event.key === "Escape" && detail) {
      event.preventDefault();
      deps.closeDetail();
      return;
    }
    if (event.key === "/" && !isTypingContext()) {
      event.preventDefault();
      const input = deps.getSearchInput();
      input?.focus();
      input?.select();
      return;
    }

    if (!event.ctrlKey && !event.metaKey) return;
    const key = event.key.toLowerCase();

    if (key === "f") {
      event.preventDefault();
      const input = deps.getSearchInput();
      input?.focus();
      input?.select();
      return;
    }
    if (key === "l") {
      event.preventDefault();
      await deps.lock();
      return;
    }
    if (isTypingContext()) return;
    const selectionLength = window.getSelection()?.toString().length ?? 0;
    if (selectionLength > 0) return;

    let target: ShortcutTarget | null = null;
    if (detail) {
      target = fromDetail(detail);
    } else {
      const rowId = focusedRowId();
      const summary = rowId ? deps.getSummary(rowId) : null;
      if (summary) target = fromSummary(summary);
    }
    if (!target) return;

    if (key === "c" && target.mayHavePassword) {
      event.preventDefault();
      try {
        const password = await deps.getPassword(target.id);
        if (password) await deps.copy(password, "password");
      } catch (e) {
        deps.onError(e);
      }
      return;
    }
    if (key === "b" && target.username) {
      event.preventDefault();
      await deps.copy(target.username, "username");
      return;
    }
    if (key === "t" && target.mayHaveTotp) {
      event.preventDefault();
      try {
        const code = await deps.getTotpCode(target.id);
        if (code) await deps.copy(code, "totp");
      } catch (e) {
        deps.onError(e);
      }
      return;
    }
    if (key === "u" && target.uri) {
      event.preventDefault();
      try {
        await openUrl(target.uri);
      } catch (e) {
        deps.onError(e);
      }
    }
  };
}
