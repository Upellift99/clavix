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
  /** Empty the search box (what its Clear button does). */
  clearSearch: () => void;
  /** The one row a settled, non-empty search leaves; null otherwise. */
  getSoleMatch: () => CipherSummary | null;
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
 * keyboard path is type, Enter or Down, Ctrl+C. When the search leaves
 * a single row, that row is the target straight from the search box:
 * type, Ctrl+C.
 *
 * Esc in a search box holding text clears it; otherwise Esc closes the
 * detail panel, and with the panel closed it clears the query from the
 * list as well.
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
    const search = deps.getSearchInput();
    const inSearch = search !== null && document.activeElement === search;

    if (event.key === "Escape") {
      // One thing per press, nearest first: in the search box the query
      // comes before the panel, and the default is cancelled so WebKit's
      // own search-field Esc doesn't run alongside.
      const hasQuery = search !== null && search.value !== "";
      if (inSearch && hasQuery) {
        event.preventDefault();
        deps.clearSearch();
        return;
      }
      if (detail) {
        event.preventDefault();
        deps.closeDetail();
        return;
      }
      // Nothing left open: Esc from the list clears the query too (Enter
      // in the search box moves focus onto the row it opens), and puts
      // the cursor back in the box for the next one. Another field's own
      // Esc (a folder rename) is left alone.
      if (hasQuery && !isTypingContext() && !event.defaultPrevented) {
        event.preventDefault();
        deps.clearSearch();
        search.focus();
        return;
      }
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
    const sole = inSearch ? deps.getSoleMatch() : null;
    if (inSearch && sole) {
      // After / or Ctrl+F the query is selected, and Ctrl+C then means
      // the query. window.getSelection() does not see inside an input.
      if (search.selectionStart !== search.selectionEnd) return;
    } else {
      if (isTypingContext()) return;
      const selectionLength = window.getSelection()?.toString().length ?? 0;
      if (selectionLength > 0) return;
    }

    let target: ShortcutTarget | null = null;
    if (sole) {
      // The outlined row is what the user is looking at, even when the
      // panel shows some other item; the panel's copy knows more when
      // it is the same one.
      target = detail?.id === sole.id ? fromDetail(detail) : fromSummary(sole);
    } else if (detail) {
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
