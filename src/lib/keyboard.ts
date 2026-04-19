import { openUrl } from "@tauri-apps/plugin-opener";
import type { CipherDetail } from "./types";

function isTypingContext(): boolean {
  const a = document.activeElement as HTMLElement | null;
  if (!a) return false;
  const tag = a.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || a.isContentEditable;
}

export type VaultKeyDeps = {
  isLoggedIn: () => boolean;
  getDetail: () => CipherDetail | null;
  getSearchInput: () => HTMLInputElement | null;
  closeDetail: () => void;
  lock: () => Promise<void> | void;
  copy: (value: string, label: string) => Promise<void> | void;
  onError: (e: unknown) => void;
};

/** Builds the global keydown handler for the vault view (Esc, /, Ctrl+F/L/C/B/U). */
export function makeVaultKeyHandler(deps: VaultKeyDeps) {
  return async function handle(event: KeyboardEvent) {
    if (!deps.isLoggedIn()) return;
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
    if (!detail || selectionLength > 0) return;
    if (key === "c" && detail.login?.password) {
      event.preventDefault();
      await deps.copy(detail.login.password, "mot de passe");
      return;
    }
    if (key === "b" && detail.login?.username) {
      event.preventDefault();
      await deps.copy(detail.login.username, "identifiant");
      return;
    }
    if (key === "u" && detail.login?.uris?.[0]) {
      event.preventDefault();
      try {
        await openUrl(detail.login.uris[0]);
      } catch (e) {
        deps.onError(e);
      }
    }
  };
}
