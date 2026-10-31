// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn().mockResolvedValue(undefined),
}));

import { openUrl } from "@tauri-apps/plugin-opener";
import { focusedRowId, isQuitShortcut, makeVaultKeyHandler, type VaultKeyDeps } from "./keyboard";
import type { CipherDetail, CipherSummary } from "./types";

const LOGIN_ROW: CipherSummary = {
  id: "row-login",
  kind: 1,
  name: "GitHub",
  folderId: null,
  organizationId: null,
  collectionIds: [],
  favorite: false,
  primaryUri: "https://github.com",
  username: "octocat",
  revisionDate: null,
  deletedDate: null,
  archivedDate: null,
  notes: null,
};

const NOTE_ROW: CipherSummary = { ...LOGIN_ROW, id: "row-note", kind: 2, username: null, primaryUri: null };

function detail(p: Partial<CipherDetail> = {}): CipherDetail {
  return {
    id: "detail-id",
    kind: 1,
    name: "Open item",
    notes: null,
    organizationId: null,
    folderId: null,
    collectionIds: [],
    revisionDate: null,
    favorite: false,
    login: {
      username: "detail-user",
      hasPassword: true,
      hasTotp: true,
      uris: ["https://example.org"],
    } as CipherDetail["login"],
    card: null,
    identity: null,
    sshKey: null,
    fields: [],
    passwordHistoryCount: 0,
    attachments: [],
    reprompt: false,
    ...p,
  };
}

function deps(overrides: Partial<VaultKeyDeps> = {}) {
  const d: VaultKeyDeps = {
    isLoggedIn: () => true,
    getDetail: () => null,
    getSummary: (id) => [LOGIN_ROW, NOTE_ROW].find((c) => c.id === id) ?? null,
    getSearchInput: () => null,
    closeDetail: vi.fn(),
    lock: vi.fn(),
    copy: vi.fn(),
    getPassword: vi.fn().mockResolvedValue("s3cret"),
    getTotpCode: vi.fn().mockResolvedValue("123456"),
    onError: vi.fn(),
    ...overrides,
  };
  return d;
}

function ctrl(key: string) {
  return new KeyboardEvent("keydown", { key, ctrlKey: true, cancelable: true });
}

/** Mount a list row button carrying `id` and give it focus. */
function focusRow(id: string) {
  const button = document.createElement("button");
  button.className = "cipher-row";
  button.dataset.id = id;
  document.body.appendChild(button);
  button.focus();
  return button;
}

beforeEach(() => {
  document.body.innerHTML = "";
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("focusedRowId", () => {
  it("reads the id off the focused row, including from a child", () => {
    const row = focusRow("abc");
    expect(focusedRowId()).toBe("abc");
    const inner = document.createElement("span");
    inner.tabIndex = 0;
    row.appendChild(inner);
    inner.focus();
    expect(focusedRowId()).toBe("abc");
  });

  it("is null when focus is elsewhere", () => {
    expect(focusedRowId()).toBeNull();
  });
});

describe("vault shortcuts on the focused row (detail closed)", () => {
  it("Ctrl+C copies the focused login's password", async () => {
    const d = deps();
    focusRow(LOGIN_ROW.id);
    const event = ctrl("c");
    await makeVaultKeyHandler(d)(event);
    expect(d.getPassword).toHaveBeenCalledWith(LOGIN_ROW.id);
    expect(d.copy).toHaveBeenCalledWith("s3cret", expect.any(String));
    expect(event.defaultPrevented).toBe(true);
  });

  it("Ctrl+B copies the focused row's username from the summary", async () => {
    const d = deps();
    focusRow(LOGIN_ROW.id);
    await makeVaultKeyHandler(d)(ctrl("b"));
    expect(d.copy).toHaveBeenCalledWith("octocat", expect.any(String));
    expect(d.getPassword).not.toHaveBeenCalled();
  });

  it("Ctrl+T asks for the TOTP and copies it when there is one", async () => {
    const d = deps();
    focusRow(LOGIN_ROW.id);
    await makeVaultKeyHandler(d)(ctrl("t"));
    expect(d.getTotpCode).toHaveBeenCalledWith(LOGIN_ROW.id);
    expect(d.copy).toHaveBeenCalledWith("123456", expect.any(String));
  });

  it("copies nothing when the item turns out to have no such secret", async () => {
    const d = deps({ getTotpCode: vi.fn().mockResolvedValue("") });
    focusRow(LOGIN_ROW.id);
    await makeVaultKeyHandler(d)(ctrl("t"));
    expect(d.copy).not.toHaveBeenCalled();
  });

  it("Ctrl+U opens the focused row's URL", async () => {
    const d = deps();
    focusRow(LOGIN_ROW.id);
    await makeVaultKeyHandler(d)(ctrl("u"));
    expect(openUrl).toHaveBeenCalledWith("https://github.com");
  });

  it("ignores the copy shortcuts on a focused note", async () => {
    const d = deps();
    focusRow(NOTE_ROW.id);
    const event = ctrl("c");
    await makeVaultKeyHandler(d)(event);
    expect(d.getPassword).not.toHaveBeenCalled();
    expect(d.copy).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(false);
  });

  it("does nothing with no detail and no focused row", async () => {
    const d = deps();
    await makeVaultKeyHandler(d)(ctrl("c"));
    expect(d.getPassword).not.toHaveBeenCalled();
  });
});

describe("vault shortcuts with the detail panel open", () => {
  it("prefers the open item over the focused row", async () => {
    const d = deps({ getDetail: () => detail() });
    focusRow(LOGIN_ROW.id);
    await makeVaultKeyHandler(d)(ctrl("b"));
    expect(d.copy).toHaveBeenCalledWith("detail-user", expect.any(String));
  });

  it("skips Ctrl+C when the open item has no password", async () => {
    const d = deps({
      getDetail: () =>
        detail({ login: { username: null, hasPassword: false, hasTotp: false, uris: [] } as CipherDetail["login"] }),
    });
    await makeVaultKeyHandler(d)(ctrl("c"));
    expect(d.getPassword).not.toHaveBeenCalled();
  });

  it("stays out of the way while typing in a field", async () => {
    const d = deps({ getDetail: () => detail() });
    const input = document.createElement("input");
    document.body.appendChild(input);
    input.focus();
    await makeVaultKeyHandler(d)(ctrl("c"));
    expect(d.getPassword).not.toHaveBeenCalled();
  });

  it("stays out of the way while a modal dialog is open", async () => {
    const d = deps({ getDetail: () => detail() });
    const dialog = document.createElement("dialog");
    dialog.setAttribute("open", "");
    document.body.appendChild(dialog);
    await makeVaultKeyHandler(d)(ctrl("c"));
    expect(d.getPassword).not.toHaveBeenCalled();
  });
});

describe("isQuitShortcut", () => {
  const key = (init: KeyboardEventInit) => new KeyboardEvent("keydown", init);

  it("matches Ctrl+Q and Cmd+Q", () => {
    expect(isQuitShortcut(ctrl("q"))).toBe(true);
    expect(isQuitShortcut(key({ key: "q", metaKey: true }))).toBe(true);
  });

  it("matches with Shift held (key comes through as Q)", () => {
    expect(isQuitShortcut(key({ key: "Q", ctrlKey: true, shiftKey: true }))).toBe(true);
  });

  it("ignores a plain q and other Ctrl combos", () => {
    expect(isQuitShortcut(key({ key: "q" }))).toBe(false);
    expect(isQuitShortcut(ctrl("w"))).toBe(false);
  });

  it("ignores Ctrl+Alt+Q, which AltGr produces on some layouts", () => {
    expect(isQuitShortcut(key({ key: "q", ctrlKey: true, altKey: true }))).toBe(false);
  });
});
