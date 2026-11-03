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
    clearSearch: vi.fn(),
    getSoleMatch: () => null,
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

/** Mount the search box holding `value`, caret at the end, and focus it. */
function focusSearch(value: string) {
  const input = document.createElement("input");
  input.type = "search";
  document.body.appendChild(input);
  input.value = value;
  input.focus();
  input.setSelectionRange(value.length, value.length);
  return input;
}

function esc() {
  return new KeyboardEvent("keydown", { key: "Escape", cancelable: true });
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

describe("search box", () => {
  it("Esc clears a search box holding text and leaves the panel open", async () => {
    const input = focusSearch("git");
    const d = deps({ getDetail: () => detail(), getSearchInput: () => input });
    const event = esc();
    await makeVaultKeyHandler(d)(event);
    expect(d.clearSearch).toHaveBeenCalledTimes(1);
    expect(d.closeDetail).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(true);
  });

  it("Esc in an empty search box closes the panel", async () => {
    const input = focusSearch("");
    const d = deps({ getDetail: () => detail(), getSearchInput: () => input });
    await makeVaultKeyHandler(d)(esc());
    expect(d.clearSearch).not.toHaveBeenCalled();
    expect(d.closeDetail).toHaveBeenCalledTimes(1);
  });

  it("Esc outside the search box closes the panel even with a query", async () => {
    const input = focusSearch("git");
    const d = deps({ getDetail: () => detail(), getSearchInput: () => input });
    focusRow(LOGIN_ROW.id);
    await makeVaultKeyHandler(d)(esc());
    expect(d.clearSearch).not.toHaveBeenCalled();
    expect(d.closeDetail).toHaveBeenCalledTimes(1);
  });

  it("Esc on a row after Enter closes the panel, then clears the query", async () => {
    const input = focusSearch("paypal");
    let open: CipherDetail | null = detail();
    const d = deps({
      getDetail: () => open,
      getSearchInput: () => input,
      closeDetail: vi.fn(() => (open = null)),
    });
    focusRow(LOGIN_ROW.id);
    const handle = makeVaultKeyHandler(d);

    await handle(esc());
    expect(d.closeDetail).toHaveBeenCalledTimes(1);
    expect(d.clearSearch).not.toHaveBeenCalled();

    const second = esc();
    await handle(second);
    expect(d.clearSearch).toHaveBeenCalledTimes(1);
    expect(second.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(input);
  });

  it("leaves the query alone when another field handles its own Esc", async () => {
    const search = focusSearch("paypal");
    const rename = document.createElement("input");
    document.body.appendChild(rename);
    rename.focus();
    const d = deps({ getSearchInput: () => search });
    await makeVaultKeyHandler(d)(esc());
    expect(d.clearSearch).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(rename);
  });

  it("does nothing on Esc with no query and nothing open", async () => {
    const input = focusSearch("");
    const d = deps({ getSearchInput: () => input });
    focusRow(LOGIN_ROW.id);
    const event = esc();
    await makeVaultKeyHandler(d)(event);
    expect(d.clearSearch).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(false);
  });

  it("Ctrl+C copies the sole match's password, over another open item", async () => {
    const input = focusSearch("git");
    const d = deps({
      getDetail: () => detail(),
      getSearchInput: () => input,
      getSoleMatch: () => LOGIN_ROW,
    });
    const event = ctrl("c");
    await makeVaultKeyHandler(d)(event);
    expect(d.getPassword).toHaveBeenCalledWith(LOGIN_ROW.id);
    expect(d.copy).toHaveBeenCalledWith("s3cret", "password");
    expect(event.defaultPrevented).toBe(true);
  });

  it("Ctrl+B copies the sole match's username", async () => {
    const input = focusSearch("git");
    const d = deps({ getSearchInput: () => input, getSoleMatch: () => LOGIN_ROW });
    await makeVaultKeyHandler(d)(ctrl("b"));
    expect(d.copy).toHaveBeenCalledWith("octocat", "username");
  });

  it("uses the open item's detail when it is the sole match", async () => {
    const input = focusSearch("git");
    const open = detail({
      id: LOGIN_ROW.id,
      login: { username: null, hasPassword: false, hasTotp: false, uris: [] } as CipherDetail["login"],
    });
    const d = deps({
      getDetail: () => open,
      getSearchInput: () => input,
      getSoleMatch: () => LOGIN_ROW,
    });
    const event = ctrl("c");
    await makeVaultKeyHandler(d)(event);
    expect(d.getPassword).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(false);
  });

  it("leaves Ctrl+C to the query when its text is selected", async () => {
    const input = focusSearch("git");
    input.select();
    const d = deps({ getSearchInput: () => input, getSoleMatch: () => LOGIN_ROW });
    const event = ctrl("c");
    await makeVaultKeyHandler(d)(event);
    expect(d.getPassword).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(false);
  });

  it("does nothing from the search box without a sole match", async () => {
    const input = focusSearch("g");
    const d = deps({ getSearchInput: () => input });
    await makeVaultKeyHandler(d)(ctrl("c"));
    expect(d.getPassword).not.toHaveBeenCalled();
  });

  it("ignores the sole match while another field has focus", async () => {
    const search = focusSearch("git");
    const other = document.createElement("input");
    document.body.appendChild(other);
    other.focus();
    const d = deps({ getSearchInput: () => search, getSoleMatch: () => LOGIN_ROW });
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
