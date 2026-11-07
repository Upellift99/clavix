// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// The prompt is driven entirely by a Tauri event and answers over IPC;
// both ends are mocked so the component test needs no backend.
const evt = vi.hoisted(() => ({
  cb: null as null | ((event: { payload: unknown }) => void),
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (_name: string, cb: (event: { payload: unknown }) => void) => {
    evt.cb = cb;
    return () => {};
  }),
}));

const apiMock = vi.hoisted(() => ({
  respondSshAgentConfirm: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("./api", () => ({ api: apiMock }));

import SshConfirmDialog from "./SshConfirmDialog.svelte";

// jsdom (29) still ships no <dialog> behaviour, so showModal/close are
// stubbed to the two things the component relies on: the open flag and
// the `close` event. Focus is deliberately NOT emulated — the component
// focuses Autoriser itself rather than leaning on the browser's dialog
// focus algorithm, which is exactly what these tests pin down.
beforeEach(() => {
  vi.useFakeTimers();
  apiMock.respondSshAgentConfirm.mockClear();
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    if (!this.open) return;
    this.open = false;
    this.dispatchEvent(new Event("close"));
  };
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  evt.cb = null;
});

const REQ = {
  id: 1,
  comment: "laptop@clavix",
  algorithm: "ssh-ed25519",
  fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  callerName: "git",
  callerPid: 4321,
  hops: [] as { host: string | null; fingerprint: string; forwarded: boolean }[],
};

// `show()` awaits a tick before opening (so the buttons exist when focus
// is moved); a couple of flushes covers that plus the listen() promise.
async function flush() {
  for (let i = 0; i < 4; i++) await tick();
}

async function emit(req = REQ) {
  evt.cb?.({ payload: req });
  await flush();
}

function buttons() {
  const all = Array.from(document.querySelectorAll("dialog button"));
  return { deny: all[0] as HTMLButtonElement, allow: all[1] as HTMLButtonElement };
}

describe("SshConfirmDialog keyboard defaults", () => {
  it("opens with focus on Autoriser, not on the dialog frame", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit();

    const { allow } = buttons();
    expect(allow.textContent?.trim()).toBe("Autoriser");
    // Pressing Entrée activates the focused button — this is what makes
    // Entrée mean "approve".
    expect(document.activeElement).toBe(allow);
  });

  it("swallows an approval that lands inside the arming delay", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit();

    buttons().allow.click();
    await flush();
    expect(apiMock.respondSshAgentConfirm).not.toHaveBeenCalled();
    expect(document.querySelector("dialog")?.open).toBe(true);
  });

  it("approves once the arming delay has passed", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit();

    vi.advanceTimersByTime(300);
    buttons().allow.click();
    await flush();
    expect(apiMock.respondSshAgentConfirm).toHaveBeenCalledWith(1, true);
  });

  it("denies immediately — the delay guards approvals only", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit();

    buttons().deny.click();
    await flush();
    expect(apiMock.respondSshAgentConfirm).toHaveBeenCalledWith(1, false);
  });

  it("re-arms for a queued request instead of inheriting the first one's state", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit();
    // Second signature arrives while the first prompt is up (parallel
    // `ssh` connections); it queues behind it.
    await emit({ ...REQ, id: 2 });

    vi.advanceTimersByTime(300);
    buttons().allow.click();
    await flush();
    expect(apiMock.respondSshAgentConfirm).toHaveBeenCalledWith(1, true);

    // The queued prompt is now showing: focused on Autoriser, and its own
    // 300 ms window applies — a held Entrée must not carry through it.
    const { allow } = buttons();
    expect(document.activeElement).toBe(allow);
    allow.click();
    await flush();
    expect(apiMock.respondSshAgentConfirm).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(300);
    allow.click();
    await flush();
    expect(apiMock.respondSshAgentConfirm).toHaveBeenCalledWith(2, true);
  });
});

describe("SshConfirmDialog session-bind display", () => {
  const JUMP = { host: "bastion.example", fingerprint: "SHA256:JUMP", forwarded: true };
  const DEST = { host: "git.example", fingerprint: "SHA256:DEST", forwarded: false };

  function rows() {
    const dts = Array.from(document.querySelectorAll("dialog dt")).map((e) => e.textContent?.trim());
    const dds = Array.from(document.querySelectorAll("dialog dd")).map((e) => e.textContent ?? "");
    return { dts, dds };
  }

  it("shows no destination row when the client sent no binding", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit();
    expect(rows().dts).not.toContain("Destination");
    expect(document.querySelector(".ssh-confirm-remote-hint")).toBeNull();
  });

  it("names the destination and the hosts it is reached through", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit({ ...REQ, hops: [JUMP, DEST] });
    const { dts, dds } = rows();
    const dest = dts.indexOf("Destination");
    expect(dest).toBeGreaterThan(-1);
    expect(dds[dest]).toContain("git.example");
    expect(dds[dest]).toContain("SHA256:DEST");
    const via = dts.indexOf("Via");
    expect(dds[via]).toContain("bastion.example");
    expect(document.querySelector(".ssh-confirm-remote-hint")).toBeNull();
  });

  it("flags a request coming from a forwarded agent on a remote host", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit({ ...REQ, hops: [JUMP] });
    const { dts, dds } = rows();
    expect(dts).not.toContain("Destination");
    expect(dds[dts.indexOf("Depuis")]).toContain("bastion.example");
    expect(document.querySelector(".ssh-confirm-remote-hint")).not.toBeNull();
  });

  it("falls back to the fingerprint for a host missing from known_hosts", async () => {
    render(SshConfirmDialog);
    await flush();
    await emit({ ...REQ, hops: [{ ...DEST, host: null }] });
    const { dts, dds } = rows();
    const dest = dds[dts.indexOf("Destination")];
    expect(dest).toContain("hôte absent de known_hosts");
    expect(dest).toContain("SHA256:DEST");
  });
});
