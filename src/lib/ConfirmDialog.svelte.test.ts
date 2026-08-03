// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

import ConfirmDialog from "./ConfirmDialog.svelte";
import type { ConfirmRequest } from "./types";

// jsdom ships no <dialog> behaviour; stub the three things the component
// leans on — the open flag, the `close` event, and nothing else. Focus is
// not emulated, which is the point: the component focuses Annuler itself
// rather than trusting the browser's dialog focus algorithm.
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    if (!this.open) return;
    this.open = false;
    this.dispatchEvent(new Event("close"));
  };
});

afterEach(cleanup);

const REQUEST: ConfirmRequest = {
  title: "Mettre à la corbeille ?",
  body: "« GitHub » part à la corbeille.",
  confirmLabel: "Supprimer",
  danger: true,
};

async function flush() {
  for (let i = 0; i < 3; i++) await tick();
}

function buttons() {
  const all = Array.from(document.querySelectorAll("dialog button"));
  return { cancel: all[0] as HTMLButtonElement, confirm: all[1] as HTMLButtonElement };
}

function mount() {
  const { component } = render(ConfirmDialog) as unknown as {
    component: { ask: (r: ConfirmRequest) => Promise<boolean> };
  };
  return component;
}

describe("ConfirmDialog", () => {
  it("opens with focus on Annuler so a stray Entrée cannot delete", async () => {
    const dialog = mount();
    void dialog.ask(REQUEST);
    await flush();

    const { cancel, confirm } = buttons();
    expect(document.querySelector("dialog")?.open).toBe(true);
    expect(confirm.textContent?.trim()).toBe("Supprimer");
    expect(document.activeElement).toBe(cancel);
  });

  it("resolves true only when the confirm button is activated", async () => {
    const dialog = mount();
    const answer = dialog.ask(REQUEST);
    await flush();

    buttons().confirm.click();
    expect(await answer).toBe(true);
    expect(document.querySelector("dialog")?.open).toBe(false);
  });

  it("resolves false on Annuler", async () => {
    const dialog = mount();
    const answer = dialog.ask(REQUEST);
    await flush();

    buttons().cancel.click();
    expect(await answer).toBe(false);
  });

  // Esc and the backdrop both reach the component as a `close` event; an
  // unanswered close must mean "no", never a silent yes.
  it("resolves false when the dialog is dismissed with Esc", async () => {
    const dialog = mount();
    const answer = dialog.ask(REQUEST);
    await flush();

    document.querySelector("dialog")?.close();
    expect(await answer).toBe(false);
  });

  // Nothing raises two prompts at once today; the guard exists so a
  // caller waiting on the older one is never stranded forever.
  it("settles a superseded prompt as cancelled", async () => {
    const dialog = mount();
    const first = dialog.ask(REQUEST);
    await flush();
    const second = dialog.ask({ ...REQUEST, confirmLabel: "Supprimer définitivement" });
    await flush();

    expect(await first).toBe(false);
    buttons().confirm.click();
    expect(await second).toBe(true);
  });
});
