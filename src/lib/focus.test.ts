// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { tick } from "svelte";

import { focusOnMount, focusableWithin, trapFocus } from "./focus";

afterEach(() => {
  document.body.innerHTML = "";
});

function dialog() {
  document.body.innerHTML = `
    <button id="outside">outside</button>
    <div id="panel" tabindex="-1">
      <button id="first">first</button>
      <input id="middle" />
      <button id="disabled" disabled>skip</button>
      <button id="last">last</button>
    </div>`;
  // jsdom reports no layout; make everything count as visible.
  for (const el of document.querySelectorAll<HTMLElement>("*")) {
    Object.defineProperty(el, "offsetHeight", { value: 10, configurable: true });
  }
  return {
    outside: document.getElementById("outside") as HTMLButtonElement,
    panel: document.getElementById("panel") as HTMLElement,
    first: document.getElementById("first") as HTMLButtonElement,
    middle: document.getElementById("middle") as HTMLInputElement,
    last: document.getElementById("last") as HTMLButtonElement,
  };
}

function tab(target: Element, shift = false) {
  const event = new KeyboardEvent("keydown", { key: "Tab", shiftKey: shift, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}

describe("focusableWithin", () => {
  it("lists enabled controls in document order", () => {
    const { panel } = dialog();
    expect(focusableWithin(panel).map((e) => e.id)).toEqual(["first", "middle", "last"]);
  });
});

describe("focusOnMount", () => {
  it("focuses the node after a tick", async () => {
    const { first } = dialog();
    focusOnMount(first);
    expect(document.activeElement).not.toBe(first);
    await tick();
    expect(document.activeElement).toBe(first);
  });
});

describe("trapFocus", () => {
  it("focuses the first control on open, or the requested one", async () => {
    const d = dialog();
    const trap = trapFocus(d.panel);
    await tick();
    expect(document.activeElement).toBe(d.first);
    trap.destroy();

    const trap2 = trapFocus(d.panel, { initial: "#middle" });
    await tick();
    expect(document.activeElement).toBe(d.middle);
    trap2.destroy();
  });

  it("wraps Tab from the last control and Shift+Tab from the first", async () => {
    const d = dialog();
    const trap = trapFocus(d.panel);
    await tick();
    d.last.focus();
    const forward = tab(d.last);
    expect(forward.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(d.first);

    const backward = tab(d.first, true);
    expect(backward.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(d.last);

    d.middle.focus();
    const plain = tab(d.middle);
    expect(plain.defaultPrevented).toBe(false);
    trap.destroy();
  });

  it("hands focus back to where it was when destroyed", async () => {
    const d = dialog();
    d.outside.focus();
    const trap = trapFocus(d.panel);
    await tick();
    expect(document.activeElement).toBe(d.first);
    trap.destroy();
    expect(document.activeElement).toBe(d.outside);
  });
});
