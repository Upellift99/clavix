// Multi-selection in the item list, driven through the UI.
//
// The selection is the one piece of vault state that lives in the page
// rather than in the store, and it is only reachable through modifier
// clicks — there is no checkbox column. That makes it invisible to
// every other layer of tests: the vitest suites cover the pure filter
// helpers, and the IPC-level specs never touch a row. What can break
// here is exactly what no other test would notice — a plain click that
// forgets to drop the selection, a Shift range computed against the
// unfiltered list, or a bulk delete that fires on ids the current
// filter no longer shows.
//
// Ctrl-click is dispatched as a synthetic MouseEvent rather than
// through the WebDriver key-down/click dance: what we are testing is
// the component's handling of `event.ctrlKey`, and going through the
// real keyboard adds a WebKitGTK focus dependency that has nothing to
// do with the behaviour under test.

import { loginAsSeededUser, syncAndWaitForRow } from "../helpers/auth.mjs";

const ITEMS = ["E2E bulk one", "E2E bulk two", "E2E bulk three"];
const PLAIN_ITEMS = ["E2E plain one", "E2E plain two"];

/** Create the three dedicated ciphers this spec operates on. */
async function seedBulkItems(names) {
  return browser.execute(async (itemNames) => {
    // @ts-expect-error — tauri injects this global
    const { invoke } = window.__TAURI__.core;
    const ids = [];
    for (const name of itemNames) {
      ids.push(
        await invoke("create_cipher", {
          input: {
            cipherType: 1,
            name,
            folderId: null,
            favorite: false,
            notes: null,
            organizationId: null,
            collectionIds: [],
            login: {
              username: "bulk@e2e.test",
              password: "irrelevant",
              uris: [],
              totp: null,
            },
          },
        }),
      );
    }
    await invoke("sync");
    return ids;
  }, names);
}

async function clickRow(name, modifiers = {}) {
  const row = await $(`.cipher-row*=${name}`);
  await row.waitForClickable({ timeout: 15_000 });
  await browser.execute(
    (el, mods) => el.dispatchEvent(new MouseEvent("click", { bubbles: true, ...mods })),
    row,
    modifiers,
  );
}

/** Ids the server currently reports as trashed. */
async function trashedIds() {
  return browser.execute(async () => {
    // @ts-expect-error
    const { invoke } = window.__TAURI__.core;
    const summary = await invoke("sync");
    return summary.ciphers.filter((c) => c.deletedDate).map((c) => c.id);
  });
}

describe("Bulk selection", () => {
  // One login per spec file — WDIO reuses a single browser session.
  before(async () => {
    await loginAsSeededUser();
  });

  it("selects with Ctrl-click and moves the selection to the trash", async () => {
    const ids = await seedBulkItems(ITEMS);
    // Items created over IPC live in the Rust vault; the list only
    // learns about them when the renderer syncs.
    await syncAndWaitForRow(ITEMS[0]);

    // No selection, no bar: it must not take a row of vertical space
    // for an action nobody asked for.
    const bar = await $(".selection-bar");
    if (await bar.isExisting()) {
      throw new Error("the selection bar is on screen with nothing selected");
    }

    await clickRow(ITEMS[0], { ctrlKey: true });
    await clickRow(ITEMS[1], { ctrlKey: true });

    await bar.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "selection bar never appeared after two Ctrl-clicks",
    });
    const count = await $(".selection-count").getText();
    if (!count.includes("2")) {
      throw new Error(`expected the bar to report 2 selected, got: ${count}`);
    }

    // Delete → the shared confirmation dialog, which must be answered
    // before anything is written.
    const deleteButton = await $(".selection-bar button.danger");
    await deleteButton.click();

    const dialog = await $("dialog.confirm-dialog");
    await dialog.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "bulk delete did not raise a confirmation",
    });
    const body = await dialog.$(".confirm-body").getText();
    if (!body.includes("2")) {
      throw new Error(`the confirmation should name the count, got: ${body}`);
    }

    // Second button in the row is the confirm one; the first is Annuler,
    // which is where focus deliberately lands.
    const confirmButton = await dialog.$$(".confirm-actions button")[1];
    await confirmButton.click();

    await browser.waitUntil(
      async () => {
        const trashed = await trashedIds();
        return trashed.includes(ids[0]) && trashed.includes(ids[1]);
      },
      {
        timeout: 30_000,
        timeoutMsg: "the two selected items never reached the trash on the server",
      },
    );

    // The untouched third item must still be live — a bulk action that
    // quietly widened its own scope is the failure mode that matters.
    const stillLive = await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      const c = summary.ciphers.find((c) => c.id === id);
      return c ? c.deletedDate === null : null;
    }, ids[2]);
    if (stillLive !== true) {
      throw new Error(
        `the unselected item should be untouched, deletedDate check returned ${JSON.stringify(stillLive)}`,
      );
    }
  });

  it("drops the selection on a plain click", async () => {
    await seedBulkItems(PLAIN_ITEMS);
    await syncAndWaitForRow(PLAIN_ITEMS[0]);

    await clickRow(PLAIN_ITEMS[0], { ctrlKey: true });
    const bar = await $(".selection-bar");
    await bar.waitForDisplayed({ timeout: 10_000 });

    // A plain click opens the item and clears the ticks. Without this,
    // a coche left over from three filters ago rides along into the
    // next bulk delete.
    await clickRow(PLAIN_ITEMS[1]);
    await bar.waitForDisplayed({
      reverse: true,
      timeout: 10_000,
      timeoutMsg: "the selection survived a plain click",
    });
  });
});
