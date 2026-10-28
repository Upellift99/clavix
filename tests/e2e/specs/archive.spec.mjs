// Archive and unarchive through the UI: the row menu, the sidebar entry
// and the counts, against the real server.
//
// filter.test.ts and tree.test.ts cover the rules on the pure helpers.
// What only this spec sees is the whole loop: the menu item calls
// `archive_cipher`, Vaultwarden stamps `archivedDate`, the row leaves the
// main list for the Archive drawer, and unarchiving brings it back.
//
// Labels are matched so they work in both UI languages: "Archiv" (capital
// A) is "Archive" / "Archiver" / "Archives" and never "Unarchive" /
// "Désarchiver".

import { loginAsSeededUser, syncAndWaitForRow } from "../helpers/auth.mjs";

const ITEM = "Archive me";

async function openRowMenu(name) {
  const row = await $(`.cipher-row*=${name}`);
  await row.waitForClickable({ timeout: 15_000 });
  await browser.execute(
    (el) => el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true })),
    row,
  );
  await $(".ctx-menu").waitForDisplayed({ timeout: 5_000 });
}

/** Click the open row menu's entry whose label matches `pattern`. */
async function clickMenuItem(pattern) {
  for (const item of await $$(".ctx-menu button")) {
    if (pattern.test(await item.getText())) {
      await item.click();
      return;
    }
  }
  throw new Error(`no row menu entry matching ${pattern}`);
}

async function serverArchivedDate(name) {
  return browser.execute(async (n) => {
    // @ts-expect-error — tauri injects this global
    const { invoke } = window.__TAURI__.core;
    const summary = await invoke("sync");
    const c = summary.ciphers.find((c) => c.name === n);
    if (!c) throw new Error(`no cipher named ${n}`);
    return c.archivedDate;
  }, name);
}

describe("Archive", () => {
  before(async () => {
    await loginAsSeededUser();
    await browser.execute(async (name) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("create_cipher", {
        input: {
          cipherType: 1,
          name,
          folderId: null,
          favorite: false,
          notes: null,
          organizationId: null,
          collectionIds: [],
          login: { username: "archive@e2e.test", password: "irrelevant", uris: [], totp: null },
        },
      });
    }, ITEM);
    await syncAndWaitForRow(ITEM);
  });

  it("archives from the row menu and moves the item to the Archive drawer", async () => {
    await openRowMenu(ITEM);
    await clickMenuItem(/^Archiv/);

    await browser.waitUntil(async () => !(await $(`.cipher-row*=${ITEM}`).isExisting()), {
      timeout: 10_000,
      timeoutMsg: "the archived item is still in the main list",
    });
    if (!(await serverArchivedDate(ITEM))) {
      throw new Error("the server does not report the item as archived");
    }

    const drawer = await $(".tree-all*=Archiv");
    await browser.waitUntil(async () => (await drawer.$(".tree-count").getText()) === "1", {
      timeout: 5_000,
      timeoutMsg: "the Archive count did not move to 1",
    });
    await drawer.click();
    await $(`.cipher-row*=${ITEM}`).waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "the item is not listed in the Archive drawer",
    });
  });

  it("unarchives from the row menu and brings the item back", async () => {
    await openRowMenu(ITEM);
    // In the archive the menu offers Unarchive / Désarchiver, then Delete.
    await clickMenuItem(/^(Unarchive|Désarchiver)$/);

    await browser.waitUntil(async () => !(await $(`.cipher-row*=${ITEM}`).isExisting()), {
      timeout: 10_000,
      timeoutMsg: "the unarchived item is still in the Archive drawer",
    });
    if ((await serverArchivedDate(ITEM)) !== null) {
      throw new Error("the server still reports the item as archived");
    }

    // Back on "All items": the first quick filter.
    await (await $$(".tree-all"))[0].click();
    await $(`.cipher-row*=${ITEM}`).waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "the unarchived item is not back in the main list",
    });
  });
});
