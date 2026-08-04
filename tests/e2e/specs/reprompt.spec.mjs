// The per-item master-password gate.
//
// This is the one new surface whose whole value is that it refuses
// something, so a test that only checks the happy path would miss the
// point entirely: what matters is that a wrong password reveals
// nothing, and that dismissing the prompt leaves the secret hidden.
//
// The gate lives in the page rather than in the detail panel precisely
// so every entry point honours it, so the second case here goes in
// through the row context menu — a path that has its own copy of the
// "reveal a secret" logic and would be the natural place for the gate
// to be forgotten.

import { loginAsSeededUser, syncAndWaitForRow } from "../helpers/auth.mjs";

const ITEM = "E2E reprompt subject";
const PASSWORD = "s3cret-under-guard";
const MASTER = "correct-horse-battery-staple";

async function createGuardedItem(name) {
  return browser.execute(
    async (itemName, password) => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const id = await invoke("create_cipher", {
        input: {
          cipherType: 1,
          name: itemName,
          folderId: null,
          favorite: false,
          notes: null,
          organizationId: null,
          collectionIds: [],
          login: { username: "guard@e2e.test", password, uris: [], totp: null },
          fields: [],
          reprompt: true,
        },
      });
      await invoke("sync");
      return id;
    },
    name,
    PASSWORD,
  );
}

/** Create a guarded item, sync the list, open it, return its row. */
async function openGuardedItem(name) {
  await createGuardedItem(name);
  const row = await syncAndWaitForRow(name);
  await row.click();
  return row;
}

/** The eye toggle on the password row of the detail panel. */
async function revealButton() {
  const button = await $('.detail-field button[title="Afficher"]');
  await button.waitForClickable({ timeout: 15_000 });
  return button;
}

describe("Master-password reprompt", () => {
  before(async () => {
    await loginAsSeededUser();
  });

  it("refuses to reveal on a wrong password and reveals on the right one", async () => {
    await openGuardedItem(`${ITEM} A`);

    await (await revealButton()).click();

    const dialog = await $("dialog.reprompt-dialog");
    await dialog.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "revealing a flagged item did not ask for the master password",
    });

    // Wrong password: the dialog stays, says so, and nothing is shown.
    const input = await dialog.$('input[type="password"]');
    await input.setValue("not-the-master-password");
    await dialog.$('button[type="submit"]').click();

    const error = await dialog.$(".reprompt-error");
    await error.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg: "a wrong master password was accepted silently",
    });
    if (!(await dialog.isDisplayed())) {
      throw new Error("the prompt closed on a wrong password");
    }
    const bodyText = await $(".cipher-detail").getText();
    if (bodyText.includes(PASSWORD)) {
      throw new Error("the password was on screen despite a failed reprompt");
    }

    // Right password: the dialog closes and the value appears.
    await input.setValue(MASTER);
    await dialog.$('button[type="submit"]').click();
    await dialog.waitForDisplayed({
      reverse: true,
      timeout: 15_000,
      timeoutMsg: "the prompt stayed up after the correct master password",
    });

    await browser.waitUntil(
      async () => (await $(".cipher-detail").getText()).includes(PASSWORD),
      {
        timeout: 15_000,
        timeoutMsg: "the password never appeared after a successful reprompt",
      },
    );
  });

  it("reveals nothing when the prompt is dismissed", async () => {
    await openGuardedItem(`${ITEM} B`);

    await (await revealButton()).click();
    const dialog = await $("dialog.reprompt-dialog");
    await dialog.waitForDisplayed({ timeout: 10_000 });

    // Annuler is the first button and where focus deliberately lands.
    await dialog.$("button.secondary").click();
    await dialog.waitForDisplayed({ reverse: true, timeout: 10_000 });

    const detail = await $(".cipher-detail").getText();
    if (detail.includes(PASSWORD)) {
      throw new Error("dismissing the prompt still revealed the password");
    }
    // The toggle must not have flipped either — a dismissed prompt
    // leaves the row exactly as it was.
    const stillHidden = await $('.detail-field button[title="Afficher"]');
    if (!(await stillHidden.isExisting())) {
      throw new Error("the reveal toggle flipped despite the refusal");
    }
  });

  it("guards the row context menu too, not just the detail panel", async () => {
    const row = await openGuardedItem(`${ITEM} C`);

    // Right-click the row: the menu offers "Copier le mot de passe"
    // only once the decrypted detail is known to carry one.
    await browser.execute(
      (el) => el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true })),
      row,
    );

    const menu = await $(".ctx-menu");
    await menu.waitForDisplayed({ timeout: 10_000 });

    const copyPassword = await menu.$("button*=mot de passe");
    await copyPassword.waitForClickable({
      timeout: 15_000,
      timeoutMsg: "the context menu never offered the password copy",
    });
    await copyPassword.click();

    const dialog = await $("dialog.reprompt-dialog");
    await dialog.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "copying from the row menu bypassed the reprompt",
    });
    await dialog.$("button.secondary").click();
  });
});
