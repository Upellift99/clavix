// Drives the creation of a personal Login cipher end-to-end:
// unlocked vault → "+" → fill editor → save → item visible in the
// list. The submit path goes through services::cipher::build_cipher_body
// on the Rust side (covered by unit tests), but only an E2E run
// verifies that the UI binds the inputs correctly into the IPC
// payload — a regression in Svelte's form bindings wouldn't show up
// anywhere else.

import { loginAsSeededUser } from "../helpers/auth.mjs";

// Disambiguating fixture name: unlikely to collide with the seed data
// ("GitHub", "Welcome note") so the "is it in the list?" assertion
// can't get a false positive from a pre-existing row.
const ITEM_NAME = "E2E test login ▸ created by WDIO";

describe("Create a personal login", () => {
  it("adds a new login cipher that appears in the list", async () => {
    await loginAsSeededUser();

    const addButton = await $('button[aria-label="Nouvel item"]');
    await addButton.waitForClickable({ timeout: 10_000 });
    await addButton.click();

    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    // The name field is the only required text input in the editor.
    const nameInput = await editor.$('input[type="text"][required]');
    await nameInput.waitForDisplayed({ timeout: 5_000 });
    await nameInput.setValue(ITEM_NAME);

    // Username and password are the first text + password inputs that
    // appear when the cipher type stays at its default (Login).
    const usernameInput = await editor.$("label*=Identifiant").$("input");
    await usernameInput.setValue("alice@e2e.test");

    const passwordInput = await editor.$('input[type="password"]');
    await passwordInput.setValue("sup3r-str0ng-passphrase");

    const submit = await editor.$('button[type="submit"]');
    await submit.click();

    // The editor closes on success (submitEditor → `editorOpen = false`),
    // and the freshly created item lands in the list after the triggered
    // sync. Wait for both.
    await editor.waitForExist({
      reverse: true,
      timeout: 15_000,
      timeoutMsg: "editor did not close after save",
    });

    const newRow = await $(`.cipher-row*=${ITEM_NAME}`);
    await newRow.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg: "new cipher never appeared in the list after save",
    });
  });
});
