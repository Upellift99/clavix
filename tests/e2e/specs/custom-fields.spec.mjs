// Custom fields, added through the editor and read back from the
// server.
//
// The chain under test is the one that used to lose data: the editor
// binds the rows, `payloadToRust` drops the empty ones, Rust encrypts
// name and value under the item key, and the cipher PUT — which
// replaces the server's copy wholesale — has to carry them. A body
// that omits `fields` deletes them silently, which is precisely the
// bug this suite exists to keep out.
//
// The hidden-field assertion is the interesting one: `get_cipher` must
// withhold the value (presence only, like every other secret) while
// `reveal_field("custom:<index>")` hands it over on demand. Getting
// that backwards would be invisible in the UI and would put a secret
// back into long-lived WebView state.

import { loginAsSeededUser, syncAndWaitForRow } from "../helpers/auth.mjs";

const ITEM = "E2E custom fields subject";
const ITEM_KEPT = "E2E custom fields kept";
const TEXT_FIELD = { name: "Account ID", value: "AC-42" };
const HIDDEN_FIELD = { name: "Recovery", value: "code-123" };

async function createSubject(name) {
  return browser.execute(async (itemName) => {
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
        login: {
          username: "fields@e2e.test",
          password: "irrelevant",
          uris: [],
          totp: null,
        },
      },
    });
    await invoke("sync");
    return id;
  }, name);
}

/**
 * Fill the last custom-field row of the editor.
 *
 * A row is `select`, then two inputs: name, then value. The value one
 * is `type="password"` for a hidden field and `type="text"` otherwise,
 * so it is addressed by position rather than by type.
 */
async function fillLastRow(kind, field) {
  const rows = await $$(".custom-field-row");
  const row = rows[rows.length - 1];

  if (kind !== 0) {
    await row.$("select").selectByAttribute("value", String(kind));
  }
  const inputs = await row.$$("input");
  await inputs[0].setValue(field.name);
  await inputs[1].setValue(field.value);
}

describe("Custom fields", () => {
  // One login for the whole file: WDIO keeps a single browser session
  // per spec, so a second `loginAsSeededUser` would wait forever on a
  // login form that is no longer on screen.
  before(async () => {
    await loginAsSeededUser();
  });

  it("survives a save and keeps hidden values out of get_cipher", async () => {
    const id = await createSubject(ITEM);
    const row = await syncAndWaitForRow(ITEM);
    await row.click();

    const editButton = await $("button=Éditer");
    await editButton.waitForClickable({ timeout: 10_000 });
    await editButton.click();

    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    const addField = await $("button*=Ajouter un champ");
    await addField.waitForClickable({ timeout: 10_000 });

    await addField.click();
    await fillLastRow(0, TEXT_FIELD);
    await addField.click();
    await fillLastRow(1, HIDDEN_FIELD);

    const submit = await editor.$('button[type="submit"]');
    await submit.click();
    await editor.waitForExist({
      reverse: true,
      timeout: 20_000,
      timeoutMsg: "editor did not close after saving custom fields",
    });

    // Read the item back through a fresh sync, so this asserts on what
    // Vaultwarden stored rather than on local state.
    const stored = await browser.execute(async (cipherId) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("sync");
      const detail = await invoke("get_cipher", { id: cipherId });
      const revealed = await invoke("reveal_field", {
        id: cipherId,
        field: "custom:1",
      });
      return { fields: detail.fields, revealed };
    }, id);

    if (stored.fields.length !== 2) {
      throw new Error(
        `expected 2 custom fields after save, got ${JSON.stringify(stored.fields)}`,
      );
    }

    const [text, hidden] = stored.fields;
    if (text.name !== TEXT_FIELD.name || text.value !== TEXT_FIELD.value) {
      throw new Error(`text field round-tripped wrong: ${JSON.stringify(text)}`);
    }
    if (hidden.name !== HIDDEN_FIELD.name) {
      throw new Error(`hidden field name round-tripped wrong: ${JSON.stringify(hidden)}`);
    }
    if (hidden.hidden !== true || hidden.value !== null) {
      throw new Error(
        `a hidden field must reach the WebView without its value, got ${JSON.stringify(hidden)}`,
      );
    }
    if (stored.revealed !== HIDDEN_FIELD.value) {
      throw new Error(
        `reveal_field("custom:1") returned ${JSON.stringify(stored.revealed)}`,
      );
    }
  });

  it("keeps the fields when the item is edited again", async () => {
    // The regression in one line: open an item that has custom fields,
    // change something unrelated, save. The PUT replaces the server's
    // copy, so a body that forgot the fields would wipe them here.
    const id = await createSubject(ITEM_KEPT);

    await browser.execute(async (cipherId, field, itemName) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("update_cipher", {
        cipherId,
        input: {
          cipherType: 1,
          name: itemName,
          folderId: null,
          favorite: false,
          notes: null,
          organizationId: null,
          collectionIds: [],
          login: {
            username: "fields@e2e.test",
            password: "irrelevant",
            uris: [],
            totp: null,
          },
          fields: [{ kind: 0, name: field.name, value: field.value, linkedId: null }],
          reprompt: false,
        },
      });
    }, id, TEXT_FIELD, ITEM_KEPT);

    const row = await syncAndWaitForRow(ITEM_KEPT);
    await row.click();

    const editButton = await $("button=Éditer");
    await editButton.waitForClickable({ timeout: 10_000 });
    await editButton.click();

    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    // The editor must have loaded the existing row.
    const rows = await $$(".custom-field-row");
    if (rows.length !== 1) {
      throw new Error(`editor showed ${rows.length} custom field rows, expected 1`);
    }

    // Touch something else entirely, then save.
    const favorite = await editor.$(".checkbox-row input[type='checkbox']");
    await favorite.click();
    await editor.$('button[type="submit"]').click();
    await editor.waitForExist({ reverse: true, timeout: 20_000 });

    const after = await browser.execute(async (cipherId) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("sync");
      const detail = await invoke("get_cipher", { id: cipherId });
      return detail.fields;
    }, id);

    if (after.length !== 1 || after[0].value !== TEXT_FIELD.value) {
      throw new Error(
        `an unrelated edit wiped the custom fields: ${JSON.stringify(after)}`,
      );
    }
  });
});
