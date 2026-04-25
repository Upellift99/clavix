// Drives a personal Login edit end-to-end through the UI:
// open the seeded "GitHub" cipher → Éditer → rename → save →
// verify the renamed item appears in the list and a fresh sync
// agrees (i.e. the server stored the rename, not just the local
// in-memory state).
//
// Counterpart to create-cipher.spec.mjs: same "drive the editor"
// path, but on an existing item — exercises the encrypt/PUT chain
// rather than the encrypt/POST one. A regression in the cipher
// body builder or in how the editor binds existing values would
// show up here.
//
// Issue #10 — covers "edit existing items and verify server-side
// persistence".

import { loginAsSeededUser } from "../helpers/auth.mjs";

const RENAMED = "GitHub ▸ E2E renamed";

describe("Edit a personal login", () => {
  it("renames the seeded cipher via the editor and persists across sync", async () => {
    await loginAsSeededUser();

    // Click the seeded "GitHub" row to open its detail panel.
    const ghRow = await $(".cipher-row*=GitHub");
    await ghRow.waitForClickable({ timeout: 10_000 });
    await ghRow.click();

    // The detail panel exposes a textual "Éditer" button (no
    // aria-label, just visible text). WDIO `button=...` matches on
    // text content.
    const editButton = await $("button=Éditer");
    await editButton.waitForClickable({ timeout: 10_000 });
    await editButton.click();

    // Editor panel appears; same selectors as create-cipher.spec.
    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    const nameInput = await editor.$('input[type="text"][required]');
    await nameInput.waitForDisplayed({ timeout: 5_000 });
    // Existing value is "GitHub"; clear before typing the new one.
    await nameInput.setValue(RENAMED);

    const submit = await editor.$('button[type="submit"]');
    await submit.click();

    // Editor closes on success → editorOpen flips to false.
    await editor.waitForExist({
      reverse: true,
      timeout: 15_000,
      timeoutMsg: "editor did not close after save",
    });

    // The renamed row is in the list; the old name is not.
    const renamedRow = await $(`.cipher-row*=${RENAMED}`);
    await renamedRow.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg: "renamed cipher never appeared in the list after save",
    });

    // Server-side proof: a fresh sync round-trip returns the new
    // name. Without this, a UI-only mutation that doesn't reach
    // Vaultwarden would still pass the "row exists" assertion above.
    const namesAfterSync = await browser.execute(async () => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.ciphers.map((c) => c.name);
    });

    if (!namesAfterSync.includes(RENAMED)) {
      throw new Error(
        `expected sync to return a cipher named ${JSON.stringify(RENAMED)}, got: ${JSON.stringify(namesAfterSync)}`,
      );
    }
    if (namesAfterSync.includes("GitHub")) {
      throw new Error(
        `the original "GitHub" name should not be in the synced list anymore, got: ${JSON.stringify(namesAfterSync)}`,
      );
    }

    // Restore the original "GitHub" name so the seed remains usable
    // for specs that run after this one in the alphabetical WDIO
    // order (notably share-cipher.spec.mjs, which looks up the
    // seed by name). The proper isolation would be a dedicated
    // fixture per spec — that's a follow-up.
    await browser.execute(async (rename) => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      const renamed = summary.ciphers.find((c) => c.name === rename);
      if (!renamed) return;
      const detail = await invoke("get_cipher", { id: renamed.id });
      await invoke("update_cipher", {
        cipherId: detail.id,
        input: {
          cipherType: detail.kind,
          name: "GitHub",
          folderId: detail.folderId,
          favorite: detail.favorite,
          notes: detail.notes,
          organizationId: detail.organizationId,
          collectionIds: detail.collectionIds,
          login: detail.login
            ? {
                username: detail.login.username,
                password: detail.login.password,
                uris: detail.login.uris ?? [],
                totp: detail.login.totp,
              }
            : null,
        },
      });
    }, RENAMED);
  });
});
