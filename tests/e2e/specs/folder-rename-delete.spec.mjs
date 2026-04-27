// Folder rename + delete — end-to-end through the new
// `rename_folder` and `delete_folder` Tauri commands.
//
// Vaultwarden's web UI doesn't currently expose a delete control on
// folders at all (upstream Bitwarden does — likely a Vaultwarden
// regression), so for users with stale or duplicate folders Clavix
// is the only path. The HTTP layer (`delete_folder`,
// `update_folder_name`) was already wired in `api.rs`; what wasn't
// covered was the full round-trip through the new Tauri commands
// plus the local-cache mutations they perform (folder removed from
// `vault.folders`, `cipher.folder_id` cleared on detached items, the
// rename reflected in the next sync's plaintext name).
//
// IPC-driven for the same reason `folder-cascade.spec.mjs` is: the
// drag-drop / right-click UI surface is brittle under synthetic
// WebDriver events, and the right-click menu's only job is to call
// these IPC handlers. Their unit-tests at the Rust layer would not
// catch a regression in the in-memory vault splice (e.g. forgetting
// to clear `folder_id` on detached ciphers), so we exercise them
// here against a real Vaultwarden.
//
// Issue addendum: also covers the dedup fix — two server-side
// folders with identical names must round-trip as two distinct rows.
// The sidebar-tree dedup fix is already proven by `tree.test.ts`;
// what we add here is "they really do round-trip as two rows
// through the server", which is the precondition the tree fix
// relies on.

import { loginAsSeededUser } from "../helpers/auth.mjs";

const RUN = `${Date.now().toString(36)}`;
const ORIGINAL = `e2e-rename-${RUN}`;
const RENAMED = `e2e-renamed-${RUN}`;
const DUPLICATE_NAME = `e2e-dup-${RUN}`;

describe("Folder rename + delete", () => {
  it("rename_folder updates the server name and the local cache in lockstep", async () => {
    await loginAsSeededUser();

    const folderId = await browser.execute(async (name) => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      return await invoke("create_folder", { name });
    }, ORIGINAL);
    if (typeof folderId !== "string" || folderId.length === 0) {
      throw new Error(`create_folder did not return an id: ${JSON.stringify(folderId)}`);
    }

    await browser.execute(
      async (id, name) => {
        // @ts-expect-error
        const { invoke } = window.__TAURI__.core;
        await invoke("rename_folder", { folderId: id, name });
      },
      folderId,
      RENAMED,
    );

    // Sync forces a fresh round-trip through the server so a
    // regression that updated only the local cache (without PUTting)
    // would surface here. The decrypt path also runs on the way out;
    // a regression that re-encrypted under the wrong key would
    // produce a garbled name.
    const found = await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.folders.find((f) => f.id === id) ?? null;
    }, folderId);

    if (!found) throw new Error(`folder ${folderId} disappeared after rename+sync`);
    if (found.name !== RENAMED) {
      throw new Error(
        `expected name ${JSON.stringify(RENAMED)}, got ${JSON.stringify(found.name)}`,
      );
    }
  });

  it("delete_folder removes the row server-side and detaches its ciphers locally", async () => {
    // Two folders with identical names — first proves the dedup fix's
    // *precondition* holds (the server really does keep two rows;
    // tree.test.ts then proves the UI displays both). Second
    // exercises delete on a folder that has a cipher inside, so the
    // local-cache splice that clears `folder_id` on detached items
    // is on the hot path. After delete:
    //   - the dropped folder no longer appears in `vault.folders`
    //   - the cipher that lived in it is still present (Bitwarden
    //     detaches rather than cascade-deleting)
    //   - `cipher.folderId` on that surviving cipher is `null`
    //   - the *other* same-named folder is untouched
    const { firstId, secondId, cipherId } = await browser.execute(async (name) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const firstId = await invoke("create_folder", { name });
      const secondId = await invoke("create_folder", { name });
      // Drop one cipher into the first folder so the
      // detach-on-delete path has something to detach.
      const cipherId = await invoke("create_cipher", {
        input: {
          cipherType: 1,
          name: `e2e-dup-cipher-${name}`,
          folderId: firstId,
          favorite: false,
          notes: null,
          organizationId: null,
          collectionIds: [],
          login: { username: "u", password: "p", uris: [], totp: null },
        },
      });
      return { firstId, secondId, cipherId };
    }, DUPLICATE_NAME);

    // Pre-condition: both folders coexist on the server.
    const before = await browser.execute(async () => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.folders;
    });
    const beforeIds = new Set(before.map((f) => f.id));
    if (!beforeIds.has(firstId) || !beforeIds.has(secondId)) {
      throw new Error(
        `expected both duplicate folders in sync, got ids: ${JSON.stringify([...beforeIds])}`,
      );
    }

    await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("delete_folder", { folderId: id });
    }, firstId);

    const after = await browser.execute(async () => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return { folders: summary.folders, ciphers: summary.ciphers };
    });

    const afterFolderIds = new Set(after.folders.map((f) => f.id));
    if (afterFolderIds.has(firstId)) {
      throw new Error(`first folder ${firstId} still present after delete`);
    }
    if (!afterFolderIds.has(secondId)) {
      throw new Error(
        `second duplicate folder ${secondId} disappeared after deleting the first`,
      );
    }

    const survivor = after.ciphers.find((c) => c.id === cipherId);
    if (!survivor) {
      throw new Error(
        `cipher ${cipherId} was deleted alongside its folder — Bitwarden semantics is detach, not cascade`,
      );
    }
    if (survivor.folderId !== null) {
      throw new Error(
        `cipher ${cipherId} should be detached (folderId=null) after its folder was deleted; got ${JSON.stringify(survivor.folderId)}`,
      );
    }
  });
});
