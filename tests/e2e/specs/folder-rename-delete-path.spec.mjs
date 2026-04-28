// Path-based folder rename + cascade delete — end-to-end through
// `rename_folder_path` (new) and a sequence of `delete_folder`
// invocations of the kind the sidebar issues when the user deletes a
// visual group.
//
// Why both paths matter: Bitwarden has no real folder hierarchy. A
// folder named `work/projects` and a folder named `work` are two
// independent rows. The sidebar paints them as a tree by splitting on
// `/`, which means `work` can show up as a *synthetic* parent —
// nothing on the server, just a path container the UI made up. Until
// recently right-click did nothing on those, and renaming a real
// `work` would orphan its `work/...` children. Both regressions were
// observable to users; both are silent at the server layer; both
// belong here.
//
// IPC-driven for the same reason `folder-rename-delete.spec.mjs` is.
// The right-click menu's job is just to compose paths and call IPC,
// and synthetic HTML5 events under WebDriver are flaky enough to
// drown the signal we care about.

import { loginAsSeededUser } from "../helpers/auth.mjs";

const RUN = `${Date.now().toString(36)}`;
const PARENT = `e2e-rnpath-${RUN}`;
const CHILD = `${PARENT}/child`;
const GRANDCHILD = `${PARENT}/child/leaf`;
const RENAMED_PARENT = `e2e-renamed-${RUN}`;
const RENAMED_CHILD = `${RENAMED_PARENT}/child`;
const RENAMED_GRANDCHILD = `${RENAMED_PARENT}/child/leaf`;

const SYNTH_CHILD = `e2e-synth-${RUN}/only`;
const SYNTH_RENAMED = `e2e-synth-renamed-${RUN}/only`;

const CASCADE_PARENT = `e2e-cascdel-${RUN}`;
const CASCADE_CHILD_A = `${CASCADE_PARENT}/a`;
const CASCADE_CHILD_B = `${CASCADE_PARENT}/b/deep`;

describe("Folder rename + delete (path-based, cascade)", () => {
  it("rename_folder_path renames the parent and every descendant in one batch", async () => {
    await loginAsSeededUser();

    const ids = await browser.execute(
      async (parent, child, grandchild) => {
        // @ts-expect-error — tauri injects this global
        const { invoke } = window.__TAURI__.core;
        const parentId = await invoke("create_folder", { name: parent });
        const childId = await invoke("create_folder", { name: child });
        const grandchildId = await invoke("create_folder", { name: grandchild });
        return { parentId, childId, grandchildId };
      },
      PARENT,
      CHILD,
      GRANDCHILD,
    );
    if (!ids.parentId || !ids.childId || !ids.grandchildId) {
      throw new Error(`create_folder did not return ids: ${JSON.stringify(ids)}`);
    }

    await browser.execute(
      async (sourcePath, newPath) => {
        // @ts-expect-error
        const { invoke } = window.__TAURI__.core;
        await invoke("rename_folder_path", { sourcePath, newPath });
      },
      PARENT,
      RENAMED_PARENT,
    );

    // Sync forces a server round-trip so a regression that only
    // mutated the local cache (without PUTting) would surface here.
    const folders = await browser.execute(async () => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.folders.map((f) => ({ id: f.id, name: f.name }));
    });
    const lookup = new Map(folders.map((f) => [f.id, f.name]));

    if (lookup.get(ids.parentId) !== RENAMED_PARENT) {
      throw new Error(
        `expected parent renamed to ${JSON.stringify(RENAMED_PARENT)}, got ${JSON.stringify(lookup.get(ids.parentId))}`,
      );
    }
    if (lookup.get(ids.childId) !== RENAMED_CHILD) {
      throw new Error(
        `expected child cascade-renamed to ${JSON.stringify(RENAMED_CHILD)}, got ${JSON.stringify(lookup.get(ids.childId))}`,
      );
    }
    if (lookup.get(ids.grandchildId) !== RENAMED_GRANDCHILD) {
      throw new Error(
        `expected grandchild cascade-renamed to ${JSON.stringify(RENAMED_GRANDCHILD)}, got ${JSON.stringify(lookup.get(ids.grandchildId))}`,
      );
    }
  });

  it("rename_folder_path on a synthetic parent rewrites every descendant even when the parent has no row", async () => {
    // Only the leaf exists on the server — there is no `e2e-synth-${RUN}`
    // row. The sidebar still paints `e2e-synth-${RUN}` as a folder
    // (path container for the leaf), and right-clicking it should
    // succeed: the rename cascades through the leaf without ever
    // requiring a real parent row.
    await loginAsSeededUser();

    const leafId = await browser.execute(async (name) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      return await invoke("create_folder", { name });
    }, SYNTH_CHILD);
    if (typeof leafId !== "string" || leafId.length === 0) {
      throw new Error(`create_folder did not return an id: ${JSON.stringify(leafId)}`);
    }

    const synthParent = SYNTH_CHILD.split("/")[0];
    const synthRenamedParent = SYNTH_RENAMED.split("/")[0];
    await browser.execute(
      async (sourcePath, newPath) => {
        // @ts-expect-error
        const { invoke } = window.__TAURI__.core;
        await invoke("rename_folder_path", { sourcePath, newPath });
      },
      synthParent,
      synthRenamedParent,
    );

    const found = await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.folders.find((f) => f.id === id) ?? null;
    }, leafId);

    if (!found) throw new Error(`leaf ${leafId} disappeared after synth-parent rename`);
    if (found.name !== SYNTH_RENAMED) {
      throw new Error(
        `expected leaf cascaded to ${JSON.stringify(SYNTH_RENAMED)}, got ${JSON.stringify(found.name)}`,
      );
    }
  });

  it("cascade delete drops every folder id the sidebar collected and detaches their ciphers", async () => {
    // Mirrors what `VaultSidebar.svelte`'s confirmDelete does: the
    // sidebar walks the subtree under the right-clicked node, collects
    // every real folder id (`collectFolderIds`), and then asks the
    // store to delete them in sequence. Here we play the same script
    // through IPC to verify the server ends up consistent — every
    // listed folder gone, every cipher under them detached.
    await loginAsSeededUser();

    const setup = await browser.execute(
      async (parent, childA, childB) => {
        // @ts-expect-error
        const { invoke } = window.__TAURI__.core;
        const parentId = await invoke("create_folder", { name: parent });
        const childAId = await invoke("create_folder", { name: childA });
        const childBId = await invoke("create_folder", { name: childB });
        const cipherInParent = await invoke("create_cipher", {
          input: {
            cipherType: 1,
            name: `e2e-cascdel-cipher-parent-${parent}`,
            folderId: parentId,
            favorite: false,
            notes: null,
            organizationId: null,
            collectionIds: [],
            login: { username: "u", password: "p", uris: [], totp: null },
          },
        });
        const cipherInChild = await invoke("create_cipher", {
          input: {
            cipherType: 1,
            name: `e2e-cascdel-cipher-child-${parent}`,
            folderId: childAId,
            favorite: false,
            notes: null,
            organizationId: null,
            collectionIds: [],
            login: { username: "u", password: "p", uris: [], totp: null },
          },
        });
        return { parentId, childAId, childBId, cipherInParent, cipherInChild };
      },
      CASCADE_PARENT,
      CASCADE_CHILD_A,
      CASCADE_CHILD_B,
    );

    // Delete every collected id in sequence, the way the store does.
    // Order shouldn't matter — assert that explicitly by deleting the
    // parent last.
    await browser.execute(
      async (ids) => {
        // @ts-expect-error
        const { invoke } = window.__TAURI__.core;
        for (const id of ids) {
          await invoke("delete_folder", { folderId: id });
        }
      },
      [setup.childAId, setup.childBId, setup.parentId],
    );

    const after = await browser.execute(async () => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return { folders: summary.folders, ciphers: summary.ciphers };
    });

    const folderIds = new Set(after.folders.map((f) => f.id));
    for (const id of [setup.parentId, setup.childAId, setup.childBId]) {
      if (folderIds.has(id)) {
        throw new Error(`folder ${id} still present after cascade delete`);
      }
    }

    for (const cipherId of [setup.cipherInParent, setup.cipherInChild]) {
      const survivor = after.ciphers.find((c) => c.id === cipherId);
      if (!survivor) {
        throw new Error(
          `cipher ${cipherId} was deleted alongside its folder — Bitwarden semantics is detach, not cascade`,
        );
      }
      if (survivor.folderId !== null) {
        throw new Error(
          `cipher ${cipherId} should be detached after its folder was deleted; got ${JSON.stringify(survivor.folderId)}`,
        );
      }
    }
  });
});
