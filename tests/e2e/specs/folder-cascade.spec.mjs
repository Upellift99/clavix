// Folder move with subfolder cascade — end-to-end through
// `move_folder_path`. Bitwarden has no real folder hierarchy on the
// server: each folder is a flat row with a `/`-separated name, and
// "moving" a parent means renaming every row whose name starts
// with `${oldParent}/`. The orchestration logic is unit-tested in
// `services/vault.rs::plan_folder_renames`; what's not covered
// is the full flow once you add the encrypt-the-new-name + PUT-each
// + sync round-trip on top.
//
// Setup: create three rows for this run — `parentA`, `parentA/sub`,
// and `parentB`. Move parentA under parentB. Both parentA and its
// sub must come back as `parentB/parentA` and `parentB/parentA/sub`
// on the next sync.
//
// IPC-driven for the move itself: the drag-drop UI surface is
// already covered by drag.test.ts at the unit layer, and synthetic
// HTML5 drag-drop under WebDriver is notoriously flaky. The IPC
// path is the same one the drop handler eventually calls.
//
// Issue #10 — covers "move folder path with nested children →
// verify cascade rename on server".

import { loginAsSeededUser } from "../helpers/auth.mjs";

// One unique base per run guards against running the spec twice
// against the same Vaultwarden without reset (rare in CI, common
// when iterating locally with E2E_SKIP_DOCKER=1).
const RUN = `${Date.now().toString(36)}`;
const PARENT_A = `e2e-cascade-a-${RUN}`;
const SUB_A = `${PARENT_A}/sub`;
const PARENT_B = `e2e-cascade-b-${RUN}`;
const NEW_PARENT_A = `${PARENT_B}/${PARENT_A}`;
const NEW_SUB_A = `${PARENT_B}/${PARENT_A}/sub`;

describe("Folder move cascade", () => {
  it("moves a parent folder and renames descendants in the same batch", async () => {
    await loginAsSeededUser();

    // Create the three rows. The Bitwarden API has no hierarchy of
    // its own — these are independent rows whose names happen to
    // share a prefix — so we POST them explicitly.
    const ids = await browser.execute(
      async (parentA, subA, parentB) => {
        // @ts-expect-error — tauri injects this global
        const { invoke } = window.__TAURI__.core;
        const parentAId = await invoke("create_folder", { name: parentA });
        const subAId = await invoke("create_folder", { name: subA });
        const parentBId = await invoke("create_folder", { name: parentB });
        return { parentAId, subAId, parentBId };
      },
      PARENT_A,
      SUB_A,
      PARENT_B,
    );
    if (!ids.parentAId || !ids.subAId || !ids.parentBId) {
      throw new Error(
        `create_folder did not return ids: ${JSON.stringify(ids)}`,
      );
    }

    // Move parentA under parentB. compute_new_folder_base derives
    // new_base = "${PARENT_B}/${last_segment_of_PARENT_A}" =
    // "${PARENT_B}/${PARENT_A}", and plan_folder_renames cascades
    // that to anything starting with "${PARENT_A}/" — namely SUB_A.
    await browser.execute(
      async (sourcePath, targetParentPath) => {
        // @ts-expect-error
        const { invoke } = window.__TAURI__.core;
        await invoke("move_folder_path", { sourcePath, targetParentPath });
      },
      PARENT_A,
      PARENT_B,
    );

    // Sync, then assert both rows came back with the new prefix.
    // The decrypt path runs on the way out: a regression that
    // re-encrypted under the wrong key would surface here as a
    // missing or garbled name.
    const decrypted = await browser.execute(async () => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.folders.map((f) => ({ id: f.id, name: f.name }));
    });

    const parentA = decrypted.find((f) => f.id === ids.parentAId);
    const subA = decrypted.find((f) => f.id === ids.subAId);
    const parentB = decrypted.find((f) => f.id === ids.parentBId);

    if (!parentA || !subA || !parentB) {
      throw new Error(
        `one of the folders disappeared from sync: ${JSON.stringify(decrypted)}`,
      );
    }
    if (parentA.name !== NEW_PARENT_A) {
      throw new Error(
        `expected parentA renamed to ${JSON.stringify(NEW_PARENT_A)}, got ${JSON.stringify(parentA.name)}`,
      );
    }
    if (subA.name !== NEW_SUB_A) {
      throw new Error(
        `expected subA cascade-renamed to ${JSON.stringify(NEW_SUB_A)}, got ${JSON.stringify(subA.name)}`,
      );
    }
    if (parentB.name !== PARENT_B) {
      throw new Error(
        `parentB should not have been touched, got ${JSON.stringify(parentB.name)}`,
      );
    }
  });
});
