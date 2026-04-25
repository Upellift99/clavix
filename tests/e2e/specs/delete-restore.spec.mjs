// Soft-delete + restore round-trip on a personal cipher.
//
// Driven through Tauri IPC rather than UI: the Trash filter and the
// restore button are already covered by the tree.test.ts /
// filter.test.ts vitest suites on the pure helpers; what's missing
// is end-to-end proof that `soft_delete_cipher` hits PUT
// /api/ciphers/{id}/delete on Vaultwarden, that the server stamps
// `deletedDate`, and that `restore_cipher` (PUT
// /api/ciphers/{id}/restore) clears it again.
//
// Important nuance vs the obvious approach: `delete_cipher` (DELETE
// /api/ciphers/{id}) is *permanent* — the seeded "GitHub" cipher
// would never come back, breaking every spec that runs after this
// one. `soft_delete_cipher` is the trash-bucket operation, the only
// safe one for a fixture-shared seed.
//
// Issue #10 — covers "delete -> restore -> verify visibility and
// state".

import { loginAsSeededUser } from "../helpers/auth.mjs";

// SKIPPED — see issue #25. Position-dependent flake on the shared
// Vaultwarden container; comes back when per-spec teardown lands.
describe.skip("Delete and restore", () => {
  it("soft-deletes a cipher then restores it, both observable in sync", async () => {
    await loginAsSeededUser();

    const cipherId = await browser.execute(async () => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      const seed = summary.ciphers.find((c) => c.name === "GitHub");
      return seed?.id ?? null;
    });
    if (!cipherId) {
      throw new Error('seeded "GitHub" cipher not found before delete');
    }

    // Soft delete: PUT /api/ciphers/{id}/delete (Vaultwarden) ->
    // server stamps deletedDate, item moves to trash bucket.
    await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("soft_delete_cipher", { cipherId: id });
    }, cipherId);

    const afterDelete = await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.ciphers.find((c) => c.id === id) ?? null;
    }, cipherId);

    if (afterDelete === null) {
      throw new Error(
        "cipher disappeared from sync after soft delete — should still be in the trash bucket",
      );
    }
    if (!afterDelete.deletedDate) {
      throw new Error(
        `expected deletedDate on the soft-deleted cipher, got: ${JSON.stringify(afterDelete)}`,
      );
    }

    // Restore: PUT /api/ciphers/{id}/restore -> deletedDate cleared.
    await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("restore_cipher", { cipherId: id });
    }, cipherId);

    const afterRestore = await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.ciphers.find((c) => c.id === id) ?? null;
    }, cipherId);

    if (afterRestore === null) {
      throw new Error("cipher not found in sync after restore");
    }
    if (afterRestore.deletedDate !== null) {
      throw new Error(
        `expected deletedDate to be null after restore, got: ${JSON.stringify(afterRestore.deletedDate)}`,
      );
    }
  });
});
