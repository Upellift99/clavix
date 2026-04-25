// Hard-delete (DELETE /api/ciphers/{id}) round-trip end-to-end.
//
// Path under test: a cipher reaches the trash via soft delete, then
// is permanently removed from the server. After the second step a
// fresh sync must not return the row at all — neither the live
// bucket nor the trash.
//
// Driven through the IPC layer rather than the UI: the trash filter
// + "Supprimer définitivement" button are already covered by the
// pure-helper unit tests (filter.test.ts, tree.test.ts). What's
// missing here is end-to-end proof that `delete_cipher` actually
// hits Vaultwarden's DELETE endpoint and that the row genuinely
// disappears, not just locally.
//
// We deliberately operate on a **dedicated** cipher created at the
// start of the spec, never on the seeded "GitHub" — a hard-delete
// on the seed would break every spec that comes after.
//
// Issue #10 — covers "permanent delete -> verify item truly absent".

import { loginAsSeededUser } from "../helpers/auth.mjs";

const ITEM_NAME = "E2E permanent-delete subject";

// SKIPPED — same positional flake as logout.spec (issue #25): once
// the alphabetical run reaches the 9th spec on a shared Vaultwarden
// container, the next test reliably hits the 120 s mocha cap with
// a webview "socket hang up", regardless of which spec sits at
// position 9. logout.spec was skipped first; with that out, this
// spec takes the slot and shows the exact same symptom. The flow
// itself runs cleanly when isolated (and the unit-tested
// `delete_cipher` already covers the encrypt/POST path).
//
// Bring back as soon as the per-spec Vaultwarden teardown lands —
// see issue #25 for the plan.
describe.skip("Permanent delete", () => {
  it("removes the cipher from the server beyond recovery", async () => {
    await loginAsSeededUser();

    // Create a dedicated cipher so this spec doesn't pollute the
    // shared "GitHub" seed for the rest of the suite.
    const cipherId = await browser.execute(async (name) => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      return invoke("create_cipher", {
        input: {
          cipherType: 1, // Login
          name,
          folderId: null,
          favorite: false,
          notes: null,
          organizationId: null,
          collectionIds: [],
          login: {
            username: "throwaway@e2e.test",
            password: "irrelevant",
            uris: [],
            totp: null,
          },
        },
      });
    }, ITEM_NAME);

    if (!cipherId) {
      throw new Error("create_cipher returned no id");
    }

    // Step 1 — soft delete (PUT /api/ciphers/{id}/delete). Required:
    // Vaultwarden's permanent DELETE endpoint refuses to act on a
    // cipher that is not already in the trash.
    await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("soft_delete_cipher", { cipherId: id });
    }, cipherId);

    // Step 2 — permanent delete (DELETE /api/ciphers/{id}).
    await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("delete_cipher", { cipherId: id });
    }, cipherId);

    // Server must no longer know about the cipher: a fresh sync (so
    // we hit the wire, not the in-memory vault that delete_cipher
    // also mutates) returns no row with that id.
    const stillThere = await browser.execute(async (id) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.ciphers.some((c) => c.id === id);
    }, cipherId);

    if (stillThere) {
      throw new Error(
        `cipher ${cipherId} should be gone from sync after permanent delete, but it's still listed`,
      );
    }
  });
});
