// Shares a personal cipher into the seeded org's default collection
// and verifies the server-side move landed (cipher gained an
// organization_id after the next sync).
//
// We drive the share command directly through Tauri's IPC rather than
// the drag-drop UI. Two reasons:
//
// 1. WebKitGTK's synthetic HTML5 drag-drop is notoriously flaky under
//    WebDriver — retries, long timeouts, OS quirks — and that flakiness
//    is orthogonal to what this spec is trying to prove.
// 2. The drag surface is already covered end-to-end by drag.test.ts
//    (17 vitest cases on DragController) and vault.svelte.ts pipes the
//    drop into moveCipherToCollection. What's left uncovered by units
//    is the Rust command → Vaultwarden → sync round-trip, which is
//    exactly what we exercise here.

import { loginAsSeededUser } from "../helpers/auth.mjs";

describe("Share cipher to an org collection", () => {
  it("moves a personal login into the seeded org and persists across sync", async () => {
    await loginAsSeededUser();

    // Pull the seeded state: the org is called "E2E Org" in seed.rs
    // and has a single default collection. We need both IDs to drive
    // the share command.
    const seedIds = await browser.execute(async () => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      const org = summary.organizations[0];
      const collection = summary.collections.find(
        (c) => c.organizationId === org.id,
      );
      const cipher = summary.ciphers.find((c) => c.name === "GitHub");
      return {
        orgId: org.id,
        orgName: org.name,
        collectionId: collection.id,
        cipherId: cipher.id,
      };
    });

    expect(seedIds.orgName).toBe("E2E Org");
    expect(seedIds.cipherId).toBeTruthy();
    expect(seedIds.collectionId).toBeTruthy();

    // Share: re-encrypts every cipher field under the org key, POSTs
    // /api/ciphers/:id/share, flips the in-memory cipher's org id.
    await browser.execute(
      async (cipherId, collectionId) => {
        // @ts-expect-error — tauri injects this global
        const { invoke } = window.__TAURI__.core;
        await invoke("share_cipher_to_collection", {
          cipherId,
          collectionId,
        });
      },
      seedIds.cipherId,
      seedIds.collectionId,
    );

    // Fresh sync proves the server stored the move — not just the
    // in-memory vault state that share_cipher_to_collection mutates.
    const after = await browser.execute(async (cipherId) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      const cipher = summary.ciphers.find((c) => c.id === cipherId);
      return {
        name: cipher?.name ?? null,
        organizationId: cipher?.organizationId ?? null,
        collectionIds: cipher?.collectionIds ?? [],
      };
    }, seedIds.cipherId);

    // Name must still decrypt after the server round-trip — a bug in
    // build_share_cipher_body would surface here as "[decrypt failed]"
    // because the server would be storing bytes encrypted with the
    // wrong key.
    expect(after.name).toBe("GitHub");
    expect(after.organizationId).toBe(seedIds.orgId);
    expect(after.collectionIds).toContain(seedIds.collectionId);
  });
});
