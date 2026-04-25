// Round-trip every non-Login cipher type through Vaultwarden:
// Secure Note, Card, Identity, SSH Key. create-cipher.spec already
// covers the Login default; this spec is the matrix coverage that
// makes sure the cipher-type discriminator is wired through the
// editor → IPC → encrypt-and-POST → server → decrypt path for the
// other four types.
//
// Driven through IPC for the create step and through sync for the
// verification. UI-driven creation of every cipher type would
// duplicate the existing create-cipher.spec selectors four times
// over without testing anything new at the UI layer; the encrypt /
// re-decrypt path is what's interesting here, and it's reachable
// from invoke("create_cipher").
//
// Each type gets a unique enough name to survive the assertion in
// a vault that already contains seed fixtures.
//
// Issue #10 — covers "create all supported cipher types in a
// personal vault".

import { loginAsSeededUser } from "../helpers/auth.mjs";

const FIXTURES = [
  {
    kind: 2,
    name: "E2E note ▸ Secure Note",
    payload: { notes: "throwaway content" },
  },
  {
    kind: 3,
    name: "E2E card ▸ Visa",
    payload: {
      card: {
        cardholderName: "Alice E2E",
        brand: "Visa",
        number: "4111111111111111",
        expMonth: "12",
        expYear: "2099",
        code: "123",
      },
    },
  },
  {
    kind: 4,
    name: "E2E identity ▸ Alice",
    payload: {
      identity: {
        title: "Mme",
        firstName: "Alice",
        lastName: "E2E",
        email: "alice@e2e.test",
      },
    },
  },
  {
    kind: 5,
    name: "E2E ssh ▸ ed25519",
    payload: {
      sshKey: {
        privateKey:
          "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-payload\n-----END OPENSSH PRIVATE KEY-----",
        publicKey: "ssh-ed25519 AAAAC3Nz e2e@clavix",
        keyFingerprint: "SHA256:e2e-fake-fingerprint-for-test-only",
      },
    },
  },
];

describe("Cipher types other than Login", () => {
  it("creates a Note, Card, Identity and SSH Key, all decryptable on sync", async () => {
    await loginAsSeededUser();

    // Create one of each. The base payload is identical (name,
    // folder, etc.); the per-type fields fold into the editor input
    // shape via Object.assign so each call only has to spell the
    // bits that are unique to it.
    const created = await browser.execute(async (fixtures) => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const ids = [];
      for (const f of fixtures) {
        const base = {
          cipherType: f.kind,
          name: f.name,
          folderId: null,
          favorite: false,
          notes: null,
          organizationId: null,
          collectionIds: [],
          login: null,
          card: null,
          identity: null,
          sshKey: null,
          ...f.payload,
        };
        const id = await invoke("create_cipher", { input: base });
        ids.push({ id, kind: f.kind, name: f.name });
      }
      return ids;
    }, FIXTURES);

    if (created.length !== FIXTURES.length) {
      throw new Error(
        `expected ${FIXTURES.length} ciphers created, got ${created.length}`,
      );
    }

    // Fresh sync to make sure every row reaches the server and
    // round-trips back decryptable. The name comes back through
    // EncString::decrypt_string_sym; if any step of the pipe is
    // broken (wrong key, bad cipher_type discriminator, missing
    // mandatory field) it surfaces here as a missing row or a
    // garbled name.
    const synced = await browser.execute(async () => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      return summary.ciphers.map((c) => ({
        id: c.id,
        kind: c.kind,
        name: c.name,
      }));
    });

    for (const c of created) {
      const found = synced.find((s) => s.id === c.id);
      if (!found) {
        throw new Error(
          `cipher ${JSON.stringify(c.name)} (kind=${c.kind}) missing from sync after create`,
        );
      }
      if (found.kind !== c.kind) {
        throw new Error(
          `cipher ${JSON.stringify(c.name)} came back as kind=${found.kind}, expected ${c.kind}`,
        );
      }
      if (found.name !== c.name) {
        throw new Error(
          `cipher ${JSON.stringify(c.name)} round-tripped under a different name: ${JSON.stringify(found.name)}`,
        );
      }
    }
  });
});
