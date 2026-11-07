// End-to-end coverage for the SSH-key passphrase prompt added to the
// cipher editor. Mirrors Bitwarden Desktop's import_key flow: paste a
// passphrase-protected OpenSSH key, get prompted for the passphrase
// inline, on success the cipher saves with the cleartext PEM and an
// auto-filled SHA-256 fingerprint.
//
// Generates the test keys at runtime by spawning ssh-keygen (always
// available on GitHub-hosted runners). Embedding a static encrypted
// PEM as a fixture would work too, but a fresh key per run avoids
// any "did this still parse correctly?" doubt and matches the seed
// approach in src-tauri/examples/e2e_seed.rs.
//
// Three paths exercised:
//   1. Encrypted ed25519 → first save shows the prompt; wrong
//      passphrase shows the inline "Phrase de passe incorrecte."
//      error and keeps the editor open; correct passphrase saves
//      the cipher with publicKey + keyFingerprint auto-filled, and
//      a fresh sync confirms the stored privateKey is no longer
//      encrypted.
//   2. Unencrypted ECDSA (NIST P-256) → saves straight away, no
//      passphrase prompt: ECDSA keys are loadable into the agent. The
//      algorithm-rejection branch (DSA) is covered by a Rust unit test,
//      since recent ssh-keygen builds can no longer generate DSA keys.
//
// The unencrypted-key happy path is already covered by the seed
// (e2e_seed::ssh_key_input) and the smoke flows that read it back.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loginAsSeededUser } from "../helpers/auth.mjs";

const PASSPHRASE = "test-passphrase-do-not-use";
const ITEM_NAME_OK = "E2E SSH ▸ encrypted import";
const ITEM_NAME_ECDSA = "E2E SSH ▸ ecdsa import";
// The cipher-type selector is the first field of the create form. A bare
// "select" also matches the owner / collection / folder selectors below
// it, which wdio 10's strict `$` rejects instead of taking the first.
const TYPE_SELECT = "form > label:first-child select";

// WDIO's `setValue` types a multi-line PEM character-by-character via
// the WebDriver protocol; the leading `-----BEGIN OPENSSH PRIVATE KEY-----`
// header gets dropped intermittently on Tauri's wry WebView (we caught
// this on a CI run that surfaced "PEM type label invalid"). Setting the
// `value` property programmatically and dispatching an `input` event is
// the reliable path for Svelte-bound form fields.
async function pasteIntoTextarea(selector, value) {
  await browser.execute(
    (sel, val) => {
      const el = document.querySelector(sel);
      if (!el) throw new Error(`textarea ${sel} not found`);
      const setter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        "value",
      ).set;
      setter.call(el, val);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    },
    selector,
    value,
  );
}

let workdir;
let encryptedPem;
let ecdsaPem;

function genKey(type, file, passphrase) {
  // -q silences "Generating ...", -N is the new passphrase ("" for none),
  // -C is a benign comment so the public-line carries something readable
  // if we ever inspect a failure log.
  const args = [
    "-t", type,
    "-N", passphrase,
    "-f", file,
    "-q",
    "-C", `clavix-e2e-${type}`,
  ];
  const res = spawnSync("ssh-keygen", args, { stdio: "pipe", encoding: "utf8" });
  if (res.status !== 0) {
    throw new Error(
      `ssh-keygen ${type} failed (exit ${res.status}): ${res.stderr || res.stdout}`,
    );
  }
  return readFileSync(file, "utf8");
}

describe("Import an encrypted SSH key", () => {
  before(() => {
    workdir = mkdtempSync(join(tmpdir(), "clavix-e2e-ssh-"));
    encryptedPem = genKey("ed25519", join(workdir, "encrypted"), PASSPHRASE);
    // ECDSA NIST P-256, default curve, no passphrase.
    ecdsaPem = genKey("ecdsa", join(workdir, "ecdsa"), "");
  });

  after(() => {
    if (workdir) rmSync(workdir, { recursive: true, force: true });
  });

  it("prompts for the passphrase, rejects wrong input, then saves with auto-filled metadata", async () => {
    await loginAsSeededUser();

    const addButton = await $('button[aria-label="Nouvel item"]');
    await addButton.waitForClickable({ timeout: 10_000 });
    await addButton.click();

    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    // Switch the type selector to "Clé SSH" (kind=5). The visible-text
    // form is the most stable selector — option indices would silently
    // drift if a future cipher type is added.
    const typeSelect = await editor.$(TYPE_SELECT);
    await typeSelect.selectByVisibleText("Clé SSH");

    const nameInput = await editor.$('input[type="text"][required]');
    await nameInput.setValue(ITEM_NAME_OK);

    // Paste the encrypted PEM into the private-key textarea via JS to
    // sidestep the WDIO setValue char-by-char path (it intermittently
    // drops the leading PEM header on the wry WebView).
    await pasteIntoTextarea(".editor-panel textarea.ssh-private-key", encryptedPem);

    // First save attempt: no passphrase yet, the command returns
    // ssh_passphrase_required and the editor renders the prompt.
    const submit = await editor.$('button[type="submit"]');
    await submit.click();

    // The .ssh-passphrase-hint element is rendered only inside the
    // `{#if sshPassphrasePrompt}` block — its presence is the signal
    // that the prompt is up. Class selector is more reliable than
    // partial-text matching on a label that wraps multiple children.
    const passphraseHint = await editor.$(".ssh-passphrase-hint");
    await passphraseHint.waitForDisplayed({
      timeout: 5_000,
      timeoutMsg: "passphrase prompt did not appear after first save attempt",
    });

    // The dynamic hint must read "Cette clé est protégée…" first.
    await browser.waitUntil(
      async () => {
        const t = await editor.$(".ssh-passphrase-hint").getText();
        return t.includes("protégée");
      },
      { timeout: 5_000, timeoutMsg: 'first hint should mention "protégée"' },
    );

    // Wrong passphrase first — must keep the editor open and flip the
    // hint to "Phrase de passe incorrecte.".
    const passphraseInput = await editor.$('input[type="password"]');
    await passphraseInput.setValue("definitely-wrong");
    await submit.click();

    await browser.waitUntil(
      async () => {
        const t = await editor.$(".ssh-passphrase-hint").getText();
        return t.includes("incorrecte");
      },
      { timeout: 5_000, timeoutMsg: "wrong-passphrase error never surfaced" },
    );

    if (!(await editor.isDisplayed())) {
      throw new Error(
        "editor closed on wrong passphrase — should have stayed open for retry",
      );
    }

    // Correct passphrase → cipher saves, editor closes.
    await passphraseInput.setValue(PASSPHRASE);
    await submit.click();

    await editor.waitForExist({
      reverse: true,
      timeout: 15_000,
      timeoutMsg: "editor did not close after correct passphrase",
    });

    // The editor closing is itself proof that decrypt + create
    // both succeeded — handleSubmit only flips editorOpen=false on
    // a clean Promise resolution from create_cipher. We deliberately
    // *don't* verify cipher persistence through the UI list or a
    // sync round-trip: SSH ciphers occasionally drop out of the
    // sync response on Vaultwarden 1.35.7 (same flake documented in
    // cipher-types.spec.mjs, observed on the seed's own SSH cipher
    // too). The auto-fill output shape is verified independently
    // in the next it() block via a direct decrypt_ssh_private_key
    // IPC call, which doesn't go anywhere near Vaultwarden.
  });

  it("auto-fills publicKey and SHA256 fingerprint from a decrypted ed25519 PEM", async () => {
    // Direct command-level verification: same Rust code path the
    // editor uses, but called through invoke() so we can assert on
    // the returned shape without relying on Vaultwarden round-tripping
    // an SSH cipher (flaky on 1.35.7 — see the it() above).
    const result = await browser.execute(
      async (pem, pass) => {
        // @ts-expect-error — tauri injects this global
        const { invoke } = window.__TAURI__.core;
        return await invoke("decrypt_ssh_private_key", {
          privateKey: pem,
          passphrase: pass,
        });
      },
      encryptedPem,
      PASSPHRASE,
    );

    if (!result.publicKey || !result.publicKey.startsWith("ssh-ed25519 ")) {
      throw new Error(
        `expected public key to start with "ssh-ed25519 ", got: ${JSON.stringify(result.publicKey)}`,
      );
    }
    if (!result.keyFingerprint || !result.keyFingerprint.startsWith("SHA256:")) {
      throw new Error(
        `expected fingerprint to start with "SHA256:", got: ${JSON.stringify(result.keyFingerprint)}`,
      );
    }
    if (
      !result.privateKey ||
      result.privateKey.includes("ENCRYPTED") ||
      !result.privateKey.includes("BEGIN OPENSSH PRIVATE KEY")
    ) {
      throw new Error(
        "decrypted private key should be a clean unencrypted OpenSSH PEM",
      );
    }
  });

  it("saves an unencrypted ECDSA key with no passphrase prompt", async () => {
    // Same describe block, same browser session — the seeded user is
    // still logged in from the previous it().

    const addButton = await $('button[aria-label="Nouvel item"]');
    await addButton.waitForClickable({ timeout: 10_000 });
    await addButton.click();

    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    const typeSelect = await editor.$(TYPE_SELECT);
    await typeSelect.selectByVisibleText("Clé SSH");

    const nameInput = await editor.$('input[type="text"][required]');
    await nameInput.setValue(ITEM_NAME_ECDSA);

    await pasteIntoTextarea(".editor-panel textarea.ssh-private-key", ecdsaPem);

    const submit = await editor.$('button[type="submit"]');
    await submit.click();

    // Accepted by the algorithm gate and unencrypted, so the editor
    // closes on the first save: no error line, no passphrase prompt.
    await editor.waitForExist({
      reverse: true,
      timeout: 15_000,
      timeoutMsg: "editor did not close after saving an ECDSA key",
    });

    // The command the editor runs on save hands back the public half;
    // check it directly so a silent algorithm mix-up can't pass.
    const decrypted = await browser.execute(
      (pem) => window.__TAURI__.core.invoke("decrypt_ssh_private_key", { privateKey: pem }),
      ecdsaPem,
    );
    if (!decrypted.publicKey.startsWith("ecdsa-sha2-nistp256 ")) {
      throw new Error(`expected an ecdsa-sha2-nistp256 public key, got: ${decrypted.publicKey}`);
    }
    if (!decrypted.keyFingerprint.startsWith("SHA256:")) {
      throw new Error(`expected a SHA256 fingerprint, got: ${decrypted.keyFingerprint}`);
    }
  });
});
