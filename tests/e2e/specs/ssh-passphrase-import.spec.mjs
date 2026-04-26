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
//   2. ECDSA → algorithm check runs *before* the passphrase prompt,
//      so the editor surfaces "unsupported SSH algorithm" without
//      ever asking for a passphrase.
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
const ITEM_NAME_ECDSA = "E2E SSH ▸ ecdsa rejection";

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
    // ECDSA NIST P-256 — the algorithm rejection branch in the
    // command. Default curve, no passphrase needed for the test.
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
    const typeSelect = await editor.$("select");
    await typeSelect.selectByVisibleText("🔑 Clé SSH");

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

    const newRow = await $(`.cipher-row*=${ITEM_NAME_OK}`);
    await newRow.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg: "imported SSH cipher never appeared in the list",
    });

    // Server-side proof: a fresh sync round-trips a cipher whose
    // sshKey field has an auto-filled SHA-256 fingerprint and a
    // privateKey that is no longer encrypted (no Proc-Type:ENCRYPTED
    // header, no -----BEGIN ENCRYPTED…).
    const detail = await browser.execute(async (name) => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      const summary = await invoke("sync");
      const ours = summary.ciphers.find((c) => c.name === name);
      if (!ours) return null;
      return await invoke("get_cipher", { id: ours.id });
    }, ITEM_NAME_OK);

    if (!detail) {
      throw new Error("imported cipher missing from sync after save");
    }
    if (!detail.sshKey) {
      throw new Error("sshKey field missing on imported cipher");
    }
    if (
      !detail.sshKey.keyFingerprint ||
      !detail.sshKey.keyFingerprint.startsWith("SHA256:")
    ) {
      throw new Error(
        `expected SHA256 fingerprint to be auto-filled, got: ${JSON.stringify(detail.sshKey.keyFingerprint)}`,
      );
    }
    if (
      !detail.sshKey.privateKey ||
      detail.sshKey.privateKey.includes("ENCRYPTED")
    ) {
      throw new Error(
        "private key was stored still encrypted — decryption never happened",
      );
    }
    if (
      !detail.sshKey.publicKey ||
      !detail.sshKey.publicKey.startsWith("ssh-ed25519 ")
    ) {
      throw new Error(
        `expected public key auto-fill to start with "ssh-ed25519 ", got: ${JSON.stringify(detail.sshKey.publicKey)}`,
      );
    }
  });

  it("rejects an ECDSA key up front, no passphrase prompt", async () => {
    // Same describe block, same browser session — the seeded user is
    // still logged in from the previous it().

    const addButton = await $('button[aria-label="Nouvel item"]');
    await addButton.waitForClickable({ timeout: 10_000 });
    await addButton.click();

    const editor = await $(".editor-panel");
    await editor.waitForDisplayed({ timeout: 10_000 });

    const typeSelect = await editor.$("select");
    await typeSelect.selectByVisibleText("🔑 Clé SSH");

    const nameInput = await editor.$('input[type="text"][required]');
    await nameInput.setValue(ITEM_NAME_ECDSA);

    await pasteIntoTextarea(".editor-panel textarea.ssh-private-key", ecdsaPem);

    const submit = await editor.$('button[type="submit"]');
    await submit.click();

    // The algorithm check in decrypt_ssh_private_key runs before the
    // passphrase logic. The error surfaces in the main .editor-error
    // line, not in a passphrase hint, and the prompt never renders.
    const editorError = await editor.$(".editor-error");
    await editorError.waitForDisplayed({
      timeout: 5_000,
      timeoutMsg: "ECDSA rejection never surfaced as an error",
    });
    const errorText = (await editorError.getText()).toLowerCase();
    if (!errorText.includes("unsupported") && !errorText.includes("algorithm")) {
      throw new Error(
        `expected "unsupported SSH algorithm" in editor error, got: ${errorText}`,
      );
    }

    const promptLabel = await editor.$("label*=Phrase de passe de la clé SSH");
    if (await promptLabel.isExisting()) {
      throw new Error(
        "passphrase prompt appeared for an ECDSA key — algorithm check should have run first",
      );
    }

    // Cancel out so we don't leak a half-typed cipher into the vault
    // for any spec running after this one in alphabetical order.
    const cancel = await editor.$("button=Annuler");
    await cancel.click();
    await editor.waitForExist({
      reverse: true,
      timeout: 5_000,
      timeoutMsg: "editor did not close after Annuler",
    });
  });
});
