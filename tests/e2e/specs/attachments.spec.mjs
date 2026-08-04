// Attachments, driven from the detail panel.
//
// `src-tauri/tests/attachment_round_trip.rs` already proves the wire
// format against a real Vaultwarden, but it drives `VaultwardenClient`
// directly. What it cannot see is the half of the feature that lives in
// the WebView: reading a picked file, base64-encoding it across the IPC
// boundary in chunks, and getting the decrypted bytes back out. A
// mistake there — the chunking, the encode, the `input.value` reset —
// produces a corrupted file rather than an error, which is the kind of
// failure a user discovers long after the fact.
//
// The file is handed to the input through a DataTransfer rather than
// through WebDriver's file-upload path: the input is deliberately
// `visually-hidden` (the button forwards the click), and "Element Send
// Keys" on a hidden input is not something the WebKit driver owes us.
// Building the FileList in the page is also closer to what the browser
// itself does on a real pick.

import { loginAsSeededUser, syncAndWaitForRow } from "../helpers/auth.mjs";

const ITEM = "E2E attachment subject";
const ITEM_DELETE = "E2E attachment delete subject";
const FILE_NAME = "e2e-note.txt";
// Non-ASCII on purpose: the payload travels as base64 through the IPC
// boundary, and a naive charCode-based encode mangles anything above
// U+00FF. Two lines, no trailing newline.
const FILE_CONTENT = "clavix e2e — pièce jointe\nligne deux";

async function createSubject(name) {
  return browser.execute(async (itemName) => {
    // @ts-expect-error — tauri injects this global
    const { invoke } = window.__TAURI__.core;
    const id = await invoke("create_cipher", {
      input: {
        cipherType: 1,
        name: itemName,
        folderId: null,
        favorite: false,
        notes: null,
        organizationId: null,
        collectionIds: [],
        login: {
          username: "attach@e2e.test",
          password: "irrelevant",
          uris: [],
          totp: null,
        },
      },
    });
    await invoke("sync");
    return id;
  }, name);
}

/** Hand a file to the (deliberately hidden) picker. */
async function pickFile(input, name, content) {
  await browser.execute(
    (el, fileName, fileContent) => {
      const data = new DataTransfer();
      data.items.add(new File([fileContent], fileName, { type: "text/plain" }));
      el.files = data.files;
      el.dispatchEvent(new Event("change", { bubbles: true }));
    },
    input,
    name,
    content,
  );
}

describe("Attachments", () => {
  before(async () => {
    await loginAsSeededUser();
  });

  it("uploads a picked file and reads it back byte for byte", async () => {
    const id = await createSubject(ITEM);
    const row = await syncAndWaitForRow(ITEM);
    await row.click();

    // The section exists for any live item, empty or not — that is what
    // makes "Joindre un fichier" reachable in the first place.
    const attachButton = await $("button*=Joindre un fichier");
    await attachButton.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg: "the attachments section never rendered on a live item",
    });

    const input = await $(".attachment-add input[type='file']");
    await pickFile(input, FILE_NAME, FILE_CONTENT);

    // The row appears once the upload lands and the item is re-read.
    const attachmentRow = await $(`.attachment-row*=${FILE_NAME}`);
    await attachmentRow.waitForDisplayed({
      timeout: 60_000,
      timeoutMsg: "the uploaded attachment never appeared in the detail panel",
    });

    // Server-side proof plus a full decrypt: `download_attachment`
    // returns base64, which must decode to exactly what was uploaded.
    const check = await browser.execute(async (cipherId, expected) => {
      // @ts-expect-error
      const { invoke } = window.__TAURI__.core;
      await invoke("sync");
      const detail = await invoke("get_cipher", { id: cipherId });
      const attachment = detail.attachments[0];
      if (!attachment) return { error: "no attachment on the synced cipher" };

      const base64 = await invoke("download_attachment", {
        cipherId,
        attachmentId: attachment.id,
      });
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const roundTripped = new TextDecoder().decode(bytes);
      return {
        fileName: attachment.fileName,
        size: attachment.size,
        matches: roundTripped === expected,
        roundTripped,
      };
    }, id, FILE_CONTENT);

    if (check.error) throw new Error(check.error);
    if (check.fileName !== FILE_NAME) {
      throw new Error(`attachment name came back as ${JSON.stringify(check.fileName)}`);
    }
    if (!check.matches) {
      throw new Error(
        `attachment content did not survive the round trip: ${JSON.stringify(check.roundTripped)}`,
      );
    }
    // Ciphertext, so strictly larger than the plaintext: header plus a
    // padding block. Guards against a zero-length upload passing the
    // content check by decoding to an empty string on both sides.
    if (!(check.size > 0)) {
      throw new Error(`the server recorded a size of ${check.size}`);
    }
  });

  it("deletes an attachment after confirmation", async () => {
    const id = await createSubject(ITEM_DELETE);
    const row = await syncAndWaitForRow(ITEM_DELETE);
    await row.click();

    const input = await $(".attachment-add input[type='file']");
    await input.waitForExist({ timeout: 15_000 });
    await pickFile(input, FILE_NAME, FILE_CONTENT);

    const attachmentRow = await $(`.attachment-row*=${FILE_NAME}`);
    await attachmentRow.waitForDisplayed({ timeout: 60_000 });

    // The trash icon at the end of the row.
    const deleteButton = await attachmentRow.$('button[title="Supprimer"]');
    await deleteButton.click();

    const dialog = await $("dialog.confirm-dialog");
    await dialog.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "deleting an attachment did not ask for confirmation",
    });
    const confirmButton = await dialog.$$(".confirm-actions button")[1];
    await confirmButton.click();

    await browser.waitUntil(
      async () => {
        const count = await browser.execute(async (cipherId) => {
          // @ts-expect-error
          const { invoke } = window.__TAURI__.core;
          await invoke("sync");
          const detail = await invoke("get_cipher", { id: cipherId });
          return detail.attachments.length;
        }, id);
        return count === 0;
      },
      {
        timeout: 30_000,
        timeoutMsg: "the attachment is still on the cipher after a confirmed delete",
      },
    );
  });
});
