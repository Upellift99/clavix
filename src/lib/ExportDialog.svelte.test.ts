// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup, waitFor } from "@testing-library/svelte";
import { tick } from "svelte";

// The dialog scores the file password over IPC and seals the export in
// Rust. Stub both so the component test needs no Tauri backend.
const exportEncrypted = vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3]));
vi.mock("./api", () => ({
  api: {
    scorePassword: vi.fn().mockResolvedValue({
      score: 4,
      guessesLog10: 20,
      warning: null,
    }),
    exportEncrypted: (...args: unknown[]) => exportEncrypted(...args),
  },
}));

import ExportDialog from "./ExportDialog.svelte";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function mount() {
  return render(ExportDialog, {
    props: {
      open: true,
      ciphers: [
        { id: "a", kind: 1, name: "Login", deletedDate: null, folderId: null },
        { id: "b", kind: 3, name: "Card", deletedDate: null, folderId: null },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ] as any,
      folders: [],
      onCancel: () => {},
    },
  });
}

/** The confirm button is the last one in the footer row. */
function exportButton(container: HTMLElement): HTMLButtonElement {
  const buttons = [...container.querySelectorAll(".row button")];
  return buttons[buttons.length - 1] as HTMLButtonElement;
}

async function type(input: HTMLInputElement, value: string) {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await tick();
}

describe("ExportDialog — encrypted format", () => {
  it("defaults to the encrypted format", async () => {
    const { container } = mount();
    await tick();
    const encrypted = container.querySelector<HTMLInputElement>(
      'input[type="radio"][value="encrypted"]',
    );
    expect(encrypted?.checked).toBe(true);
  });

  it("keeps export disabled until the password is long enough and confirmed", async () => {
    const { container } = mount();
    await tick();

    const password = container.querySelector<HTMLInputElement>("#export-file-password")!;
    const confirm = container.querySelector<HTMLInputElement>(
      "#export-file-password-confirm",
    )!;

    expect(exportButton(container).disabled).toBe(true);

    // Long enough, but unconfirmed.
    await type(password, "a-very-long-passphrase");
    expect(exportButton(container).disabled).toBe(true);

    // Confirmed but mismatched.
    await type(confirm, "a-very-long-passphrasX");
    expect(exportButton(container).disabled).toBe(true);

    await type(confirm, "a-very-long-passphrase");
    expect(exportButton(container).disabled).toBe(false);
  });

  it("refuses a short password even when both fields match", async () => {
    const { container } = mount();
    await tick();
    const password = container.querySelector<HTMLInputElement>("#export-file-password")!;
    const confirm = container.querySelector<HTMLInputElement>(
      "#export-file-password-confirm",
    )!;

    await type(password, "short");
    await type(confirm, "short");

    expect(exportButton(container).disabled).toBe(true);
    // And says why, rather than leaving a dead button.
    expect(container.textContent).toMatch(/12/);
  });

  it("never sends the vault through the webview — only the file password goes out", async () => {
    const { container } = mount();
    await tick();
    const password = container.querySelector<HTMLInputElement>("#export-file-password")!;
    const confirm = container.querySelector<HTMLInputElement>(
      "#export-file-password-confirm",
    )!;
    await type(password, "a-very-long-passphrase");
    await type(confirm, "a-very-long-passphrase");

    exportButton(container).click();

    await waitFor(() => expect(exportEncrypted).toHaveBeenCalledTimes(1));
    expect(exportEncrypted).toHaveBeenCalledWith("a-very-long-passphrase");
  });

  it("switches to the CSV filters when the CSV format is picked", async () => {
    const { container } = mount();
    await tick();

    const csv = container.querySelector<HTMLInputElement>(
      'input[type="radio"][value="csv"]',
    )!;
    csv.click();
    await tick();

    expect(container.querySelector("#export-file-password")).toBeNull();
    expect(container.querySelectorAll('input[type="checkbox"]').length).toBe(2);
  });
});
