// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// The editor talks to Rust only for SSH key work, which none of these
// cases reach — stubbed so the component mounts without a backend.
vi.mock("./api", () => ({
  api: {
    generateSshKey: vi.fn(),
    decryptSshPrivateKey: vi.fn(),
  },
}));

import CipherEditor from "./CipherEditor.svelte";
import { EMPTY_EDITOR_INITIAL } from "./types";

function mount(overrides: Record<string, unknown> = {}) {
  const onCancel = vi.fn();
  const { container } = render(CipherEditor, {
    props: {
      open: true,
      mode: "create" as const,
      initial: { ...EMPTY_EDITOR_INITIAL },
      folders: [],
      organizations: [],
      collections: [],
      currentLocale: "fr" as const,
      onCancel,
      onSubmit: vi.fn().mockResolvedValue(undefined),
      onCopy: vi.fn(),
      ...overrides,
    },
  });
  const backdrop = container.querySelector(".editor-backdrop") as HTMLElement;
  const panel = container.querySelector(".editor-panel") as HTMLElement;
  return { onCancel, container, backdrop, panel };
}

/** Type into the "Nom" field — the cheapest way to make the form dirty. */
async function typeName(container: HTMLElement, value: string) {
  const input = container.querySelector("input[type='text']") as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await tick();
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("CipherEditor close guards", () => {
  it("closes on a backdrop click while the form is untouched", async () => {
    const { onCancel, backdrop } = mount();
    await tick();
    backdrop.click();
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("ignores a backdrop click once something has been typed", async () => {
    const { onCancel, backdrop, container } = mount();
    await tick();
    await typeName(container, "Nouveau compte");
    backdrop.click();
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("ignores Escape on a dirty form", async () => {
    const { onCancel, panel, container } = mount();
    await tick();
    await typeName(container, "Nouveau compte");
    panel.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("still closes on Escape while the form is untouched", async () => {
    const { onCancel, panel } = mount();
    await tick();
    panel.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  // Annuler and ✕ are unambiguous, so they close a dirty form outright.
  // The E2E SSH spec depends on this: it fills the key field, gets the
  // ECDSA rejection, then clicks Annuler and expects the dialog gone.
  it("closes on Annuler even with unsaved changes", async () => {
    const { onCancel, container } = mount();
    await tick();
    await typeName(container, "Nouveau compte");
    const cancel = [...container.querySelectorAll("button")].find(
      (b) => b.textContent?.trim() === "Annuler",
    ) as HTMLButtonElement;
    expect(cancel).toBeTruthy();
    cancel.click();
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("treats a field edited back to its starting value as clean", async () => {
    const { onCancel, backdrop, container } = mount({
      mode: "edit" as const,
      initial: { ...EMPTY_EDITOR_INITIAL, id: "abc", name: "CloudFlare" },
    });
    await tick();
    await typeName(container, "CloudFlar");
    await typeName(container, "CloudFlare");
    backdrop.click();
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});

/** The "+ Ajouter un champ" button, whatever the surrounding markup. */
function addFieldButton(container: HTMLElement): HTMLButtonElement {
  return [...container.querySelectorAll("button")].find((b) =>
    b.textContent?.includes("Ajouter un champ"),
  ) as HTMLButtonElement;
}

function fieldRows(container: HTMLElement): NodeListOf<HTMLElement> {
  return container.querySelectorAll(".custom-field-row");
}

describe("CipherEditor custom fields", () => {
  it("adds and removes rows", async () => {
    const { container } = mount();
    await tick();
    expect(fieldRows(container).length).toBe(0);

    addFieldButton(container).click();
    await tick();
    expect(fieldRows(container).length).toBe(1);

    // The ✕ at the end of the row.
    const remove = [...fieldRows(container)[0].querySelectorAll("button")].at(
      -1,
    ) as HTMLButtonElement;
    remove.click();
    await tick();
    expect(fieldRows(container).length).toBe(0);
  });

  it("submits the fields it was given, hidden ones included", async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const { container } = mount({
      mode: "edit" as const,
      onSubmit,
      initial: {
        ...EMPTY_EDITOR_INITIAL,
        id: "abc",
        name: "Bank",
        fields: [
          { kind: 0, name: "Account", value: "AC-42", linkedId: null },
          { kind: 1, name: "Recovery", value: "code-123", linkedId: null },
        ],
        reprompt: true,
      },
    });
    await tick();
    expect(fieldRows(container).length).toBe(2);

    (container.querySelector("form") as HTMLFormElement).dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await tick();

    expect(onSubmit).toHaveBeenCalledTimes(1);
    const payload = onSubmit.mock.calls[0][0];
    // Custom fields and the reprompt flag have to make the round trip:
    // the cipher PUT replaces the server's copy, so anything the editor
    // fails to send back is deleted from the item.
    expect(payload.fields).toEqual([
      { kind: 0, name: "Account", value: "AC-42", linkedId: null },
      { kind: 1, name: "Recovery", value: "code-123", linkedId: null },
    ]);
    expect(payload.reprompt).toBe(true);
  });

  it("counts an added field as an unsaved change", async () => {
    const { onCancel, backdrop, container } = mount();
    await tick();
    addFieldButton(container).click();
    await tick();
    backdrop.click();
    expect(onCancel).not.toHaveBeenCalled();
  });
});
