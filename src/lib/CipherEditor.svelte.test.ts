// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
      onCancel,
      onSubmit: vi.fn().mockResolvedValue(undefined),
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

beforeEach(() => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

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
    // Not even a prompt: a stray click outside must be a no-op, not a
    // question the user can answer wrong and lose the form to.
    expect(window.confirm).not.toHaveBeenCalled();
  });

  it("asks before discarding when Escape is pressed on a dirty form", async () => {
    const { onCancel, panel, container } = mount();
    await tick();
    await typeName(container, "Nouveau compte");
    panel.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(window.confirm).toHaveBeenCalledTimes(1);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("keeps the form open when the discard prompt is declined", async () => {
    vi.mocked(window.confirm).mockReturnValue(false);
    const { onCancel, panel, container } = mount();
    await tick();
    await typeName(container, "Nouveau compte");
    panel.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(onCancel).not.toHaveBeenCalled();
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
