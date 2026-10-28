// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// The dialog probes the agent, the Yubikey and the screen-lock on open;
// none of that exists under jsdom.
vi.mock("./api", () => ({
  api: {
    autostartEnabled: vi.fn().mockResolvedValue(false),
    setAutostart: vi.fn().mockResolvedValue(undefined),
    sshAgentStatus: vi.fn().mockResolvedValue({ running: false, socketPath: null, keys: [], skipped: [] }),
    sshAuthSock: vi.fn().mockResolvedValue(null),
    yubikeyUnlockState: vi.fn().mockResolvedValue({ enrolled: false, requiresPin: false }),
    screenLockAvailable: vi.fn().mockResolvedValue(true),
    startSshAgent: vi.fn(),
    stopSshAgent: vi.fn(),
    enrollYubikeyUnlock: vi.fn(),
    disenrollYubikeyUnlock: vi.fn(),
  },
}));

import PreferencesDialog from "./PreferencesDialog.svelte";
import { api } from "./api";

beforeEach(() => {
  vi.mocked(api.autostartEnabled).mockResolvedValue(false);
  vi.mocked(api.setAutostart).mockReset().mockResolvedValue(undefined);
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.open = false;
  };
});

afterEach(cleanup);

async function flush() {
  for (let i = 0; i < 4; i++) await tick();
}

function mount() {
  const onApplyTheme = vi.fn();
  const { component, container } = render(PreferencesDialog, {
    props: {
      currentLocale: "fr" as const,
      themePref: "auto" as const,
      autoLockMinutes: 10,
      autoLockTrigger: "idle" as const,
      closeToTray: true,
      minimizeToTray: false,
      hideDockOnTray: false,
      trayIconStyle: "color" as const,
      onApplyTrayIconStyle: vi.fn(),
      requireNarrowing: true,
      toolbarAlign: "left" as const,
      autoSyncMinutes: 30,
      sshAgentConfirm: "session" as const,
      sshAgentAutoStart: false,
      blurNotes: true,
      onApplyBlurNotes: vi.fn(),
      onApplyLocale: vi.fn(),
      onApplyTheme,
      onApplyAutoLock: vi.fn(),
      onApplyCloseToTray: vi.fn(),
      onApplyMinimizeToTray: vi.fn(),
      onApplyHideDockOnTray: vi.fn(),
      onApplyRequireNarrowing: vi.fn(),
      onApplyToolbarAlign: vi.fn(),
      onApplyAutoSyncMinutes: vi.fn(),
      onApplySshAgentConfirm: vi.fn(),
      onApplySshAgentAutoStart: vi.fn(),
      onCopySocketPath: vi.fn(),
      onCopyShellCommand: vi.fn(),
    },
  }) as unknown as { component: { open: () => Promise<void> }; container: HTMLElement };
  const tabs = () => Array.from(container.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
  const panel = () => container.querySelector('[role="tabpanel"]') as HTMLElement;
  return { component, container, tabs, panel, onApplyTheme };
}

function key(target: Element, k: string) {
  const event = new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true });
  target.dispatchEvent(event);
  return event;
}

describe("PreferencesDialog", () => {
  it("reads the OS autostart setting and disables it on request", async () => {
    vi.mocked(api.autostartEnabled).mockResolvedValue(true);
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[2].click();
    await flush();
    const checkbox = panel().querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    expect(checkbox.checked).toBe(true);
    checkbox.click();
    await flush();
    expect(api.setAutostart).toHaveBeenCalledWith(false);
    expect(checkbox.checked).toBe(false);
  });

  it("keeps autostart off and displays an error if OS registration fails", async () => {
    vi.mocked(api.setAutostart).mockRejectedValueOnce(new Error("Registration denied"));
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[2].click();
    await flush();
    const checkbox = panel().querySelector<HTMLInputElement>('input[type="checkbox"]')!;
    checkbox.click();
    await flush();
    expect(api.setAutostart).toHaveBeenCalledWith(true);
    expect(checkbox.checked).toBe(false);
    expect(panel().querySelector('[role="alert"]')?.textContent).toContain("Registration denied");
  });

  it("opens on the general tab with one panel and one Tab stop", async () => {
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    expect(tabs()).toHaveLength(5);
    expect(tabs().filter((t) => t.tabIndex === 0)).toHaveLength(1);
    expect(tabs()[0].getAttribute("aria-selected")).toBe("true");
    expect(panel().id).toBe("prefs-panel-general");
    expect(panel().querySelector("select")).not.toBeNull();
  });

  it("switches panels on click", async () => {
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[1].click();
    await flush();
    expect(panel().id).toBe("prefs-panel-security");
    expect(panel().querySelector("optgroup")).not.toBeNull();
  });

  it("moves between tabs with the arrow keys, wrapping at the ends", async () => {
    const { component, tabs, panel } = mount();
    await component.open();
    await flush();
    tabs()[0].focus();
    key(tabs()[0], "ArrowLeft");
    await flush();
    expect(panel().id).toBe("prefs-panel-yubikey");
    expect(document.activeElement).toBe(tabs()[4]);
    key(tabs()[4], "ArrowRight");
    await flush();
    expect(panel().id).toBe("prefs-panel-general");
    key(tabs()[0], "End");
    await flush();
    expect(panel().id).toBe("prefs-panel-yubikey");
  });

  it("applies the theme from the general panel", async () => {
    const { component, panel, onApplyTheme } = mount();
    await component.open();
    await flush();
    const selects = panel().querySelectorAll("select");
    const theme = selects[1] as HTMLSelectElement;
    theme.value = "light";
    theme.dispatchEvent(new Event("change", { bubbles: true }));
    expect(onApplyTheme).toHaveBeenCalledWith("light");
  });
});
