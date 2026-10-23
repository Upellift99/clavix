import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { clipboardWrite, clipboardClearIfOurs } = vi.hoisted(() => ({
  clipboardWrite: vi.fn().mockResolvedValue(undefined),
  clipboardClearIfOurs: vi.fn().mockResolvedValue(true),
}));
vi.mock("./api", () => ({ api: { clipboardWrite, clipboardClearIfOurs } }));

import { CLIPBOARD_CLEAR_SECONDS, ClipboardController } from "./clipboard.svelte";

beforeEach(() => {
  vi.useFakeTimers();
  clipboardWrite.mockClear();
  clipboardClearIfOurs.mockClear();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("ClipboardController", () => {
  it("writes through Rust and asks it to clear only its own value after the delay", async () => {
    const clipboard = new ClipboardController();
    await clipboard.copy("hunter2", "password");
    expect(clipboardWrite).toHaveBeenCalledWith("hunter2");
    expect(clipboard.secondsLeft).toBe(CLIPBOARD_CLEAR_SECONDS);

    await vi.advanceTimersByTimeAsync((CLIPBOARD_CLEAR_SECONDS - 1) * 1000);
    expect(clipboardClearIfOurs).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1000);
    expect(clipboardClearIfOurs).toHaveBeenCalledTimes(1);
    expect(clipboard.secondsLeft).toBeNull();
  });

  it("a second copy restarts the delay instead of clearing early", async () => {
    const clipboard = new ClipboardController();
    await clipboard.copy("first", "username");
    await vi.advanceTimersByTimeAsync(20_000);
    await clipboard.copy("second", "password");
    await vi.advanceTimersByTimeAsync(20_000);
    expect(clipboardClearIfOurs).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(clipboardClearIfOurs).toHaveBeenCalledTimes(1);
  });

  it("clear now goes through the same ownership check", async () => {
    const clipboard = new ClipboardController();
    await clipboard.copy("hunter2", "password");
    await clipboard.clearNow();
    expect(clipboardClearIfOurs).toHaveBeenCalledTimes(1);
    expect(clipboard.secondsLeft).toBeNull();
  });
});
