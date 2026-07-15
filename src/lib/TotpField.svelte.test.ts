// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, cleanup, waitFor } from "@testing-library/svelte";

// The TOTP secret stays in Rust; TotpField asks `api.totpCode(id)` for the
// current code. Mock that so the component test doesn't need a Tauri backend.
vi.mock("./api", () => ({
  api: {
    totpCode: vi.fn().mockResolvedValue({ code: "287082", secondsRemaining: 12 }),
  },
}));

import TotpField from "./TotpField.svelte";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// Collect Svelte's effect_update_depth_exceeded, whether surfaced synchronously
// on mount or via console.error / window error events during the flush.
function captureErrors(): { errors: string[]; stop: () => void } {
  const errors: string[] = [];
  const origError = console.error;
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
    origError(...(args as []));
  });
  const onError = (e: ErrorEvent) => errors.push(String(e.message ?? e.error));
  window.addEventListener("error", onError);
  return { errors, stop: () => window.removeEventListener("error", onError) };
}

describe("TotpField reactivity", () => {
  it("mounts a TOTP source without entering an $effect update loop", () => {
    const { errors, stop } = captureErrors();

    let threw: unknown = null;
    try {
      render(TotpField, {
        // RFC 6238 test secret ("12345678901234567890" base32-encoded)
        props: { id: "cipher-1", onCopy: () => {} },
      });
    } catch (e) {
      threw = e;
    }
    stop();

    const blob = [String((threw as Error)?.message ?? threw ?? ""), ...errors].join("\n");
    expect(blob, `unexpected update-depth loop:\n${blob}`).not.toMatch(
      /update_depth_exceeded|Maximum update depth/i,
    );
  });

  it("renders a formatted TOTP code", async () => {
    const { getByText } = render(TotpField, {
      props: { source: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", onCopy: () => {} },
    });
    // Default 6-digit code formatted as "xxx xxx".
    await waitFor(() => {
      expect(getByText(/^\d{3} \d{3}$/)).toBeTruthy();
    });
  });
});
