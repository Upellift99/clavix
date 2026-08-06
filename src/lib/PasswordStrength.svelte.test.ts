// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { render, cleanup } from "@testing-library/svelte";

import PasswordStrength from "./PasswordStrength.svelte";

afterEach(cleanup);

function meter(container: HTMLElement): HTMLElement {
  const el = container.querySelector('[role="meter"]');
  if (!el) throw new Error("no meter rendered");
  return el as HTMLElement;
}

function band(container: HTMLElement): string | null {
  return container.querySelector(".strength")?.getAttribute("data-band") ?? null;
}

describe("PasswordStrength", () => {
  it("fills more segments for a stronger score", () => {
    const weak = render(PasswordStrength, { props: { score: 0 } });
    const weakFilled = weak.container.querySelectorAll(".strength-seg.on").length;
    cleanup();

    const strong = render(PasswordStrength, { props: { score: 4 } });
    const strongFilled = strong.container.querySelectorAll(".strength-seg.on").length;

    expect(strongFilled).toBeGreaterThan(weakFilled);
  });

  it("maps the zxcvbn score to the band the audit would agree with", () => {
    // WEAK_SCORE_MAX is 2 in Rust: scores at or below it must never
    // paint as good/strong, or the editor would bless a password the
    // audit lists as weak.
    for (const [score, expected] of [
      [0, "weak"],
      [1, "weak"],
      [2, "fair"],
      [3, "good"],
      [4, "strong"],
    ] as const) {
      const { container } = render(PasswordStrength, { props: { score } });
      expect(band(container), `score ${score}`).toBe(expected);
      cleanup();
    }
  });

  it("renders nothing filled and no verdict when there is no score yet", () => {
    const { container } = render(PasswordStrength, { props: { score: null } });
    expect(band(container)).toBe("empty");
    expect(container.querySelectorAll(".strength-seg.on")).toHaveLength(0);
    expect(container.querySelector(".strength-text")).toBeNull();
  });

  it("uses the bits scale when given bits, not the score scale", () => {
    // 20 chars over the full 84-character alphabet ≈ 128 bits.
    const { container } = render(PasswordStrength, { props: { bits: 128 } });
    expect(band(container)).toBe("strong");
    expect(container.querySelector(".strength-detail")?.textContent).toMatch(/128/);
  });

  it("calls a short generated password weak on the bits scale", () => {
    const { container } = render(PasswordStrength, { props: { bits: 28 } });
    expect(band(container)).toBe("weak");
  });

  it("translates a zxcvbn warning slug instead of showing the slug", () => {
    const { container } = render(PasswordStrength, {
      props: { score: 0, warning: "top-10-password" },
    });
    const text = container.querySelector(".strength-warning")?.textContent ?? "";
    expect(text.length).toBeGreaterThan(0);
    expect(text).not.toContain("top-10-password");
  });

  it("stays silent on an unknown warning slug rather than printing it raw", () => {
    // A slug added upstream that we haven't mapped yet must not leak
    // into the UI as kebab-case debris.
    const { container } = render(PasswordStrength, {
      props: { score: 0, warning: "not-a-real-slug" },
    });
    expect(container.querySelector(".strength-warning")).toBeNull();
  });

  it("exposes the verdict to assistive tech, not just a bare number", () => {
    const { container } = render(PasswordStrength, { props: { score: 4 } });
    const el = meter(container);
    expect(el.getAttribute("aria-valuenow")).toBe("4");
    expect(el.getAttribute("aria-valuetext")?.length ?? 0).toBeGreaterThan(0);
    expect(el.getAttribute("aria-label")?.length ?? 0).toBeGreaterThan(0);
  });

  it("hides the verdict line in compact mode but keeps the bar", () => {
    const { container } = render(PasswordStrength, {
      props: { score: 3, compact: true },
    });
    expect(container.querySelector(".strength-text")).toBeNull();
    expect(container.querySelectorAll(".strength-seg.on").length).toBeGreaterThan(0);
  });
});
