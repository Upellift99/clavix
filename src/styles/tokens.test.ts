import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The dark palette is written twice in tokens.css (system dark and the
// in-app force-dark class); CSS cannot share one block between them.
// This keeps the two copies from drifting and the light set from
// gaining a token the dark set does not define.

const css = readFileSync(new URL("./tokens.css", import.meta.url), "utf8");

function declarations(block: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) out.set(m[1], m[2].trim());
  return out;
}

function blockAfter(marker: string, from = 0): string {
  const start = css.indexOf(marker, from);
  if (start === -1) throw new Error(`marker not found: ${marker}`);
  const open = css.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) return css.slice(open, i + 1);
  }
  throw new Error("unbalanced block");
}

// The header comment mentions the selectors too, so every search starts
// past it: the light block is the first `:root {` after the comment and
// the dark blocks live between the two markers.
const lightStart = css.indexOf(":root {", css.indexOf("*/"));
const darkStart = css.indexOf("/* DARK-TOKENS-BEGIN */");
const darkEnd = css.indexOf("/* DARK-TOKENS-END */");
const light = declarations(blockAfter(":root {", lightStart));
const darkSection = css.slice(darkStart, darkEnd);
const systemDark = declarations(blockAfter("@media (prefers-color-scheme: dark)", darkStart));
const forcedDark = declarations(darkSection.slice(darkSection.indexOf(":root.force-dark")));

describe("tokens.css", () => {
  it("defines the same tokens for light and dark", () => {
    expect([...systemDark.keys()].sort()).toEqual([...light.keys()].sort());
  });

  it("keeps the two dark copies identical", () => {
    expect(Object.fromEntries(forcedDark)).toEqual(Object.fromEntries(systemDark));
  });

  it("has no token that is the same in both themes without a reason", () => {
    // Brand and state colours legitimately survive the theme switch;
    // anything else identical is usually a dark value someone forgot.
    const allowed = new Set([
      "--primary",
      "--primary-pressed",
      "--row-selected",
      "--row-selected-text",
      "--rename-border",
      "--shadow-sm",
      "--shadow-card",
      "--toast-password",
      "--toast-username",
      "--toast-totp",
      "--toast-default",
      "--danger",
      "--error-border",
      "--star",
      "--drop-bg",
      "--drop-text",
      "--drop-outline",
      "--status-fresh",
      "--status-busy",
      "--status-offline",
      "--status-unknown",
      "--on-primary",
    ]);
    const same = [...light].filter(([k, v]) => systemDark.get(k) === v && !allowed.has(k)).map(([k]) => k);
    expect(same).toEqual([]);
  });
});
