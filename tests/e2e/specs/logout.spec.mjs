// Exercises the logout flow end-to-end.
//
// Logout drops the in-memory session AND clears `session.json` and
// the encrypted SQLite cache from disk. The observable difference
// from a regular Lock is that AuthGate must re-render the **login**
// form (server URL + email + password), not the **unlock** form
// (password only) — Lock keeps the persisted session, Logout
// removes it. A regression that keeps the file on disk would land
// users on Unlock again on next launch even after they explicitly
// asked to switch account.
//
// Issue #9 — covers the "logout → session and cache cleared as
// expected" scenario.

import { loginAsSeededUser } from "../helpers/auth.mjs";

describe("Logout", () => {
  it("clears stored_account and lands on the initial login form", async () => {
    await loginAsSeededUser();

    // Toolbar button is icon-only (⏻); match on aria-label like the
    // lock-unlock spec does for the lock button.
    const logoutBtn = await $('button[aria-label="Se déconnecter"]');
    await logoutBtn.waitForClickable({ timeout: 10_000 });
    await logoutBtn.click();

    // The discriminator: a successful logout shows the login form
    // (server URL field present). A bug that only locked would show
    // the unlock form, where there's no `input[type="url"]`.
    const urlInput = await $('input[type="url"]');
    await urlInput.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg:
        'login form (input[type="url"]) never appeared after logout — likely the persisted session was not cleared',
    });

    // Sanity check at the IPC layer: stored_account must return null.
    // This is the contract the next launch reads — if it still
    // resolves to the seeded account, the .json file on disk was
    // not removed.
    const stored = await browser.execute(async () => {
      // @ts-expect-error — tauri injects this global
      const { invoke } = window.__TAURI__.core;
      return invoke("stored_account");
    });
    if (stored !== null) {
      throw new Error(
        `stored_account should be null after logout, got ${JSON.stringify(stored)}`,
      );
    }
  });
});
