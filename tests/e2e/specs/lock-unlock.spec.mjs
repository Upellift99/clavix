// Exercises the lock / unlock cycle end-to-end.
//
// Locking clears the in-memory session (tokens, user key, decrypted
// vault) on the Rust side; the persisted session file stays on disk,
// encrypted under the user key. Unlock re-derives the master key from
// the password, decrypts the persisted session, and the auto-sync
// hook repopulates the vault. Any regression on this path lands
// users locked out of their own data on the next launch.

import { e2ePassword } from "../wdio.conf.mjs";
import { loginAsSeededUser, showAllItems } from "../helpers/auth.mjs";

describe("Lock → unlock", () => {
  it("clears the vault on lock and restores it on unlock", async () => {
    await loginAsSeededUser();

    // Match on aria-label rather than text content: the toolbar button
    // is icon-only (🔒) and exposes its label via aria-label / title.
    const lockButton = await $("button[aria-label='Verrouiller']");
    await lockButton.click();

    // After lock, the session bar is gone and the UnlockForm is
    // painted in its place. Its password field is the only visible
    // input on screen.
    const unlockPassword = await $('input[type="password"]');
    await unlockPassword.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "unlock form never rendered after clicking Lock",
    });

    // Sanity: the vault list is gone — the seeded cipher must no
    // longer be mounted in the DOM. Otherwise "unlock restored it"
    // would trivially pass because it never disappeared.
    const ghWhileLocked = await $(".cipher-row*=GitHub");
    await ghWhileLocked.waitForExist({
      reverse: true,
      timeout: 5_000,
      timeoutMsg: "GitHub cipher still in DOM after lock",
    });

    await unlockPassword.setValue(e2ePassword);
    const submit = await $('button[type="submit"]');
    await submit.click();

    // Post-unlock, the auto-sync hook (same as post-login) brings the
    // vault back. The list gate is back too — the "show all" override is
    // deliberately per-session, so locking drops it — hence the second
    // call here. Assert on a seeded cipher to prove the chain went all
    // the way through: refresh_token decrypt → access token → /api/sync
    // → decode ciphers with user key.
    await showAllItems();

    const ghAfterUnlock = await $(".cipher-row*=GitHub");
    await ghAfterUnlock.waitForDisplayed({
      timeout: 20_000,
      timeoutMsg: "GitHub cipher never reappeared after unlock",
    });
  });
});
