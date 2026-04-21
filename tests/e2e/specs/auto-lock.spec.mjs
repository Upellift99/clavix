// Exercises the idle auto-lock path end-to-end.
//
// Clavix has two guards: a JS setInterval in +page.svelte and a tokio
// watchdog on the Rust side. Only the JS timer flips `auth.phase` to
// "unlock" and repaints UnlockForm — the tokio path is a pure safety
// net that drops the in-memory session so a frozen WebView can't keep
// the vault unlocked. This spec targets the JS timer: it seeds a
// sub-minute lock window, logs in, then stays completely idle until
// the unlock screen appears on its own.
//
// `seedAutoLockWindow(0.05)` writes 0.05 minutes (= 3 s) into
// localStorage before the prefs controller's bootstrap — that's why
// PrefsController.bootstrap() parses with parseFloat, not parseInt.
// The adaptive poll interval in +page.svelte shrinks the setInterval
// cadence to ~750 ms when the window is tiny, so the worst-case
// observed lock delay is ~3.75 s post-login.

import { loginAsSeededUser } from "../helpers/auth.mjs";
import { seedAutoLockWindow } from "../helpers/lock.mjs";

describe("Auto-lock", () => {
  it("drops the vault after the configured idle window", async () => {
    await seedAutoLockWindow(0.05);
    await loginAsSeededUser();

    // No mouse / keyboard events from here on — WebDriver polling
    // doesn't move the pointer or type anything, so lastActivityAt
    // stays frozen and the idle window elapses naturally.
    const unlockPassword = await $('input[type="password"]');
    await unlockPassword.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg: "auto-lock never triggered within the idle window",
    });

    // Sanity: the seeded GitHub row must be gone, otherwise
    // "the vault was dropped" would be vacuously true if it was
    // still mounted from the earlier sync.
    const ghAfterLock = await $(".cipher-row*=GitHub");
    await ghAfterLock.waitForExist({
      reverse: true,
      timeout: 5_000,
      timeoutMsg: "GitHub cipher still in DOM after auto-lock",
    });
  });
});
