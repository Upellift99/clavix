// Full login flow against a live seeded Vaultwarden: onboarding (if
// shown) → login form → vault list containing the seeded ciphers.
// Exercises the real Tauri ↔ Rust ↔ HTTP path end-to-end.

import { e2eServer, e2eEmail, e2ePassword } from "../wdio.conf.mjs";

describe("Login flow", () => {
  it("logs into the seeded vault and shows the seeded ciphers", async () => {
    // Wait for the app to finish bootstrapping. The bootstrap goes
    // through an IPC round-trip, so there's a flash of a loading state
    // before either the onboarding or the login form is painted.
    await browser.waitUntil(
      async () => (await $("body").getText()).trim().length > 20,
      { timeout: 15_000, timeoutMsg: "body still empty / loading" },
    );

    // Fresh XDG_DATA_HOME means WebKitGTK's localStorage is also fresh,
    // so the onboarding gate shows. Future commits that move the
    // onboarding flag elsewhere can make this a no-op; treat as optional.
    const onboardingContinue = await $(
      "section.onboarding button:not(.secondary)",
    );
    if (await onboardingContinue.isExisting()) {
      await onboardingContinue.click();
    }

    // --- login form ---
    const urlInput = await $('input[type="url"]');
    await urlInput.waitForDisplayed({ timeout: 10_000 });
    await urlInput.setValue(e2eServer);

    const emailInput = await $('input[type="email"]');
    await emailInput.setValue(e2eEmail);

    const pwdInput = await $('input[type="password"]');
    await pwdInput.setValue(e2ePassword);

    const submit = await $('button[type="submit"]');
    await submit.click();

    // With post-login auto-sync wired up, the vault populates on its own —
    // no need for the test to click "Synchroniser" anymore.
    const seededRow = await $(`.cipher-row*=GitHub`);
    await seededRow.waitForDisplayed({
      timeout: 20_000,
      timeoutMsg: "seeded 'GitHub' cipher never appeared in the list",
    });

    const noteRow = await $(`.cipher-row*=Welcome note`);
    await noteRow.waitForDisplayed({
      timeout: 5_000,
      timeoutMsg: "seeded 'Welcome note' cipher never appeared",
    });
  });
});
