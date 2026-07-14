// Shared WebdriverIO flow that drives the app from a fresh process all
// the way to a populated vault. Used by every spec that needs to run
// as the seeded user — extracting it avoids re-asserting on the
// authentication UI in every test and keeps the diff readable when
// the onboarding / login layout changes.
import { e2eServer, e2eEmail, e2ePassword } from "../wdio.conf.mjs";

export async function loginAsSeededUser() {
  // Wait for the initial paint. The AuthGate spends a frame or two in
  // its "init" phase (IPC round-trip to load the stored account), then
  // switches to onboarding or login.
  await browser.waitUntil(
    async () => (await $("body").getText()).trim().length > 20,
    { timeout: 15_000, timeoutMsg: "body still empty / loading" },
  );

  // Onboarding shows once per fresh XDG sandbox — click through.
  const onboardingContinue = await $(
    "section.onboarding button:not(.secondary)",
  );
  if (await onboardingContinue.isExisting()) {
    await onboardingContinue.click();
  }

  const urlInput = await $('input[type="url"]');
  await urlInput.waitForDisplayed({ timeout: 10_000 });
  await urlInput.setValue(e2eServer);

  const emailInput = await $('input[type="email"]');
  await emailInput.setValue(e2eEmail);

  const pwdInput = await $('input[type="password"]');
  await pwdInput.setValue(e2ePassword);

  const submit = await $('button[type="submit"]');
  await submit.click();

  await showAllItems();

  const seededRow = await $(".cipher-row*=GitHub");
  await seededRow.waitForDisplayed({
    timeout: 20_000,
    timeoutMsg: "auto-sync never populated the vault with the seeded ciphers",
  });
}

/**
 * Clear the item-list gate.
 *
 * The list holds itself back until the user searches or picks a folder
 * (`prefs.requireNarrowing`, on by default), so a freshly synced vault
 * lands on the gate rather than on the rows — and the gate comes back
 * after every lock, since the "show all" override is per-session. Specs
 * that assert on rows take the same escape hatch a user would.
 *
 * Resolves as soon as rows are present, so it is a no-op when the gate
 * is off.
 */
export async function showAllItems() {
  await browser.waitUntil(
    async () => {
      if (await (await $(".cipher-row")).isExisting()) return true;
      const showAll = await $(".empty-state button");
      if (await showAll.isExisting()) {
        await showAll.click();
        return true;
      }
      return false;
    },
    {
      timeout: 20_000,
      timeoutMsg: "auto-sync never populated the vault with the seeded ciphers",
    },
  );
}
