// Helper to seed an abnormally short auto-lock window via localStorage
// before the app ever authenticates. prefs.bootstrap() reads
// clavix.autoLockMinutes exactly once in onMount(), so we set the key
// from WebdriverIO and reload the page to make the controller pick it
// up. We also set clavix.onboarded=1 to skip the onboarding screen —
// it's not what we're exercising here and would otherwise need another
// click for every reload.

export async function seedAutoLockWindow(minutes) {
  // Wait for the first paint so we know the Tauri WebView has booted
  // and window.localStorage is reachable.
  await browser.waitUntil(
    async () => (await $("body").getText()).trim().length > 20,
    { timeout: 15_000, timeoutMsg: "body still empty / loading" },
  );

  await browser.execute((mins) => {
    localStorage.setItem("clavix.autoLockMinutes", String(mins));
    localStorage.setItem("clavix.onboarded", "1");
    window.location.reload();
  }, minutes);

  // Post-reload, the prefs are seeded and the app lands directly on the
  // login form (onboarded=1 short-circuits the walkthrough). Anchor on
  // the URL input so subsequent helpers can proceed without racing the
  // refresh.
  const urlInput = await $('input[type="url"]');
  await urlInput.waitForDisplayed({
    timeout: 15_000,
    timeoutMsg: "login form never rendered after reload",
  });
}
