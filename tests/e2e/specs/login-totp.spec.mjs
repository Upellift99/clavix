// TOTP-2FA login flow end-to-end against the seeded
// `e2e-2fa@clavix.test` fixture.
//
// The default `loginAsSeededUser` helper drives the no-2FA account
// (`e2e@clavix.test`); this spec exists specifically to exercise
// the second-factor branch: login → server replies
// TwoFactorRequired with provider 0 → user types the TOTP code →
// login_with_two_factor → vault unlocks → seeded "Behind 2FA"
// cipher reachable via sync.
//
// Why a dedicated spec: the 2FA branch in `auth.svelte.ts` and the
// `PendingTwoFactor` state in Rust (issue #21) only run on this
// path. Without it the 2FA-aware code is exclusively covered by
// unit tests on the Rust side, which means a regression in the UI
// wiring (provider selection, code submission, AuthGate transition
// after success) ships green to users.
//
// Issue #23 — covers "first login with supported 2FA methods".

import { totpCode } from "../helpers/totp.mjs";
import { e2eServer } from "../wdio.conf.mjs";

// Mirrors `TWO_FA_*` constants in `e2e_seed.rs`. Hard-coded here
// rather than re-exported from wdio.conf.mjs because they're
// fixture-local — the rest of the suite has no business knowing
// about the 2FA account at all.
const TOTP_EMAIL = "e2e-2fa@clavix.test";
const TOTP_PASSWORD = "two-factor-fixture";
const TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

describe("Login flow ▸ TOTP 2FA", () => {
  it("logs into the seeded TOTP account and surfaces the 2FA-only cipher", async () => {
    // Onboarding may already have been clicked by an earlier spec;
    // wait for the body to settle and dismiss it if it's still up.
    await browser.waitUntil(
      async () => (await $("body").getText()).trim().length > 20,
      { timeout: 15_000, timeoutMsg: "body still empty / loading" },
    );
    const onboardingContinue = await $("section.onboarding button:not(.secondary)");
    if (await onboardingContinue.isExisting()) {
      await onboardingContinue.click();
    }

    // Standard login form with the 2FA-bound credentials.
    const urlInput = await $('input[type="url"]');
    await urlInput.waitForDisplayed({ timeout: 10_000 });
    await urlInput.setValue(e2eServer);
    await (await $('input[type="email"]')).setValue(TOTP_EMAIL);
    await (await $('input[type="password"]')).setValue(TOTP_PASSWORD);
    await (await $('button[type="submit"]')).click();

    // The TOTP input only appears once `login` returns
    // TwoFactorRequired and the AuthController flips to
    // phase="twoFactor". Match by the canonical TOTP attributes
    // set in TwoFactorForm.svelte: `inputmode="numeric"` +
    // `maxlength="6"` is the unambiguous selector even if the
    // wrapping label or surrounding text changes.
    const totpInput = await $('input[inputmode="numeric"][maxlength="6"]');
    await totpInput.waitForDisplayed({
      timeout: 10_000,
      timeoutMsg: "TOTP input never appeared after submit — 2FA branch not entered",
    });

    // RFC 6238 code at "now". The window is 30 s, so even a slow
    // Argon2id step on the previous IPC call won't have us land
    // outside the validity window of the code we just minted.
    const code = totpCode(TOTP_SECRET);
    await totpInput.setValue(code);

    // The 2FA form's submit button. There are several `button`
    // elements visible at this phase (Cancel, switch provider,
    // …); the only one of `type=submit` is the one that posts
    // the code.
    const submit = await $('button[type="submit"]');
    await submit.click();

    // Post-2FA, the auto-sync hook brings the seeded fixture down.
    // The 2FA account only has one cipher — "Behind 2FA" — so its
    // presence in the list is the sharpest possible "we're past
    // the 2FA gate and the vault decrypted".
    const seededRow = await $(".cipher-row*=Behind 2FA");
    await seededRow.waitForDisplayed({
      timeout: 20_000,
      timeoutMsg:
        '"Behind 2FA" cipher never showed after 2FA submit — login_with_two_factor likely returned an error',
    });
  });
});
