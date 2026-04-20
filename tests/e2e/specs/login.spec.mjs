// Full login flow against a live seeded Vaultwarden: onboarding (if
// shown) → login form → auto-synced vault containing the seeded
// ciphers. Exercises the real Tauri ↔ Rust ↔ HTTP path end-to-end.

import { loginAsSeededUser } from "../helpers/auth.mjs";

describe("Login flow", () => {
  it("logs into the seeded vault and shows the seeded ciphers", async () => {
    await loginAsSeededUser();

    // loginAsSeededUser already asserts that "GitHub" rendered — here
    // we additionally check that the secure note fixture also made it
    // through, proving the sync decoded multiple cipher types.
    const noteRow = await $(`.cipher-row*=Welcome note`);
    await noteRow.waitForDisplayed({
      timeout: 5_000,
      timeoutMsg: "seeded 'Welcome note' cipher never appeared",
    });
  });
});
