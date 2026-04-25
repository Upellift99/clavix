// Smoke test — validates that the tauri-driver + WebdriverIO pipeline
// can launch the built Clavix binary and that the WebView **hydrates**.
// No network, no Vaultwarden required: we're only proving the pipe
// works before building richer scenarios on top.
//
// We don't just check `<body>` has any text. The bundled `index.html`
// contains an inline bootstrap `<script>` and a couple of `<link
// rel=modulepreload>` tags that show up under `body.getText()` in
// some WebDriver implementations even when the JS never executes —
// that loophole is exactly how the 0.1.11 release `.deb` shipped a
// blank window through CI: the CSP `script-src 'self'` blocked the
// bootstrap, the body looked "populated" to the smoke check, and
// nobody noticed until a user installed the deb.
//
// To close that loophole we assert on a node Svelte writes after
// hydration: the `<h1>{m.app_name()}</h1>` in +page.svelte. If
// hydration failed, the h1 is never inserted into the DOM and the
// spec fails — caught long before tagging a release.
//
// Deliberately state-agnostic: a fresh profile shows onboarding, a
// returning profile shows login or unlock — we assert the binary is
// alive and the Svelte tree has rendered, not the specific phase.
describe("Clavix launches", () => {
  it("hydrates the Svelte app and renders the title", async () => {
    const title = await $("h1");
    await title.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg:
        "no <h1> rendered after 15 s — Svelte didn't hydrate (likely a CSP regression blocking the inline bootstrap, see issue #22)",
    });

    const text = (await title.getText()).trim();
    if (text !== "Clavix") {
      throw new Error(
        `expected the title to read "Clavix" after hydration, got ${JSON.stringify(text)}`,
      );
    }
  });
});
