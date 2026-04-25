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
// hydration: the `<main class="container">` from +page.svelte. The
// static `app.html` body contains only an empty wrapper div, so this
// element only exists once Svelte has run — if hydration failed, the
// selector never resolves and the spec fails, catching the regression
// long before tagging a release.
//
// Deliberately state-agnostic: a fresh profile shows onboarding, a
// returning profile shows login or unlock — we assert the binary is
// alive and the Svelte tree has rendered, not the specific phase.
describe("Clavix launches", () => {
  it("hydrates the Svelte app and renders the root container", async () => {
    const root = await $("main.container");
    await root.waitForDisplayed({
      timeout: 15_000,
      timeoutMsg:
        "no <main.container> rendered after 15 s — Svelte didn't hydrate (likely a CSP regression blocking the inline bootstrap, see issue #22)",
    });
  });
});
