// Smoke test — validates that the tauri-driver + WebdriverIO pipeline
// can launch the built Clavix binary and that the webview renders. No
// network, no Vaultwarden required: we're only proving the pipe works
// before building richer scenarios on top.
//
// Deliberately state-agnostic: a fresh profile shows onboarding, a
// returning profile shows login or unlock — we assert the binary is
// alive and some UI is up, not the specific phase.
describe("Clavix launches", () => {
  it("renders a webview with a populated <body>", async () => {
    const body = await $("body");
    await body.waitForExist({ timeout: 15_000 });

    await browser.waitUntil(
      async () => ((await body.getText()) ?? "").trim().length > 0,
      {
        timeout: 15_000,
        timeoutMsg: "<body> never rendered any text",
      },
    );
  });
});
