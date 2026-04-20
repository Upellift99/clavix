# Clavix E2E

End-to-end tests driving the native Tauri binary via `tauri-driver` +
`WebdriverIO`. Runs on Linux only — `tauri-driver` relies on
WebKitGTK's `WebKitWebDriver`, which has no macOS/Windows counterpart.

## One-time setup

System packages:

```bash
sudo apt install webkit2gtk-driver xvfb
```

Rust & JS tooling:

```bash
cargo install tauri-driver --locked
pnpm install
```

## Running locally

Build the app in debug mode, then run the suite:

```bash
pnpm tauri build --debug
pnpm test:e2e
```

Headless (CI-style):

```bash
xvfb-run -a pnpm test:e2e
```

Running `pnpm test:e2e` assumes the Tauri binary already exists at
`src-tauri/target/debug/clavix`. The WebdriverIO config errors out early
if the binary or `tauri-driver` is missing, with a hint.

## Phases

- **Phase 1 (current)** — smoke only: the binary launches and the login
  form renders. No server required.
- **Phase 2 (TBD)** — Vaultwarden-backed flows (login, create cipher,
  share, lock/unlock). `docker-compose.yml` is pre-staged for this.
  Seeding will likely go through the Bitwarden CLI in a sidecar
  container rather than re-implementing the crypto dance in JS.

## Known gotchas

- `WebKitWebDriver` binds IPv6 (`::1`) by default, which breaks on IPv4-only
  environments. Our `wdio.conf.mjs` passes `--native-host 127.0.0.1` to
  sidestep this ([tauri-apps/tauri#3815]).
- GPU compositing in WebKitGTK misbehaves under WebDriver sessions. We
  export `WEBKIT_DISABLE_COMPOSITING_MODE=1` to force the CPU path.
- WebdriverIO v8+ has reported regressions with `tauri-driver` — we pin
  to v7. If you update, re-run the smoke before touching anything else.
- The Tauri app writes to `~/.local/share/clavix/` even during tests. A
  future Phase 2 commit will sandbox this via `XDG_DATA_HOME`.

[tauri-apps/tauri#3815]: https://github.com/tauri-apps/tauri/issues/3815
