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

## Specs

The suite is driven by a seeded Vaultwarden instance (Docker, port
`8765`) brought up automatically by `tests/e2e/wdio.conf.mjs` via
`docker compose`. `src-tauri/examples/e2e_seed.rs` registers a test
user (with an RSA keypair) and seeds a canonical fixture set — one of
each cipher type (Login, SecureNote, Card, Identity, SSH key), a
TOTP-enabled login, a personal folder with a cipher inside, and an
organization with two collections plus one org-scoped cipher. All
using the app's own crypto path (`build_cipher_body`) so a regression
in production code surfaces here before it reaches the UI tests.

| Spec                  | What it covers                                               |
| --------------------- | ------------------------------------------------------------ |
| `smoke.spec.mjs`      | Pipeline sanity — binary launches, webview renders           |
| `login.spec.mjs`      | Onboarding → login → auto-sync shows seeded ciphers          |
| `create-cipher.spec.mjs` | `＋` → fill editor → save → new item in list             |
| `share-cipher.spec.mjs`  | Personal cipher → org collection via `share_cipher_to_collection` IPC |
| `lock-unlock.spec.mjs`   | Lock → unlock round-trip restores the vault              |
| `auto-lock.spec.mjs`     | Idle window elapses → `UnlockForm` reappears             |

Two env vars to iterate locally without recycling Docker each run:

- `E2E_SKIP_DOCKER=1` — reuse an externally-managed container
- `E2E_KEEP_CONTAINER=1` — don't tear down after the suite (useful for
  inspecting Vaultwarden logs)

## Known gotchas

- `WebKitWebDriver` binds IPv6 (`::1`) by default, which breaks on IPv4-only
  environments. `wdio.conf.mjs` passes `--native-host 127.0.0.1` to
  sidestep this ([tauri-apps/tauri#3815]).
- GPU compositing in WebKitGTK misbehaves under WebDriver sessions. We
  export `WEBKIT_DISABLE_COMPOSITING_MODE=1` to force the CPU path.
- WebdriverIO v8+ has reported regressions with `tauri-driver` — we pin
  to v7. If you update, re-run the smoke before touching anything else.
- Tauri `withGlobalTauri=true` is intentional: the share-cipher spec
  drives `window.__TAURI__.core.invoke` directly to bypass the flaky
  drag-drop UI. The drag logic itself is covered by `drag.test.ts` on
  the vitest side.
- The Tauri app's data dir is sandboxed to `tests/e2e/sandbox/` via
  `XDG_DATA_HOME` so runs never touch the real `~/.local/share/clavix/`.

[tauri-apps/tauri#3815]: https://github.com/tauri-apps/tauri/issues/3815
