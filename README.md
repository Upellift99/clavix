# Clavix

[![CI](https://github.com/Upellift99/clavix/actions/workflows/ci.yml/badge.svg)](https://github.com/Upellift99/clavix/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Upellift99/clavix/actions/workflows/codeql.yml/badge.svg)](https://github.com/Upellift99/clavix/actions/workflows/codeql.yml)
[![Latest release](https://img.shields.io/github/v/release/Upellift99/clavix?include_prereleases&sort=semver)](https://github.com/Upellift99/clavix/releases)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](https://github.com/Upellift99/clavix/releases)
[![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri%202-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![Website](https://img.shields.io/badge/website-clavix.org-175ddc)](https://clavix.org)

🌐 **Website: [clavix.org](https://clavix.org)**

> ⚠️ **Alpha software.** Do not use with a real Vaultwarden vault yet.
> The cryptography has not been independently audited, no stable release
> has shipped, and a significant portion of the code was produced with
> AI assistance under human review. See [DISCLAIMER.md](DISCLAIMER.md)
> for the full picture before you clone.

**A modern desktop client for Vaultwarden and Bitwarden.**

Clavix is an alternative to the official Bitwarden client and Keyguard,
built for the self-hosted Vaultwarden community. The goal: finally
provide a comfortable tree-based vault with drag & drop, the way
KeePassXC has offered for years.

> **Status: alpha, read+write.** Releases starting from `v0.1.7`
> support creating and editing items, full 2FA (including WebAuthn
> and YubiKey OTP), an embedded SSH agent, KeePassXC import and a
> built-in security audit. See [CHANGELOG.md](CHANGELOG.md) for the
> full picture per version.

## What Clavix can do today

Against a real Vaultwarden instance, Clavix:

- **signs you in** (email + master password, PBKDF2 and Argon2id
  KDFs), with full **2FA support**: TOTP, YubiKey OTP, and **WebAuthn
  / FIDO2** — Clavix drives the hardware key over CTAP2/HID itself
  so it works even though the desktop app doesn't run under the
  vault's domain;
- **persists the session locally** under `~/.local/share/clavix/` —
  on restart you land on an *Unlock* screen that only asks for the
  master password, the OAuth2 token refreshes automatically 60 s
  before expiry, and the refresh token stored on disk is itself
  encrypted under the user key;
- **unlocks with a Yubikey** (optional) — after an enrolment from
  Préférences, touching a registered FIDO2 token releases the
  cached user key without re-typing the master password (CTAP2
  `hmac-secret`, conceptually identical to Bitwarden Web's "PRF
  Unlock"). The master password remains accepted in fallback;
  rotating it on another client invalidates the wrap automatically
  rather than producing wrong decrypts;
- syncs the full vault (items, folders, collections, organizations);
- **decrypts and encrypts everything client-side**: AES-256-CBC +
  HMAC-SHA256 for the personal vault, RSA-OAEP-SHA1 for organization
  keys;
- **creates, edits and deletes items** (logins, secure notes, cards,
  identities, SSH keys) either in your personal vault or inside an
  organization you belong to — org items are encrypted with the org
  key and posted through the dedicated `/ciphers/create` endpoint;
- **auto-locks** after your configured idle window, with a tokio
  watchdog on the Rust side that drops the in-memory session even if
  the WebView freezes;
- **lives in the system tray**: an icon with a right-click menu
  (Ouvrir / Verrouiller maintenant / Quitter) keeps Clavix one click
  away while the window is hidden. The X button and the `_` minimise
  button both hide into the tray by default (KeePassXC / Bitwarden
  Desktop semantics) — flip either of them to "quit" / "minimise to
  taskbar" from Préférences if you'd rather keep the platform default;
- **generates TOTP codes** live from the stored secret (supports
  `otpauth://` URIs with custom period, digits, or hash algorithm);
- **scans QR codes** through the device camera to populate the TOTP
  field when creating or editing a login (`jsQR` + `getUserMedia`);
- keeps an **encrypted SQLite cache** of the vault, so the next
  unlock (even offline) shows the vault instantly;
- shows the complete list of items with a live substring search and
  **favicons** for logins (fetched via the Vaultwarden icons endpoint,
  cached server-side; silent emoji fallback per cipher type when the
  favicon is unavailable);
- navigates through a hierarchical **TreeView** built from the
  Bitwarden `/` naming convention (personal folders + collections
  per organization), with a **draggable splitter** to resize the
  tree panel (width persisted to localStorage);
- shows item details with masked sensitive fields, one-click copy,
  and automatic **clipboard clearing after 30 seconds**;
- **drag & drops items** onto folders or organization collections —
  including personal → org (automatic share + re-encryption),
  cross-org transfer (re-encryption from source to target org key)
  and all cipher types;
- **drag & drops whole folders** to rearrange the tree — all their
  sub-folders are renamed in cascade on the server;
- **right-click on any folder** in the sidebar to rename or delete
  it (Vaultwarden's web UI doesn't expose a delete control today),
  including the path-only synthetic parents the tree builds from
  `parent/child` names — both actions cascade through every folder
  whose path falls under the clicked node, so deleting `work` also
  drops `work/projects` and detaches its ciphers in one batch.
  Same-name folders coming from the server are shown as separate
  entries instead of being silently merged;
- runs a **security audit** (🛡) combining HIBP k-anonymity breach
  lookups with local detection of **reused** and **weak** passwords
  (zxcvbn score ≤ 2);
- **imports a KeePassXC CSV export** and creates a folder per
  *Group* value on the fly (📥 button);
- embeds an **SSH agent** (Linux / macOS): exposes the Ed25519 and
  RSA keys from your vault over a Unix socket so `ssh`, `git`,
  `scp`, `rsync`, … can use them without writing the private keys
  to disk, the same way Bitwarden Desktop now does.

The master password never hits the server nor the disk: only derived
values are exchanged (master password hash for authentication, master
key for local decryption). Every sensitive key (`MasterKey`,
`SymmetricKey`) derives `ZeroizeOnDrop` to wipe its memory on
destruction.

---

## Why this project

The official Bitwarden client (Electron) has a dated UX and does not
offer real tree-drag-and-drop. Keyguard, the most serious alternative,
is read-only without a premium subscription and handles deep
hierarchies poorly. Clavix aims to fill that gap for the self-hosted
community.

## Tech stack

- **Framework** — [Tauri 2](https://tauri.app) (Rust + native WebView)
- **Frontend** — [Svelte 5](https://svelte.dev) + TypeScript + Vite
- **Backend** — Rust (Bitwarden crypto inspired by [rbw](https://github.com/doy/rbw))
- **Drag & drop** — native HTML5 (svelte-dnd-action only if sortable
  lists become needed later)
- **Local session** — JSON files under `~/.local/share/clavix/` with
  0600 permissions (cross-platform via the `dirs` crate)
- **Offline cache** — SQLite (`rusqlite` bundled) with the whole
  `SyncResponse` encrypted by the user key before being stored

> Clavix does **not** use the official Bitwarden SDK (ambiguous
> license). The crypto is reimplemented in-project, under GPL-3.0.

## MVP roadmap

### Phase 1 — Read-only
- [x] Login against a Vaultwarden instance (custom URL)
- [x] Master password unlock (PBKDF2 + Argon2id)
- [x] TOTP / YubiKey OTP / WebAuthn / FIDO2 2FA
- [x] Initial sync: items, folders, collections, organizations
- [x] Decrypt names and fields (AES-CBC + HMAC, RSA-OAEP)
- [x] Persisted session on disk + *Unlock* screen (refresh token
  encrypted at rest, access token auto-refreshed)
- [x] Full list with live search
- [x] Item details + clipboard copy with 30 s auto-clear
- [x] Encrypted local cache (offline read-only mode)
- [x] Auto-lock watchdog (JS timer + tokio backend safety net)

### Phase 2 — Tree view
- [x] Parse `/`-separated names into a hierarchy
- [x] TreeView with expand/collapse
- [x] Tree of personal folders **and** organization collections
- [x] Draggable splitter to resize the tree panel

### Phase 3 — Drag & drop (killer feature)
- [x] Drag items onto a folder (PUT `/ciphers/{id}/partial`)
- [x] Drag items onto an organization collection
- [x] Drag a folder onto another folder, with cascade rename of
  sub-folders
- [x] Share a personal item into an organization collection
  (PUT `/ciphers/{id}/share`, re-encrypted client-side with the
  target org key)
- [x] Cross-org item transfer (re-encryption source → target org)
- [x] All cipher types supported for sharing (logins, secure notes,
  cards, identities, SSH keys)

### Phase 4 — Read / write
- [x] Create and edit personal items (all 5 cipher types)
- [x] Create and edit inside an organization + collection
- [x] Restore / permanently delete items
- [x] Built-in password generator
- [x] Live TOTP code generation + QR scanner to import TOTP secrets
- [x] Security audit: HIBP + reused + weak (zxcvbn)
- [x] KeePassXC CSV import with automatic folder creation
- [x] **SSH agent** (Unix socket) — Ed25519 and RSA
- [x] **WebAuthn / FIDO2** in 2FA via CTAP2/HID (no browser needed)
- [x] **Yubikey re-unlock** via the CTAP2 `hmac-secret` extension
  (touch instead of master password after auto-lock)
- [x] **Folder management** — right-click delete + rename on any
  node (real or synthetic path-only parent), with cascade through
  descendants; fix for same-name folders showing as one entry
- [x] **System tray** — icon, right-click menu (Ouvrir / Verrouiller
  / Quitter), and configurable close-to-tray + minimize-to-tray

### Planned

- 🪟 **Windows SSH agent** via named pipes / Pageant compatibility
  (today the SSH agent is Unix-only).
- 🛂 **ECDSA / DSA** SSH keys in the agent.
- 🌐 **Server-side error translation** (`data.message` from the
  Vaultwarden API is still returned as-is).
- 📦 **Flatpak / Flathub** packaging.
- ✅ **Code signing** for macOS and Windows builds.
- 🗄️ **KDBX** (direct native KeePass file) import.

### Out of MVP scope (for now)

Attachments, Sends, passkeys (storing them in the vault), browser
autofill.

## Development requirements

- **Rust** ≥ 1.85 (edition 2024 required by deps)
- **Node.js** ≥ 20 and **pnpm** ≥ 10

### Ubuntu / Debian

```bash
sudo apt install \
  libwebkit2gtk-4.1-dev \
  libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev \
  libxdo-dev \
  libssl-dev \
  librsvg2-dev \
  libayatana-appindicator3-dev \
  libudev-dev \
  build-essential pkg-config curl wget file
```

> `libudev-dev` is pulled in by `hidapi` (used by the FIDO2
> WebAuthn path). Without it, `cargo build` errors out on the
> `hidapi` sys crate.

### Other platforms

See the [Tauri prerequisites](https://tauri.app/start/prerequisites/).

## Run the app in development

```bash
pnpm install
pnpm tauri dev
```

The first Rust compilation takes a few minutes (full Tauri dependency
graph). Subsequent compiles are incremental thanks to the `target/`
cache.

## End-to-end tests (optional)

The WebdriverIO suite (`pnpm test:e2e`) drives the real Tauri binary
against a disposable Vaultwarden container. On top of the base
requirements above, you need:

- **`tauri-driver`** — installed via Cargo into `~/.cargo/bin/`:

  ```bash
  cargo install tauri-driver --locked
  ```

- **WebKitWebDriver + a virtual display** on Linux:

  ```bash
  sudo apt install webkit2gtk-driver xvfb
  ```

- **Docker** + **Docker Compose plugin** — the suite boots a
  Vaultwarden container from `tests/e2e/docker-compose.yml` and tears
  it down on exit. Set `E2E_SKIP_DOCKER=1` to reuse an
  externally-managed instance.

Then build the debug binary once and run the suite under `xvfb-run`:

```bash
pnpm tauri build --debug --no-bundle
xvfb-run -a pnpm test:e2e
```

## Repository layout

```
clavix/
├── src-tauri/        Rust backend (Tauri)
│   └── src/
│       ├── main.rs         Binary entry point
│       ├── lib.rs          Tauri setup + command registry
│       ├── commands/       Tauri commands, one module per domain
│       │                   (auth, vault, cipher, move_share, ssh,
│       │                   audit)
│       ├── services/       Internal helpers used by commands (auth
│       │                   token refresh, cipher body builder,
│       │                   vault summary projection)
│       ├── api.rs          Vaultwarden HTTP client
│       ├── crypto.rs       Key derivation, EncString (AES / RSA),
│       │                   encrypt / re-encrypt for server updates
│       ├── audit.rs        HIBP k-anonymity + reused/weak detection
│       ├── ssh_agent.rs    Unix-socket SSH agent (Ed25519 + RSA)
│       ├── webauthn.rs     CTAP2 / HID WebAuthn path for 2FA
│       ├── models.rs       API types and DTOs sent to the UI
│       ├── state.rs        AppState (session, ssh agent handle,
│       │                   auto-lock watchdog timestamps)
│       ├── store.rs        On-disk session persistence
│       ├── cache.rs        Encrypted SQLite vault cache + op-log
│       └── error.rs        Unified Error type, serialized as
│                           { code, message, data }
├── src/              SvelteKit frontend (static output, no SSR)
│   ├── app.html
│   ├── lib/
│   │   ├── *.svelte        One component per UI area (AuthGate,
│   │   │                   VaultSidebar, CipherList, CipherDetail,
│   │   │                   CipherEditor, ImportDialog, QrScanner,
│   │   │                   TotpField, …)
│   │   ├── *.svelte.ts     Runes-based controllers
│   │   │                   (auth, vault, prefs, clipboard, drag)
│   │   ├── api.ts          Typed wrappers around Tauri commands
│   │   ├── types.ts        Shared TS types
│   │   ├── totp.ts         RFC 6238 TOTP generator (Web Crypto)
│   │   ├── csv.ts          KeePassXC CSV parser
│   │   └── paraglide/      Compiled i18n (gitignored)
│   └── routes/
│       ├── +layout.svelte  Global styles + locale bootstrap
│       └── +page.svelte    Orchestrates the controllers + layout
├── messages/{fr,en}.json   i18n source strings (paraglide-js)
├── .github/workflows/
│   ├── ci.yml              fmt + clippy + audit + svelte-check +
│   │                       vitest + cargo test
│   ├── codeql.yml          CodeQL scan
│   └── release.yml         Multi-OS release bundles
└── CHANGELOG.md            Per-version notes
```

## Security

- The master password and every derived symmetric key (`MasterKey`,
  `SymmetricKey`) derive `ZeroizeOnDrop`: their memory is wiped on
  scope exit. The password travels through `SecretString` (`secrecy`
  crate), which prevents `Debug` from leaking it into logs.
- All decryption happens **client-side**; the server never sees any
  secret in clear text.
- HMAC verification of AES-CBC ciphertext runs in **constant time**
  (`hmac::Mac::verify_slice`) before decryption.
- The clipboard is automatically cleared **30 seconds** after a copy,
  with a banner counting down.
- The session is persisted to `~/.local/share/clavix/session.json`
  (0600 permissions on Unix). Sensitive fields (`Key`, `PrivateKey`)
  stay encrypted by the stretched master key, and the OAuth2 refresh
  token is itself encrypted under the user key. Clavix still assumes
  your user disk is under your control; full-disk encryption such as
  LUKS is recommended.
- Clavix is primarily tested against **Vaultwarden**. Official
  Bitwarden compatibility is a bonus, not a guarantee.
- Security review notes live in [SECURITY.md](SECURITY.md),
  [THREAT_MODEL.md](THREAT_MODEL.md), [CRYPTO.md](CRYPTO.md), and
  [AUDIT_SCOPE.md](AUDIT_SCOPE.md).

Vulnerabilities should be reported privately to the maintainer before
any public disclosure.

## Quality / CI

Every push and pull request against `master` triggers a GitHub
Actions workflow that runs:

- `cargo fmt --check` — Rust style.
- `cargo clippy --all-targets -- -D warnings` — strict lint.
- `cargo test` — Rust unit tests on crypto, audit, ssh agent,
  webauthn challenge parsing, cipher body builder, and the API
  helpers (`extract_*`, `normalize_base_url`).
- `cargo audit` — vulnerability scan on dependencies
  (RUSTSEC-2023-0071 on the `rsa` crate is ignored, see the comment
  in `.github/workflows/ci.yml`).
- `pnpm check` (svelte-check) — TypeScript / Svelte typing.
- `pnpm test` (vitest) — unit tests on the pure TS helpers (tree,
  filter, drag, format, generator, CSV).
- CodeQL analysis (`javascript-typescript`) on a separate workflow.

Tauri system libraries are installed on every run; the `target/`
cache is handled by `Swatinem/rust-cache`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the setup, code style,
and PR conventions. Security-sensitive changes (`crypto.rs`,
`webauthn.rs`, `ssh_agent.rs`, session storage) should come with
matching tests.

## License

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).
