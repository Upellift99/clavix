# Changelog

All notable changes to Clavix are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.12] — 2026-04-25

### Fixed
- **Blank window in the `0.1.11.deb` (and earlier release builds).**
  `index.html` produced by `adapter-static` boots the app via an
  inline `<script>` that imports the SvelteKit entry chunks; the
  previous CSP `script-src 'self'` blocked it silently in release
  builds, leaving an empty body. The CI E2E suite never noticed
  because it runs `pnpm tauri build --debug` (Tauri does not
  enforce the same CSP in debug). Loosen `script-src` to
  `'self' 'unsafe-inline'`. The downgrade is bounded in this
  codebase: bundled HTML, no `{@html}` anywhere in `src/`, Svelte 5
  always escapes interpolations. Tighter hash/nonce-based CSP
  tracked separately as a follow-up.

### Security
- **Strict-exact-match WebAuthn rpId.** `0.1.11` accepted both
  `host == rp_id` and `host.ends_with(".{rp_id}")`. The second
  branch was a textual DNS suffix, which is too loose: `rpId="com"`
  matched any `*.com` host. A hostile or MITM'd Vaultwarden could
  exploit that. Drop the suffix branch entirely; only exact host
  match passes. The rare apex-with-subdomain case is now rejected
  and should come back, if at all, behind an explicit per-account
  opt-in.
- **HTTPS required for the Vaultwarden URL** (with an allow-list
  of `localhost` / `127.0.0.1` / `::1` for local dev with Docker
  Vaultwarden over plain HTTP). `normalize_base_url` used to swallow
  any scheme `Url::parse` could parse — `http://`, `file://`,
  `javascript:`, `ftp://`, … — and just appended a trailing slash.
  Posting a master-password hash over plaintext on a hostile WiFi
  was one config-import or copy-paste away.

### Documentation
- **Three corrections in `MANUAL_VALIDATION.md`** flagged by external
  review:
  - The rpId-mismatch failure path now quotes the new strict-match
    error message.
  - The SSH-agent "expected" line no longer claims keys are wiped
    "immediately after" each signature — the lifecycle is the
    agent's, not the individual sign call's. Keys are never on
    disk and disappear on stop / lock / logout / quit.
  - The socket-permissions check now expects `srw-------` (0600)
    to match what `ssh_agent.rs` actually sets.

### CI
- **Discord webhook** posts a release notification once all three
  platform builds succeed (silently no-ops without
  `DISCORD_RELEASE_WEBHOOK_URL`). Pulls highlights for the freshly-
  tagged version out of `CHANGELOG.md`, capped at 80 lines so we
  stay under Discord's 4096-char description limit. Embed colour is
  the Bitwarden brand blue (`0x175DDC`). `allowed_mentions:
  { parse: [] }` is set on the payload so a stray `@everyone` in a
  future CHANGELOG entry can't ping the entire Discord server.

## [0.1.11] — 2026-04-25

### Security
- **WebAuthn rpId validation.** The 2FA WebAuthn path used to trust
  whatever `rpId` Vaultwarden sent in the challenge and feed it into
  the `clientDataJSON` we hand to the FIDO2 token. A hostile or
  MITM'd server could pick `rpId="other-service.com"` and walk away
  with a valid assertion for that origin. We now reject any rpId that
  is not the configured `server_url`'s host or a registrable suffix
  of it (with a strict dot-boundary check so `example.com.attacker.com`
  is rejected). The `server_url` is plumbed from the user's typed
  login form value through the Tauri command, so the comparison is
  anchored on user input rather than anything the server controls.
- **Tokens no longer cross the IPC boundary.** `login`,
  `login_with_two_factor` and `unlock` used to return the full
  `TokenSet` (access + refresh tokens, encrypted user key, encrypted
  private key) to the WebView — useful as a "yes we got something"
  signal during early bring-up, irrelevant now. They now return
  `LoginOk { email }` (or a similar `LoginOutcome` for the 2FA branch)
  and the Rust `AppState` is the single owner of every session secret.
  The frontend cannot accidentally log, persist, or post a token it
  doesn't have.
- **9 Dependabot alerts cleared** in 0.1.10's tail (`rustls-webpki`
  CVE on the Rust side, plus `tar-fs`, `ws`, `serialize-javascript`,
  `minimatch`, `tmp`, … pulled transitively by `@wdio/*` v7 — fixed
  via `pnpm.overrides` rather than a wdio major bump). One additional
  `uuid < 14.0.0` advisory closed shortly after.

### Added
- **KeePassXC-style top toolbar.** Action buttons used to live in two
  places: the SessionBar under the title (Sync / Lock / Logout) and
  the bottom of the VaultSidebar (Add / Import / Generator / Audit /
  Stats). They are now grouped into a single horizontal toolbar with
  three vertical-divider-separated sections. Buttons are icon-only
  with `title` + `aria-label` for tooltip / a11y; the live session-
  freshness dot and "il y a N min" label are tucked to the right
  edge of the bar.
- **Zebra-striped cipher list** with the Bitwarden / Vaultwarden blue
  palette (`#eaf2fc` / `#cfe0f5` / `#a8c8f0` in light mode, navy
  equivalents in dark). Stripes are driven by absolute row index
  rather than `:nth-child(even)` so they stay stable as the user
  scrolls the virtualised list.
- **Property-based tests on `EncString` parsing** (proptest, 64
  cases per property): the parser must never panic on arbitrary
  input, encrypt/parse/decrypt is the identity for any 0..512 byte
  payload, and any single-bit flip in IV / ciphertext / MAC must be
  caught by the HMAC. `proptest` is dev-only; release artefacts are
  unchanged.
- **E2E fixture matrix.** The seed binary now covers the canonical
  test matrix (more cipher types, folders, organisations) and
  provisions a secondary 2FA-enabled account so future 2FA-aware
  specs have something to log into.

### Changed
- **Recovery snapshots / op-log honesty.** `CRYPTO.md`,
  `THREAT_MODEL.md` and `AUDIT_SCOPE.md` used to describe the
  per-cipher pre-modification snapshots and folder-rename op-log
  written around destructive flows as a "crash recovery" mechanism,
  but nothing in the running app actually replays them: they are
  inserted, marked completed, and dropped on logout. The four
  mentions are now reworded as a write-only forensic trail useful
  for post-mortem analysis, with the gap called out explicitly so
  reviewers don't treat it as a mitigation.

### Internal
- E2E `lock-unlock` spec switched its lock-button selector from
  text-content match (`button=Verrouiller`) to `button[aria-label=
  'Verrouiller']`, since the toolbar button is now icon-only. More
  robust against future label changes too.
- Removed `truncate` and `formatExpiry` helpers (and their tests):
  they only existed to format the pre-alpha access-token / expiry
  debug strip in the SessionBar, which is gone.

## [0.1.10] — 2026-04-21

### Added
- **End-to-end test suite** driving the real Tauri binary via
  `tauri-driver` + WebdriverIO against a disposable Vaultwarden
  (Docker). Six specs cover the smoke pipeline, login with auto-sync,
  cipher creation, share-to-organization, lock/unlock round-trip, and
  idle auto-lock. Seed is a standalone Rust binary
  (`src-tauri/examples/e2e_seed.rs`) that reuses the production crypto
  (RSA-2048 keypair, AES-CBC+HMAC, HKDF) so any regression surfaces in
  the seed before hitting the UI tests. Wired into CI as a blocking
  check.
- **Post-login auto-sync** (Bitwarden-style): `loadCached()` paints
  the UI instantly from the encrypted local cache, then a background
  `sync()` reconciles against the server. A fresh profile used to land
  on an empty vault until the user hit *Sync* manually — now the
  ciphers appear on their own.
- **Session freshness indicator** in the session bar. Five states
  (`fresh`, `stale`, `syncing`, `offline`, `unknown`) with a live
  relative-time label that refreshes itself every minute. Logic
  extracted as a pure `computeSessionStatus` helper and covered by
  vitest.
- Root **`Makefile`** wrapping the CI checks so a single
  `make check-full` reproduces fmt + clippy + cargo test +
  svelte-check + vitest + the full E2E suite locally.
- **Security documentation** stack: `SECURITY.md`, `THREAT_MODEL.md`,
  `CRYPTO.md`, `AUDIT_SCOPE.md`. Report channels, disclosure
  expectations, assets and attacker model, crypto primitives and
  review checklist, prioritised scope for a future external audit.

### Changed
- The session lock primitives moved from `std::sync::Mutex` to
  `parking_lot::Mutex`. A panic inside one command handler used to
  poison the session mutex and make every subsequent command panic
  too, effectively locking the app until relaunch — the new primitive
  has no poisoning, so isolated failures stay isolated.
- The vault sidebar toolbar (`＋`, import, password generator, audit,
  stats) is now always visible. Previously it was gated behind "user
  has at least one folder or organization", which made it impossible
  to create a new item on a brand-new vault with only personal
  ciphers.
- `set_auto_lock_minutes` now accepts `f64` instead of `u32`, keeping
  the backend watchdog and the front-end `parseFloat`ed pref in sync
  for sub-minute values. Filtering uses `is_finite() && > 0` so NaN
  and infinities map to "disabled".
- HTML window title changed from the default SvelteKit template to
  *Clavix* — visible in the OS window chrome and task bar.

### Internal
- `build_share_cipher_body`, `validate_move_to_collection`, and
  `plan_folder_renames` extracted out of `commands/move_share.rs`
  orchestration and unit-tested. Rust test count rose from 71 to 101.
- `recover_refresh_token`, `compute_expires_at`, and
  `build_sync_summary` gained explicit coverage against their key
  selection and fallback rules.
- `setupAutoLock` extracted as a reusable Svelte 5 helper so the JS
  timer and the backend mirror no longer live inline in
  `+page.svelte` (332 → 303 lines).
- Vitest bumped 2.1.9 → 4.1.4, `@sveltejs/vite-plugin-svelte`
  5.1.1 → 7.0.0 (had to go together — vitest 2 could not consume
  plugin-svelte 7), `actions/upload-artifact` 4 → 7.

## [0.1.9] — 2026-04-19

### Added
- **WebAuthn / FIDO2 in 2FA** (provider 7). Clavix now drives a
  hardware security key directly over CTAP2/HID (YubiKey, SoloKey,
  …) — no browser involved. The `clientDataJSON` is built in Rust
  with `origin = https://{rpId}` so the authenticator's signature
  is accepted by Vaultwarden even though the app itself doesn't run
  under the vault's domain. Activates automatically when the server
  offers WebAuthn as a 2FA method. Closes the SSH-agent companion
  of issue #1.
- **Create and edit in an organization / collection**. The cipher
  editor gained an *Owner* selector (Personal / any org you belong
  to) and, for org items, a *Collection* picker. Backend splits
  into `POST /ciphers/create` (with org key and `collectionIds`)
  vs the existing `POST /ciphers` for personal items. Edits pick
  the right key from the item's current owner — changing owner in
  the editor is blocked, the share command handles that.
- **Import from KeePassXC** (CSV export). `📥` button in the tree
  toolbar opens a modal that parses the standard KeePassXC CSV
  columns (Title / Username / Password / URL / Notes / TOTP /
  Group), previews the first 15 rows, and imports the lot with an
  option to auto-create a folder per *Group* value.

### Security / CI
- `libudev-dev` added to the Ubuntu CI and release pipelines
  (needed by `hidapi` → `ctap-hid-fido2` on Linux). Previous
  `cargo clippy` failures were caused by this missing dep.
- Bumped `github/codeql-action` from v3 to v4: clears the
  deprecation warning for Node.js 20 and gets ahead of the CodeQL
  Action v3 deprecation scheduled for December 2026.

## [0.1.8] — 2026-04-19

### Added
- **SSH agent now signs RSA keys** (SHA-256 and SHA-512) on top of
  Ed25519. Vault-stored RSA private keys are parsed via `ssh-key` and
  signatures are produced with `rsa::pkcs1v15` under the right hash
  depending on the SSH agent `flags` field. ECDSA and DSA remain
  skipped for now.
- **Create and edit every cipher type** (Login, Secure Note, Card,
  Identity, SSH Key) from a single `CipherEditor` modal, with a
  cipher-type selector in create mode. Backend dispatches on
  `cipherType` via a unified `create_cipher` / `update_cipher` pair.
- **TOTP QR scanner** inside `CipherEditor`: a 📷 button opens the
  camera via `navigator.mediaDevices.getUserMedia` and fills in the
  TOTP field as soon as jsQR detects an `otpauth://` URI.
- **UI density pass**: bumped base font size back up, stopped
  truncating cipher list cells, and the detail panel is now
  resizable against the list via a vertical splitter (position
  persisted in `localStorage`).

### Security
- **Refresh token is encrypted at rest** under `user_key` (AES-CBC +
  HMAC-SHA256). A stolen `session.json` no longer hands an attacker a
  reusable OAuth2 credential without the master password. The legacy
  plaintext field is still read on unlock for a silent migration,
  then purged on the next save.
- **Backend auto-lock watchdog**: a tokio task polls every 30 s and
  drops the session + SSH agent once inactivity exceeds
  `auto_lock_minutes`. Safety net for when the JS timer is disabled
  or the WebView is frozen.
- **Share / folder-rename operation log** (`cipher_snapshots` +
  `folder_op_log` tables in the SQLite cache). A cipher is
  snapshotted before a cross-org share and marked completed on
  success; folder-rename batches log each row. Groundwork for a
  future replay / recovery flow.

### CI
- Rust fmt / clippy / audit re-enforced after the big refactor —
  caught formatting drift in `commands/cipher.rs` and `crypto.rs`.

## [0.1.7] — 2026-04-19

### Changed
- **Compact visual redesign**: reduced base font size (13.5 px),
  tighter paddings, flatter vault cards (hairline borders instead
  of box-shadow), alternating row stripes in the cipher list,
  inline single-line SessionBar. Inter for UI text; Atkinson
  Hyperlegible for data fields (inputs, passwords, URIs) so
  `0/O` and `l/1/I` are unambiguous.
- **Large refactor**: `+page.svelte` dropped from 3631 → 262 lines
  and `lib.rs` from 1310 → 47 lines. Domain code is now split into
  Svelte components (AuthLoginForm, UnlockForm, TwoFactorForm,
  SessionBar, VaultSidebar, CipherList, CipherDetail, *Dialog,
  ClipboardToast), `auth/vault/prefs` controllers in
  `.svelte.ts` files, and Rust modules under
  `src-tauri/src/{commands,services}/`.
- Styles moved to `src/styles/*.css`, imported from `+layout.svelte`.
- Vitest tests added for the pure TS helpers, plus Rust tests for
  folder-tree logic, both wired into CI.

### Performance
- Smoother folder-tree hover: `contain: content` on `.tree-pane`
  isolates repaints; removed an inherited global `filter:
  brightness` that was triggering tree-wide paints on hover.

### Security
- `esbuild` transitive dep pinned to `>= 0.25.0` via pnpm override,
  which clears GHSA-67mh-4wv8-2f99 (esbuild dev-server CORS). Only
  affects local `pnpm tauri dev`, never the shipped binary.

### CI
- Bumped `actions/checkout`, `actions/setup-node` and
  `pnpm/action-setup` to v6 (via Dependabot PRs).

## [0.1.6] — 2026-04-19

### Added
- **Access-token auto-refresh**: every API-hitting command now
  refreshes the OAuth2 access token 60 s before its expiry, so
  long-running sessions no longer silently 401.
- **Forced dark mode** in Preferences (Auto / Sombre). The toggle
  lives next to the language selector and is persisted to
  `localStorage`.
- **Security audit extended**: the 🛡 modal now also surfaces
  reused passwords (grouped by the ciphers sharing them) and weak
  passwords (zxcvbn score ≤ 2), in addition to HIBP breach hits.
  Detection happens fully locally; no additional data leaves the
  machine.

## [0.1.5] — 2026-04-19

### Added
- **SSH agent** (Linux / macOS) that exposes the Ed25519 SSH keys
  stored in your vault over a Unix socket at
  `$XDG_RUNTIME_DIR/clavix/agent.sock` (or the user cache dir as a
  fallback), with file mode `0600`. Toggle from the Preferences
  section of the Infos modal, then `export SSH_AUTH_SOCK=...` in
  your shell. Supports `SSH_AGENTC_REQUEST_IDENTITIES` and
  `SSH_AGENTC_SIGN_REQUEST`. The agent is automatically stopped on
  lock / logout. RSA and ECDSA keys are detected but skipped for
  now. Windows ships a stub that returns a "not supported yet"
  error (named pipes / Pageant in a future release).

## [0.1.4] — 2026-04-19

### Added
- **Live TOTP generation** in the detail panel: the stored secret is
  parsed (plain Base32 or `otpauth://` URI with custom period / digits /
  algorithm), and the 6-digit code is generated in the browser via Web
  Crypto, refreshed every second, with a countdown and a Copy button.
  Algorithm validated against the RFC 6238 test vectors.
- **Create and edit Login items**: new `＋` button in the tree toolbar
  opens a modal (`LoginEditor.svelte`) with fields for name, folder,
  username, password, URLs (one per line), TOTP secret, notes and the
  favorite flag, plus an inline password generator. The detail panel
  gets an "Edit" button on non-deleted Login items. Field encryption
  is performed client-side with the user key before the
  `POST /ciphers` or `PUT /ciphers/{id}` call.

### Security
- `.claude/` directory now in `.gitignore` (internal Claude Code files
  should never be versioned).

## [0.1.3] — 2026-04-19

### Added
- **Onboarding screen** on first launch, explaining what Clavix does and
  pointing to the alpha-stage disclaimer. Dismissed permanently once
  acknowledged (stored in `localStorage`).
- **Password security audit** via the Have I Been Pwned range API,
  using k-anonymity: only the first 5 hex characters of the SHA-1 hash
  ever leave your machine. Results listed per compromised item with a
  jump-to-item shortcut. Accessible from the shield button (🛡) in the
  tree toolbar.
- **Password generator** with configurable length, character classes
  and ambiguous-character filter (🎲 button in the tree toolbar).
- **Quick filter by cipher type** (Login / Note / Card / Identity /
  SSH) in the sidebar, with per-type counts.
- **Trash actions**: restore a deleted item or permanently delete it
  from the detail panel.
- **YubiKey OTP support** as a 2FA provider (provider 3): a dedicated
  input captures the 44-character Modhex code and auto-submits once
  the YubiKey has finished typing it. If the server offers both TOTP
  and YubiKey, a method picker is shown.

### Security
- Activated Dependabot alerts, Dependabot security updates, secret
  scanning and push protection on the public repository.
- Added a CodeQL workflow running on every push, PR and weekly schedule
  for JavaScript/TypeScript analysis.
- `cookie` transitive dep pinned to `>= 0.7.0` via a pnpm override
  (fixes GHSA-pxg6-pf52-xh8x).

### Changed
- The onboarding screen lives in its own component
  (`src/lib/Onboarding.svelte`), a first step towards splitting the
  large `+page.svelte` into smaller units.
- Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub issue and pull
  request templates, and a Dependabot config for routine dependency
  updates.

## [0.1.2] — 2026-04-19

### Added
- **Multilingual UI** (Français + English) via `paraglide-js`. Language
  is detected from the browser at first launch, persisted in
  localStorage, and switchable from the vault Infos modal.
- **Translated error messages**: every backend error code
  (`invalid_url`, `auth_failed`, `network_error`, etc.) is rendered
  through the i18n table instead of the raw English fallback.
- **Favorites** and **Trash** quick filters in the sidebar, with
  counts. Deleted items (soft-delete via `deleted_date`) are now
  visible in the Trash view and hidden from all other views.
- **Sortable columns**: click Name / Username / URL headers to sort
  ascending or descending, with a visual indicator.
- **Username and URL columns** in the cipher list, with responsive
  breakpoints.
- Search now matches across name, username and URL (not just name).

### Changed
- `svelte-check` in CI now compiles Paraglide first (messages JSON →
  `src/lib/paraglide/`).
- CI release matrix targets Ubuntu, macOS and Windows. `v0.1.1` only
  shipped Linux; `v0.1.2` ships all three.

## [0.1.1] — 2026-04-19

### Added
- **Detail panel for all cipher types**: cards, identities and SSH keys now
  show decrypted fields with masking on sensitive ones (card number, CVV,
  SSN, SSH private key) and one-click copy to clipboard.
- **KeePassXC-style keyboard shortcuts**: `Ctrl+C` / `Ctrl+B` / `Ctrl+U` for
  copying password / username / opening the URL of the focused item,
  `Ctrl+L` to lock, `Ctrl+F` or `/` to focus the search, `Escape` to close
  the detail panel.
- **Auto-lock on inactivity**, configurable from the vault Infos modal
  (Never / 1 / 5 / 10 / 15 / 30 min / 1 h). Setting persisted to
  localStorage. Default: 10 minutes.
- **List columns**: username and URL are now visible next to each cipher
  name, with responsive breakpoints that hide columns on narrow windows.
- macOS and Windows added to the release matrix (will take effect from
  the next tag; `v0.1.1` is still Linux-only).

### Changed
- **Virtualised cipher list**: only the items currently visible are rendered
  in the DOM, saving memory and making scroll fluid on large vaults.
- **Debounced search** (150 ms) to avoid re-filtering on every keystroke.
- **Parallelised vault decryption** in the Rust backend via `rayon`: sync
  and cache load are now noticeably faster on multi-core machines.
- **Tree counts** are computed in O(1) per node from a pre-built
  HashMap index, instead of re-scanning all ciphers per node.

### Fixed
- `folderId` was not being cleared when sharing a personal item to an
  organization, leaving a stale folder path visible on the official iOS
  client. It is now forcefully `null`-ed during a share.

## [0.1.0] — 2026-04-19 (initial release)

### Added
- Login against a self-hosted Vaultwarden instance (custom URL).
- Master password unlock with both PBKDF2 and Argon2id KDFs.
- TOTP 2FA challenge handling.
- Full vault sync: items, folders, collections, organizations.
- Client-side decryption: AES-256-CBC + HMAC-SHA256 for the personal vault,
  RSA-OAEP-SHA1 for organisation keys.
- Encrypted local SQLite cache for instant offline reads after unlock.
- Hierarchical tree view built from the Bitwarden `/` naming convention
  (personal folders + organisation collections), with a resizable
  splitter.
- Item detail for logins (username, hidden password with show/copy,
  URLs, TOTP secret, notes), clipboard auto-clear after 30 s.
- Item favicons fetched via the Vaultwarden icon service, with an emoji
  fallback per type (🔐 / 📝 / 💳 / 🪪 / 🔑).
- Drag and drop:
  - item onto a folder;
  - item onto an organisation collection (same organisation: move;
    personal → organisation or cross-org: re-encrypted share);
  - folder onto another folder, with cascade rename of sub-folders on
    the server.
- Persisted session on disk at `~/.local/share/clavix/`, with an Unlock
  screen that skips the 2FA and refreshes the OAuth token.
- GitHub Actions CI (`fmt`, `clippy`, `cargo audit`, `svelte-check`) and
  release workflow that bundles `.AppImage`, `.deb` and `.rpm`.

[0.1.9]: https://github.com/Upellift99/clavix/releases/tag/v0.1.9
[0.1.8]: https://github.com/Upellift99/clavix/releases/tag/v0.1.8
[0.1.7]: https://github.com/Upellift99/clavix/releases/tag/v0.1.7
[0.1.6]: https://github.com/Upellift99/clavix/releases/tag/v0.1.6
[0.1.5]: https://github.com/Upellift99/clavix/releases/tag/v0.1.5
[0.1.4]: https://github.com/Upellift99/clavix/releases/tag/v0.1.4
[0.1.3]: https://github.com/Upellift99/clavix/releases/tag/v0.1.3
[0.1.2]: https://github.com/Upellift99/clavix/releases/tag/v0.1.2
[0.1.1]: https://github.com/Upellift99/clavix/releases/tag/v0.1.1
[0.1.0]: https://github.com/Upellift99/clavix/releases/tag/v0.1.0
