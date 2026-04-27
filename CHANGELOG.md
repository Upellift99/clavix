# Changelog

All notable changes to Clavix are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.20] — 2026-04-27

### Added
- **Yubikey re-unlock with FIDO2 hmac-secret.** After a normal
  master-password sign-in, the user can release the cached user key
  by touching a registered FIDO2 token instead of re-typing the
  password. Conceptually the same flow as Bitwarden Web's "PRF
  Unlock"; under the hood we register a non-resident credential
  with the CTAP2 `hmac-secret` extension turned on, derive a wrap
  key via HKDF-SHA256 from the per-credential PRF output, and wrap
  the 64-byte user key under it using the existing AES-256-CBC +
  HMAC-SHA256 EncString primitive (same code path the rest of the
  app already runs through). The wrap, the per-credential salt, the
  credential id and a 16-byte HKDF fingerprint of the user key live
  in `session.json`; the wrap key never touches disk. Stale-wrap
  detection: rotating the master password on another client
  invalidates the fingerprint, the unlock command drops the wrap
  and surfaces a clear "re-enrol after sign-in" message instead of
  handing back a key the server no longer accepts. Three new Tauri
  commands (`enroll_yubikey_unlock`, `unlock_with_yubikey`,
  `disenroll_yubikey_unlock`) plus `yubikey_unlock_state` for the
  unlock view to know whether to render the touch button. UI lives
  in Préférences (enrol / disenrol with explicit threat-model
  warning, master-password confirmation required to disenrol) and
  on the unlock view (touch button next to the password field, PIN
  input for tokens with one set). The full design + threat-model
  addendum landed in `YUBIKEY_UNLOCK.md` and `THREAT_MODEL.md`
  ahead of any code; CTAP I/O sits behind a `FidoDevice` trait so
  the crypto path is fully covered by unit + property tests
  without a real authenticator on the runner.
- **Right-click delete + rename on personal folders.** Vaultwarden's
  web UI doesn't expose a folder-delete control today (upstream
  Bitwarden does — looks like a regression), so for users with
  cluttered or duplicate folders Clavix is now the only path. Right-
  click on a folder leaf in the sidebar pops up a small menu with
  Rename and Delete; rename is an inline editable input, delete
  confirms before firing and matches Bitwarden semantics (ciphers
  detach to "no folder", they are not cascade-deleted). Two new
  Tauri commands (`delete_folder`, `rename_folder`) wrap the
  pre-existing HTTP layer in `api.rs`; both update the in-memory
  vault in lockstep so the sidebar reflects the change without a
  full re-sync. New E2E spec `folder-rename-delete.spec.mjs`
  exercises both commands through the IPC layer (mirrors the
  cascade spec — synthetic right-click under WebDriver is too
  brittle, the menu's only job is to call these handlers anyway).
- **"Mon coffre" header** above the personal folder tree, mirroring
  the existing "Organisations" h4 — clearly separates personal
  items from shared org items at a glance.

### Fixed
- **Same-name folders no longer collapse into one sidebar entry.**
  `insertIntoTree` matched leaves by label, so two server-side
  folders named "Finance" merged into a single node and the second
  silently rewrote the first's `folderId` — every cipher in folder
  #1 disappeared from the tree (the count was still right under
  "All items", but you couldn't filter to it). The fix keeps merging
  *synthetic-parent* nodes (so "work/a" and "work/b" still hang
  under one shared "work" ancestor) but creates a sibling when two
  real folders share a path. Disambiguator suffix on the colliding
  React-style key keeps Svelte happy without polluting the natural
  path key for the common single-folder case;
  `folderPathFromKey` strips the suffix back so drag-drop and
  `move_folder_path` continue working unchanged. New tests cover
  the duplicate cases.

## [0.1.19] — 2026-04-26

### Added
- **CSV export** matching Bitwarden Desktop's column set
  (`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`),
  so the resulting file imports directly back into Bitwarden if you
  decide to migrate elsewhere. Toolbar gets a new upload-arrow button
  next to import; the dialog shows live counts per type, lets you
  toggle Logins / Secure Notes independently, displays a warning
  banner about plaintext-on-disk, and triggers the download via a
  Blob URL named `clavix-export-YYYY-MM-DD.csv`. Cards, Identities,
  SSH keys and trashed items are skipped — same as Bitwarden's own
  CSV export — since the column schema doesn't carry their fields.
  New `csv.ts` helpers: `escapeCsvField` and `serializeBitwardenCsv`,
  both covered by vitest including a CSV roundtrip via `parseCsv`.
- **Generate an Ed25519 SSH key from the cipher editor.** When you
  open a new SSH-key cipher and the private-key field is still empty,
  a "Générer une clé Ed25519" button shows up above the textarea —
  one click runs `ssh_key::PrivateKey::random` server-side and fills
  privateKey + publicKey + keyFingerprint with a fresh OpenSSH PEM,
  ssh-ed25519 line and SHA-256 fingerprint. The key is generated
  in the Rust process, never touches disk, and lands directly in
  the cipher (which is then encrypted under the master key like any
  other field). RSA generation can come later as an algorithm
  parameter; users with infra requiring RSA can paste an existing
  key for now. New Tauri command `generate_ssh_key`.
- **Detailed SSH agent panel.** The agent section in Préférences now
  lists every exposed key by comment + algorithm + truncated SHA-256
  fingerprint (full hash on hover via `title`), so you can tell at a
  glance which keys `ssh-add -l` will surface. Below it, a
  `<details>` summary shows skipped keys with a per-key reason —
  ECDSA/DSA unsupported algorithm, leftover passphrase-encrypted PEM
  pre-dating the import-time decrypt flow, malformed key, etc. A new
  `ssh_auth_sock` Tauri command reads the `SSH_AUTH_SOCK` env var so
  the dialog can show "✓ pointe sur Clavix", "pointe ailleurs" or
  "non définie" inline next to the socket path. The `SshAgentStatus`
  shape now carries `keys: ExposedKey[]` and `skipped: SkippedKey[]`
  instead of the previous opaque counts.

## [0.1.18] — 2026-04-26

### Added
- **SSH passphrase prompt at cipher import.** When you paste a
  passphrase-protected OpenSSH private key into the cipher editor,
  Clavix now asks for the passphrase, decrypts the PEM client-side,
  and stores the cleartext key inside the cipher (which itself stays
  encrypted at rest under the master key). Same model as Bitwarden
  Desktop's `import_key`: the passphrase is consumed once and never
  stored. Public key and SHA-256 fingerprint are auto-filled when
  empty. ECDSA / DSA inputs are rejected up front before any
  passphrase prompt, so you don't type a passphrase for nothing.
  New Tauri command `decrypt_ssh_private_key` with typed errors
  `ssh_passphrase_required` and `ssh_wrong_passphrase`. Closes the
  silent-skip behaviour where `start_ssh_agent` would just bump
  `skipped_count` for any encrypted key in the vault.

### Tests
- **End-to-end SSH passphrase import spec**
  (`tests/e2e/specs/ssh-passphrase-import.spec.mjs`). Drives the new
  prompt through the real Tauri WebView: generates a fresh
  passphrase-protected ed25519 key (and a no-passphrase ECDSA key)
  via `ssh-keygen` in the `before` hook, opens the cipher editor,
  asserts the passphrase prompt appears, that a wrong passphrase
  surfaces "Phrase de passe incorrecte." inline without closing
  the editor, that the correct passphrase saves a cipher whose
  `keyFingerprint` is auto-filled with `SHA256:…` and whose
  `privateKey` is the cleartext PEM (no `ENCRYPTED` marker), and
  that an ECDSA paste fails fast in the main editor error line
  without ever rendering the passphrase prompt.

## [0.1.17] — 2026-04-25

### Fixed
- **No more global window scroll.** The default user-agent
  `<body>` margin (8 px top + 8 px bottom) was overflowing every
  `100vh` layout by exactly 16 px, producing a permanent vertical
  scrollbar regardless of window size or content. Reset
  `html`/`body` margins to 0, locked `body { overflow: hidden }`,
  and switched `.container.wide` from `100vh` to `100%`. Inner
  panes (folder tree, cipher list, detail panel, dialogs) keep
  their own `overflow: auto`, so long content still scrolls
  inside its panel — only the chrome can no longer scroll.

### Changed
- **Cleaner main view chrome.** Removed the redundant
  `<h1>{m.app_name()}</h1>` page title — the OS window chrome
  already shows the app name, and the duplicate was wasting
  vertical space on the 800×600 default window.
- **Tighter cipher detail values.** `.value` rows now use
  `flex: 0 1 auto` instead of `flex: 1 1 auto` so action buttons
  (copy / show / hide) sit snug against the value text instead
  of being pushed to the panel's right edge.

### Tests
- **TOTP 2FA spec stability.** `login-totp.spec` now waits one
  extra step before submitting the 2FA code, eliminating a race
  where the form was being submitted before the WebView had
  finished swapping to the 2FA prompt.
- **Smoke spec re-anchored to `main.container`.** Following the
  `<h1>` removal above, `tests/e2e/specs/smoke.spec.mjs` now
  asserts on the Svelte-injected `<main class="container">`
  element. Same anti-blank-window guarantee (the static
  `app.html` body is an empty wrapper, so this node only exists
  post-hydration), no app-code change needed.

### Tooling
- **Manual Linux dev-build workflow.**
  `.github/workflows/dev-build.yml`, triggered via
  `workflow_dispatch`, builds an `.AppImage` on a GitHub runner
  and uploads it as a 14-day artifact. Lets contributors test
  changes on a real Tauri build without running `tauri dev`
  locally — the parallel Rust + Vite + WebView pipeline is too
  heavy on lower-RAM machines.

## [0.1.16] — 2026-04-25

### Added
- **Project logo.** Replaces the Tauri default with a Clavix mark
  — a wide white "C" whose right-hand opening carries two short
  horizontal teeth (a key bow), painted on a Bitwarden-blue
  rounded square that matches the in-app accent. Source SVG
  lives at `assets/clavix-logo.svg`; `scripts/regen-icons.sh`
  rasters every PNG / ICO / ICNS Tauri ships with.
- **Inline SVG icons** across the toolbar, cipher list, sidebar
  and detail panel, replacing the previous emoji set. Lucide-
  style geometry, monochrome, inheriting `currentColor`. Fixes
  the rendering inconsistency between Linux GTK / macOS / Windows
  emoji stacks.
- **Restructured `CipherDetail` panel.** Fields are now grouped
  into typed sections (Identifiants / URLs / Sécurité / Carte
  bancaire / Identité / Clé SSH / Notes) with small uppercase
  headers and a consistent label-vs-value grid. Verbose
  Copier / Afficher / Masquer word buttons collapse into icon-
  only marks (copy / eye / eye-off) with title + aria-label, same
  hit area as the toolbar buttons.
- **Empty states** with a large icon, title, body and CTA, on the
  cipher list (no search match → "Effacer la recherche" button;
  empty folder → guidance to create or import).
- **Subtle motion**: 100 ms fade on cipher-row hover/selection
  (no more snap-flash) and 140 ms fade-up on the detail panel
  when it mounts.

### Security
- **In-flight 2FA login state is parked Rust-side.** New
  `PendingTwoFactor` slot in `AppState` carrying server_url,
  email, master_key, password_hash, prelogin and client. Derives
  `ZeroizeOnDrop`. `webauthn_sign_challenge` and
  `login_with_two_factor` now read from this slot rather than
  re-receiving the same values from the renderer between calls.
  A compromised JS layer can no longer swap the rpId anchor or
  the master key between `login()` and the second-factor IPC.
  5-minute TTL on the slot. Closes the gap noted in #21.

### Tests
- **TOTP 2FA E2E spec** (`login-totp.spec`) walks the full second-
  factor login against the seeded `e2e-2fa@clavix.test` account.
  Pure-Node RFC 6238 helper (~25 lines, no `otplib` dep).
- **Rust integration tests** for the session-lifecycle pieces
  that don't fit a WDIO spec: `refresh_token_endpoint.rs` mocks
  `/identity/connect/token` and asserts the form payload + the
  400 → AuthFailed mapping; `persisted_session_disk.rs` covers
  the save / load / clear round-trip and the legacy-plaintext
  refresh-token recovery in an XDG_DATA_HOME tempdir.
- Six new E2E specs are now actively running again after #25
  landed: cipher-types, delete-restore, edit-cipher, folder-
  cascade, logout, permanent-delete. The suite stands at 13
  specs.

### Changed
- **Per-spec Vaultwarden reset** in `wdio.conf.mjs` (gated
  behind `E2E_PER_SPEC_RESET=1`, set in CI). docker-compose-down
  + up + reseed before each spec so cumulative state can't make
  late-position specs hang in `socket hang up`. Adds ~3 minutes
  to the suite, removes the position-dependent flake entirely.
- **Strict-exact-match WebAuthn rpId** (continued from 0.1.12 —
  the 0.1.11 implementation accepted any DNS suffix).
- `delete_folder` was added to `VaultwardenClient` for future
  per-account teardown helpers.

### Tooling
- `mockito`, `tempfile`, `tokio` (test feature) added as Rust
  dev-dependencies for the new integration suite.

## [0.1.15] — 2026-04-25

### Added
- **Trash bucket workflow.** `soft_delete_cipher` (PUT
  `/api/ciphers/{id}/delete`) sends a cipher to the server's trash
  with `deletedDate` stamped; `restore_cipher` clears it again. The
  cipher detail panel now shows a "Supprimer" button on a normal
  item (alongside "Éditer"); a trashed item still gets the existing
  "Restaurer" / "Supprimer définitivement" pair. Before this
  release Clavix could only hard-delete (DELETE) — items only ever
  reached the trash if a different client put them there.
- **User-pickable visible columns on the cipher list.** The
  Identifiant and URL columns are now hideable per user preference
  (Type icon and Name stay always-on). Choice is persisted in
  `localStorage` under `clavix.visibleColumns`. Native
  `<details>/<summary>` popover anchored to the leftmost header
  cell — click-outside-to-close, ESC-to-close and tab-trapping
  come for free without a popover library.

### Changed
- **Cipher list polish**:
  - Searching no longer leaves a tall blank band at the top of the
    virtualised list. Filter shrinks `items.length`, scrollTop is
    clamped to the new content range so the rendered slice stays
    within the viewport.
  - Rows paint flush edge-to-edge: the `<li>` is `align-items:
    stretch`, the `<button>` is `height: 100%`, no more thin white
    sliver above and below each row.
  - Hover and selected states pulled up two notches in saturation
    so they're clearly distinct from the zebra background. Same
    treatment in dark mode and on the tree view.
  - Identifiant and URL columns rendered at `0.82em`, smaller than
    the name column. Bump them (and the name) so all three text
    columns read at roughly the same size.

### Tests
- Three new E2E specs: `logout.spec` (asserts session.json
  cleared, AuthGate re-renders the login form not the unlock
  form), `edit-cipher.spec` (UI-driven rename round-trip), and
  `delete-restore.spec` (soft delete → trash → restore). Brings
  the E2E suite from 6 specs to 9.

### Internal
- The previous CI run shipped a self-inflicted regression where
  `delete-restore.spec` called `delete_cipher` (hard delete)
  thinking it was soft, wiping the seed for every spec that ran
  after it (six in a row failed). The new soft-delete plumbing
  fixes the root cause; the spec now uses `soft_delete_cipher`
  with a comment that calls out the trap explicitly.

## [0.1.14] — 2026-04-25

### Fixed
- **Blank window on Linux desktops where the running user is not in
  the `render` group.** Ubuntu 24.04 ships WebKit2GTK 4.1 with the
  DMABUF renderer enabled by default; that renderer needs to allocate
  GBM buffers through `/dev/dri/*`, which fresh installs gate behind
  the `render` (or sometimes `video`) group. Users who weren't added
  to that group saw exactly one symptom: a blank window. The
  underlying message
  `KMS: DRM_IOCTL_MODE_CREATE_DUMB failed: Permission denied` only
  showed up when launching from a terminal — invisible to anyone
  starting Clavix from the desktop launcher.

  This was the actual cause behind the 0.1.11/0.1.12/0.1.13 "blank
  window" reports. The CSP fixes in 0.1.12/0.1.13 were correct and
  necessary on their own merits but they were chasing the wrong
  bug — the .deb didn't paint anything regardless of the policy.

  Set `WEBKIT_DISABLE_DMABUF_RENDERER=1` from `main.rs` before
  starting the Tauri runtime so WebKit falls back to the non-DMABUF
  compositor. The fallback's perf cost is negligible for a CSS-only
  UI like Clavix's (no canvas, no animation). Power users with a
  working DMABUF stack can opt back in by exporting
  `WEBKIT_DISABLE_DMABUF_RENDERER=0` before launching.

## [0.1.13] — 2026-04-25

### Fixed
- **Blank window in `0.1.12.deb` (and 0.1.11.deb).** The
  `'unsafe-inline'` mitigation in 0.1.12 was a non-fix: Tauri 2
  injects its own nonce into `script-src` at runtime (the
  `__TAURI_SCRIPT_NONCE__` placeholder is visible in the binary
  strings), and CSP3 says the presence of a nonce in a directive
  causes `'unsafe-inline'` to be ignored. So the SvelteKit
  bootstrap (which has neither nonce nor hash) was still blocked.
  Cause was identified by inspecting the actual `.deb` and the
  CSP3 spec — there was nothing wrong with the build.

  The real fix is hash-based: `svelte.config.js` now uses
  `kit.csp.mode = "hash"`, which makes SvelteKit emit a
  `<meta http-equiv="content-security-policy">` listing the
  exact SHA-256 of every inline script it generated. The CSP
  permits exactly that script and nothing else inline. Hashes
  are recomputed on every build so chunk-name churn is
  invisible. `tauri.conf.json` sets `"csp": null` so Tauri does
  not re-inject its own conflicting policy.

### CI
- **`smoke-release` job** rebuilds in release and runs only
  `smoke.spec` against the production binary. v0.1.11/0.1.12
  shipped blank-window `.deb`s because the existing E2E job runs
  `pnpm tauri build --debug`, where the release CSP isn't
  enforced. The new job (cached separately, `key: release`) is
  the floor: any future CSP / hydration regression that would
  ship a blank `.deb` now turns CI red on the PR.
- **`smoke.spec`** no longer asserts on "body has any text" — that
  was a false positive on the 0.1.11/0.1.12 case because the
  inline `<script>` and `<link rel=modulepreload>` tags can
  register as text under some WebDriver implementations even when
  the JS never runs. It now checks the post-hydration
  `<h1>Clavix</h1>`, which only exists if Svelte actually
  rendered.
- **`wdio.conf.mjs`** is now parametric: `E2E_BUILD_PROFILE`
  picks `target/debug` vs `target/release`, `E2E_SKIP_SEED=1`
  skips Vaultwarden Docker + the Rust seed for jobs that don't
  need them. Default behaviour unchanged.

### Documentation
- The `MANUAL_VALIDATION.md` rpId-mismatch step quotes the new
  strict-match error message text.

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
