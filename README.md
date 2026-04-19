# Clavix

**A modern desktop client for Vaultwarden and Bitwarden.**

Clavix is an alternative to the official Bitwarden client and Keyguard,
built for the self-hosted Vaultwarden community. The goal: finally
provide a comfortable tree-based vault with drag & drop, the way
KeePassXC has offered for years.

> **Status: work in progress.** No usable release has shipped yet,
> but the read-only MVP is functionally complete: login, 2FA, sync,
> full decryption, tree navigation, drag & drop, offline cache.

## What Clavix can do today

Against a real Vaultwarden instance, Clavix already:

- signs you in (email + master password, PBKDF2 and Argon2id KDFs);
- handles a TOTP 2FA challenge;
- **persists the session locally** under `~/.local/share/clavix/` —
  on restart you land on an *Unlock* screen that only asks for the
  master password (no 2FA again, OAuth2 token refreshed
  automatically);
- syncs the full vault (items, folders, collections, organizations);
- **decrypts everything client-side**: AES-256-CBC + HMAC-SHA256 for
  the personal vault, RSA-OAEP-SHA1 for organization keys;
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
- shows item details: username, hidden password, URLs, notes. The
  *Copy* button places the value on the clipboard and **automatically
  clears it after 30 seconds**;
- **drag & drop items** onto folders or organization collections —
  including personal → org (automatic share + re-encryption),
  cross-org transfer (re-encryption from source to target org key)
  and all cipher types (logins, secure notes, cards, identities,
  SSH keys);
- **drag & drop whole folders** to rearrange the tree — all their
  sub-folders are renamed in cascade on the server.

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
- [x] TOTP 2FA
- [x] Initial sync: items, folders, collections, organizations
- [x] Decrypt names and fields (AES-CBC + HMAC, RSA-OAEP)
- [x] Persisted session on disk + *Unlock* screen
- [x] Full list with live search
- [x] Item details + clipboard copy with 30 s auto-clear
- [x] Encrypted local cache (offline read-only mode)

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

### Planned (tracked as issues)

- 🔑 **[YubiKey / WebAuthn 2FA](https://github.com/Upellift99/clavix/issues/1)**
  — handle the FIDO2 challenge during login so users who secured their
  Vaultwarden account with a hardware key can sign in with Clavix.
- 🔐 **[SSH agent mode](https://github.com/Upellift99/clavix/issues/2)**
  — expose the SSH keys stored in the vault over a Unix socket so
  `ssh`, `git`, `scp` etc. can use them without writing the private
  key to disk, the same way Bitwarden Desktop now does.

### Out of MVP scope

Creating/editing/deleting items, password generation, attachments,
Sends, passkeys, browser autofill, KeePass import (phase 5+).

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
  build-essential curl wget file
```

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

## Repository layout

```
clavix/
├── src-tauri/        Rust backend (Tauri)
│   └── src/
│       ├── main.rs       Binary entry point
│       ├── lib.rs        Tauri commands exposed to Svelte
│       ├── api.rs        Vaultwarden HTTP client
│       ├── crypto.rs     Key derivation, EncString (AES / RSA),
│       │                 encrypt/re-encrypt for server updates
│       ├── models.rs     API types and DTOs sent to the UI
│       ├── state.rs      AppState (in-memory session + keys)
│       ├── store.rs      On-disk session persistence
│       ├── cache.rs      Encrypted SQLite vault cache
│       └── error.rs      Unified Error type, serialized as
│                         { code, message, data }
├── src/              SvelteKit frontend (static output, no SSR)
│   ├── app.html
│   └── routes/
│       ├── +layout.ts
│       └── +page.svelte  Single screen for now
├── .github/workflows/ci.yml   CI (fmt, clippy, cargo audit,
│                               svelte-check)
└── CLAUDE.md         Project context for pair programming
```

As the app grows, `src/routes/+page.svelte` will be split into
components under `src/lib/components/` and stores under
`src/lib/stores/`.

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
  stay encrypted by the stretched master key; only the OAuth2 refresh
  token lives there in clear — Clavix thus assumes your user disk is
  under your control (full-disk encryption such as LUKS is
  recommended).
- Clavix is primarily tested against **Vaultwarden**. Official
  Bitwarden compatibility is a bonus, not a guarantee.

Vulnerabilities should be reported privately to the maintainer before
any public disclosure.

## Quality / CI

Every push and pull request against `main` or `master` triggers a
GitHub Actions workflow that runs:

- `cargo fmt --check` — Rust style.
- `cargo clippy --all-targets -- -D warnings` — strict lint.
- `cargo audit` — vulnerability scan on dependencies
  (RUSTSEC-2023-0071 on the `rsa` crate is ignored, see the comment
  in `.github/workflows/ci.yml`).
- `pnpm check` (svelte-check) — TypeScript / Svelte typing.

Tauri system libraries are installed on every run; the `target/`
cache is handled by `Swatinem/rust-cache`.

## Contributing

The project is at an early stage and the architecture still moves
around. Issues and suggestions are welcome; pull requests will be
opened once the first usable release ships (phase 1 complete).

## License

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).
