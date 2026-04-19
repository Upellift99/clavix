# Changelog

All notable changes to Clavix are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.1]: https://github.com/Upellift99/clavix/releases/tag/v0.1.1
[0.1.0]: https://github.com/Upellift99/clavix/releases/tag/v0.1.0
