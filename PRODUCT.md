# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users today: technical self-hosters who run their own Vaultwarden instance, often coming from KeePassXC, who use `ssh` and `git` daily and want a dense, fast vault with a real folder tree.

Later, in this order and only if the project matures: non-technical household members sharing the same vault (clarity over density), then small teams and organizations working mainly through Vaultwarden organizations and collections.

## Product Purpose

Clavix is a desktop client for Vaultwarden and Bitwarden, an alternative to the official Electron client and to Keyguard. It exists to give the self-hosted community the comfortable tree-based vault with drag and drop that KeePassXC has offered for years. Success means a self-hoster can leave KeePassXC without losing their habits: hierarchy, keyboard speed, SSH agent, local-first unlock.

Status: alpha, read+write. The cryptography has not been independently audited and the README tells users not to point it at a real vault yet.

## Positioning

The only Vaultwarden client with a true hierarchical tree (derived from the Bitwarden `/` folder naming convention) that supports drag and drop of items and whole folders, including personal to organization transfers with re-encryption. Also: an embedded SSH agent on every platform, FIDO2 unlock without the master password, and password strength scored in Rust so a still-masked password can be rated without crossing the IPC boundary.

## Operating Context

- Usage scenes, confirmed: a full-screen or large window where tree, list and detail sit side by side; brief openings from the system tray to copy a password or TOTP code and close again; and long unattended background sessions serving `ssh` and `git` through the SSH agent. The default window is 800x600 with no minimum size enforced.
- Desktop only: Linux (primary dev environment, GNOME), macOS and Windows, inside a native WebView via Tauri 2. Light and dark follow the OS (`prefers-color-scheme`).
- Locales: French is the base locale, English is the second; all UI copy lives in `messages/{fr,en}.json` via Paraglide.
- Works against a live Vaultwarden server, against the encrypted offline cache in read-only standalone mode when the server is unreachable, and against an encrypted backup file with no server and no account.
- Clipboard auto-clears after 30 seconds; the vault auto-locks after an idle window and may lock while a user is mid-task.
- Items come from Bitwarden imports, KeePassXC imports and manual creation, so names, URLs and notes can be long, nested or missing.

## Capabilities and Constraints

- Login with email + master password, PBKDF2 and Argon2id, full 2FA (TOTP, YubiKey OTP, WebAuthn/FIDO2 driven over CTAP2/HID by Clavix itself).
- Unlock screen on restart, optional FIDO2 unlock, master password always accepted as fallback.
- Full sync of items, folders, collections and organizations, decrypted client-side; background sync every 30 minutes (configurable).
- Create, edit, delete logins, secure notes, cards, identities and SSH keys; attachments, custom fields and password history.
- Tree view with resizable splitter, drag and drop of items and folders, right-click rename and delete with cascade.
- Live TOTP, QR scanning via camera, favicons with emoji fallback per type.
- Password generator with exact entropy in bits; zxcvbn score in editor and detail view; security audit combining HIBP k-anonymity with local reused and weak detection.
- KeePassXC CSV and KDBX import; encrypted backup export and emergency restore.
- Embedded SSH agent (Unix socket, Windows named pipe and Pageant IPC).
- Technical constraints: Svelte 5 + TypeScript + Vite frontend, Rust backend, no Bitwarden SDK (license), GPL-3.0-or-later. IPC types are generated from Rust with ts-rs (`pnpm run bindings`). Every string must go through Paraglide messages.
- Terminology: Vaultwarden terms are kept (vault, item/cipher, folder, collection, organization, master password, unlock vs login). French UI calls the preferences dialog "Préférences" and the about dialog "Infos".
- Explicitly undecided: whether non-technical users and organizations become first-class audiences; nothing in the product should block them, nothing should be optimized for them yet.

## Brand Commitments

- Name: Clavix. Logo: `assets/clavix-logo.svg`. Website: clavix.org (separate repo, clavix-website).
- Undecided: whether the website's visual design is binding on the application. Until decided, the app follows its own desktop conventions and shares only the name and logo with the site.
- Readability commitment: the owner chose Atkinson Hyperlegible for the auth screens and for data fields so that usernames and passwords read unambiguously (no confusable glyphs). This is a deliberate product decision about reading secrets, not a formal accessibility standard, and future work must preserve it wherever a secret or identifier is displayed.

## Evidence on Hand

- Real feature set documented in `README.md`; threat model in `THREAT_MODEL.md`; crypto notes in `CRYPTO.md`; manual QA scripts in `MANUAL_VALIDATION.md`.
- E2E suite in `tests/e2e` drives the real Tauri binary against a Dockerized Vaultwarden; failure screenshots land in `tests/e2e/screenshots/` (gitignored, two local captures from April 2026).
- No testimonials, customer logos, benchmarks or press. Do not fabricate any. The README itself carries an alpha warning and an AI-assistance disclosure (`DISCLAIMER.md`).

## Product Principles

1. Secrets must be read correctly the first time: identifiers and passwords are displayed in a confusable-free data font, masked by default, copied in one action, and cleared from the clipboard automatically.
2. Hierarchy is the product: the folder tree, drag and drop and keyboard navigation get the density and precision a KeePassXC user expects before anything else gets room.
3. Fast in, fast out: a tray opening to copy one code must take seconds, so search, selection and copy are reachable without a mouse.
4. Never lie about state: locked, syncing, offline read-only, standalone backup, unaudited alpha are all states the UI names plainly.
5. Honor the three usage scenes together: a large side-by-side window, a brief tray popup, and a long unattended background session with the SSH agent.

## Accessibility & Inclusion

No formal standard is targeted yet. Confirmed requirement: maximum legibility of usernames and passwords (Atkinson Hyperlegible on auth screens and data fields, ~10% larger auth form sizing for fatigue and dim light). Light and dark themes must both hold that bar.
