# Threat Model

This document describes the security goals and assumptions of Clavix as
it exists today. It is not a proof of security. It is a map for code
review, design discussion, and future hardening work.

## Security Goals

Clavix aims to:

- authenticate to Vaultwarden / Bitwarden-compatible servers without
  sending the master password in clear text
- decrypt and encrypt vault data client-side
- keep sensitive long-lived material encrypted at rest on disk
- auto-lock and drop in-memory session state after inactivity
- support organization items and re-encryption flows without leaking
  plaintext to the server
- expose SSH private keys to local SSH clients without writing those
  private keys to standalone PEM files on disk

## Assets to Protect

Primary assets:

- master password
- derived master key
- user symmetric key
- decrypted organization keys
- decrypted vault items and item metadata
- refresh token and access token
- private SSH keys stored in the vault
- TOTP secrets stored in login items

Secondary assets:

- item names, usernames, URIs, notes, and folder structure
- local cache contents
- session metadata stored on disk
- device identifier used for Vaultwarden auth flows

## Trust Boundaries

Clavix crosses these main boundaries:

1. Svelte frontend to Rust backend via Tauri commands
2. Rust backend to remote Vaultwarden / Bitwarden-compatible HTTP API
3. In-memory decrypted state to persisted local state on disk
4. Clavix process to local OS integrations:
   clipboard, camera, SSH agent socket, WebAuthn HID access

The most security-sensitive boundary is the Tauri IPC surface. The
frontend is trusted application code shipped with the app, but the Rust
side must still treat command inputs as untrusted and validate them
accordingly.

## Attacker Model

Clavix primarily tries to resist:

- a malicious or curious server operator who can observe ciphertext,
  protocol fields, and timing, but should not learn vault plaintext
- a passive attacker reading local storage files such as `session.json`
  or `vault.db`
- an attacker who tampers with encrypted server or cache data and tries
  to trigger unsafe parsing or incorrect decryption
- accidental data loss or inconsistent state during destructive flows
  such as share, move, delete, and folder rename cascades

Clavix does not fully resist:

- a fully compromised local OS user session
- malware running as the same desktop user
- a hostile kernel, debugger, or root account
- physical attacks against a powered-on unlocked machine
- side-channel attacks outside the guarantees of the underlying crypto
  libraries and operating system

## Explicit Assumptions

Current design assumptions include:

- the local machine is under the user's control to a reasonable degree
- disk encryption is recommended for real-world use
- the remote server may be untrusted for confidentiality, but is still
  relied upon for protocol correctness and item storage
- Tauri, the system WebView, RustCrypto crates, and OS APIs are trusted
  dependencies unless a known vulnerability says otherwise
- once the vault is unlocked, plaintext necessarily exists in process
  memory and may be exposed by a local compromise

## Sensitive Data Lifecycle

### Authentication and Unlock

- the frontend sends login and unlock requests to Rust commands
- the Rust backend derives the master key from the password and server
  KDF parameters
- the backend authenticates to the server with derived values rather
  than the raw master password
- the user key is recovered from encrypted server material and held in
  memory for the unlocked session

### Persistence

- the session file stores server URL, email, KDF parameters, encrypted
  user key, optional encrypted private key, and an encrypted refresh
  token
- the offline cache stores an encrypted blob keyed by account identity
- Unix builds try to apply restrictive permissions to these files

### Runtime

- decrypted vault contents live in Rust memory while the session is open
- selected item details also flow into frontend state for rendering
- copied secrets enter the system clipboard temporarily
- SSH keys may be loaded into the local Unix-domain SSH agent

## High-Risk Flows

These flows deserve concentrated review:

- key derivation and EncString parsing/decryption
- persisted session unlock using stored encrypted material
- token refresh and migration away from legacy plaintext refresh tokens
- offline cache encryption and decryption
- organization item sharing and cross-org re-encryption
- folder rename batch operations and the (write-only, not yet replayed)
  pre-operation snapshots and op-log entries persisted around them
- SSH agent socket exposure and request handling
- WebAuthn challenge parsing and authenticator interaction
- clipboard handling and auto-lock behavior when the UI freezes

## Likely Failure Modes

Examples of realistic failures to look for:

- using the wrong key when decrypting or re-encrypting an item
- accepting malformed ciphertext or weakly validating EncString parts
- persisting secrets longer than intended
- command handlers trusting frontend state too much
- leaving secrets behind after lock/logout/crash
- stale or partially-applied move/share operations corrupting data
- insecure file or socket permissions on some platforms
- information disclosure through logs, error serialization, or UI state

## Out of Scope for the Current Design

The current project does not attempt to solve:

- protection against local malware with user-level access
- hardened memory isolation between frontend and backend
- resistance to screenshots, screen readers, or shoulder surfing
- enterprise policy controls
- forensic-grade deletion of secrets from swap, crash dumps, or all
  allocator internals

## Existing Mitigations

Current mitigations visible in the codebase include:

- `SecretString` and `ZeroizeOnDrop` for sensitive key material
- HMAC verification before AES-CBC decryption
- encrypted refresh token persistence
- encrypted SQLite cache
- auto-lock mirrored in Rust as a backend watchdog
- Unix file and socket permission tightening where applicable
- focused unit tests on crypto, auth/session helpers, SSH agent
  framing, and WebAuthn challenge parsing

These mitigations reduce risk; they do not replace external review.

## Open Questions for Future Review

- Are all decrypted secrets kept for the minimum necessary lifetime?
- Is the Tauri command surface too broad, or missing validation in any
  command path?
- Are there platform-specific permission or path issues on macOS and
  Windows not visible from Linux-centric testing?
- Crash windows in move/share are currently **not** auto-recovered: the
  pre-operation snapshots and op-log entries written by `cache.rs` are
  not replayed on restart. Reviewers should treat this as a known gap
  rather than as a mitigation, and assess whether the resulting risk
  (locally inconsistent state until next successful sync) is acceptable.
- Is the SSH agent feature acceptable for the intended threat model, or
  should it be more isolated or more explicit about risk?
