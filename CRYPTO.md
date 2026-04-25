# Crypto Notes

Clavix re-implements the Bitwarden client-side cryptographic model in
Rust. This document is an orientation guide for reviewers. It is not a
formal specification, and it does not claim the implementation has been
externally audited.

Main implementation file:

- `src-tauri/src/crypto.rs`

Related files:

- `src-tauri/src/services/auth.rs`
- `src-tauri/src/services/cipher.rs`
- `src-tauri/src/services/vault.rs`
- `src-tauri/src/commands/auth.rs`
- `src-tauri/src/commands/vault.rs`
- `src-tauri/src/store.rs`
- `src-tauri/src/cache.rs`

## Design Intent

The goal is compatibility with Vaultwarden / Bitwarden-style encrypted
vault data while keeping plaintext handling inside the local client.

Clavix is not inventing a new end-to-end scheme on purpose. Where
possible, it follows the data model and encrypted string formats used by
Bitwarden-compatible servers.

## Main Primitives

Current primitives used in the codebase:

- PBKDF2-HMAC-SHA256
- Argon2id
- HKDF-SHA256
- AES-256-CBC with PKCS#7 padding
- HMAC-SHA256 for integrity
- RSA-OAEP-SHA1 for organization/private-key compatibility

The use of RSA-OAEP-SHA1 is driven by Bitwarden compatibility, not by a
desire to choose SHA-1 for new designs.

## Key Material

### Master Key

The master key is derived from:

- the master password
- the normalized email address
- server-provided KDF settings

See `derive_master_key` in `crypto.rs`.

Supported KDFs:

- PBKDF2
- Argon2id

### Master Password Hash

The derived master key is used to compute the authentication hash sent
to the server. The raw master password is not intended to be persisted.

See `derive_master_password_hash` in `crypto.rs`.

### User Symmetric Key

The server returns encrypted user-key material. Clavix decrypts that
material locally using the master key and keeps the resulting symmetric
key in memory for vault operations.

The symmetric key is split into:

- 32-byte encryption key
- 32-byte MAC key

See `SymmetricKey` in `crypto.rs`.

### Organization Keys

Organization keys are decrypted locally and cached in the in-memory
session when organization ciphers or collections are accessed.

## EncString Format

Clavix parses Bitwarden-style encrypted strings through `EncString`.

Supported variants currently include:

- type `2`: AES-CBC-256 + HMAC-SHA256
- type `4`: RSA-OAEP-SHA1

The parser validates structure and lengths before use. For symmetric
payloads, MAC verification happens before decryption.

Important review target:

- malformed or adversarial `EncString` parsing
- key confusion between user key and organization key
- clear failure behavior on tampered data

## At-Rest Protection

### Session File

The persisted session currently contains:

- server URL
- email
- KDF parameters
- encrypted user key
- optional encrypted private key
- encrypted refresh token

The refresh token is encrypted under the user key before being written
to disk. A legacy plaintext refresh-token field may still be accepted
for migration from older session files.

See:

- `src-tauri/src/store.rs`
- `src-tauri/src/services/auth.rs`

### Offline Cache

The local SQLite cache stores an encrypted vault blob keyed by account.
Per-cipher pre-modification snapshots and a folder-rename op-log are
also written to encrypted columns before destructive operations
(move, share, cross-org re-encryption, cascade folder rename).

These snapshots are currently a **forensic trail, not an automated
recovery mechanism**: nothing in the running app replays them after a
crash. They can help a maintainer reconstruct what was attempted in
post-mortem analysis, but the user-visible state after a partially
applied operation is whatever the server returns on the next sync.

See:

- `src-tauri/src/cache.rs`

## Re-Encryption Flows

The most delicate application-level crypto flows are:

- creating encrypted item payloads for the server
- editing existing items
- sharing a personal item into an organization
- moving ciphers across organizations with re-encryption
- decrypting organization collection names and item fields

These paths live mainly in:

- `src-tauri/src/services/cipher.rs`
- `src-tauri/src/commands/move_share.rs`
- `src-tauri/src/services/vault.rs`

These paths should be reviewed for:

- source-key / target-key confusion
- accidental plaintext persistence
- failure atomicity around destructive updates
- treatment of optional and null fields

## Memory Hygiene

Clavix uses:

- `SecretString` for the master password
- `ZeroizeOnDrop` on `MasterKey` and `SymmetricKey`

This is useful but limited. It does not guarantee that every copy,
allocation, UI string, log, or OS artifact is scrubbed. Reviewers
should treat "memory is perfect" as a false assumption.

## What This Document Does Not Claim

This document does not claim:

- cryptographic novelty
- formal verification
- resistance to all local compromise scenarios
- completion of a third-party audit

It is a guide for reviewers, not a trust badge.

## Review Checklist

Questions worth asking while reading the crypto paths:

- Does every decrypt path authenticate before plaintext use?
- Can malformed `EncString` values trigger inconsistent behavior?
- Is any secret persisted in clear text unexpectedly?
- Are organization items always encrypted with the correct target key?
- Are legacy migration paths safe and bounded?
- Are error messages or serialized failures leaking sensitive details?
