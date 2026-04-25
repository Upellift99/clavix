# Audit Scope

This document defines the review scope that would be most useful for
Clavix once the project is ready to solicit broader external feedback.

Clavix is a Tauri desktop client for Vaultwarden / Bitwarden-compatible
servers. The highest-value review is a white-box code review of the
security-sensitive paths, not a generic web pentest.

## Review Goals

The review should answer:

- Can a malicious server or tampered ciphertext cause plaintext
  disclosure, incorrect decryption, or unsafe state transitions?
- Are secrets persisted or retained in memory longer than intended?
- Is the Tauri IPC surface validating inputs appropriately?
- Are move/share/re-encryption flows correct under normal and failure
  conditions?
- Are local integrations such as SSH agent, clipboard, and WebAuthn
  exposing avoidable risk?

## Priority Order

If reviewer time is limited, this is the preferred order:

1. Crypto and key-management review
2. Session persistence and offline unlock review
3. Tauri command-surface review
4. Organization re-encryption and destructive operation review
5. SSH agent and WebAuthn review
6. Frontend handling of sensitive state

## In Scope

### 1. Cryptographic Implementation

Primary files:

- `src-tauri/src/crypto.rs`
- `src-tauri/src/services/auth.rs`
- `src-tauri/src/services/cipher.rs`
- `src-tauri/src/services/vault.rs`

Review topics:

- KDF handling and parameter validation
- EncString parsing and failure behavior
- MAC verification and decryption order
- user-key and org-key derivation / usage
- re-encryption logic for create, update, share, move

### 2. Session and Local Persistence

Primary files:

- `src-tauri/src/store.rs`
- `src-tauri/src/cache.rs`
- `src-tauri/src/state.rs`
- `src-tauri/src/commands/auth.rs`

Review topics:

- session.json contents and migration paths
- refresh token protection at rest
- local file permissions and path choices
- encrypted cache design
- pre-operation snapshots and op-log entries written around destructive
  flows — note these are currently a write-only forensic trail (no
  automatic replay on restart), not a crash-recovery mechanism

### 3. Tauri Command Surface

Primary files:

- `src-tauri/src/lib.rs`
- `src-tauri/src/commands/`
- `src/lib/api.ts`

Review topics:

- trust boundary assumptions
- command parameter validation
- error serialization and information disclosure
- frontend/backend contract mismatches

### 4. SSH Agent

Primary files:

- `src-tauri/src/ssh_agent.rs`
- `src-tauri/src/commands/ssh.rs`

Review topics:

- socket path and permissions
- supported key parsing
- request framing and bounds
- signing behavior and misuse resistance
- lock/logout cleanup

### 5. WebAuthn / FIDO2

Primary files:

- `src-tauri/src/webauthn.rs`
- `src-tauri/src/commands/auth.rs`

Review topics:

- challenge parsing
- device interaction failure modes
- trust assumptions vs browser-origin model
- error handling and UX-visible security properties

### 6. Frontend Handling of Secrets

Primary files:

- `src/routes/+page.svelte`
- `src/lib/auth.svelte.ts`
- `src/lib/vault.svelte.ts`
- `src/lib/clipboard.svelte.ts`
- `src/lib/TotpField.svelte`
- `src/lib/CipherDetail.svelte`
- `src/lib/CipherEditor.svelte`

Review topics:

- lifetime of decrypted values in UI state
- copy-to-clipboard behavior and auto-clear
- lock/logout state reset
- accidental rendering, logging, or persistence of sensitive values

## Out of Scope

Usually out of scope for a first serious review:

- visual design and non-security UX issues
- general feature completeness
- browser extensions / autofill, which Clavix does not implement
- attachments and passkey storage, which are not currently in scope for
  the product
- vulnerability classes requiring a fully compromised local OS user,
  unless the code makes such compromise substantially easier

## Suggested Review Method

Most useful review format:

- white-box code review
- threat-model sanity check
- manual adversarial testing of key flows
- targeted verification of crash/failure behavior
- retest after fixes

Less useful on its own:

- generic SAST scan without manual review
- web-only pentest assumptions applied to the Tauri app

## Environment for Review

Reviewers should be able to:

- build the Rust backend and Svelte frontend locally
- run unit tests:
  `cargo test`, `pnpm test`, `pnpm check`
- run or inspect end-to-end flows against a disposable Vaultwarden
  instance

Helpful supporting docs:

- [README.md](README.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)
- [CRYPTO.md](CRYPTO.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)

## Deliverables Expected from a Serious Review

An effective review should produce:

- findings ordered by severity
- reproduction steps or proof sketches
- impact explanation tied to Clavix's threat model
- concrete remediation guidance
- explicit note of what was not reviewed
- optional retest after fixes

## Current Caveat

As of today, Clavix should still be described as:

- unaudited
- alpha-stage
- suitable for review and testing
- not yet suitable for high-trust production use

This wording should remain conservative until external review and
additional hardening work actually happen.
