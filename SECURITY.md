# Security Policy

Clavix is alpha-stage software. There is no formal third-party security
audit yet, and the project should not be treated as production-ready for
real credentials.

This file explains how to report vulnerabilities and what kind of review
is useful for this repository.

## Reporting a Vulnerability

Please do not open a public GitHub issue for a security problem.

Preferred channel:

1. Open a private GitHub Security Advisory for this repository.
2. If you already have a private contact channel with the maintainer, you
   may use it instead and reference the affected commit / version.

Include, when possible:

- affected version, commit, or branch
- operating system and architecture
- Vaultwarden / Bitwarden server version if relevant
- reproduction steps
- expected security property and observed failure
- whether credentials, vault data, or local secrets may be exposed

## Disclosure Expectations

Clavix aims for coordinated disclosure.

- Initial acknowledgement target: best effort, typically within 7 days
- Status updates: best effort while a fix is being prepared
- Public disclosure: after a fix is available, or after a reasonable
  coordination window if a fix is not immediately possible

Because this is a volunteer open source project, no SLA is promised.

## Supported Versions

At this stage, security fixes are best-effort and usually apply to:

- the latest tagged release
- the current `master` branch

Older versions may not receive backports.

## What Review Is Most Valuable

High-value review areas for Clavix are:

- `src-tauri/src/crypto.rs`
- session persistence and unlock flow:
  `src-tauri/src/store.rs`, `src-tauri/src/services/auth.rs`
- encrypted offline cache:
  `src-tauri/src/cache.rs`, `src-tauri/src/commands/vault.rs`
- Tauri command surface and frontend/backend trust boundary:
  `src-tauri/src/commands/`, `src/lib/api.ts`
- organization re-encryption and move/share flows:
  `src-tauri/src/services/cipher.rs`,
  `src-tauri/src/commands/move_share.rs`
- WebAuthn and SSH agent paths:
  `src-tauri/src/webauthn.rs`, `src-tauri/src/ssh_agent.rs`

For broader context, see:

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [CRYPTO.md](CRYPTO.md)
- [AUDIT_SCOPE.md](AUDIT_SCOPE.md)
- [DISCLAIMER.md](DISCLAIMER.md)

## Non-Goals

The project does not currently claim:

- formal certification
- external cryptographic audit
- side-channel resistance beyond normal library guarantees
- resistance against a fully compromised local user account
- support for hostile browser-style web origins, since Clavix is a
  desktop Tauri client rather than a website

## Hall of Fame

Responsible reports and meaningful security review may be credited in
the project documentation or release notes, unless the reporter prefers
to stay anonymous.
