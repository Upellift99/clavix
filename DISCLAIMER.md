# Disclaimer

Clavix is **alpha-stage software**. Do not use it with a vault containing
real credentials you rely on. Use a dedicated, isolated Vaultwarden
instance filled with test data only.

## What you should know before running Clavix

- **The cryptography has not been audited** by an independent expert.
  The protocol is a re-implementation of Bitwarden's client-side
  encryption (PBKDF2 / Argon2id, AES-256-CBC + HMAC-SHA256, RSA-OAEP-SHA1,
  HKDF-SHA256). The code follows the published Bitwarden specification
  but has not been externally reviewed.
- **A significant portion of the code was produced with AI assistance**
  ([Claude Code](https://claude.com/claude-code), Anthropic). Architecture
  decisions, threat-model trade-offs and every security-sensitive change
  were reviewed by a human maintainer, but individual lines of code have
  not been inspected by a third party.
- **No stable release has been published.** All versions to date are
  development previews. Expect breaking changes, data-format churn, and
  bugs that can, in the worst case, corrupt items on the server (for
  instance, a drag-and-drop operation that re-encrypts a cipher with the
  wrong key).
- **Test coverage is partial.** Unit tests exist for critical crypto
  primitives but most features have been validated through manual end-to-end
  testing against a real Vaultwarden instance, not automated tests.

## What Clavix is *not* yet

- A drop-in replacement for the official Bitwarden client.
- A product fit for daily use by anyone other than the maintainer and
  early testers who understand the risks above.
- Certified, audited, or warranted in any way. See the GPL-3.0 license
  for the full wording; in practical terms: **no warranty, no liability**.

## Reporting a security issue

If you find a security vulnerability, **do not open a public GitHub
issue**. Instead:

1. Open a [private Security Advisory](https://github.com/Upellift99/clavix/security/advisories/new)
   on the repository. This is the preferred channel — it keeps the
   discussion private until a fix is ready, and gives us the tooling to
   assign a CVE if needed.
2. Or reach the maintainer privately by another mean you already have.

Please allow a reasonable coordinated-disclosure window (typically 90
days, less if the issue is already exploited in the wild) before any
public discussion.

## Roadmap to stability

Clavix will only be considered stable after all of the following are
reached:

- **Phase 1 — read-only:** authentication, 2FA, sync, decryption,
  offline cache, detail view. *Status: functional.*
- **Phase 2 — tree navigation:** personal folders and organisation
  collections displayed as a hierarchy with expand / collapse.
  *Status: functional.*
- **Phase 3 — drag & drop:** moving items between folders, sharing to
  collections, cross-organisation transfers, folder rename cascade.
  *Status: functional.*
- **Pre-v1.0 milestones:**
  - Community code review from maintainers of comparable projects
    (`rbw`, `keyguard`, Vaultwarden itself).
  - Paid security audit from a freelance consultant with
    Rust / cryptography background. The scope will cover at least the
    `crypto.rs` module, the session handling, and the IPC surface
    exposed from Rust to the Svelte frontend through Tauri commands.
  - A broader automated test suite with fuzz targets on the EncString
    parser and the AES-CBC / HMAC decryption paths.

Until those boxes are checked, please treat Clavix as an interesting
prototype, not as a production password manager.
