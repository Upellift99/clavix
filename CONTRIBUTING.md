# Contributing to Clavix

Thanks for taking the time to consider contributing. Clavix is in
**alpha** — the architecture still moves — so please read this short
guide before opening an issue or a pull request.

## Before you start

- Read the [DISCLAIMER](DISCLAIMER.md) to understand the current
  maturity of the project.
- If you found a **security issue**, do NOT open a public issue. Use a
  [private Security Advisory](https://github.com/Upellift99/clavix/security/advisories/new)
  instead.
- For features that touch crypto, storage, or the IPC surface between
  Rust and Svelte, open a discussion first so we can align on the
  approach before you write code.

## Opening an issue

Use the issue templates on GitHub. In short:

- **Bug report** — what you expected, what happened, your platform,
  your Vaultwarden version, and whether the bug is reproducible on a
  fresh install.
- **Feature request** — the user problem first, the solution second.
  A feature that only you would use is unlikely to ship before 1.0.

## Opening a pull request

1. Fork, branch off `master`, and keep the branch focused on one
   logical change.
2. Run the full check suite locally before pushing. The root `Makefile`
   wraps the CI commands:

   ```bash
   pnpm install
   make check        # fmt + clippy + cargo test + svelte-check + vitest
   make check-full   # same + E2E (needs Docker + webkit2gtk-driver + xvfb)
   ```

   Raw commands if you prefer calling them directly:

   ```bash
   pnpm check        # compiles Paraglide + svelte-check
   cd src-tauri
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo audit       # optional, install with cargo install cargo-audit
   ```

   The CI runs the same checks — a green `make check-full` locally
   means the GitHub Actions pipeline should pass too.
3. Write a descriptive commit message. We loosely follow
   [Conventional Commits](https://www.conventionalcommits.org/) with
   prefixes like `feat(…)`, `fix(…)`, `docs(…)`, `ci(…)`, `perf(…)`.
4. Keep the diff small. Large changes are easier to review in several
   PRs than in one; if in doubt, ask.
5. Do not add dependencies casually. Every crate or npm package adds
   surface; the maintainer reserves the right to reject a PR purely on
   dependency grounds.

## Code style

- **Rust**: whatever `cargo fmt` says is canonical. Clippy is run with
  `-D warnings`.
- **Svelte / TypeScript**: keep types strict. `svelte-check` is the
  source of truth.
- **Comments**: default to no comments. Only add one when the *why* is
  non-obvious (a hidden invariant, a workaround for an upstream bug).
  Well-named identifiers should do the rest.
- **i18n**: any visible string goes through `messages/fr.json` and
  `messages/en.json`, then `m.key()` in the component. New keys in a
  PR must be translated in both locales at once.

## Local development quickstart

```bash
# Ensure Node 22+ for Paraglide
nvm use        # reads .nvmrc
pnpm install

# Run the Tauri dev window
pnpm tauri dev
```

System dependencies for Linux are listed in the [README](README.md).

## AI-assisted contributions

Clavix itself has been developed with the help of Claude Code. You are
welcome to use AI tools on your contributions too, but:

- You remain fully responsible for the code you submit. Don't paste a
  diff you can't explain.
- If a significant part of the contribution is AI-generated, please
  mention it in the PR description. Transparency helps review.
- The same standards apply: tests, `cargo clippy -D warnings`,
  `svelte-check`, descriptive commit messages.

## Licensing

By submitting a contribution, you agree that it is licensed under
[GPL-3.0-or-later](LICENSE), the same license as the project.
