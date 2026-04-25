# Manual Validation Checklists

Some Clavix features depend on real hardware, OS-level USB/HID stacks, or
external client tooling that automated tests cannot exercise meaningfully.
This document is the canonical, reproducible checklist for those features.
Run it before every minor release (`0.X.0`) and after any change that
touches `webauthn.rs`, `ssh_agent.rs`, or related Tauri commands.

## How to use

1. Pick a checklist below.
2. Fill in the **Run header** at the top of the section (paste the values
   into the related PR or release issue, *not* into this file).
3. Walk the steps in order. Mark `[x]` for pass, `[ ]` for not-yet, and
   write a `FAIL:` line under any step that didn't behave as expected.
4. If you hit a documented limitation, flag it as a "known" rather than
   a fail.

## Run header template

Copy-paste this block into your validation note:

```
- Clavix version / commit : v0.X.Y / abc1234
- OS                       : <distro version | macOS X.Y | Windows N>
- Vaultwarden / Bitwarden  : <version>
- Hardware key model       : <YubiKey 5, SoloKey v2, …> | n/a
- Date                     : YYYY-MM-DD
- Tester                   : <name>
```

---

## WebAuthn / FIDO2 (2FA unlock)

Code path: `src-tauri/src/webauthn.rs` (CTAP2 over USB HID via
`ctap-hid-fido2`). Driven from `commands::auth::webauthn_sign_challenge`
once the server replies `twoFactorProviders: [7]`.

### Platform matrix

- **Linux** — covered. Requires `libudev-dev` at build time, and udev
  rules letting the running user open the FIDO2 HID device (Yubico
  ships `70-u2f.rules`; if you don't have those, run as root once to
  confirm the path works, then fix udev).
- **macOS** — covered.
- **Windows** — covered (CTAP2/HID via the same crate; users on
  Windows 10+ may need to grant access via the WebAuthn platform UI).

### Prerequisites

- A Vaultwarden instance with a test account that has a registered
  WebAuthn credential (provider 7).
- A FIDO2 hardware key plugged in. Use one **known-good** model
  (default in matrix: YubiKey 5C). A second model is optional but
  recommended on releases that touch `webauthn.rs`.
- Clavix is installed and able to reach the test Vaultwarden URL.
- *Not* a production vault — registering a FIDO2 credential on a real
  vault and then losing the key locks you out.

### Happy path

- [ ] Launch Clavix, enter `server_url` + `email` + `password`, submit.
- [ ] The 2FA screen appears with WebAuthn / FIDO2 listed as a
  provider.
- [ ] Click the WebAuthn button; the LED on the hardware key starts
  blinking within ~1 s and the app shows a "touch your key" state.
- [ ] Touch the key; within ~2 s the vault opens and the cipher list
  syncs.

**Expected**: vault is unlocked, `last_activity` is bumped, the SSH
agent (if previously enabled) does *not* auto-start — that toggle is
session-scoped on purpose.

### Failure paths (must each fail cleanly, not hang)

- [ ] **No key plugged in** — click WebAuthn → app reports a
  user-visible error within ~3 s ("FIDO2 not supported on this
  platform" or "no FIDO2 device available"), 2FA screen stays usable.
- [ ] **Wrong key** (a different FIDO2 token, not registered with the
  account) — touch it on the prompt → server rejects the assertion
  → app shows the "2FA code rejected by the server" error and
  returns to the 2FA screen.
- [ ] **Key not touched within timeout** — wait 60 s without touching
  → app surfaces the timeout error, 2FA screen still usable.
- [ ] **rpId mismatch** *(synthetic test, optional)*: configure a
  Vaultwarden instance whose advertised `rpId` does not match the
  URL the user typed → app refuses to sign with an
  `Error::Crypto { reason: "WebAuthn rpId … is not a registrable
  suffix of server host …" }`. This is the safety net added in
  `0.1.11`; if it doesn't trigger, the rpId validation has regressed.

### Known limitations

- **Bluetooth-only authenticators are not supported.** Only USB HID
  is wired up. NFC works only if the OS exposes the key over HID
  (rare).
- **Hardware key with PIN** (CTAP2 user verification = required) —
  the prompt currently relies on whatever the OS offers; behaviour
  varies. Document the OS prompt path in your run notes.
- **Multiple registered credentials** for the same account — the
  first usable assertion wins. If a user has several keys, they
  cannot pick which one to use; this is a UX gap, not a security
  one.

---

## SSH agent

Code path: `src-tauri/src/ssh_agent.rs` (Unix-domain socket, OpenSSH
agent protocol). Started via `commands::ssh::start_ssh_agent`, exposed
in the *Infos* (Stats) dialog with a copy-the-`SSH_AUTH_SOCK`-export
button.

### Platform matrix

- **Linux** — covered. Socket path is under `$XDG_RUNTIME_DIR` (or a
  fallback under the user's home if the var is unset).
- **macOS** — covered.
- **Windows** — **not implemented yet** (planned via named pipes /
  Pageant compatibility; tracked separately).

### Prerequisites

- An unlocked Clavix vault containing **at least one Ed25519 key**
  and **at least one RSA key** (cipher type 5). Skipped key types
  (ECDSA, DSA) are intentional; the agent should report them as
  "skipped" rather than fail to start.
- A reachable SSH test target. A throwaway Git host
  (`gitea`/`gitlab` self-hosted) or a local container running
  `sshd` works. Don't validate against production servers.

### Happy path

- [ ] In the *Infos* dialog, toggle **Enable SSH agent**. The dialog
  shows a socket path and key count.
- [ ] Copy the `export SSH_AUTH_SOCK=…` line, paste it into a fresh
  terminal session.
- [ ] `ssh-add -L` lists every supported key from the vault, one
  line per key, in OpenSSH `authorized_keys` format. Skipped types
  are *not* listed (and that's fine — match this against the
  "skipped" count shown in the dialog).
- [ ] `ssh -T -o StrictHostKeyChecking=accept-new <user>@<host>`
  authenticates without ever asking for a password and without ever
  writing the private key to disk.
- [ ] `git ls-remote git@<host>:<path>.git` works the same way (this
  is the realistic developer use case).

**Expected**: each successful sign uses the in-memory decrypted key,
which is wiped immediately after.

### Lifecycle / lockdown

- [ ] **Lock the vault** in the Clavix UI. Within ~1 s, `ssh-add -L`
  in the terminal returns "Could not open a connection to your
  authentication agent" (socket gone) and any subsequent `ssh`
  attempt prompts for a password.
- [ ] **Unlock the vault** again. The agent does *not* auto-restart
  — by design, the toggle is session-scoped. Re-enable it from the
  dialog and confirm `ssh-add -L` works again.
- [ ] **Auto-lock** (set the timer to 1 min, idle for 65 s). Same
  observable as manual lock: socket disappears, `ssh-add -L` fails.
- [ ] **Logout / switch account**. Same as lock — the socket is
  gone, the cache cleared.

### Failure paths

- [ ] **Vault has zero supported keys** — toggle on → dialog reports
  0 keys / N skipped, but the socket is still alive (so the
  `SSH_AUTH_SOCK` env var stays valid even if no key is loaded yet).
- [ ] **Stale socket file from a previous crash** — start the
  agent → it cleans up the prior socket and binds afresh, no
  EADDRINUSE error.
- [ ] **Socket permissions** — `ls -l "$SSH_AUTH_SOCK"` shows
  `srwx------` (0700, owner only). Anyone else on a multi-user
  machine cannot connect to the agent.

### Known limitations

- **ECDSA / DSA keys are not signed.** They appear in the vault but
  are skipped by the agent. Adding ECDSA is tracked as part of the
  SSH-agent roadmap.
- **One agent per running Clavix instance.** Two simultaneous
  sessions would race on the same socket path; this is not the
  intended usage.
- **No per-signature consent prompt** today. Once the agent is
  enabled, every `ssh`/`git` call signs silently. A "ask before
  sign" mode is on the roadmap but not in this checklist.
