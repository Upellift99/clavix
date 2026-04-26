# Yubikey-only unlock — Design

This document describes the planned "unlock with a FIDO2 hardware token
after a previous master-password sign-in" feature. It is a design
sketch reviewed before any code lands. Implementation will follow in a
separate PR; until then this is a contract we can argue over without
the cost of churn.

The corresponding addition to `THREAT_MODEL.md` is in the same PR.

## Scope

What this feature is:

- A *re-unlock* path. After a normal master-password sign-in, the
  user's master key can be released by a touch on a registered FIDO2
  token, instead of re-typing the master password.

What it is **not**:

- It is not an alternative to the master password at first sign-in.
  The first sign-in still derives the master key from the password
  via PBKDF2 / Argon2id and authenticates against the server.
- It is not a recovery mechanism. Losing the Yubikey does not lock
  the user out — they fall back to the master password, which is
  always accepted.
- It is not multi-device. The wrap is bound to one specific FIDO2
  credential on one specific token.

## What other vaults do

- **Bitwarden Web + browser extension** ship "PRF Unlock" since PR
  bitwarden/clients#16662 (merged 2026-01). It uses CTAP2's
  `hmac-secret` extension (a.k.a. WebAuthn PRF) to derive a stable
  per-credential secret used to unwrap the user key.
- **Bitwarden Desktop** has not shipped this yet — POC remains in
  bitwarden/clients#17420 at the time of writing.
- **1Password** and **KeePassXC** use OS biometrics (Touch ID,
  Windows Hello, kwallet) for re-unlock and treat hardware tokens as
  a second factor at full open, not as a re-unlock path. So Clavix's
  flow is closer to Bitwarden's PRF Unlock than to KeePassXC's
  challenge-response model.

## Cryptographic primitive

We use the **CTAP2 `hmac-secret`** extension exposed by
`ctap-hid-fido2` (already in our dependency tree for WebAuthn 2FA).

At enrollment we make a credential with `hmac-secret: true`. At unlock
time we present the same per-app `salt` to that credential, the
authenticator returns `HMAC-SHA256(CredRandom, salt)` (32 bytes,
deterministic for the lifetime of the credential), and we feed that
into HKDF to derive a wrap key. The encrypted master key on disk is
unwrapped with that wrap key.

This is the same primitive Microsoft uses for Windows Hello
"passwordless sign-in with security key", and the same primitive
Bitwarden's PRF Unlock relies on. We are not inventing a new scheme.

### Why hmac-secret rather than HMAC-SHA1 challenge-response slot 2

| Property | hmac-secret (CTAP2) | HMAC-SHA1 slot 2 |
| --- | --- | --- |
| Pre-config required | none — registration is in-app | `ykman otp chalresp` first |
| Hash | HMAC-SHA-256 | HMAC-SHA-1 |
| Token support | Yubikey 5+, Solokey 2, Nitrokey 3 | Yubikey 4 / 5 / NEO / Bio |
| User verification | PIN + touch | touch only |
| Native to app | uses existing `ctap-hid-fido2` | needs a new HID/OTP crate |

`hmac-secret` is the modern path and avoids forcing the user through
`ykman` to set up the slot. We accept the loss of Yubikey 4 / NEO
support.

## On-disk format

A new optional field is added to the existing session file
(`session.json` under XDG_DATA_HOME). Persisted only when the user
opts in to Yubikey unlock:

```jsonc
{
  // ... existing session fields ...
  "yubikey_unlock": {
    "version": 1,
    "rp_id": "clavix.local",
    "credential_id": "<base64url>",      // CTAP2 credential id
    "salt": "<base64 32 bytes>",         // hmac-secret input, random per enrolment
    "wrapped_user_key": {                // AES-256-GCM ciphertext of the user key
      "ciphertext": "<base64>",
      "nonce": "<base64 12 bytes>",
      "tag": "<base64 16 bytes>"
    },
    "user_key_fingerprint": "<base64>"   // HKDF(user_key, info="clavix-yk-fp-v1") trunc 16 bytes
  }
}
```

Field-by-field rationale:

- **version**: future-proofing. Bumped on any wire change.
- **rp_id**: stable Relying Party identifier for the credential.
  We use a fixed local string — the credential is bound to Clavix on
  this machine, not to a domain.
- **credential_id**: returned by the authenticator at registration.
  Stored client-side because we use **non-resident** credentials —
  saves the limited resident-key slots on the user's token (typically
  ~25-50 slots on a Yubikey 5).
- **salt**: 32 random bytes, fresh per enrolment. Same value reused
  for every unlock. Bound to this credential.
- **wrapped_user_key**: the user key encrypted with the wrap key
  derived from the hmac-secret output. Format is AES-256-GCM, the
  same primitive already used elsewhere in the app for at-rest data.
- **user_key_fingerprint**: a non-secret HKDF derivative of the user
  key. Lets us detect that the master password was changed on
  another client (which rotates the user key) so we can drop the
  stale wrap and force re-enrolment instead of producing wrong
  decrypts. Truncated to 16 bytes — collision risk is irrelevant for
  this purpose.

## Key derivation

```
prf_secret  = hmac-secret response (32 bytes from authenticator)
wrap_key    = HKDF-SHA256(prf_secret, salt = "", info = b"clavix-yubikey-unlock-v1")[:32]
nonce       = random 12 bytes (fresh per wrap)
ciphertext  = AES-256-GCM-Encrypt(wrap_key, nonce, user_key)
```

`wrap_key` is zeroized as soon as encrypt or decrypt finishes. `prf_secret`
likewise. Both are wrapped in `Zeroizing<[u8; 32]>` for the duration
of the call.

## Flows

### Enrolment (after a successful master-password unlock)

1. User opens **Préférences → Déverrouillage par Yubikey** and clicks
   *Configurer*.
2. UI shows a touch-and-PIN prompt and warns explicitly that, once
   enabled, the wrapped user key on disk is protected by the Yubikey
   secret rather than the master password.
3. Backend:
   - Generates `salt` (32 random bytes).
   - Calls `make_credential_with_args` on the FIDO2 device with
     `Mext::HmacSecret(Some(true))` and the configured `rp_id`.
   - Calls `get_assertion_with_args` immediately, supplying the
     fresh `salt` via `Gext::create_hmac_secret_from_string`.
   - Derives `wrap_key`, encrypts the in-memory user key with
     AES-256-GCM, computes the user-key fingerprint.
   - Writes the new `yubikey_unlock` block to the session file
     atomically (rename pattern, the same way the rest of the
     session file is updated).
4. UI reports success; the next auto-lock or manual lock will offer
   the Yubikey path.

### Unlock

1. The unlock view detects the presence of `yubikey_unlock` in the
   session file.
2. UI shows a "Toucher la Yubikey pour déverrouiller" button **next
   to** (not in place of) the master-password field.
3. On click:
   - Backend calls `get_assertion_with_args` with the stored
     credential id and salt.
   - Reproduces `wrap_key` and decrypts the wrapped user key.
   - Verifies that the resulting user key matches
     `user_key_fingerprint`. If it doesn't:
     - Drop the `yubikey_unlock` block from the session file (it is
       stale — master password has been rotated elsewhere).
     - Surface a clear UI message: re-enrol once you've signed in.
   - If everything matches, restore the in-memory session as if a
     master-password unlock had run, refresh the access token if
     needed, and continue.
4. Failure modes — no Yubikey plugged in, wrong PIN, user cancels
   the touch prompt — leave the master-password field functional. No
   silent fallback: the user must explicitly retry or use the
   password.

### Disenrolment

1. User toggles *Configurer* off in Préférences (master-password
   confirmation required to avoid an attacker-with-shoulder-access
   scenario).
2. Backend wipes the `yubikey_unlock` block from the session file.
3. The credential remains on the token until the user removes it
   manually with their token's management tool — we do not delete
   it for them, since that requires a separate FIDO2 management
   flow and we are not running a credential lifecycle service.

## Implementation plan

Estimated total: **~500-700 LOC across Rust + Svelte**, plus tests.
The FIDO2 stack is already in place for 2FA, so we extend rather
than introduce a new dependency.

### Rust

| File | Change |
| --- | --- |
| `src-tauri/src/yubikey_unlock.rs` *(new)* | Enrolment + unwrap functions. Encapsulates the call into `ctap-hid-fido2`, the HKDF + AES-GCM wrap, and the user-key-fingerprint computation. |
| `src-tauri/src/store.rs` | Extend the session file struct with the optional `yubikey_unlock` block. Atomic-rename writers already exist. |
| `src-tauri/src/state.rs` | No change expected — the unlocked session is the same shape regardless of how it was unlocked. |
| `src-tauri/src/commands/auth.rs` | Two new commands: `enroll_yubikey_unlock`, `unlock_with_yubikey`. Plus `disenroll_yubikey_unlock`. |
| `src-tauri/src/error.rs` | New variants: `YubikeyNoDevice`, `YubikeyPinRequired`, `YubikeyWrongPin`, `YubikeyUserCancelled`, `YubikeyStaleWrap` (fingerprint mismatch). |

### Front-end

| File | Change |
| --- | --- |
| `src/lib/UnlockForm.svelte` | Optional "Déverrouiller avec Yubikey" button rendered when the session reports a stored wrap. The master-password input stays. |
| `src/lib/StatsDialog.svelte` (or a new `Preferences*.svelte`) | Enrolment / disenrolment toggle with the explicit threat-model warning. |
| `src/lib/api.ts` | Three new bindings. |
| `src/lib/types.ts` | `YubikeyUnlockState` flag visible to the unlock view. |
| `messages/{fr,en}.json` | Strings for enrolment, errors, threat warning. |

### Tests

- **Unit (Rust)**: HKDF / AES-GCM round-trip, fingerprint stability,
  staleness detection. The CTAP2 path itself is mocked via a small
  trait so unit tests don't need a real device. Property-test the
  stale-wrap behaviour.
- **Integration**: documented manual steps in `MANUAL_VALIDATION.md`
  since CI cannot present a Yubikey to the runner.
- **No E2E**: WDIO can't drive a hardware token. Smoke test that the
  enrolment UI renders correctly and rejects clicks without a session.

## Open questions worth a second look during code review

1. Should the enrolment flow ask for a fresh master-password
   confirmation before persisting the wrap, even though a session
   is already unlocked? Bitwarden's PRF Unlock does. It hardens
   against the "logged-in laptop briefly unattended" scenario.
2. Is `rp_id` chosen well? `clavix.local` is fine for an
   isolated-app credential, but check whether platform
   authenticators object to non-DNS strings.
3. Multiple registered tokens? Out of scope for v1, but the on-disk
   format leaves the door open by allowing the field to grow into
   an array later.
4. Auto-lock interaction: when the session auto-locks, do we keep
   the Yubikey path enabled by default or default to the master
   password? Current plan: keep it enabled — that's the point.

## Out of scope for this PR

- Resident credentials.
- Multiple registered tokens.
- Recovery codes (master password is the recovery path).
- iOS / Android (no platform target today).
- Headless / WSL (no plug-in expected to surface a FIDO2 token).
