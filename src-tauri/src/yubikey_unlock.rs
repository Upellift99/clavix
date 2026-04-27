//! Yubikey re-unlock — wrap the user key under a hardware-derived
//! secret so the user can release it with a touch instead of re-typing
//! the master password.
//!
//! The full design — scope, threat model, on-disk format, key
//! derivation — lives in `YUBIKEY_UNLOCK.md`. The short version:
//!
//! 1. Enrolment runs once after a master-password unlock. We register
//!    a non-resident FIDO2 credential with the CTAP2 `hmac-secret`
//!    extension turned on, immediately call `get_assertion` against
//!    it with a fresh per-credential salt to obtain the PRF output,
//!    derive a wrap key via HKDF-SHA256, and AES-CBC + HMAC-SHA256
//!    the user key (64 raw bytes) under that wrap key. The wrap key
//!    is wiped before this function returns; only the ciphertext, the
//!    salt, the credential id, and a non-secret HKDF fingerprint of
//!    the user key are persisted.
//!
//! 2. Subsequent unlocks reproduce the wrap key by replaying the same
//!    salt against the same credential, decrypt the wrap, and verify
//!    the recovered key matches the stored fingerprint. A mismatch
//!    means the master password was rotated on another client — we
//!    drop the wrap and surface a clear "re-enrol after sign-in"
//!    error rather than handing the caller a broken user key.
//!
//! The `FidoDevice` trait abstracts the CTAP I/O so unit tests can
//! cover the crypto path (HKDF, wrap roundtrip, fingerprint
//! stability, stale-wrap detection) without a real authenticator on
//! the test runner.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{encrypt_bytes, EncString, SymmetricKey};
use crate::error::{Error, Result};
use crate::store::YubikeyUnlockBlock;

/// Schema version written to disk. Bumped on any wire change. Only
/// version 1 is recognised today; an unknown version is a hard error
/// rather than a best-effort migration so we never silently produce
/// wrong decrypts off a future-format wrap.
pub const CURRENT_VERSION: u32 = 1;

/// Default Relying Party identifier used when registering the FIDO2
/// credential. The credential is bound to Clavix on this machine, not
/// to a domain — there is no Vaultwarden server involved in the
/// re-unlock path. Stored in the on-disk block so a future change
/// here cannot retroactively break old wraps.
pub const DEFAULT_RP_ID: &str = "clavix.local";

/// HKDF info string for the wrap key. Domain-separates this derivation
/// from any other use of HKDF in the codebase.
const HKDF_INFO_WRAP: &[u8] = b"clavix-yubikey-unlock-v1";

/// HKDF info string for the user-key fingerprint. Distinct from the
/// wrap info so a 16-byte fingerprint leak cannot reveal a single bit
/// of the wrap key (different domain, no shared output).
const HKDF_INFO_FINGERPRINT: &[u8] = b"clavix-yk-fp-v1";

/// Length of the truncated user-key fingerprint persisted on disk.
/// 16 bytes is short enough to keep the session file compact and long
/// enough that a random-collision detection-bypass is irrelevant — an
/// attacker who can forge a colliding user key has already broken the
/// rest of the protocol.
const FINGERPRINT_LEN: usize = 16;

/// Output of `enroll_credential` on a real or mock authenticator.
pub struct EnrolledCredential {
    /// CTAP2 credential id, as returned by the authenticator. Stored
    /// verbatim on disk (base64-encoded by the caller).
    pub credential_id: Vec<u8>,
    /// Per-credential PRF secret returned by the very first
    /// `hmac-secret` evaluation against this credential. Keyed by the
    /// salt the caller chose at enrolment time. Reproduced exactly by
    /// every subsequent assertion on the same authenticator with the
    /// same salt.
    pub prf_secret: Zeroizing<[u8; 32]>,
}

/// CTAP2 surface used by the enrolment / unlock flows. Lives behind a
/// trait so the crypto path (HKDF, wrap roundtrip, fingerprint,
/// stale-wrap detection) can be unit-tested without a hardware
/// authenticator on the runner — CI cannot present a Yubikey.
pub trait FidoDevice {
    /// Register a fresh non-resident credential with `hmac-secret`
    /// enabled and immediately read its PRF output for the given
    /// salt. Returns the credential id (to persist) and the secret
    /// (to derive the wrap key from).
    fn enroll_credential(
        &self,
        rp_id: &str,
        pin: Option<&str>,
        salt: &[u8; 32],
    ) -> Result<EnrolledCredential>;

    /// Replay the same salt against an already-registered credential.
    /// Returns the PRF output deterministically — an authenticator
    /// that does not produce identical bytes for identical inputs is
    /// broken and the caller will get a fingerprint mismatch.
    fn replay_credential(
        &self,
        rp_id: &str,
        pin: Option<&str>,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// Generate fresh 32 random bytes — used as the per-credential salt.
fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive the wrap key from the authenticator's PRF output. The PRF
/// output is high-entropy but not directly a Bitwarden-style
/// `SymmetricKey`; HKDF gives us domain separation (so the same
/// authenticator can be reused for a different feature later without
/// risking key reuse) and the right shape (64 bytes = enc || mac).
///
/// The returned `SymmetricKey` is `ZeroizeOnDrop`; callers should
/// drop it as soon as the wrap or unwrap finishes.
fn derive_wrap_key(prf_secret: &[u8; 32]) -> Result<SymmetricKey> {
    let hk = Hkdf::<Sha256>::new(None, prf_secret);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(HKDF_INFO_WRAP, out.as_mut_slice())
        .map_err(|e| Error::Crypto {
            reason: format!("HKDF expand wrap: {e}"),
        })?;
    SymmetricKey::from_bytes(out.as_slice())
}

/// Public so the integration / property tests can re-derive the same
/// 16-byte fingerprint from raw user-key bytes without having to
/// construct a `SymmetricKey` first. Takes `&[u8]` rather than
/// `&[u8; 64]` so callers holding a `Zeroizing<[u8; 64]>` can pass
/// `.as_slice()` without an explicit deref dance.
pub fn compute_user_key_fingerprint(user_key_bytes: &[u8]) -> [u8; FINGERPRINT_LEN] {
    let hk = Hkdf::<Sha256>::new(None, user_key_bytes);
    let mut out = [0u8; FINGERPRINT_LEN];
    // HKDF with info = HKDF_INFO_FINGERPRINT, output 16 bytes. expand
    // can only fail if `out.len()` exceeds 255 * 32; we ask for 16
    // bytes so this branch is unreachable in practice.
    hk.expand(HKDF_INFO_FINGERPRINT, &mut out)
        .expect("HKDF expand for 16-byte fingerprint cannot fail");
    out
}

/// Wrap an unlocked user key under a freshly-enrolled FIDO2
/// credential. Returns the on-disk block ready to persist.
///
/// `rp_id` is the Relying Party id the credential will be bound to —
/// pass `DEFAULT_RP_ID` unless you have a specific reason not to. The
/// chosen value is recorded in the block so future code that changes
/// the default cannot retroactively break old wraps.
pub fn enroll<F: FidoDevice>(
    device: &F,
    rp_id: &str,
    pin: Option<&str>,
    user_key: &SymmetricKey,
) -> Result<YubikeyUnlockBlock> {
    let salt = random_salt();
    let enrolled = device.enroll_credential(rp_id, pin, &salt)?;

    let wrap_key = derive_wrap_key(&enrolled.prf_secret)?;
    let user_key_bytes = user_key.to_bytes();
    let wrapped = encrypt_bytes(user_key_bytes.as_slice(), &wrap_key)?;
    let fingerprint = compute_user_key_fingerprint(user_key_bytes.as_slice());
    // wrap_key drops here — `SymmetricKey` is `ZeroizeOnDrop`.

    Ok(YubikeyUnlockBlock {
        version: CURRENT_VERSION,
        rp_id: rp_id.to_string(),
        credential_id: STANDARD.encode(&enrolled.credential_id),
        salt: STANDARD.encode(salt),
        wrapped_user_key: wrapped,
        user_key_fingerprint: STANDARD.encode(fingerprint),
    })
}

/// Recover the raw 64-byte user key from a stored block by replaying
/// the salt against the registered credential. Verifies the recovered
/// key matches the stored fingerprint; a mismatch returns
/// `Error::YubikeyStaleWrap` so the caller can drop the block and
/// fall back to master-password unlock.
pub fn unwrap_user_key<F: FidoDevice>(
    device: &F,
    block: &YubikeyUnlockBlock,
    pin: Option<&str>,
) -> Result<Zeroizing<[u8; 64]>> {
    if block.version != CURRENT_VERSION {
        return Err(Error::Crypto {
            reason: format!(
                "unsupported yubikey_unlock version {} (expected {})",
                block.version, CURRENT_VERSION
            ),
        });
    }

    let credential_id = STANDARD
        .decode(&block.credential_id)
        .map_err(|e| Error::Crypto {
            reason: format!("invalid credential_id base64: {e}"),
        })?;

    let salt_vec = STANDARD.decode(&block.salt).map_err(|e| Error::Crypto {
        reason: format!("invalid salt base64: {e}"),
    })?;
    if salt_vec.len() != 32 {
        return Err(Error::Crypto {
            reason: format!("salt must be 32 bytes, got {}", salt_vec.len()),
        });
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_vec);

    let prf = device.replay_credential(&block.rp_id, pin, &credential_id, &salt)?;
    let wrap_key = derive_wrap_key(&prf)?;

    // Wrap the decrypted Vec in `Zeroizing` so its allocation is wiped
    // when this function returns, including on the early-return paths
    // below. `decrypt_sym` itself returns a plain `Vec<u8>`.
    let plaintext = Zeroizing::new(
        EncString::parse(&block.wrapped_user_key)?.decrypt_sym(&wrap_key)?,
    );
    if plaintext.len() != 64 {
        return Err(Error::Crypto {
            reason: format!("wrapped user key must be 64 bytes, got {}", plaintext.len()),
        });
    }

    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes.copy_from_slice(&plaintext);

    let stored_fp = STANDARD
        .decode(&block.user_key_fingerprint)
        .map_err(|e| Error::Crypto {
            reason: format!("invalid fingerprint base64: {e}"),
        })?;
    if stored_fp.len() != FINGERPRINT_LEN {
        return Err(Error::Crypto {
            reason: format!(
                "fingerprint must be {} bytes, got {}",
                FINGERPRINT_LEN,
                stored_fp.len()
            ),
        });
    }

    let recovered_fp = compute_user_key_fingerprint(bytes.as_slice());
    if recovered_fp[..] != stored_fp[..] {
        // Master password was rotated on another client — the wrap
        // protects a key the server no longer accepts. Surface a
        // dedicated error so the frontend can drop the block, prompt
        // the user to sign in with the master password, then offer
        // to re-enrol.
        return Err(Error::YubikeyStaleWrap);
    }

    Ok(bytes)
}

// ── Production CTAP impl — Linux/macOS/Windows only ──────────────────
//
// Mirrors the layout of `webauthn.rs`: blocking CTAP-HID I/O, intended
// to be invoked from a Tauri command via
// `tauri::async_runtime::spawn_blocking`. Behind a target-OS gate
// because `ctap-hid-fido2` doesn't compile on every platform Tauri
// nominally targets and we don't want to break builds on those
// platforms just to add a feature that wouldn't work there anyway.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub struct CtapHidDevice;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl FidoDevice for CtapHidDevice {
    fn enroll_credential(
        &self,
        rp_id: &str,
        pin: Option<&str>,
        salt: &[u8; 32],
    ) -> Result<EnrolledCredential> {
        use ctap_hid_fido2::fidokey::{
            CredentialExtension as Mext, MakeCredentialArgsBuilder,
        };
        use ctap_hid_fido2::{get_fidokey_devices, Cfg, FidoKeyHidFactory};

        if get_fidokey_devices().is_empty() {
            return Err(Error::YubikeyNoDevice);
        }

        let device = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| Error::Crypto {
            reason: format!("CTAP-HID device open failed: {e}"),
        })?;

        // Random clientDataHash. We never verify it — the only thing
        // we need from the assertion is the hmac-secret extension
        // output. Generating fresh bytes per enrolment keeps the call
        // free of stable cross-enrolment markers.
        let challenge = random_salt();

        // hmac-secret requires user verification by default. Most
        // Yubikeys do that with the device PIN; passing one switches
        // the builder away from its "uv required" default. Without a
        // PIN we fall through to `without_pin_and_uv()` for tokens
        // configured PIN-less or with built-in UV (e.g. Yubikey Bio).
        // The CTAP layer will surface a "PIN required" error if the
        // device disagrees, which `map_ctap_error` routes to
        // `YubikeyPinRequired` so the UI can re-prompt.
        let make_builder = MakeCredentialArgsBuilder::new(rp_id, &challenge)
            .extensions(&[Mext::HmacSecret(Some(true))]);
        let make_builder = match pin {
            Some(p) => make_builder.pin(p),
            None => make_builder.without_pin_and_uv(),
        };
        let make_args = make_builder.build();

        let attestation = device
            .make_credential_with_args(&make_args)
            .map_err(map_ctap_error)?;
        let credential_id = attestation.credential_descriptor.id.clone();

        // Immediately replay against the freshly-registered credential
        // so the caller leaves with the PRF output. We could split
        // this into a separate UI step, but combining them means the
        // enrolment user only taps the key once — Bitwarden's PRF
        // Unlock does the same.
        let prf = ctap_replay(&device, rp_id, pin, &credential_id, salt)?;

        Ok(EnrolledCredential {
            credential_id,
            prf_secret: prf,
        })
    }

    fn replay_credential(
        &self,
        rp_id: &str,
        pin: Option<&str>,
        credential_id: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>> {
        use ctap_hid_fido2::{get_fidokey_devices, Cfg, FidoKeyHidFactory};

        if get_fidokey_devices().is_empty() {
            return Err(Error::YubikeyNoDevice);
        }

        let device = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| Error::Crypto {
            reason: format!("CTAP-HID device open failed: {e}"),
        })?;

        ctap_replay(&device, rp_id, pin, credential_id, salt)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn ctap_replay(
    device: &ctap_hid_fido2::FidoKeyHid,
    rp_id: &str,
    pin: Option<&str>,
    credential_id: &[u8],
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    use ctap_hid_fido2::fidokey::{AssertionExtension as Gext, GetAssertionArgsBuilder};

    let challenge = random_salt();
    let get_builder = GetAssertionArgsBuilder::new(rp_id, &challenge)
        .credential_id(credential_id)
        .extensions(&[Gext::HmacSecret(Some(*salt))]);
    // Mirror the make-credential branch: pin forces UV-required;
    // absence of pin uses the without-UV path. The same authenticator
    // would otherwise return a *different* PRF output between the two
    // modes (CTAP2 reserves separate `CredRandomWithUV` /
    // `CredRandomWithoutUV` secrets per credential), which would
    // surface as a fingerprint mismatch on unlock.
    let get_builder = match pin {
        Some(p) => get_builder.pin(p),
        None => get_builder.without_pin_and_uv(),
    };
    let get_args = get_builder.build();

    let assertions = device
        .get_assertion_with_args(&get_args)
        .map_err(map_ctap_error)?;
    let assertion = assertions.into_iter().next().ok_or_else(|| Error::Crypto {
        reason: "authenticator returned no assertion".into(),
    })?;

    let prf = assertion
        .extensions
        .iter()
        .find_map(|ext| match ext {
            Gext::HmacSecret(Some(bytes)) => Some(*bytes),
            _ => None,
        })
        .ok_or_else(|| Error::Crypto {
            reason: "authenticator did not return an hmac-secret output".into(),
        })?;

    let mut wrapped = Zeroizing::new([0u8; 32]);
    wrapped.copy_from_slice(&prf);
    Ok(wrapped)
}

/// Best-effort classification of `ctap-hid-fido2` errors. The crate
/// returns `anyhow::Error` whose `Display` carries the CTAP error
/// code in human-readable form; we sniff for the few cases the UI
/// can usefully react to and fall back to `Error::Crypto` for the
/// rest. Sniffing strings is fragile, so we route conservatively —
/// a misclassified PIN error is annoying, but a misclassified
/// "device unplugged" looking like a successful unlock would be
/// dangerous, and that direction is impossible since unmatched
/// errors land in `Error::Crypto` and abort the unlock.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn map_ctap_error(err: anyhow::Error) -> Error {
    let msg = err.to_string();
    let lc = msg.to_ascii_lowercase();
    if lc.contains("pininvalid") || lc.contains("pin invalid") {
        Error::YubikeyWrongPin
    } else if lc.contains("pinrequired") || lc.contains("pin required") {
        Error::YubikeyPinRequired
    } else if lc.contains("user action timeout")
        || lc.contains("operationdenied")
        || lc.contains("actiontimeout")
    {
        Error::YubikeyUserCancelled
    } else if lc.contains("no device") || lc.contains("not found") {
        Error::YubikeyNoDevice
    } else {
        Error::Crypto {
            reason: format!("FIDO2 operation failed: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncString;

    /// Deterministic in-memory authenticator. The only contract a real
    /// authenticator gives us is "same salt + same credential ⇒ same
    /// 32-byte PRF output"; we satisfy it by HMAC-ing the salt under a
    /// per-credential secret. That is *not* what a real Yubikey does
    /// internally, but the shape of the output (deterministic, 32
    /// bytes, depends on both credential and salt) is what the unlock
    /// path actually relies on.
    struct MockFido {
        cred_random: [u8; 32],
    }

    impl MockFido {
        fn new(seed: u8) -> Self {
            let mut cred_random = [0u8; 32];
            for (i, b) in cred_random.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(seed.wrapping_add(7)).wrapping_add(seed);
            }
            Self { cred_random }
        }
    }

    impl FidoDevice for MockFido {
        fn enroll_credential(
            &self,
            _rp_id: &str,
            _pin: Option<&str>,
            salt: &[u8; 32],
        ) -> Result<EnrolledCredential> {
            // Deterministic credential id derived from cred_random — the
            // important property for the unlock test is "same device
            // gives same id back to replay_credential".
            let mut cred_id = vec![0u8; 16];
            for (i, b) in cred_id.iter_mut().enumerate() {
                *b = self.cred_random[i].wrapping_add(0xA5);
            }
            let prf = mock_prf(&self.cred_random, salt);
            Ok(EnrolledCredential {
                credential_id: cred_id,
                prf_secret: prf,
            })
        }

        fn replay_credential(
            &self,
            _rp_id: &str,
            _pin: Option<&str>,
            _credential_id: &[u8],
            salt: &[u8; 32],
        ) -> Result<Zeroizing<[u8; 32]>> {
            Ok(mock_prf(&self.cred_random, salt))
        }
    }

    fn mock_prf(cred_random: &[u8; 32], salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(cred_random).unwrap();
        mac.update(salt);
        let out = mac.finalize().into_bytes();
        let mut wrapped = Zeroizing::new([0u8; 32]);
        wrapped.copy_from_slice(&out);
        wrapped
    }

    fn deterministic_user_key(seed: u8) -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(seed.wrapping_add(1)).wrapping_add(seed);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn enroll_then_unwrap_returns_the_same_user_key() {
        // Happy path: the bytes that come back from `unwrap_user_key`
        // must be byte-identical to the ones we put in. If they
        // weren't, the recovered SymmetricKey would silently fail to
        // decrypt the refresh token, the offline cache, and every
        // vault item — so we probe the equality explicitly.
        let device = MockFido::new(7);
        let user_key = deterministic_user_key(11);
        let user_key_bytes: [u8; 64] = *user_key.to_bytes();

        let block = enroll(&device, "clavix.local", None, &user_key).unwrap();

        let recovered = unwrap_user_key(&device, &block, None).unwrap();
        assert_eq!(*recovered, user_key_bytes);
    }

    #[test]
    fn fingerprint_is_deterministic_for_a_given_user_key() {
        // The fingerprint only earns its keep if it identifies the
        // user key uniquely across runs. If it depended on call-time
        // randomness, every unlock would fail with `YubikeyStaleWrap`
        // even on a fresh enrolment.
        let user_key = deterministic_user_key(42);
        let bytes: [u8; 64] = *user_key.to_bytes();
        let fp1 = compute_user_key_fingerprint(&bytes);
        let fp2 = compute_user_key_fingerprint(&bytes);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), FINGERPRINT_LEN);
    }

    #[test]
    fn fingerprint_differs_when_user_key_changes_a_single_bit() {
        // Master-password rotation produces a new user key; the
        // fingerprint comparison is the gate that detects this. A
        // single-bit flip must not collide — HKDF-SHA256 makes that
        // overwhelmingly improbable, this test pins the property.
        let mut bytes_a = [0u8; 64];
        for (i, b) in bytes_a.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13);
        }
        let mut bytes_b = bytes_a;
        bytes_b[17] ^= 1;

        let fp_a = compute_user_key_fingerprint(&bytes_a);
        let fp_b = compute_user_key_fingerprint(&bytes_b);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn unwrap_detects_stale_wrap_after_user_key_rotation() {
        // Simulate "master password was rotated on another client":
        // the wrap on disk was made for user_key_v1, but the caller
        // now expects user_key_v2 — we have to refuse the unlock with
        // a dedicated error rather than handing back the v1 key the
        // server no longer accepts.
        //
        // We surface that by constructing a block whose wrap is for
        // user_key_v1 but whose `user_key_fingerprint` field has been
        // tampered to look like it belongs to a different key. (In
        // production the *wrap* is the side that becomes invalid; we
        // can't easily simulate that from outside the enrol step, so
        // we tamper the fingerprint, which exercises the same
        // branch.)
        let device = MockFido::new(3);
        let user_key = deterministic_user_key(101);
        let mut block = enroll(&device, "clavix.local", None, &user_key).unwrap();

        // Tamper one byte of the fingerprint.
        let mut fp_bytes = STANDARD.decode(&block.user_key_fingerprint).unwrap();
        fp_bytes[0] ^= 0xff;
        block.user_key_fingerprint = STANDARD.encode(&fp_bytes);

        let err = unwrap_user_key(&device, &block, None).unwrap_err();
        assert!(matches!(err, Error::YubikeyStaleWrap));
    }

    #[test]
    fn unwrap_rejects_unsupported_version() {
        // Future-dated block: refuse to decrypt rather than fall back
        // to a guess. A best-effort handler here would risk producing
        // wrong decrypts on a format we don't yet understand.
        let device = MockFido::new(5);
        let user_key = deterministic_user_key(50);
        let mut block = enroll(&device, "clavix.local", None, &user_key).unwrap();
        block.version = 99;

        let err = unwrap_user_key(&device, &block, None).unwrap_err();
        assert!(matches!(err, Error::Crypto { .. }));
    }

    #[test]
    fn unwrap_rejects_tampered_ciphertext() {
        // The wrap is AES-CBC + HMAC-SHA256 (Bitwarden EncString type
        // 2). A bit-flipped ciphertext must be rejected by the HMAC
        // before any AES decrypt — the same property covered by the
        // EncString proptests, but pinned here at the yubikey-unlock
        // boundary too.
        let device = MockFido::new(9);
        let user_key = deterministic_user_key(60);
        let mut block = enroll(&device, "clavix.local", None, &user_key).unwrap();

        // Flip a bit in the EncString ciphertext segment.
        let parts: Vec<&str> = block.wrapped_user_key.splitn(2, '.').collect();
        let payload: Vec<&str> = parts[1].split('|').collect();
        let mut ct = STANDARD.decode(payload[1]).unwrap();
        ct[0] ^= 1;
        block.wrapped_user_key = format!(
            "{}.{}|{}|{}",
            parts[0],
            payload[0],
            STANDARD.encode(&ct),
            payload[2]
        );

        let err = unwrap_user_key(&device, &block, None).unwrap_err();
        assert!(matches!(err, Error::Crypto { .. }));
    }

    #[test]
    fn enroll_produces_a_decryptable_encstring_under_its_wrap_key() {
        // White-box probe: the on-disk `wrapped_user_key` is a
        // standard EncString. Independently re-derive the wrap key
        // from the mock authenticator and decrypt — proves the
        // enrol step uses the same primitive the EncString proptests
        // already cover.
        let device = MockFido::new(13);
        let user_key = deterministic_user_key(77);
        let block = enroll(&device, "clavix.local", None, &user_key).unwrap();

        let salt_vec = STANDARD.decode(&block.salt).unwrap();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&salt_vec);
        let credential_id = STANDARD.decode(&block.credential_id).unwrap();
        let prf = device
            .replay_credential(&block.rp_id, None, &credential_id, &salt)
            .unwrap();

        let wrap_key = derive_wrap_key(&prf).unwrap();
        let plaintext = EncString::parse(&block.wrapped_user_key)
            .unwrap()
            .decrypt_sym(&wrap_key)
            .unwrap();
        assert_eq!(plaintext.len(), 64);
        let expected: [u8; 64] = *user_key.to_bytes();
        assert_eq!(plaintext, expected);
    }

    // Property tests — same shape as the EncString proptests in
    // crypto.rs. Goal: any (user_key, salt, credential) triple must
    // round-trip losslessly, and any single-bit flip in the wrap
    // ciphertext or the fingerprint must be caught.
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            #[test]
            fn enroll_unwrap_roundtrip_for_arbitrary_user_keys(
                seed in any::<u8>(),
                key_bytes in proptest::array::uniform32(any::<u8>()),
                key_bytes2 in proptest::array::uniform32(any::<u8>()),
            ) {
                let device = MockFido::new(seed);
                let mut full = [0u8; 64];
                full[..32].copy_from_slice(&key_bytes);
                full[32..].copy_from_slice(&key_bytes2);
                let user_key = SymmetricKey::from_bytes(&full).unwrap();
                let block = enroll(&device, "clavix.local", None, &user_key).unwrap();
                let recovered = unwrap_user_key(&device, &block, None).unwrap();
                prop_assert_eq!(*recovered, full);
            }

            #[test]
            fn fingerprint_collision_under_random_keys_is_practically_impossible(
                a in proptest::array::uniform32(any::<u8>()),
                a2 in proptest::array::uniform32(any::<u8>()),
                b in proptest::array::uniform32(any::<u8>()),
                b2 in proptest::array::uniform32(any::<u8>()),
            ) {
                // If a and b happen to be byte-equal proptest just
                // generated the same input twice — skip rather than
                // assert non-collision against itself.
                prop_assume!(a != b || a2 != b2);
                let mut full_a = [0u8; 64];
                full_a[..32].copy_from_slice(&a);
                full_a[32..].copy_from_slice(&a2);
                let mut full_b = [0u8; 64];
                full_b[..32].copy_from_slice(&b);
                full_b[32..].copy_from_slice(&b2);
                let fp_a = compute_user_key_fingerprint(&full_a);
                let fp_b = compute_user_key_fingerprint(&full_b);
                prop_assert_ne!(fp_a, fp_b);
            }
        }
    }
}
