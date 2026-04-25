//! WebAuthn (FIDO2) 2FA via CTAP2 over USB HID.
//!
//! Bitwarden/Vaultwarden gate their WebAuthn 2FA on provider id 7.  During
//! login the server returns a challenge shaped like a standard
//! `PublicKeyCredentialRequestOptions`; we drive a hardware authenticator
//! through it (no browser involved) and craft the
//! `PublicKeyCredential`-shaped response the server expects to receive as
//! a JSON blob in `twoFactorToken`.
//!
//! Origin trick: Tauri webviews don't run under the vault's domain, so a
//! browser-side `navigator.credentials.get()` would produce a
//! `clientDataJSON` with the wrong origin and the server would reject it.
//! We therefore build `clientDataJSON` ourselves with `origin =
//! https://{rpId}`.  The hardware key only signs the hash of whatever we
//! give it; there is no origin enforcement at that layer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
struct RawAllowCredential {
    id: String,
    #[serde(default)]
    #[serde(rename = "type")]
    _kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawChallenge {
    challenge: String,
    #[serde(rename = "rpId")]
    rp_id: String,
    #[serde(default, rename = "allowCredentials")]
    allow_credentials: Vec<RawAllowCredential>,
    #[serde(default, rename = "userVerification")]
    _user_verification: Option<String>,
    #[serde(default)]
    _timeout: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: &'a str,
    origin: String,
    cross_origin: bool,
}

#[derive(Debug, Serialize)]
struct ResponseBody {
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
    #[serde(rename = "userHandle")]
    user_handle: String,
}

#[derive(Debug, Serialize)]
struct CredentialResponse {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    response: ResponseBody,
    extensions: serde_json::Value,
}

fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    // Vaultwarden sometimes emits base64 with `+` / `/` / padding; accept
    // both flavours to stay robust.
    let cleaned = s
        .trim()
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    URL_SAFE_NO_PAD.decode(cleaned).map_err(|e| Error::Crypto {
        reason: format!("base64url decode: {e}"),
    })
}

fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validate that `rp_id` is the user-facing host of `server_url` or a
/// registrable suffix of it. Without this check, a hostile (or MITM'd)
/// Vaultwarden can pick any `rpId` it likes and trick the FIDO2 token
/// into signing an assertion that is valid for an unrelated origin.
///
/// Acceptance rule (matches the WebAuthn spec's "registrable domain
/// suffix" notion at the textual level — we don't pull in the full
/// public suffix list, but the comparison is strict enough that an
/// attacker can't pass `rpId="attacker.com"` for `server="vault.x.y"`):
///   - exact match: host == rp_id
///   - subdomain match: host ends with `.{rp_id}`
fn validate_rp_id(rp_id: &str, server_url: &str) -> Result<()> {
    let rp_id = rp_id.trim().to_ascii_lowercase();
    if rp_id.is_empty() || rp_id.contains('/') || rp_id.contains(':') {
        return Err(Error::InvalidResponse {
            reason: format!("malformed rpId from server: {rp_id:?}"),
        });
    }

    let host = url::Url::parse(server_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .ok_or_else(|| Error::InvalidResponse {
            reason: format!("server_url has no host: {server_url}"),
        })?;

    if host == rp_id || host.ends_with(&format!(".{rp_id}")) {
        Ok(())
    } else {
        Err(Error::Crypto {
            reason: format!(
                "WebAuthn rpId {rp_id:?} is not a registrable suffix of server host {host:?} — refusing to sign"
            ),
        })
    }
}

/// Blocking call that talks to the first attached FIDO2 device.  Meant to
/// be invoked from a Tauri async command via
/// `tauri::async_runtime::spawn_blocking`.
pub fn sign_bitwarden_challenge(challenge_json: &str, server_url: &str) -> Result<String> {
    let raw: RawChallenge =
        serde_json::from_str(challenge_json).map_err(|e| Error::InvalidResponse {
            reason: format!("webauthn challenge parse: {e}"),
        })?;

    validate_rp_id(&raw.rp_id, server_url)?;

    // 1. Construct clientDataJSON exactly like a browser would.  The
    //    stringification has to be byte-stable because the authenticator
    //    signs its SHA-256 hash — any field reordering and the server
    //    rejects the assertion.
    let client_data = serde_json::to_string(&ClientData {
        kind: "webauthn.get",
        challenge: &raw.challenge, // already base64url, pass through
        origin: format!("https://{}", raw.rp_id),
        cross_origin: false,
    })
    .map_err(|e| Error::Crypto {
        reason: format!("clientDataJSON serialize: {e}"),
    })?;
    let client_data_hash: [u8; 32] = Sha256::digest(client_data.as_bytes()).into();

    // 2. Decode allowed credential IDs.
    let cred_ids: Vec<Vec<u8>> = raw
        .allow_credentials
        .iter()
        .map(|c| b64url_decode(&c.id))
        .collect::<Result<_>>()?;

    // 3. Ask the connected authenticator for an assertion.  Runs CTAP2
    //    over HID; user must touch the key.  60 s server timeout.
    let assertion = ctap_assertion(&raw.rp_id, &client_data_hash, cred_ids)?;

    // 4. Shape the response the way Bitwarden/Vaultwarden expects.
    let cred_id_b64 = b64url_encode(&assertion.credential_id);
    let body = CredentialResponse {
        id: cred_id_b64.clone(),
        raw_id: cred_id_b64,
        kind: "public-key",
        response: ResponseBody {
            authenticator_data: b64url_encode(&assertion.auth_data),
            client_data_json: b64url_encode(client_data.as_bytes()),
            signature: b64url_encode(&assertion.signature),
            user_handle: assertion
                .user_handle
                .as_deref()
                .map(b64url_encode)
                .unwrap_or_default(),
        },
        extensions: serde_json::json!({}),
    };

    serde_json::to_string(&body).map_err(|e| Error::Crypto {
        reason: format!("assertion serialize: {e}"),
    })
}

struct Assertion {
    credential_id: Vec<u8>,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn ctap_assertion(_rp_id: &str, _hash: &[u8; 32], _ids: Vec<Vec<u8>>) -> Result<Assertion> {
    Err(Error::Crypto {
        reason: "FIDO2 not supported on this platform".into(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn ctap_assertion(rp_id: &str, hash: &[u8; 32], ids: Vec<Vec<u8>>) -> Result<Assertion> {
    use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

    let device = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| Error::Crypto {
        reason: format!("no FIDO2 device available: {e}"),
    })?;

    let mut builder = GetAssertionArgsBuilder::new(rp_id, hash);
    for id in ids {
        builder = builder.credential_id(&id);
    }
    let args = builder.build();

    let assertions = device
        .get_assertion_with_args(&args)
        .map_err(|e| Error::Crypto {
            reason: format!("FIDO2 get_assertion failed: {e}"),
        })?;

    let picked = assertions.into_iter().next().ok_or_else(|| Error::Crypto {
        reason: "authenticator returned no assertion".into(),
    })?;

    Ok(Assertion {
        credential_id: picked.credential_id,
        auth_data: picked.auth_data,
        signature: picked.signature,
        user_handle: if picked.user.id.is_empty() {
            None
        } else {
            Some(picked.user.id)
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip_standard_alphabet() {
        let raw: &[u8] = &[0, 255, 170, 17, 34, 128];
        let enc = b64url_encode(raw);
        assert!(!enc.contains('='), "no padding: {enc}");
        let dec = b64url_decode(&enc).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn b64url_decode_accepts_standard_b64() {
        let with_padding = "YWJjZA==";
        let dec = b64url_decode(with_padding).unwrap();
        assert_eq!(dec, b"abcd");
    }

    #[test]
    fn b64url_decode_rejects_garbage() {
        assert!(b64url_decode("not*valid*base64").is_err());
    }

    #[test]
    fn challenge_json_parses_the_shape_vaultwarden_sends() {
        let json = r#"{
            "challenge":"abc-challenge",
            "rpId":"vault.example.com",
            "allowCredentials":[{"id":"Y3JlZGVudGlhbA","type":"public-key"}],
            "userVerification":"discouraged",
            "timeout":60000
        }"#;
        let parsed: RawChallenge = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.rp_id, "vault.example.com");
        assert_eq!(parsed.challenge, "abc-challenge");
        assert_eq!(parsed.allow_credentials.len(), 1);
        assert_eq!(parsed.allow_credentials[0].id, "Y3JlZGVudGlhbA");
    }

    #[test]
    fn challenge_json_tolerates_missing_allow_credentials() {
        let json = r#"{"challenge":"x","rpId":"y"}"#;
        let parsed: RawChallenge = serde_json::from_str(json).unwrap();
        assert!(parsed.allow_credentials.is_empty());
    }

    #[test]
    fn client_data_json_is_stable_and_well_formed() {
        let data = serde_json::to_string(&ClientData {
            kind: "webauthn.get",
            challenge: "abc",
            origin: "https://vault.example.com".into(),
            cross_origin: false,
        })
        .unwrap();
        // Vaultwarden / the authenticator signs the SHA-256 of this exact
        // string, so any reordering here would silently break 2FA.
        assert_eq!(
            data,
            r#"{"type":"webauthn.get","challenge":"abc","origin":"https://vault.example.com","crossOrigin":false}"#
        );
    }

    #[test]
    fn sign_bitwarden_challenge_reports_missing_device_as_crypto_error() {
        // rpId matches server host, so validate_rp_id passes. The error
        // bubbles up later from the missing FIDO2 device. We assert
        // Error::Crypto specifically because the rpId-mismatch path also
        // returns Error::Crypto — the next two tests guard against false
        // positives by comparing the error message.
        let json =
            r#"{"challenge":"Y2hhbGxlbmdl","rpId":"vault.example.com","allowCredentials":[]}"#;
        let res = sign_bitwarden_challenge(json, "https://vault.example.com");
        match res {
            Err(Error::Crypto { reason }) => {
                assert!(
                    !reason.contains("registrable suffix"),
                    "rpId path should not have triggered, got: {reason}"
                );
            }
            other => panic!("expected Error::Crypto, got {other:?}"),
        }
    }

    #[test]
    fn validate_rp_id_accepts_exact_host_match() {
        assert!(validate_rp_id("vault.example.com", "https://vault.example.com").is_ok());
        assert!(validate_rp_id("vault.example.com", "https://vault.example.com:8443").is_ok());
        assert!(validate_rp_id("vault.example.com", "https://vault.example.com/path").is_ok());
    }

    #[test]
    fn validate_rp_id_accepts_apex_when_user_logs_into_subdomain() {
        // Vaultwarden admins sometimes register the FIDO2 credential at
        // the apex domain even though users connect via a subdomain.
        // Spec calls this "registrable suffix" — we accept it so users
        // with apex-registered keys can still log in.
        assert!(validate_rp_id("example.com", "https://vault.example.com").is_ok());
    }

    #[test]
    fn validate_rp_id_rejects_unrelated_domain() {
        // Hostile or MITM'd server tries to make us sign an assertion
        // for an unrelated origin. This is the whole point of the check.
        let err = validate_rp_id("attacker.com", "https://vault.example.com").unwrap_err();
        assert!(matches!(err, Error::Crypto { .. }));
    }

    #[test]
    fn validate_rp_id_rejects_suffix_lookalike() {
        // "example.com.attacker.com" trivially "ends with example.com"
        // string-wise, but the registrable-suffix rule requires the
        // dot-separated boundary. Make sure we don't naively substring.
        let err = validate_rp_id("example.com", "https://example.com.attacker.com").unwrap_err();
        assert!(matches!(err, Error::Crypto { .. }));
    }

    #[test]
    fn validate_rp_id_rejects_malformed_rp_id() {
        assert!(validate_rp_id("", "https://vault.example.com").is_err());
        assert!(validate_rp_id("https://vault.example.com", "https://vault.example.com").is_err());
        assert!(validate_rp_id("vault.example.com/x", "https://vault.example.com").is_err());
    }

    #[test]
    fn validate_rp_id_is_case_insensitive() {
        // Hosts are case-insensitive by spec; some servers are sloppy
        // about casing in the rpId field.
        assert!(validate_rp_id("Vault.Example.Com", "https://vault.example.com").is_ok());
        assert!(validate_rp_id("vault.example.com", "https://VAULT.EXAMPLE.COM").is_ok());
    }
}
