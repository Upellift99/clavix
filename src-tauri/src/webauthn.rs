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
    #[serde(default)]
    extensions: Option<RawExtensions>,
}

#[derive(Debug, Deserialize)]
struct RawExtensions {
    /// FIDO AppID extension. Present when the account has a security key that
    /// was originally enrolled over U2F: the key handle is bound to
    /// `SHA256(appid)` rather than `SHA256(rpId)`, so the assertion has to be
    /// produced under the appId and echoed back with `appid: true`.
    #[serde(default)]
    appid: Option<String>,
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
    // Omit `userHandle` entirely when the authenticator returns none, exactly
    // as a browser does. Sending `"userHandle": ""` deserializes server-side to
    // `Some(empty)` rather than `None`, and webauthn-rs then rejects the
    // assertion with a bare "Webauthn" — a non-resident 2FA key has no user
    // handle to send.
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    user_handle: Option<String>,
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

/// Validate that `rp_id` is **exactly** the user-facing host of
/// `server_url`. Without this check, a hostile (or MITM'd) Vaultwarden
/// can pick any `rpId` it likes and trick the FIDO2 token into signing
/// an assertion valid for an unrelated origin.
///
/// We deliberately do **not** accept registrable suffixes:
///
/// 1. Doing so correctly requires the Public Suffix List (otherwise
///    `rpId="com"` slips through against `vault.example.com` because
///    `.com` is a textual suffix). PSL is a non-trivial dependency.
/// 2. The "user logs into a subdomain but the FIDO2 credential is
///    registered on the apex domain" case is rare for self-hosted
///    Vaultwarden — the typical setup uses `rpId == host`.
/// 3. If someone really needs the apex case, it can be added later
///    behind an explicit per-account opt-in (e.g. a stored
///    `accepted_rp_id` distinct from the host) so the trust decision
///    is made once by the human, not on every login by a remote
///    server.
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

    if host == rp_id {
        Ok(())
    } else {
        Err(Error::Crypto {
            reason: format!(
                "WebAuthn rpId {rp_id:?} does not match server host {host:?} exactly — refusing to sign"
            ),
        })
    }
}

/// Validate a FIDO AppID before signing under it. The appId is a full URL
/// (e.g. `https://pass.example.com/app-id.json`); accept it only when it is
/// https and its host matches the server's host. `validate_rp_id` already
/// pins the rpId to that same host, so this keeps the appId path from being
/// abused by a hostile server to make the key sign for an unrelated origin.
fn validate_app_id(app_id: &str, server_url: &str) -> Result<()> {
    let app = url::Url::parse(app_id.trim()).map_err(|_| Error::Crypto {
        reason: format!("malformed WebAuthn appId from server: {app_id:?}"),
    })?;
    if app.scheme() != "https" {
        return Err(Error::Crypto {
            reason: format!("WebAuthn appId is not https: {app_id:?} — refusing to sign"),
        });
    }
    let app_host = app.host_str().map(str::to_ascii_lowercase);
    let server_host = url::Url::parse(server_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    match (app_host, server_host) {
        (Some(a), Some(s)) if a == s => Ok(()),
        (app_host, _) => Err(Error::Crypto {
            reason: format!(
                "WebAuthn appId host {app_host:?} does not match server host — refusing to sign"
            ),
        }),
    }
}

/// Pick the credential id to echo back to the server. Prefer the one the
/// authenticator returned, but fall back to the single requested id when the
/// authenticator omitted it — CTAP2 permits omitting the credential when the
/// allowList held exactly one entry, and an empty `id`/`rawId` makes the
/// server unable to find the credential (bare "Webauthn" rejection).
fn effective_credential_id(from_assertion: &[u8], requested: &[Vec<u8>]) -> Vec<u8> {
    if !from_assertion.is_empty() {
        from_assertion.to_vec()
    } else {
        requested.first().cloned().unwrap_or_default()
    }
}

/// True when the authenticator reported that none of the allowed credentials
/// exist under the requested rpId — CTAP2_ERR_NO_CREDENTIALS (0x2E). A key
/// answers this without asking for a touch, which is what lets us probe the
/// appId first and cheaply fall back to the rpId.
fn is_no_credentials(e: &Error) -> bool {
    matches!(e, Error::Crypto { reason }
        if reason.contains("0x2E") || reason.to_ascii_uppercase().contains("NO_CREDENTIALS"))
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
    //
    //    Try the rpId first: a natively-registered WebAuthn key (the common
    //    case) is bound to the rpId and asserts here in a single touch. Only
    //    if the key has no credential under the rpId
    //    (CTAP2_ERR_NO_CREDENTIALS) do we fall back to the FIDO AppID
    //    extension: Vaultwarden ships `extensions.appid` so a key enrolled
    //    back in the U2F era — whose handle is bound to `SHA256(appId)`, not
    //    `SHA256(rpId)` — still works, provided we sign under the appId and
    //    echo `appid: true`.
    let app_id = raw
        .extensions
        .as_ref()
        .and_then(|e| e.appid.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let (assertion, appid_used) =
        match ctap_assertion(&raw.rp_id, &client_data_hash, cred_ids.clone()) {
            Ok(a) => (a, false),
            Err(e) if is_no_credentials(&e) => match app_id {
                Some(app_id) => {
                    validate_app_id(app_id, server_url)?;
                    (
                        ctap_assertion(app_id, &client_data_hash, cred_ids.clone())?,
                        true,
                    )
                }
                None => return Err(e),
            },
            Err(e) => return Err(e),
        };

    // 4. Shape the response the way Bitwarden/Vaultwarden expects. When the
    //    assertion was produced under the appId, echo `appid: true` so the
    //    server verifies the rpIdHash against the appId instead of the rpId.
    //
    //    CTAP2 lets the authenticator OMIT the credential from the response
    //    when the allowList held exactly one entry (YubiKeys do exactly this).
    //    That left `id`/`rawId` empty, so Vaultwarden could not identify which
    //    credential signed and rejected the login with a bare "Webauthn". Fall
    //    back to the single requested credential id in that case.
    let credential_id = effective_credential_id(&assertion.credential_id, &cred_ids);
    let cred_id_b64 = b64url_encode(&credential_id);
    let body = CredentialResponse {
        id: cred_id_b64.clone(),
        raw_id: cred_id_b64,
        kind: "public-key",
        response: ResponseBody {
            authenticator_data: b64url_encode(&assertion.auth_data),
            client_data_json: b64url_encode(client_data.as_bytes()),
            signature: b64url_encode(&assertion.signature),
            // Only include a user handle when the authenticator actually
            // returned a non-empty one (resident keys); otherwise omit it,
            // like a browser does.
            user_handle: assertion
                .user_handle
                .as_deref()
                .filter(|h| !h.is_empty())
                .map(b64url_encode),
        },
        // Echo the `appid` result whenever the server offered the extension —
        // `true` if we asserted under the appId, `false` if under the rpId.
        // A browser sends exactly `{"appid": false}` in the rpId case; sending
        // `{}` instead is one of the shapes webauthn-rs rejects. When the
        // challenge carried no appid extension, send `{}`.
        extensions: if app_id.is_some() {
            serde_json::json!({ "appid": appid_used })
        } else {
            serde_json::json!({})
        },
    };

    let json = serde_json::to_string(&body).map_err(|e| Error::Crypto {
        reason: format!("assertion serialize: {e}"),
    })?;
    // Diagnostic (no secrets — everything here is sent to the server anyway):
    // makes the exact shape visible from a terminal launch when a login is
    // rejected, so the credential-id / appid path can be confirmed.
    eprintln!(
        "[clavix] webauthn assertion: id_len={} appid_used={} omitted_credential={}",
        credential_id.len(),
        appid_used,
        assertion.credential_id.is_empty(),
    );
    Ok(json)
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

    // `GetAssertionArgs::default()` ships `uv: Some(true)`, so the builder
    // would put `{ up: true, uv: true }` in the CTAP2 options map. A standard
    // YubiKey (5-series, no on-device biometric) does not implement the `uv`
    // option and answers CTAP2_ERR_UNSUPPORTED_OPTION (0x2B) — which is exactly
    // the failure users hit logging in with their key. WebAuthn used as a
    // *second factor* only needs user presence (a touch); Vaultwarden requests
    // `userVerification: "discouraged"` and never inspects the UV flag. So drop
    // the `uv` option entirely and let the key assert on touch alone.
    let mut builder = GetAssertionArgsBuilder::new(rp_id, hash).without_pin_and_uv();
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
    fn challenge_json_reads_the_appid_extension() {
        // The exact shape Vaultwarden sends for a U2F-enrolled key.
        let json = r#"{
            "challenge":"8woBZU0K",
            "rpId":"pass.clicface.fr",
            "allowCredentials":[{"id":"Y3JlZA","type":"public-key"}],
            "extensions":{"appid":"https://pass.clicface.fr/app-id.json"},
            "userVerification":"discouraged"
        }"#;
        let parsed: RawChallenge = serde_json::from_str(json).unwrap();
        assert_eq!(
            parsed.extensions.and_then(|e| e.appid).as_deref(),
            Some("https://pass.clicface.fr/app-id.json"),
        );
    }

    #[test]
    fn challenge_json_without_extensions_has_no_appid() {
        let json = r#"{"challenge":"x","rpId":"y"}"#;
        let parsed: RawChallenge = serde_json::from_str(json).unwrap();
        assert!(parsed.extensions.is_none());
    }

    #[test]
    fn validate_app_id_accepts_same_host_https() {
        assert!(validate_app_id(
            "https://pass.clicface.fr/app-id.json",
            "https://pass.clicface.fr",
        )
        .is_ok());
    }

    #[test]
    fn validate_app_id_rejects_a_foreign_host() {
        // A hostile server must not point the appId at another origin.
        assert!(validate_app_id(
            "https://attacker.example/app-id.json",
            "https://pass.clicface.fr",
        )
        .is_err());
    }

    #[test]
    fn validate_app_id_rejects_non_https() {
        assert!(validate_app_id(
            "http://pass.clicface.fr/app-id.json",
            "https://pass.clicface.fr",
        )
        .is_err());
    }

    #[test]
    fn effective_credential_id_prefers_the_asserted_id() {
        let asserted = vec![1u8, 2, 3];
        let requested = vec![vec![9u8, 9, 9]];
        assert_eq!(
            effective_credential_id(&asserted, &requested),
            vec![1u8, 2, 3]
        );
    }

    #[test]
    fn effective_credential_id_falls_back_when_the_authenticator_omits_it() {
        // Single-entry allowList: a YubiKey may omit the credential, leaving
        // the asserted id empty. We must echo the requested id instead.
        let asserted: Vec<u8> = Vec::new();
        let requested = vec![vec![9u8, 9, 9]];
        assert_eq!(
            effective_credential_id(&asserted, &requested),
            vec![9u8, 9, 9]
        );
    }

    #[test]
    fn response_body_omits_an_absent_user_handle() {
        // A browser omits `userHandle` for a non-resident 2FA key; sending
        // `"userHandle":""` instead makes webauthn-rs reject the assertion.
        let body = ResponseBody {
            authenticator_data: "ad".into(),
            client_data_json: "cdj".into(),
            signature: "sig".into(),
            user_handle: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("userHandle"), "must be omitted: {json}");
    }

    #[test]
    fn response_body_keeps_a_present_user_handle() {
        let body = ResponseBody {
            authenticator_data: "ad".into(),
            client_data_json: "cdj".into(),
            signature: "sig".into(),
            user_handle: Some("dWg".into()),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains(r#""userHandle":"dWg""#), "{json}");
    }

    #[test]
    fn is_no_credentials_matches_only_the_no_credentials_status() {
        let no_cred = Error::Crypto {
            reason: "FIDO2 get_assertion failed: response_status err = 0x2E \
                     CTAP2_ERR_NO_CREDENTIALS No Credentials."
                .into(),
        };
        assert!(is_no_credentials(&no_cred));

        // The unsupported-option status (0x2B) must NOT be treated as a
        // no-credentials fallback trigger.
        let unsupported = Error::Crypto {
            reason: "FIDO2 get_assertion failed: response_status err = 0x2B \
                     CTAP2_ERR_UNSUPPORTED_OPTION"
                .into(),
        };
        assert!(!is_no_credentials(&unsupported));
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
        // rpId matches server host exactly, so validate_rp_id passes.
        // The error bubbles up later from the missing FIDO2 device. We
        // assert Error::Crypto specifically and check the message does
        // not mention the rpId path — the rpId-mismatch path also
        // returns Error::Crypto, so a regression that silently moved
        // the failure earlier would otherwise stay invisible.
        let json =
            r#"{"challenge":"Y2hhbGxlbmdl","rpId":"vault.example.com","allowCredentials":[]}"#;
        let res = sign_bitwarden_challenge(json, "https://vault.example.com");
        match res {
            Err(Error::Crypto { reason }) => {
                assert!(
                    !reason.contains("does not match server host"),
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
    fn validate_rp_id_rejects_apex_even_when_user_logs_into_subdomain() {
        // Without a Public Suffix List we can't tell "example.com" (a
        // legitimate apex) from "com" (a TLD a hostile server could
        // pass to widen its reach). To stay strict by default we
        // reject every non-exact match, including legitimate apexes.
        // If someone truly needs the apex case it should be a per-
        // account explicit opt-in, not a server-driven decision.
        let err = validate_rp_id("example.com", "https://vault.example.com").unwrap_err();
        assert!(matches!(err, Error::Crypto { .. }));
    }

    #[test]
    fn validate_rp_id_rejects_bare_tld() {
        // Regression guard: prior implementation accepted any DNS
        // suffix, so rpId="com" matched vault.example.com. Strict
        // exact-match closes this.
        let err = validate_rp_id("com", "https://vault.example.com").unwrap_err();
        assert!(matches!(err, Error::Crypto { .. }));
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
        // "example.com.attacker.com" superficially "ends with example.com"
        // string-wise. With strict exact match this is a non-issue, but
        // the test still pulls its weight: it pins the behaviour so a
        // future "let's loosen this back to suffix matching" change
        // can't sneak past review without either flipping this test or
        // facing the question head-on.
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
