use serde::{Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid URL: {url}")]
    InvalidUrl { url: String },

    #[error("Network error: {source}")]
    Network {
        #[from]
        source: reqwest::Error,
    },

    #[error("Invalid server response: {reason}")]
    InvalidResponse { reason: String },

    #[error("HTTP error {status}: {message}")]
    HttpStatus { status: u16, message: String },

    #[error("Authentication failed: {message}")]
    AuthFailed { message: String },

    #[error("Crypto derivation error: {reason}")]
    Crypto { reason: String },

    #[error("Unsupported 2FA provider: {provider}")]
    TwoFactorProviderUnsupported { provider: u8 },

    #[error("No active session — please sign in")]
    NotAuthenticated,

    #[error("Local storage error: {reason}")]
    Storage { reason: String },

    #[error("SSH private key is passphrase-protected — passphrase required")]
    SshPassphraseRequired,

    #[error("SSH passphrase is incorrect")]
    SshWrongPassphrase,

    #[error("No FIDO2 device found — plug in your security key and retry")]
    YubikeyNoDevice,

    #[error("This security key requires a PIN")]
    YubikeyPinRequired,

    #[error("PIN refused by the security key")]
    YubikeyWrongPin,

    #[error("Operation cancelled on the security key")]
    YubikeyUserCancelled,

    /// Saved Yubikey wrap was produced under a previous user key (the
    /// master password was rotated on another client). The frontend
    /// should prompt for re-enrolment after a master-password unlock.
    #[error("Yubikey wrap is stale — re-enrol after signing in with your master password")]
    YubikeyStaleWrap,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Map a Vaultwarden/Bitwarden auth-error message to a stable code
/// the renderer can switch on for localisation. Returns `None` when
/// the message doesn't match any known pattern — the caller then
/// surfaces the raw `message` verbatim, which is what the UI did
/// before this lookup landed.
///
/// Patterns observed against Vaultwarden 1.35.7 (the version used in
/// the E2E suite) and the Bitwarden upstream that Vaultwarden mirrors
/// on `/identity/connect/token`. Order matters — the classifier
/// returns on the first hit, so put the more specific patterns first.
fn classify_auth_message(message: &str) -> Option<&'static str> {
    let lower = message.to_ascii_lowercase();

    // 2FA second-factor failure. Catches both the Vaultwarden message
    // and the synthetic "2FA code rejected by the server" string our
    // own client sets in `api::login_with_two_factor` when the server
    // responds TwoFactorRequired *again* on the second-step call.
    if lower.contains("two-step")
        || lower.contains("two-factor")
        || lower.contains("two factor")
        || lower.contains("totp code")
        || lower.contains("2fa code rejected")
    {
        return Some("two_factor_invalid");
    }

    // Refresh-token grant failures. Vaultwarden returns "Refresh token
    // expired" verbatim or, on slightly older builds, the OAuth
    // generic "invalid_grant" with no `message`.
    if lower.contains("refresh token")
        && (lower.contains("expired")
            || lower.contains("invalid")
            || lower.contains("not found"))
    {
        return Some("refresh_expired");
    }

    // Captcha gating — Vaultwarden enables this under brute-force
    // suspicion. The user has to solve it on the web UI first.
    if lower.contains("captcha") {
        return Some("captcha_required");
    }

    // Wrong email / password on the password grant. Bitwarden upstream
    // returns "Username or password is incorrect" word-for-word;
    // Vaultwarden also surfaces "Invalid password" / "Bad password".
    if lower.contains("username or password is incorrect")
        || lower.contains("invalid password")
        || lower.contains("bad password")
        || lower == "invalid_grant"
    {
        return Some("invalid_credentials");
    }

    // Unknown account on prelogin / login.
    if lower.contains("user does not exist") || lower.contains("username does not exist") {
        return Some("user_not_found");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognises_invalid_credentials() {
        assert_eq!(
            classify_auth_message("Username or password is incorrect. Try again."),
            Some("invalid_credentials"),
        );
        assert_eq!(
            classify_auth_message("Invalid password"),
            Some("invalid_credentials"),
        );
        assert_eq!(
            classify_auth_message("invalid_grant"),
            Some("invalid_credentials"),
        );
    }

    #[test]
    fn classify_recognises_two_factor_failures() {
        assert_eq!(
            classify_auth_message("Two-step token is invalid."),
            Some("two_factor_invalid"),
        );
        assert_eq!(
            classify_auth_message("2FA code rejected by the server"),
            Some("two_factor_invalid"),
        );
        assert_eq!(
            classify_auth_message("Invalid TOTP code"),
            Some("two_factor_invalid"),
        );
    }

    #[test]
    fn classify_recognises_refresh_expired() {
        assert_eq!(
            classify_auth_message("Refresh token expired"),
            Some("refresh_expired"),
        );
        assert_eq!(
            classify_auth_message("Refresh token is invalid"),
            Some("refresh_expired"),
        );
    }

    #[test]
    fn classify_recognises_captcha_required() {
        assert_eq!(
            classify_auth_message("Captcha required"),
            Some("captcha_required"),
        );
        assert_eq!(
            classify_auth_message("Captcha is invalid."),
            Some("captcha_required"),
        );
    }

    #[test]
    fn classify_returns_none_for_app_internal_messages() {
        // App-internal AuthFailed messages — these should not match
        // any pattern; we want them to round-trip verbatim because
        // they're already shown to the right user-facing context.
        assert!(classify_auth_message(
            "cipher already belongs to this organization — use move instead",
        )
        .is_none());
        assert!(classify_auth_message(
            "personal items cannot be dropped on an organization collection directly — share the item first",
        )
        .is_none());
    }

    #[test]
    fn classify_returns_none_for_truly_unknown_strings() {
        assert!(classify_auth_message("Some other server message").is_none());
        assert!(classify_auth_message("").is_none());
    }
}

#[derive(Serialize)]
struct ErrorPayload<'a> {
    code: &'a str,
    message: String,
    data: serde_json::Value,
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (code, data): (&'static str, serde_json::Value) = match self {
            Error::InvalidUrl { url } => ("invalid_url", serde_json::json!({ "url": url })),
            Error::Network { source } => (
                "network_error",
                serde_json::json!({ "cause": source.to_string() }),
            ),
            Error::InvalidResponse { reason } => {
                ("invalid_response", serde_json::json!({ "reason": reason }))
            }
            Error::HttpStatus { status, message } => (
                "http_status",
                serde_json::json!({ "status": status, "message": message }),
            ),
            Error::AuthFailed { message } => {
                // Classify the message against known Vaultwarden /
                // Bitwarden patterns so the renderer can pick a
                // localised string instead of falling back to the raw
                // English message. The classifier is purely
                // additive: anything we don't recognise still
                // round-trips through `data.message`, so adding a
                // pattern is safe and removing one only loses the
                // localisation, not the error itself. See
                // classify_auth_message + its unit tests below.
                let reason = classify_auth_message(message);
                let mut data = serde_json::json!({ "message": message });
                if let Some(code) = reason {
                    if let Some(obj) = data.as_object_mut() {
                        obj.insert("reason".into(), serde_json::Value::from(code));
                    }
                }
                ("auth_failed", data)
            }
            Error::Crypto { reason } => ("crypto_error", serde_json::json!({ "reason": reason })),
            Error::TwoFactorProviderUnsupported { provider } => (
                "two_factor_provider_unsupported",
                serde_json::json!({ "provider": provider }),
            ),
            Error::NotAuthenticated => ("not_authenticated", serde_json::json!({})),
            Error::Storage { reason } => ("storage_error", serde_json::json!({ "reason": reason })),
            Error::SshPassphraseRequired => ("ssh_passphrase_required", serde_json::json!({})),
            Error::SshWrongPassphrase => ("ssh_wrong_passphrase", serde_json::json!({})),
            Error::YubikeyNoDevice => ("yubikey_no_device", serde_json::json!({})),
            Error::YubikeyPinRequired => ("yubikey_pin_required", serde_json::json!({})),
            Error::YubikeyWrongPin => ("yubikey_wrong_pin", serde_json::json!({})),
            Error::YubikeyUserCancelled => ("yubikey_user_cancelled", serde_json::json!({})),
            Error::YubikeyStaleWrap => ("yubikey_stale_wrap", serde_json::json!({})),
        };

        ErrorPayload {
            code,
            message: self.to_string(),
            data,
        }
        .serialize(serializer)
    }
}
