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
                ("auth_failed", serde_json::json!({ "message": message }))
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
