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
        };

        ErrorPayload {
            code,
            message: self.to_string(),
            data,
        }
        .serialize(serializer)
    }
}
