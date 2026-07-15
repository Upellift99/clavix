//! TOTP (RFC 6238) computed in Rust so the shared secret / otpauth URI never
//! crosses into the WebView. `get_cipher` no longer returns the seed; the
//! renderer asks `commands::cipher::totp_code` for the current code only, and
//! the editor asks `reveal_login_totp` when it needs the raw secret to edit.
//!
//! Mirrors the previous JS implementation (`src/lib/totp.ts`) — same base32
//! decode, otpauth parsing, clamping, and HOTP truncation — verified against
//! the RFC 6238 Appendix B vectors below.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

struct TotpConfig {
    secret: Vec<u8>,
    period: u64,
    digits: u32,
    algorithm: Algorithm,
}

/// The current code plus how many seconds until it rolls over. Serialised to
/// the renderer for the live-updating TOTP field.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for ch in input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
    {
        let idx = BASE32_ALPHABET
            .iter()
            .position(|&b| b as char == ch)
            .ok_or_else(|| Error::Crypto {
                reason: format!("invalid base32 char: {ch}"),
            })?;
        value = (value << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((value >> bits) & 0xff) as u8);
        }
    }
    Ok(bytes)
}

/// Clamp an untrusted numeric parameter to a sane range, falling back when the
/// value is missing or out of range — prevents an aberrant `digits` from a
/// hostile otpauth URI triggering a huge allocation.
fn clamp_param(raw: Option<&str>, min: u64, max: u64, fallback: u64) -> u64 {
    match raw.and_then(|s| s.parse::<f64>().ok()) {
        Some(n) if n.is_finite() && n > 0.0 => (n.trunc() as u64).clamp(min, max),
        _ => fallback,
    }
}

fn parse_totp(source: &str) -> Result<TotpConfig> {
    let trimmed = source.trim();
    if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        let url = url::Url::parse(trimmed).map_err(|e| Error::Crypto {
            reason: format!("otpauth parse: {e}"),
        })?;
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let secret_raw = params.get("secret").ok_or_else(|| Error::Crypto {
            reason: "otpauth URI missing secret".into(),
        })?;
        let algorithm = match params
            .get("algorithm")
            .map(|s| s.to_ascii_uppercase())
            .as_deref()
        {
            Some("SHA256") | Some("SHA-256") => Algorithm::Sha256,
            Some("SHA512") | Some("SHA-512") => Algorithm::Sha512,
            _ => Algorithm::Sha1,
        };
        Ok(TotpConfig {
            secret: decode_base32(secret_raw)?,
            period: clamp_param(params.get("period").map(String::as_str), 1, 3600, 30),
            digits: clamp_param(params.get("digits").map(String::as_str), 4, 10, 6) as u32,
            algorithm,
        })
    } else {
        Ok(TotpConfig {
            secret: decode_base32(trimmed)?,
            period: 30,
            digits: 6,
            algorithm: Algorithm::Sha1,
        })
    }
}

fn hmac_sign(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    fn finalize<M: Mac>(mut mac: M, msg: &[u8]) -> Vec<u8> {
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }
    fn key_err(e: hmac::digest::InvalidLength) -> Error {
        Error::Crypto {
            reason: format!("HMAC key: {e}"),
        }
    }
    Ok(match algorithm {
        Algorithm::Sha1 => finalize(Hmac::<Sha1>::new_from_slice(key).map_err(key_err)?, msg),
        Algorithm::Sha256 => finalize(Hmac::<Sha256>::new_from_slice(key).map_err(key_err)?, msg),
        Algorithm::Sha512 => finalize(Hmac::<Sha512>::new_from_slice(key).map_err(key_err)?, msg),
    })
}

fn generate(config: &TotpConfig, now_seconds: u64) -> Result<String> {
    let counter = now_seconds / config.period;
    let sig = hmac_sign(config.algorithm, &config.secret, &counter.to_be_bytes())?;
    let offset = (sig[sig.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(sig[offset]) & 0x7f) << 24)
        | (u32::from(sig[offset + 1]) << 16)
        | (u32::from(sig[offset + 2]) << 8)
        | u32::from(sig[offset + 3]);
    let modulo = 10u32.pow(config.digits);
    let code = binary % modulo;
    Ok(format!(
        "{code:0width$}",
        code = code,
        width = config.digits as usize
    ))
}

/// Parse `source` (bare base32 secret or otpauth URI) and return the code valid
/// at `now_seconds` plus the seconds remaining in the current window.
pub fn code_at(source: &str, now_seconds: u64) -> Result<TotpCode> {
    let config = parse_totp(source)?;
    let code = generate(&config, now_seconds)?;
    let seconds_remaining = config.period - (now_seconds % config.period);
    Ok(TotpCode {
        code,
        seconds_remaining,
    })
}

/// The code valid right now.
pub fn code_now(source: &str) -> Result<TotpCode> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Crypto {
            reason: format!("system clock before epoch: {e}"),
        })?
        .as_secs();
    code_at(source, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B seeds (ASCII), one per hash size, as bare base32.
    // "12345678901234567890" -> base32:
    const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    // 32-byte and 64-byte seeds via otpauth URIs below.

    #[test]
    fn rfc6238_sha1_vectors() {
        // 8-digit codes from RFC 6238 Appendix B (SHA-1 seed).
        let uri = format!("otpauth://totp/x?secret={SEED_SHA1}&digits=8");
        assert_eq!(code_at(&uri, 59).unwrap().code, "94287082");
        assert_eq!(code_at(&uri, 1111111109).unwrap().code, "07081804");
        assert_eq!(code_at(&uri, 1234567890).unwrap().code, "89005924");
        assert_eq!(code_at(&uri, 2000000000).unwrap().code, "69279037");
    }

    #[test]
    fn rfc6238_sha256_and_sha512_vectors() {
        // 12345678901234567890123456789012 (32 bytes) base32:
        let sha256_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        let uri = format!("otpauth://totp/x?secret={sha256_secret}&digits=8&algorithm=SHA256");
        assert_eq!(code_at(&uri, 59).unwrap().code, "46119246");

        // 1234567890123456789012345678901234567890123456789012345678901234 (64) base32:
        let sha512_secret =
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
        let uri = format!("otpauth://totp/x?secret={sha512_secret}&digits=8&algorithm=SHA512");
        assert_eq!(code_at(&uri, 59).unwrap().code, "90693936");
    }

    #[test]
    fn bare_secret_defaults_to_6_digits_sha1() {
        // Low 6 digits of the 8-digit "94287082" at t=59.
        let c = code_at(SEED_SHA1, 59).unwrap();
        assert_eq!(c.code, "287082");
        assert_eq!(c.code.len(), 6);
    }

    #[test]
    fn seconds_remaining_counts_down_in_the_window() {
        assert_eq!(code_at(SEED_SHA1, 0).unwrap().seconds_remaining, 30);
        assert_eq!(code_at(SEED_SHA1, 1).unwrap().seconds_remaining, 29);
        assert_eq!(code_at(SEED_SHA1, 29).unwrap().seconds_remaining, 1);
        assert_eq!(code_at(SEED_SHA1, 30).unwrap().seconds_remaining, 30);
    }

    #[test]
    fn rejects_invalid_base32() {
        assert!(code_at("not base32!!!", 0).is_err());
    }
}
