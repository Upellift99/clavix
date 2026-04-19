use reqwest::Client;
use serde_json::json;
use url::Url;

use crate::crypto::MasterPasswordHash;
use crate::error::{Error, Result};
use crate::models::{LoginResult, Prelogin, SyncResponse, TokenSet, TwoFactorProvider};

#[derive(Debug, Clone)]
pub struct VaultwardenClient {
    http: Client,
    base_url: Url,
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub identifier: String,
    pub name: String,
    pub device_type: u8,
}

impl VaultwardenClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = normalize_base_url(base_url)?;
        let http = Client::builder()
            .user_agent(concat!("Clavix/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { http, base_url })
    }

    fn api_endpoint(&self, path: &str) -> Result<Url> {
        self.base_url
            .join("api/")
            .and_then(|u| u.join(path))
            .map_err(|_| Error::InvalidUrl {
                url: path.to_string(),
            })
    }

    fn identity_endpoint(&self, path: &str) -> Result<Url> {
        self.base_url
            .join("identity/")
            .and_then(|u| u.join(path))
            .map_err(|_| Error::InvalidUrl {
                url: path.to_string(),
            })
    }

    pub async fn prelogin(&self, email: &str) -> Result<Prelogin> {
        let url = self.api_endpoint("accounts/prelogin")?;
        let response = self
            .http
            .post(url)
            .json(&json!({ "email": email }))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }

        response
            .json::<Prelogin>()
            .await
            .map_err(|e| Error::InvalidResponse {
                reason: e.to_string(),
            })
    }

    pub async fn login(
        &self,
        email: &str,
        password_hash: &MasterPasswordHash,
        device: &DeviceInfo,
    ) -> Result<LoginResult> {
        self.login_inner(email, password_hash, device, None).await
    }

    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        device: &DeviceInfo,
    ) -> Result<TokenSet> {
        let url = self.identity_endpoint("connect/token")?;

        let form: Vec<(&str, String)> = vec![
            ("grant_type", "refresh_token".into()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", "connector".into()),
            ("deviceType", device.device_type.to_string()),
            ("deviceIdentifier", device.identifier.clone()),
            ("deviceName", device.name.clone()),
        ];

        let response = self.http.post(url).form(&form).send().await?;
        let status = response.status();
        let body = response.bytes().await?;

        if status.is_success() {
            return serde_json::from_slice(&body).map_err(|e| Error::InvalidResponse {
                reason: e.to_string(),
            });
        }

        if status.as_u16() == 400 {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
                return Err(Error::AuthFailed {
                    message: extract_auth_error_message(&value),
                });
            }
        }

        Err(Error::HttpStatus {
            status: status.as_u16(),
            message: String::from_utf8_lossy(&body).into_owned(),
        })
    }

    pub async fn restore_cipher(&self, access_token: &str, cipher_id: &str) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/restore"))?;
        let response = self.http.put(url).bearer_auth(access_token).send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    pub async fn create_cipher(
        &self,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<crate::models::Cipher> {
        let url = self.api_endpoint("ciphers")?;
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
    }

    /// Create a cipher inside an organization. Body must carry
    /// `cipher` (the usual cipher payload, with `organizationId` set)
    /// and `collectionIds` (non-empty in practice).
    pub async fn create_org_cipher(
        &self,
        access_token: &str,
        body: &serde_json::Value,
    ) -> Result<crate::models::Cipher> {
        let url = self.api_endpoint("ciphers/create")?;
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
    }

    pub async fn update_cipher(
        &self,
        access_token: &str,
        cipher_id: &str,
        body: &serde_json::Value,
    ) -> Result<crate::models::Cipher> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}"))?;
        let response = self
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
    }

    pub async fn delete_cipher(&self, access_token: &str, cipher_id: &str) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}"))?;
        let response = self
            .http
            .delete(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    pub async fn update_cipher_partial(
        &self,
        access_token: &str,
        cipher_id: &str,
        folder_id: Option<&str>,
        favorite: bool,
    ) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/partial"))?;
        let response = self
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(&json!({
                "folderId": folder_id,
                "favorite": favorite,
            }))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    pub async fn update_cipher_collections(
        &self,
        access_token: &str,
        cipher_id: &str,
        collection_ids: &[String],
    ) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/collections"))?;
        let response = self
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(&json!({ "collectionIds": collection_ids }))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    /// Create a new folder (encrypted name). Returns the server's
    /// canonical `Folder` JSON which the caller can drop into the vault.
    pub async fn create_folder(
        &self,
        access_token: &str,
        encrypted_name: &str,
    ) -> Result<crate::models::Folder> {
        let url = self.api_endpoint("folders")?;
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(&json!({ "name": encrypted_name }))
            .send()
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
    }

    pub async fn update_folder_name(
        &self,
        access_token: &str,
        folder_id: &str,
        encrypted_name: &str,
    ) -> Result<()> {
        let url = self.api_endpoint(&format!("folders/{folder_id}"))?;
        let response = self
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(&json!({ "name": encrypted_name }))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    pub async fn share_cipher(
        &self,
        access_token: &str,
        cipher_id: &str,
        body: &serde_json::Value,
    ) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/share"))?;
        let response = self
            .http
            .put(url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }
        Ok(())
    }

    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        let url = self.api_endpoint("sync")?;
        let response = self.http.get(url).bearer_auth(access_token).send().await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                message: body,
            });
        }

        response
            .json::<SyncResponse>()
            .await
            .map_err(|e| Error::InvalidResponse {
                reason: e.to_string(),
            })
    }

    pub async fn login_with_two_factor(
        &self,
        email: &str,
        password_hash: &MasterPasswordHash,
        device: &DeviceInfo,
        provider: TwoFactorProvider,
        code: &str,
    ) -> Result<TokenSet> {
        match self
            .login_inner(email, password_hash, device, Some((provider, code)))
            .await?
        {
            LoginResult::Success(tokens) => Ok(tokens),
            LoginResult::TwoFactorRequired { .. } => Err(Error::AuthFailed {
                message: "2FA code rejected by the server".into(),
            }),
        }
    }

    async fn login_inner(
        &self,
        email: &str,
        password_hash: &MasterPasswordHash,
        device: &DeviceInfo,
        two_factor: Option<(TwoFactorProvider, &str)>,
    ) -> Result<LoginResult> {
        let url = self.identity_endpoint("connect/token")?;
        let email_lower = email.trim().to_ascii_lowercase();

        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "password".into()),
            ("scope", "api offline_access".into()),
            ("client_id", "connector".into()),
            ("username", email_lower),
            ("password", password_hash.as_str().into()),
            ("deviceType", device.device_type.to_string()),
            ("deviceIdentifier", device.identifier.clone()),
            ("deviceName", device.name.clone()),
        ];
        if let Some((provider, code)) = two_factor {
            form.push(("twoFactorToken", code.into()));
            form.push(("twoFactorProvider", (provider as u8).to_string()));
            form.push(("twoFactorRemember", "0".into()));
        }

        let response = self.http.post(url).form(&form).send().await?;
        let status = response.status();
        let body = response.bytes().await?;

        if status.is_success() {
            let tokens: TokenSet =
                serde_json::from_slice(&body).map_err(|e| Error::InvalidResponse {
                    reason: e.to_string(),
                })?;
            return Ok(LoginResult::Success(tokens));
        }

        if status.as_u16() == 400 {
            eprintln!(
                "[clavix] login 400 body: {}",
                String::from_utf8_lossy(&body)
            );

            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
                if let Some(providers) = extract_two_factor_providers(&value) {
                    let webauthn_challenge = if providers
                        .iter()
                        .any(|p| matches!(p, TwoFactorProvider::WebAuthn))
                    {
                        extract_webauthn_challenge(&value)
                    } else {
                        None
                    };
                    return Ok(LoginResult::TwoFactorRequired {
                        providers,
                        webauthn_challenge,
                    });
                }

                return Err(Error::AuthFailed {
                    message: extract_auth_error_message(&value),
                });
            }
        }

        Err(Error::HttpStatus {
            status: status.as_u16(),
            message: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

fn extract_auth_error_message(value: &serde_json::Value) -> String {
    let string_candidates = [
        value.get("message"),
        value.get("errorModel").and_then(|m| m.get("message")),
        value.get("ErrorModel").and_then(|m| m.get("Message")),
        value.get("error_description"),
    ];

    for candidate in string_candidates {
        if let Some(s) = candidate.and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    if let Some(obj) = value.get("validationErrors").and_then(|v| v.as_object()) {
        let messages: Vec<String> = obj
            .values()
            .filter_map(|v| v.as_array())
            .flat_map(|a| a.iter())
            .filter_map(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !messages.is_empty() {
            return messages.join("; ");
        }
    }

    value
        .get("error")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("auth_error")
        .to_string()
}

fn extract_two_factor_providers(value: &serde_json::Value) -> Option<Vec<TwoFactorProvider>> {
    for key in [
        "TwoFactorProviders",
        "twoFactorProviders",
        "two_factor_providers",
    ] {
        if let Some(arr) = value.get(key).and_then(|v| v.as_array()) {
            let providers = collect_known_providers(arr.iter().filter_map(|v| v.as_u64()));
            if !providers.is_empty() {
                return Some(providers);
            }
        }
    }

    for key in ["TwoFactorProviders2", "twoFactorProviders2"] {
        if let Some(obj) = value.get(key).and_then(|v| v.as_object()) {
            let providers =
                collect_known_providers(obj.keys().filter_map(|k| k.parse::<u64>().ok()));
            if !providers.is_empty() {
                return Some(providers);
            }
        }
    }

    None
}

/// Digs the WebAuthn challenge out of whatever shape the server emits.
/// Returns a JSON-encoded string ready to hand to the CTAP2 backend.
fn extract_webauthn_challenge(value: &serde_json::Value) -> Option<String> {
    for key in ["TwoFactorProviders2", "twoFactorProviders2"] {
        let Some(obj) = value.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        let Some(entry) = obj.get("7") else { continue };
        // Vaultwarden sometimes double-encodes this as a JSON string,
        // sometimes leaves it as an object.  Accept both.
        if let Some(s) = entry.as_str() {
            if !s.trim().is_empty() {
                return Some(s.to_string());
            }
        }
        if entry.is_object() {
            if let Ok(s) = serde_json::to_string(entry) {
                return Some(s);
            }
        }
    }
    None
}

fn collect_known_providers(ids: impl Iterator<Item = u64>) -> Vec<TwoFactorProvider> {
    ids.filter_map(|n| u8::try_from(n).ok())
        .filter_map(|n| TwoFactorProvider::try_from(n).ok())
        .collect()
}

fn normalize_base_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input.trim()).map_err(|_| Error::InvalidUrl {
        url: input.to_string(),
    })?;
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_base_url_adds_trailing_slash() {
        let u = normalize_base_url("https://vault.example.com").unwrap();
        assert_eq!(u.as_str(), "https://vault.example.com/");
        let u = normalize_base_url("https://vault.example.com/api").unwrap();
        assert!(u.as_str().ends_with("/api/"));
    }

    #[test]
    fn normalize_base_url_trims_whitespace() {
        let u = normalize_base_url("  https://vault.example.com/  ").unwrap();
        assert_eq!(u.as_str(), "https://vault.example.com/");
    }

    #[test]
    fn normalize_base_url_rejects_garbage() {
        assert!(normalize_base_url("not a url").is_err());
        assert!(normalize_base_url("").is_err());
    }

    #[test]
    fn extract_two_factor_providers_reads_array() {
        let v = json!({"twoFactorProviders": [0, 3]});
        let providers = extract_two_factor_providers(&v).unwrap();
        assert_eq!(providers.len(), 2);
        assert!(matches!(providers[0], TwoFactorProvider::Authenticator));
        assert!(matches!(providers[1], TwoFactorProvider::YubiKey));
    }

    #[test]
    fn extract_two_factor_providers_reads_keyed_map() {
        let v = json!({"TwoFactorProviders2": {"0": null, "7": {"challenge": "x"}}});
        let providers = extract_two_factor_providers(&v).unwrap();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn extract_two_factor_providers_skips_unknown() {
        let v = json!({"twoFactorProviders": [42, 99]});
        assert!(extract_two_factor_providers(&v).is_none());
    }

    #[test]
    fn extract_webauthn_challenge_from_object() {
        let v = json!({
            "twoFactorProviders": [7],
            "twoFactorProviders2": {"7": {"challenge": "abc", "rpId": "example.com"}}
        });
        let s = extract_webauthn_challenge(&v).expect("challenge");
        assert!(s.contains("\"challenge\":\"abc\""));
        assert!(s.contains("\"rpId\":\"example.com\""));
    }

    #[test]
    fn extract_webauthn_challenge_from_double_encoded_string() {
        let inner = r#"{"challenge":"abc","rpId":"example.com"}"#;
        let v = json!({
            "twoFactorProviders": [7],
            "twoFactorProviders2": {"7": inner}
        });
        assert_eq!(extract_webauthn_challenge(&v).as_deref(), Some(inner));
    }

    #[test]
    fn extract_webauthn_challenge_absent_when_no_7() {
        let v = json!({"twoFactorProviders2": {"0": null}});
        assert!(extract_webauthn_challenge(&v).is_none());
    }

    #[test]
    fn extract_auth_error_message_prefers_error_model_message() {
        let v = json!({"errorModel": {"message": "Bad password"}, "error_description": ""});
        assert_eq!(extract_auth_error_message(&v), "Bad password");
    }

    #[test]
    fn extract_auth_error_message_falls_back_to_validation_errors() {
        let v = json!({"validationErrors": {"Username": ["must be an email"]}});
        assert_eq!(extract_auth_error_message(&v), "must be an email");
    }

    #[test]
    fn extract_auth_error_message_default_when_nothing_useful() {
        let v = json!({});
        // Returns the generic bucket — we only care that it doesn't panic
        // and that it doesn't return empty garbage.
        let s = extract_auth_error_message(&v);
        assert!(!s.is_empty());
    }
}
