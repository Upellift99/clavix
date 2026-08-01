use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use serde_json::json;
use url::Url;

use crate::crypto::MasterPasswordHash;
use crate::error::{Error, Result};
use crate::models::{LoginResult, Prelogin, SyncResponse, TokenSet, TwoFactorProvider};

#[derive(Debug, Clone)]
pub struct VaultwardenClient {
    http: Client,
    /// Canonical server identity, used to pin pre-auth calls and to
    /// persist which server a session belongs to. Not necessarily the
    /// host we hit for a given call — see `api_base` / `identity_base`.
    base_url: Url,
    /// Where the REST API lives. Self-hosted: `<base>/api/`. Bitwarden
    /// cloud: `https://api.bitwarden.<tld>/` (a separate sub-domain).
    api_base: Url,
    /// Where the identity/token service lives. Self-hosted:
    /// `<base>/identity/`. Bitwarden cloud: `https://identity.bitwarden.<tld>/`.
    identity_base: Url,
    /// Where `accounts/prelogin` lives. Vaultwarden serves it under the
    /// API host (kept as-is to avoid regressing the primary target);
    /// Bitwarden cloud moved it to the identity host.
    prelogin_base: Url,
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
        let (api_base, identity_base, prelogin_base) = resolve_endpoints(&base_url)?;

        // Vaultwarden strips SSH-key ciphers (type 5) from the /sync
        // response unless the client advertises a version >= 2024.12.0
        // through this header — see vaultwarden `src/api/core/ciphers.rs`
        // (`show_ssh_keys`) and `ClientVersion` in `src/auth.rs`. Absent
        // the header the server treats us as a pre-SSH client and the keys
        // silently never reach us. The value only has to parse as semver
        // and clear the >=2024.12.0 gate; we pin the minimum rather than a
        // higher one to avoid opting into any newer version-gated wire
        // behaviour we don't yet handle.
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("bitwarden-client-version"),
            HeaderValue::from_static("2024.12.0"),
        );

        let http = Client::builder()
            .user_agent(concat!("Clavix/", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .build()?;
        Ok(Self {
            http,
            base_url,
            api_base,
            identity_base,
            prelogin_base,
        })
    }

    /// The normalized server base URL this client talks to. Used to pin
    /// pre-auth `prelogin`/`login` to the active session's server.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    fn api_endpoint(&self, path: &str) -> Result<Url> {
        self.api_base.join(path).map_err(|_| Error::InvalidUrl {
            url: path.to_string(),
        })
    }

    fn identity_endpoint(&self, path: &str) -> Result<Url> {
        self.identity_base
            .join(path)
            .map_err(|_| Error::InvalidUrl {
                url: path.to_string(),
            })
    }

    pub async fn prelogin(&self, email: &str) -> Result<Prelogin> {
        let url = self
            .prelogin_base
            .join("accounts/prelogin")
            .map_err(|_| Error::InvalidUrl {
                url: "accounts/prelogin".to_string(),
            })?;
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

    /// Soft-delete: PUT /api/ciphers/{id}/delete. The cipher is moved
    /// to the trash bucket on the server (the row stays, but
    /// `deletedDate` is stamped). Reversible via `restore_cipher` and
    /// permanently removable via `delete_cipher` (DELETE).
    pub async fn soft_delete_cipher(&self, access_token: &str, cipher_id: &str) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/delete"))?;
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

    /// Permanent delete: DELETE /api/ciphers/{id}. The row is gone
    /// from the server. Used for the "Supprimer définitivement" path
    /// from inside the trash; outside of trash, prefer
    /// `soft_delete_cipher`.
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

    /// Delete a personal folder. Bitwarden detaches every cipher that
    /// referenced the folder rather than cascade-deleting them, so it's
    /// safe to wipe folders without losing user content.
    pub async fn delete_folder(&self, access_token: &str, folder_id: &str) -> Result<()> {
        let url = self.api_endpoint(&format!("folders/{folder_id}"))?;
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

/// Hosts where we tolerate plain `http://` for development convenience
/// (running Vaultwarden locally in Docker is the typical case). Any
/// other host must use `https://`. Match is exact and case-insensitive.
fn is_local_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1" | "[::1]"
    )
}

fn normalize_base_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input.trim()).map_err(|_| Error::InvalidUrl {
        url: input.to_string(),
    })?;

    // Reject anything that is not http(s) outright. `file://`,
    // `javascript:`, etc. parse as URLs but have no business reaching
    // a Vaultwarden client. http is allowed only for clearly-local
    // hosts so a user can't be tricked (or trick themselves) into
    // posting a master password hash over plaintext on a hostile WiFi.
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("").to_string();
    match scheme {
        "https" => {}
        "http" if is_local_host(&host) => {}
        _ => {
            return Err(Error::InvalidUrl {
                url: input.to_string(),
            });
        }
    }

    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    Ok(url)
}

/// Resolve the `(api, identity, prelogin)` base URLs for a server.
///
/// Vaultwarden and self-hosted Bitwarden serve everything under one host
/// with `/api` and `/identity` path prefixes, and Clavix has always
/// posted `accounts/prelogin` to the API host — kept as-is so the primary
/// (Vaultwarden) target can't regress.
///
/// Bitwarden's hosted service instead splits these across dedicated
/// sub-domains (`api.bitwarden.<tld>`, `identity.bitwarden.<tld>`) and,
/// unlike Vaultwarden, serves `prelogin` from the identity host. We
/// recognise the two regions by host and map them to the right split
/// endpoints; anything else falls through to the single-domain layout.
fn resolve_endpoints(base: &Url) -> Result<(Url, Url, Url)> {
    let cloud_tld = match base.host_str().unwrap_or("") {
        "bitwarden.com" | "vault.bitwarden.com" | "api.bitwarden.com" => Some("com"),
        "bitwarden.eu" | "vault.bitwarden.eu" | "api.bitwarden.eu" => Some("eu"),
        _ => None,
    };

    if let Some(tld) = cloud_tld {
        let api = Url::parse(&format!("https://api.bitwarden.{tld}/")).map_err(|_| {
            Error::InvalidUrl {
                url: format!("api.bitwarden.{tld}"),
            }
        })?;
        let identity = Url::parse(&format!("https://identity.bitwarden.{tld}/")).map_err(|_| {
            Error::InvalidUrl {
                url: format!("identity.bitwarden.{tld}"),
            }
        })?;
        // Cloud serves prelogin from the identity host, not the API host.
        return Ok((api, identity.clone(), identity));
    }

    // Self-hosted single-domain layout. `base` already ends in `/`.
    let api = base.join("api/").map_err(|_| Error::InvalidUrl {
        url: "api/".to_string(),
    })?;
    let identity = base.join("identity/").map_err(|_| Error::InvalidUrl {
        url: "identity/".to_string(),
    })?;
    // Vaultwarden serves prelogin under the API host; unchanged.
    Ok((api.clone(), identity, api))
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
    fn resolve_endpoints_self_hosted_uses_path_prefixes() {
        let base = normalize_base_url("https://pass.example.com").unwrap();
        let (api, identity, prelogin) = resolve_endpoints(&base).unwrap();
        assert_eq!(api.as_str(), "https://pass.example.com/api/");
        assert_eq!(identity.as_str(), "https://pass.example.com/identity/");
        // Vaultwarden prelogin lives on the API host — unchanged.
        assert_eq!(prelogin.as_str(), "https://pass.example.com/api/");
        // Concrete endpoints resolve as before.
        assert_eq!(
            api.join("sync").unwrap().as_str(),
            "https://pass.example.com/api/sync"
        );
        assert_eq!(
            identity.join("connect/token").unwrap().as_str(),
            "https://pass.example.com/identity/connect/token"
        );
        assert_eq!(
            prelogin.join("accounts/prelogin").unwrap().as_str(),
            "https://pass.example.com/api/accounts/prelogin"
        );
    }

    #[test]
    fn resolve_endpoints_bitwarden_cloud_splits_hosts() {
        // Both the vault URL and the bare apex resolve to the same region.
        for input in ["https://vault.bitwarden.com", "https://bitwarden.com"] {
            let base = normalize_base_url(input).unwrap();
            let (api, identity, prelogin) = resolve_endpoints(&base).unwrap();
            assert_eq!(api.as_str(), "https://api.bitwarden.com/");
            assert_eq!(identity.as_str(), "https://identity.bitwarden.com/");
            // Cloud serves prelogin from the identity host, not the API host.
            assert_eq!(prelogin.as_str(), "https://identity.bitwarden.com/");
            assert_eq!(
                api.join("sync").unwrap().as_str(),
                "https://api.bitwarden.com/sync"
            );
            assert_eq!(
                prelogin.join("accounts/prelogin").unwrap().as_str(),
                "https://identity.bitwarden.com/accounts/prelogin"
            );
        }
    }

    #[test]
    fn resolve_endpoints_bitwarden_eu_region() {
        let base = normalize_base_url("https://vault.bitwarden.eu").unwrap();
        let (api, identity, prelogin) = resolve_endpoints(&base).unwrap();
        assert_eq!(api.as_str(), "https://api.bitwarden.eu/");
        assert_eq!(identity.as_str(), "https://identity.bitwarden.eu/");
        assert_eq!(prelogin.as_str(), "https://identity.bitwarden.eu/");
    }

    #[test]
    fn normalize_base_url_rejects_garbage() {
        assert!(normalize_base_url("not a url").is_err());
        assert!(normalize_base_url("").is_err());
    }

    #[test]
    fn normalize_base_url_rejects_plain_http_against_remote_host() {
        // Cleartext over the internet would let a wifi-cafe attacker
        // collect every master password hash on the wire. Block it
        // explicitly rather than rely on Vaultwarden's TLS posture.
        assert!(normalize_base_url("http://vault.example.com").is_err());
        assert!(normalize_base_url("http://example.com:8080/path").is_err());
    }

    #[test]
    fn normalize_base_url_allows_http_for_local_dev() {
        // The standard self-hosted dev loop is `docker compose up` on
        // localhost without TLS — refusing it would force every
        // contributor to wire up a self-signed cert, which is the kind
        // of friction that pushes people to disable security elsewhere.
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let u = normalize_base_url(&format!("http://{host}:8080/")).unwrap();
            assert!(u.as_str().starts_with("http://"));
        }
    }

    #[test]
    fn normalize_base_url_rejects_non_http_schemes() {
        // Defence in depth against an `Url::parse`-friendly but
        // semantically wrong input (config import, copy-paste from a
        // browser address bar, etc.).
        assert!(normalize_base_url("file:///etc/passwd").is_err());
        assert!(normalize_base_url("javascript:alert(1)").is_err());
        assert!(normalize_base_url("ftp://vault.example.com").is_err());
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
