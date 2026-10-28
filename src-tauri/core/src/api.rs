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
    /// Where the identity/token service lives, `accounts/prelogin`
    /// included. Self-hosted: `<base>/identity/`. Bitwarden cloud:
    /// `https://identity.bitwarden.<tld>/`.
    ///
    /// Prelogin used to be fetched from the API host on self-hosted
    /// servers because Vaultwarden answered it there too. Vaultwarden
    /// 1.37.4 removed that legacy `/api/accounts/prelogin` route; the
    /// identity one has been served by every Vaultwarden release Clavix
    /// supports and by Bitwarden cloud, so it is the only one used now.
    identity_base: Url,
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
        let (api_base, identity_base) = resolve_endpoints(&base_url)?;

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
        let url = self.identity_endpoint("accounts/prelogin")?;
        let response = self
            .http
            .post(url)
            .json(&json!({ "email": email }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(http_error(response).await);
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
        let content_type = content_type_of(&response);
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

        Err(http_error_from_parts(
            status.as_u16(),
            content_type.as_deref(),
            &body,
        ))
    }

    pub async fn restore_cipher(&self, access_token: &str, cipher_id: &str) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/restore"))?;
        let response = self.http.put(url).bearer_auth(access_token).send().await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        Ok(())
    }

    /// Archive: PUT /api/ciphers/{id}/archive (Vaultwarden >= 1.36). The
    /// archive is per user, org items included: it stamps `archivedDate`
    /// for the signed-in user only and leaves the cipher itself untouched.
    /// Answers with the cipher, `archivedDate` included.
    pub async fn archive_cipher(
        &self,
        access_token: &str,
        cipher_id: &str,
    ) -> Result<crate::models::Cipher> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/archive"))?;
        let response = self.http.put(url).bearer_auth(access_token).send().await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
    }

    /// Undo of `archive_cipher`: PUT /api/ciphers/{id}/unarchive.
    pub async fn unarchive_cipher(
        &self,
        access_token: &str,
        cipher_id: &str,
    ) -> Result<crate::models::Cipher> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/unarchive"))?;
        let response = self.http.put(url).bearer_auth(access_token).send().await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        Ok(())
    }

    /// Step 1 of the two-step attachment upload: reserve a slot and get
    /// back an attachment id plus where to PUT the bytes. The body carries
    /// the encrypted file name, the wrapped per-file key and the
    /// *ciphertext* length.
    ///
    /// Returns the raw JSON: callers need `attachmentId`, and the shape of
    /// the rest differs between Vaultwarden and Bitwarden cloud.
    pub async fn attachment_upload_slot(
        &self,
        access_token: &str,
        cipher_id: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/attachment/v2"))?;
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidResponse {
            reason: e.to_string(),
        })
    }

    /// Step 2: the encrypted bytes themselves, as multipart/form-data on
    /// the direct-upload endpoint (`fileUploadType: 0`, the only one
    /// Vaultwarden implements). The part must be named `data` and carry a
    /// file name, or Vaultwarden rejects the request.
    pub async fn upload_attachment_data(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
        encrypted_name: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/attachment/{attachment_id}"))?;
        // The file name in the multipart part is metadata for the server's
        // form parser; the name that matters is the encrypted one already
        // registered in step 1.
        let part = reqwest::multipart::Part::bytes(data)
            .file_name(encrypted_name.to_owned())
            .mime_str("application/octet-stream")
            .map_err(|e| Error::InvalidResponse {
                reason: format!("multipart part: {e}"),
            })?;
        let form = reqwest::multipart::Form::new().part("data", part);
        let response = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .multipart(form)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        Ok(())
    }

    /// The encrypted bytes of an attachment.
    ///
    /// `url` comes from the vault (the server put it there), so it is
    /// treated as untrusted input: the bearer token is attached **only**
    /// when the URL is on the server we are logged in to. A hostile or
    /// compromised server that points an attachment at a third-party host
    /// gets an anonymous GET, never our access token. Anything that is not
    /// HTTPS on a foreign host is refused outright.
    pub async fn download_attachment(&self, access_token: &str, url: &str) -> Result<Vec<u8>> {
        let parsed = Url::parse(url).map_err(|_| Error::InvalidUrl {
            url: url.to_string(),
        })?;
        let same_origin = parsed.scheme() == self.base_url.scheme()
            && parsed.host_str() == self.base_url.host_str()
            && parsed.port_or_known_default() == self.base_url.port_or_known_default();
        if !same_origin && parsed.scheme() != "https" {
            return Err(Error::InvalidUrl {
                url: url.to_string(),
            });
        }

        let mut request = self.http.get(parsed);
        if same_origin {
            request = request.bearer_auth(access_token);
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }

    pub async fn delete_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
    ) -> Result<()> {
        let url = self.api_endpoint(&format!("ciphers/{cipher_id}/attachment/{attachment_id}"))?;
        let response = self
            .http
            .delete(url)
            .bearer_auth(access_token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(http_error(response).await);
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

        if !response.status().is_success() {
            return Err(http_error(response).await);
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

        if !response.status().is_success() {
            return Err(http_error(response).await);
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        let bytes = response.bytes().await?;
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
        if !response.status().is_success() {
            return Err(http_error(response).await);
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

        if !response.status().is_success() {
            return Err(http_error(response).await);
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

        if !response.status().is_success() {
            return Err(http_error(response).await);
        }
        Ok(())
    }

    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse> {
        let url = self.api_endpoint("sync")?;
        let response = self.http.get(url).bearer_auth(access_token).send().await?;

        if !response.status().is_success() {
            return Err(http_error(response).await);
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
        let content_type = content_type_of(&response);
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

        Err(http_error_from_parts(
            status.as_u16(),
            content_type.as_deref(),
            &body,
        ))
    }
}

/// Longest raw error body kept in a message. Anything past this is a
/// stack trace or a page of markup, not something a dialog should show.
const ERROR_BODY_MAX_CHARS: usize = 300;

/// Longest `<title>` kept from an HTML error page.
const HTML_TITLE_MAX_CHARS: usize = 120;

/// The `Content-Type` of a response, if it has a readable one.
fn content_type_of(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Turn a failed response into the error a human can read in a dialog.
///
/// Consumes the response: the body is what decides between a Vaultwarden
/// JSON error (its `message` is the useful part), an HTML page served by
/// whatever sits in front of the server (only its `<title>` is worth
/// showing), and a raw text body (kept, but truncated).
async fn http_error(response: reqwest::Response) -> Error {
    let status = response.status().as_u16();
    let content_type = content_type_of(&response);
    let body = response
        .bytes()
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    http_error_from_parts(status, content_type.as_deref(), &body)
}

/// Same as [`http_error`] for callers that already consumed the body.
fn http_error_from_parts(status: u16, content_type: Option<&str>, body: &[u8]) -> Error {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();

    if looks_like_html(content_type, text) {
        return Error::HtmlResponse {
            status,
            title: html_title(text),
        };
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(message) = json_error_message(&value) {
            return Error::HttpStatus { status, message };
        }
    }

    Error::HttpStatus {
        status,
        message: truncate_chars(text, ERROR_BODY_MAX_CHARS),
    }
}

/// An HTML body is one the server labels as such, or one that opens like
/// a document: a proxy error page often comes with no `Content-Type`.
fn looks_like_html(content_type: Option<&str>, body: &str) -> bool {
    if content_type.is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html")) {
        return true;
    }
    let head = body.as_bytes();
    ["<!doctype", "<html"].iter().any(|tag| {
        head.len() >= tag.len() && head[..tag.len()].eq_ignore_ascii_case(tag.as_bytes())
    })
}

/// The trimmed text of the first `<title>` element, whitespace collapsed
/// and the common entities decoded. `None` when the page has no title or
/// an empty one.
fn html_title(body: &str) -> Option<String> {
    // ASCII lowercasing keeps byte offsets stable, so indices found in the
    // lowered copy index the original.
    let lower = body.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let after_tag = open + lower[open..].find('>')? + 1;
    let close = after_tag + lower[after_tag..].find("</title")?;
    let raw = &body[after_tag..close];
    let decoded = raw
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(truncate_chars(&collapsed, HTML_TITLE_MAX_CHARS))
    }
}

/// `s` cut to `max` characters, with an ellipsis when something was cut.
fn truncate_chars(s: &str, max: usize) -> String {
    let mut chars = s.chars();
    let kept: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{kept}…")
    } else {
        kept
    }
}

/// The human-readable message inside a Vaultwarden / Bitwarden JSON error
/// body, trying each of the shapes the servers have used. `None` when the
/// body carries no such message.
fn json_error_message(value: &serde_json::Value) -> Option<String> {
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
                return Some(trimmed.to_string());
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
            return Some(messages.join("; "));
        }
    }

    value
        .get("error")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn extract_auth_error_message(value: &serde_json::Value) -> String {
    json_error_message(value).unwrap_or_else(|| "auth_error".to_string())
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
fn resolve_endpoints(base: &Url) -> Result<(Url, Url)> {
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
        return Ok((api, identity));
    }

    // Self-hosted single-domain layout. `base` already ends in `/`.
    let api = base.join("api/").map_err(|_| Error::InvalidUrl {
        url: "api/".to_string(),
    })?;
    let identity = base.join("identity/").map_err(|_| Error::InvalidUrl {
        url: "identity/".to_string(),
    })?;
    Ok((api, identity))
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
        let (api, identity) = resolve_endpoints(&base).unwrap();
        assert_eq!(api.as_str(), "https://pass.example.com/api/");
        assert_eq!(identity.as_str(), "https://pass.example.com/identity/");
        // Concrete endpoints resolve as before.
        assert_eq!(
            api.join("sync").unwrap().as_str(),
            "https://pass.example.com/api/sync"
        );
        assert_eq!(
            identity.join("connect/token").unwrap().as_str(),
            "https://pass.example.com/identity/connect/token"
        );
        // Prelogin goes through the identity host, never `/api/`: Vaultwarden
        // 1.37.4 dropped the legacy `/api/accounts/prelogin` route.
        assert_eq!(
            identity.join("accounts/prelogin").unwrap().as_str(),
            "https://pass.example.com/identity/accounts/prelogin"
        );
    }

    #[test]
    fn resolve_endpoints_bitwarden_cloud_splits_hosts() {
        // Both the vault URL and the bare apex resolve to the same region.
        for input in ["https://vault.bitwarden.com", "https://bitwarden.com"] {
            let base = normalize_base_url(input).unwrap();
            let (api, identity) = resolve_endpoints(&base).unwrap();
            assert_eq!(api.as_str(), "https://api.bitwarden.com/");
            assert_eq!(identity.as_str(), "https://identity.bitwarden.com/");
            assert_eq!(
                api.join("sync").unwrap().as_str(),
                "https://api.bitwarden.com/sync"
            );
            assert_eq!(
                identity.join("accounts/prelogin").unwrap().as_str(),
                "https://identity.bitwarden.com/accounts/prelogin"
            );
        }
    }

    #[test]
    fn resolve_endpoints_bitwarden_eu_region() {
        let base = normalize_base_url("https://vault.bitwarden.eu").unwrap();
        let (api, identity) = resolve_endpoints(&base).unwrap();
        assert_eq!(api.as_str(), "https://api.bitwarden.eu/");
        assert_eq!(identity.as_str(), "https://identity.bitwarden.eu/");
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

    #[test]
    fn http_error_reduces_an_html_page_to_its_title() {
        // A login portal or reverse proxy answering for the server. The
        // page is a few kilobytes of markup; only the title is shown.
        let page = "<!doctype html>\n<html lang=\"fr\"><head><meta charset=\"utf-8\" />\n\
            <title>\n  Page indisponible &mdash; 401 &amp; co  \n</title>\
            <style>body { margin: 0; }</style></head><body>...</body></html>";
        match http_error_from_parts(401, Some("text/html; charset=utf-8"), page.as_bytes()) {
            Error::HtmlResponse { status, title } => {
                assert_eq!(status, 401);
                assert_eq!(title.as_deref(), Some("Page indisponible &mdash; 401 & co"));
            }
            other => panic!("expected HtmlResponse, got {other:?}"),
        }
    }

    #[test]
    fn http_error_detects_html_without_a_content_type() {
        let page = "  <HTML><HEAD></HEAD><BODY>Forbidden</BODY></HTML>";
        match http_error_from_parts(403, None, page.as_bytes()) {
            Error::HtmlResponse {
                status: 403,
                title: None,
            } => {}
            other => panic!("expected an untitled HtmlResponse, got {other:?}"),
        }
    }

    #[test]
    fn http_error_keeps_the_vaultwarden_json_message() {
        let body = r#"{"message":"Cipher doesn't exist","object":"error","validationErrors":{"":["Cipher doesn't exist"]}}"#;
        match http_error_from_parts(404, Some("application/json"), body.as_bytes()) {
            Error::HttpStatus { status, message } => {
                assert_eq!(status, 404);
                assert_eq!(message, "Cipher doesn't exist");
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[test]
    fn http_error_truncates_a_raw_text_body() {
        let body = "x".repeat(ERROR_BODY_MAX_CHARS + 50);
        match http_error_from_parts(502, Some("text/plain"), body.as_bytes()) {
            Error::HttpStatus { message, .. } => {
                assert_eq!(message.chars().count(), ERROR_BODY_MAX_CHARS + 1);
                assert!(message.ends_with('…'));
            }
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[test]
    fn http_error_passes_a_short_text_body_through() {
        match http_error_from_parts(500, None, b"  upstream timed out  ") {
            Error::HttpStatus { message, .. } => assert_eq!(message, "upstream timed out"),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[test]
    fn http_error_json_without_a_message_falls_back_to_the_raw_body() {
        let body = r#"{"object":"error"}"#;
        match http_error_from_parts(500, Some("application/json"), body.as_bytes()) {
            Error::HttpStatus { message, .. } => assert_eq!(message, body),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }
}
