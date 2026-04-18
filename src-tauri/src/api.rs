use reqwest::Client;
use serde_json::json;
use url::Url;

use crate::error::{Error, Result};
use crate::models::Prelogin;

#[derive(Debug, Clone)]
pub struct VaultwardenClient {
    http: Client,
    base_url: Url,
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
            .map_err(|_| Error::InvalidUrl(path.to_string()))
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
            .map_err(|e| Error::InvalidResponse(e.to_string()))
    }
}

fn normalize_base_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input.trim()).map_err(|_| Error::InvalidUrl(input.to_string()))?;
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    Ok(url)
}
