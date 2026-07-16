//! Update check: ask the GitHub Releases API whether a newer Clavix is out.
//!
//! This runs in Rust — never in the WebView — on purpose. The renderer's CSP
//! (`connect-src 'self' ipc:`) deliberately forbids reaching any external host,
//! so a compromised renderer can't exfiltrate the vault. The version check is
//! the one "phone home" the app makes besides HIBP, and keeping it behind an
//! IPC command preserves that boundary: JS only ever sees a small verdict
//! struct, never gets to make the outbound request itself.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const RELEASES_LATEST_API: &str = "https://api.github.com/repos/Upellift99/clavix/releases/latest";
const USER_AGENT: &str = concat!("Clavix/", env!("CARGO_PKG_VERSION"));

/// Verdict handed to the WebView. `update_available` is the only thing the UI
/// really acts on; the rest lets it render "vX.Y.Z is available" + a link.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// The version this build reports (`CARGO_PKG_VERSION`).
    pub current: String,
    /// The latest published release's version, tag stripped of a leading `v`.
    pub latest: String,
    /// True only when `latest` parses as a strictly-greater semver than
    /// `current`. A malformed/older/equal tag yields false — we never nag on
    /// something we can't confidently compare.
    pub update_available: bool,
    /// The release's human page on GitHub, opened via the system browser.
    pub url: String,
}

/// Minimal shape of the GitHub "latest release" payload.
#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
}

/// Parse a `vX.Y.Z` (or `X.Y.Z`) tag into a comparable triple. Extra
/// pre-release/build suffix after the patch number is ignored — Clavix ships
/// plain release-please tags, so this covers every real tag while refusing to
/// guess on anything odd (returns None → treated as "no update").
fn parse_semver(tag: &str) -> Option<(u64, u64, u64)> {
    let core = tag.trim().trim_start_matches('v');
    // Drop any pre-release/build metadata so "1.2.3-rc1" still compares by core.
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// Query GitHub for the latest release and compare it to this build. Network
/// or parse failures surface as `Err` — the caller (command) decides whether to
/// swallow them, but a failed check must never disrupt the app.
pub async fn check_for_update() -> Result<UpdateInfo> {
    let current = env!("CARGO_PKG_VERSION").to_string();

    let client = reqwest::Client::builder().build()?;
    let response = client
        .get(RELEASES_LATEST_API)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: "GitHub releases API error".into(),
        });
    }

    let release: GithubRelease = response.json().await.map_err(|e| Error::InvalidResponse {
        reason: format!("could not parse GitHub release JSON: {e}"),
    })?;

    let latest = release.tag_name.trim_start_matches('v').to_string();
    let update_available = match (parse_semver(&current), parse_semver(&release.tag_name)) {
        (Some(cur), Some(new)) => new > cur,
        _ => false,
    };

    Ok(UpdateInfo {
        current,
        latest,
        update_available,
        url: release.html_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_v_prefixed_tags() {
        assert_eq!(parse_semver("v0.5.0"), Some((0, 5, 0)));
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver(" v10.20.30 "), Some((10, 20, 30)));
    }

    #[test]
    fn ignores_prerelease_and_build_suffixes() {
        assert_eq!(parse_semver("v1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_semver("1.2.3+build7"), Some((1, 2, 3)));
    }

    #[test]
    fn rejects_malformed_tags() {
        assert_eq!(parse_semver("nightly"), None);
        assert_eq!(parse_semver("v1.2"), None);
        assert_eq!(parse_semver(""), None);
    }

    #[test]
    fn newer_tag_is_greater() {
        assert!(parse_semver("v0.5.0") > parse_semver("v0.4.9"));
        assert!(parse_semver("v1.0.0") > parse_semver("v0.9.9"));
        assert!(parse_semver("v0.4.1") > parse_semver("v0.4.0"));
        assert!(parse_semver("v0.4.0") <= parse_semver("v0.4.0"));
        assert!(parse_semver("v0.3.0") <= parse_semver("v0.4.0"));
    }
}
