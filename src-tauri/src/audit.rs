use std::collections::{HashMap, HashSet};

use futures::stream::{self, StreamExt};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::error::{Error, Result};

const HIBP_API: &str = "https://api.pwnedpasswords.com/range/";
const HIBP_USER_AGENT: &str = concat!("Clavix/", env!("CARGO_PKG_VERSION"));
const CONCURRENT_REQUESTS: usize = 8;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PasswordAuditEntry {
    pub cipher_id: String,
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReusedGroup {
    /// All ciphers that share the same password.
    pub cipher_ids: Vec<String>,
    pub names: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WeakEntry {
    pub cipher_id: String,
    pub name: String,
    /// zxcvbn score, 0 (très faible) à 4 (très fort).  Ici on ne garde
    /// que les entrées <= 2.
    pub score: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordAuditResult {
    pub checked: usize,
    pub pwned: Vec<PasswordAuditEntry>,
    pub reused: Vec<ReusedGroup>,
    pub weak: Vec<WeakEntry>,
}

fn sha1_hex_upper(data: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    let mut out = String::with_capacity(40);
    use std::fmt::Write;
    for byte in hash.iter() {
        let _ = write!(out, "{:02X}", byte);
    }
    out
}

async fn fetch_prefix(client: &Client, prefix: &str) -> Result<HashMap<String, u64>> {
    let url = format!("{HIBP_API}{prefix}");
    let response = client
        .get(&url)
        .header("User-Agent", HIBP_USER_AGENT)
        .header("Add-Padding", "true")
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            message: "HIBP range API error".into(),
        });
    }
    let body = response.text().await?;
    let mut map = HashMap::new();
    for line in body.lines() {
        if let Some((suffix, count)) = line.trim().split_once(':') {
            if let Ok(n) = count.parse::<u64>() {
                if n > 0 {
                    map.insert(suffix.to_ascii_uppercase(), n);
                }
            }
        }
    }
    Ok(map)
}

pub async fn audit_passwords(
    entries: Vec<(String, String, SecretString)>,
) -> Result<PasswordAuditResult> {
    let checked = entries.len();
    if entries.is_empty() {
        return Ok(PasswordAuditResult {
            checked: 0,
            pwned: vec![],
            reused: vec![],
            weak: vec![],
        });
    }

    // Compute reused groups + weak entries locally before we drop plaintext.
    let (reused, weak) = analyze_local(&entries);

    let hashed: Vec<(String, String, String)> = entries
        .into_iter()
        .map(|(cid, name, password)| {
            let h = sha1_hex_upper(password.expose_secret());
            (cid, name, h)
        })
        .collect();

    let prefixes: HashSet<String> = hashed.iter().map(|(_, _, h)| h[..5].to_string()).collect();

    let client = Client::builder().build()?;

    let results: Vec<Result<(String, HashMap<String, u64>)>> = stream::iter(prefixes)
        .map(|prefix| {
            let client = &client;
            async move {
                let m = fetch_prefix(client, &prefix).await?;
                Ok::<_, Error>((prefix, m))
            }
        })
        .buffer_unordered(CONCURRENT_REQUESTS)
        .collect()
        .await;

    let mut full_hash_counts: HashMap<String, u64> = HashMap::new();
    for r in results {
        let (prefix, map) = r?;
        for (suffix, count) in map {
            full_hash_counts.insert(format!("{prefix}{suffix}"), count);
        }
    }

    let mut pwned = Vec::new();
    for (cid, name, hash) in hashed {
        if let Some(&count) = full_hash_counts.get(&hash) {
            pwned.push(PasswordAuditEntry {
                cipher_id: cid,
                name,
                count,
            });
        }
    }

    pwned.sort_by_key(|e| std::cmp::Reverse(e.count));

    Ok(PasswordAuditResult {
        checked,
        pwned,
        reused,
        weak,
    })
}

fn analyze_local(entries: &[(String, String, SecretString)]) -> (Vec<ReusedGroup>, Vec<WeakEntry>) {
    // --- Reused: group by plaintext password ---
    let mut by_password: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (cid, name, pw) in entries {
        by_password
            .entry(pw.expose_secret().to_string())
            .or_default()
            .push((cid.clone(), name.clone()));
    }
    let mut reused: Vec<ReusedGroup> = by_password
        .into_values()
        .filter(|v| v.len() >= 2)
        .map(|v| {
            let (cipher_ids, names): (Vec<_>, Vec<_>) = v.into_iter().unzip();
            ReusedGroup { cipher_ids, names }
        })
        .collect();
    reused.sort_by_key(|g| std::cmp::Reverse(g.cipher_ids.len()));

    // --- Weak: zxcvbn score <= 2 ---
    let mut weak = Vec::new();
    for (cid, name, pw) in entries {
        let pw_str = pw.expose_secret();
        let score_enum = zxcvbn::zxcvbn(pw_str, &[]).score();
        let score = score_enum as u8;
        if score <= 2 {
            weak.push(WeakEntry {
                cipher_id: cid.clone(),
                name: name.clone(),
                score,
            });
        }
    }
    weak.sort_by_key(|w| w.score);

    (reused, weak)
}
