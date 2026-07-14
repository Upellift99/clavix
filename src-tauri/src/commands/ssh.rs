use serde::Serialize;
use tauri::State;

use crate::crypto::decrypt_name;
use crate::error::{Error, Result};
use crate::models::CipherType;
use crate::ssh_agent;
use crate::state::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposedKey {
    /// Comment field of the OpenSSH key — falls back to the cipher name
    /// when the key's own comment is empty.
    pub comment: String,
    /// Wire-format algorithm name, e.g. `"ssh-ed25519"` / `"ssh-rsa"`.
    pub algorithm: String,
    /// Same `"SHA256:…"` format `ssh-add -l` prints.
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedKey {
    /// Cipher name (or key comment if cipher decryption failed).
    pub name: String,
    /// Human-readable reason — surfaced to the user so they know whether
    /// the key was skipped because of an unsupported algorithm
    /// (ECDSA / DSA), a leftover passphrase-encrypted PEM that pre-dates
    /// the import-time decrypt flow, or a malformed key.
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentStatus {
    pub running: bool,
    pub socket_path: Option<String>,
    pub keys: Vec<ExposedKey>,
    /// Populated only by the `start_ssh_agent` response — the
    /// `ssh_agent_status` command keeps it empty since it doesn't
    /// re-attempt the load from the vault.
    pub skipped: Vec<SkippedKey>,
}

#[tauri::command]
pub async fn start_ssh_agent(state: State<'_, AppState>) -> Result<SshAgentStatus> {
    // Stop any previous instance first — simpler than reconciling state.
    let previous = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = previous {
        h.stop().await;
    }

    // Decrypt every SSH key item from the current vault, inside the lock.
    let decrypted: Vec<(String, String, String)> = {
        let guard = state.session.lock();
        let session = guard.as_ref().ok_or(Error::NotAuthenticated)?;
        let vault = session.vault.as_ref().ok_or_else(|| Error::Storage {
            reason: "no vault synced yet — synchronise first".into(),
        })?;
        vault
            .ciphers
            .iter()
            .filter(|c| c.deleted_date.is_none())
            .filter(|c| matches!(c.kind, CipherType::SshKey))
            .filter_map(|c| {
                let ssh = c.ssh_key.as_ref()?;
                let pk_enc = ssh.private_key.as_deref()?;
                let owner = crate::services::cipher::owning_key(c, &session.user_key, &session.org_keys);
                let item = crate::services::cipher::item_key(c, owner);
                let key = item.as_ref().unwrap_or(owner);
                let name = decrypt_name(&c.name, key).ok()?;
                let pem = decrypt_name(pk_enc, key).ok()?;
                Some((c.id.clone(), name, pem))
            })
            .collect()
    };

    let socket_path = ssh_agent::default_socket_path()?;

    let mut agent_keys = Vec::new();
    let mut skipped: Vec<SkippedKey> = Vec::new();
    for (_id, name, pem) in &decrypted {
        match ssh_agent::try_load_agent_key(pem, name) {
            Ok(Some(k)) => agent_keys.push(k),
            Ok(None) => skipped.push(SkippedKey {
                name: name.clone(),
                reason: "unsupported algorithm (only Ed25519 and RSA load into the agent today)"
                    .into(),
            }),
            Err(Error::Crypto { reason }) => {
                // The most common case here is the legacy "passphrase-protected"
                // marker from before the import-time decrypt flow shipped.
                // Surface the underlying message verbatim so the user
                // understands what to do (re-open the cipher to decrypt it,
                // or fix a malformed PEM).
                eprintln!("[clavix agent] skipping '{name}': {reason}");
                skipped.push(SkippedKey {
                    name: name.clone(),
                    reason,
                });
            }
            Err(e) => {
                eprintln!("[clavix agent] skipping '{name}': {e}");
                skipped.push(SkippedKey {
                    name: name.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    let handle = ssh_agent::start_agent(socket_path.clone(), agent_keys).await?;
    let exposed: Vec<ExposedKey> = handle
        .keys
        .iter()
        .map(|k| ExposedKey {
            comment: k.comment.clone(),
            algorithm: k.algorithm.clone(),
            fingerprint: k.fingerprint.clone(),
        })
        .collect();
    let status = SshAgentStatus {
        running: true,
        socket_path: Some(handle.socket_path.to_string_lossy().into_owned()),
        keys: exposed,
        skipped,
    };

    {
        let mut slot = state.ssh_agent.lock();
        *slot = Some(handle);
    }
    Ok(status)
}

#[tauri::command]
pub async fn stop_ssh_agent(state: State<'_, AppState>) -> Result<()> {
    let handle = {
        let mut slot = state.ssh_agent.lock();
        slot.take()
    };
    if let Some(h) = handle {
        h.stop().await;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedSshKey {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}

/// Parse an OpenSSH private key, decrypt it with `passphrase` if needed,
/// and return the canonical unencrypted PEM together with the SSH public-key
/// line and SHA-256 fingerprint. Mirrors the import-time UX of Bitwarden
/// Desktop: the passphrase is consumed once, never stored.
#[tauri::command]
pub fn decrypt_ssh_private_key(
    private_key: String,
    passphrase: Option<String>,
) -> Result<DecryptedSshKey> {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let mut pk = PrivateKey::from_openssh(&private_key).map_err(|e| Error::Crypto {
        reason: format!("ssh key parse: {e}"),
    })?;

    // Check the algorithm BEFORE prompting for or consuming a passphrase.
    // The algorithm header is in the unencrypted portion of the OpenSSH
    // format, so we can reject ECDSA / DSA up front instead of having the
    // user type a passphrase that turns out to be useless.
    match pk.algorithm() {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } => {}
        other => {
            return Err(Error::Crypto {
                reason: format!(
                    "unsupported SSH algorithm: {other} — only Ed25519 and RSA can be loaded into the agent"
                ),
            });
        }
    }

    if pk.is_encrypted() {
        let pass = passphrase.ok_or(Error::SshPassphraseRequired)?;
        pk = pk
            .decrypt(pass.as_bytes())
            .map_err(|_| Error::SshWrongPassphrase)?;
    }

    let private_pem = pk
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Crypto {
            reason: format!("ssh key re-encode: {e}"),
        })?
        .to_string();
    let public_pem = pk.public_key().to_openssh().map_err(|e| Error::Crypto {
        reason: format!("ssh public encode: {e}"),
    })?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    Ok(DecryptedSshKey {
        private_key: private_pem,
        public_key: public_pem,
        key_fingerprint: fingerprint,
    })
}

/// Generate a fresh Ed25519 SSH keypair, returning the canonical
/// OpenSSH-format private key, the public-key line, and the SHA-256
/// fingerprint. Same shape as `decrypt_ssh_private_key` so the editor
/// can drop the result straight into its sshKey state.
///
/// Ed25519 only for now: it's the modern default (`ssh-keygen` picks
/// it by default since OpenSSH 9.5), 256-bit equivalent security with
/// 32-byte keys, generation is essentially instantaneous. RSA support
/// can ship later as a separate algorithm parameter — until then,
/// users with infra that requires RSA can paste an existing key.
#[tauri::command]
pub fn generate_ssh_key() -> Result<DecryptedSshKey> {
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let mut rng = rand::thread_rng();
    let pk = PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(|e| Error::Crypto {
        reason: format!("generate ed25519 ssh key: {e}"),
    })?;

    let private_pem = pk
        .to_openssh(LineEnding::LF)
        .map_err(|e| Error::Crypto {
            reason: format!("encode generated private key: {e}"),
        })?
        .to_string();
    let public_pem = pk.public_key().to_openssh().map_err(|e| Error::Crypto {
        reason: format!("encode generated public key: {e}"),
    })?;
    let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();

    Ok(DecryptedSshKey {
        private_key: private_pem,
        public_key: public_pem,
        key_fingerprint: fingerprint,
    })
}

#[cfg(test)]
mod decrypt_tests {
    use super::*;

    #[test]
    fn rejects_non_pem_garbage() {
        let res = decrypt_ssh_private_key("this is definitely not an OpenSSH key".into(), None);
        match res {
            Err(Error::Crypto { reason }) => assert!(reason.starts_with("ssh key parse:")),
            other => panic!("expected Crypto parse error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_input() {
        let res = decrypt_ssh_private_key(String::new(), None);
        assert!(matches!(res, Err(Error::Crypto { .. })));
    }

    #[test]
    fn rejects_truncated_pem_header() {
        // Truncated mid-header — must not panic, must return parse error.
        let res = decrypt_ssh_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\n".into(), None);
        assert!(matches!(res, Err(Error::Crypto { .. })));
    }
}

#[cfg(test)]
mod generate_tests {
    use super::*;

    #[test]
    fn generated_key_round_trips_through_decrypt_command() {
        // Fresh Ed25519 → returned PEM is unencrypted, so feeding it
        // back through decrypt_ssh_private_key (no passphrase) gives
        // a stable result. Catches regressions where the encoder and
        // parser disagree on the wire format.
        let gen = generate_ssh_key().expect("generate ed25519");
        assert!(gen.public_key.starts_with("ssh-ed25519 "));
        assert!(gen.key_fingerprint.starts_with("SHA256:"));
        assert!(gen.private_key.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!gen.private_key.contains("ENCRYPTED"));

        let parsed = decrypt_ssh_private_key(gen.private_key.clone(), None)
            .expect("freshly generated key parses back");
        assert_eq!(parsed.public_key, gen.public_key);
        assert_eq!(parsed.key_fingerprint, gen.key_fingerprint);
    }

    #[test]
    fn two_calls_produce_different_keys() {
        // Sanity check that the RNG is actually being consumed —
        // a wedged generator that returned a constant key would
        // be a serious zero-day (and a hilarious test failure).
        let a = generate_ssh_key().unwrap();
        let b = generate_ssh_key().unwrap();
        assert_ne!(a.key_fingerprint, b.key_fingerprint);
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }
}

#[tauri::command]
pub fn ssh_agent_status(state: State<'_, AppState>) -> Result<SshAgentStatus> {
    let slot = state.ssh_agent.lock();
    Ok(match slot.as_ref() {
        Some(h) => SshAgentStatus {
            running: true,
            socket_path: Some(h.socket_path.to_string_lossy().into_owned()),
            keys: h
                .keys
                .iter()
                .map(|k| ExposedKey {
                    comment: k.comment.clone(),
                    algorithm: k.algorithm.clone(),
                    fingerprint: k.fingerprint.clone(),
                })
                .collect(),
            skipped: Vec::new(),
        },
        None => SshAgentStatus {
            running: false,
            socket_path: None,
            keys: Vec::new(),
            skipped: Vec::new(),
        },
    })
}

/// Returns whatever `SSH_AUTH_SOCK` was set to in the process
/// environment when Clavix launched. Used by the agent UI to tell the
/// user whether the variable already points at our socket or whether
/// they still need to export it. Reads only this single variable, no
/// arbitrary env access.
#[tauri::command]
pub fn ssh_auth_sock() -> Option<String> {
    std::env::var("SSH_AUTH_SOCK").ok()
}
