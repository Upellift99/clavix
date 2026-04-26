use serde::Serialize;
use tauri::State;

use crate::crypto::decrypt_name;
use crate::error::{Error, Result};
use crate::models::CipherType;
use crate::ssh_agent;
use crate::state::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentStatus {
    pub running: bool,
    pub socket_path: Option<String>,
    pub key_count: usize,
    pub skipped_count: usize,
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
                let key = c
                    .organization_id
                    .as_ref()
                    .and_then(|oid| session.org_keys.get(oid))
                    .unwrap_or(&session.user_key);
                let name = decrypt_name(&c.name, key).ok()?;
                let pem = decrypt_name(pk_enc, key).ok()?;
                Some((c.id.clone(), name, pem))
            })
            .collect()
    };

    let socket_path = ssh_agent::default_socket_path()?;

    let mut agent_keys = Vec::new();
    let mut skipped = 0usize;
    for (_id, name, pem) in &decrypted {
        match ssh_agent::try_load_agent_key(pem, name) {
            Ok(Some(k)) => agent_keys.push(k),
            Ok(None) => skipped += 1, // unsupported type (rsa, ecdsa, ...)
            Err(e) => {
                eprintln!("[clavix agent] skipping '{name}': {e}");
                skipped += 1;
            }
        }
    }

    let handle = ssh_agent::start_agent(socket_path.clone(), agent_keys).await?;
    let status = SshAgentStatus {
        running: true,
        socket_path: Some(handle.socket_path.to_string_lossy().into_owned()),
        key_count: handle.key_count,
        skipped_count: skipped,
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

#[tauri::command]
pub fn ssh_agent_status(state: State<'_, AppState>) -> Result<SshAgentStatus> {
    let slot = state.ssh_agent.lock();
    Ok(match slot.as_ref() {
        Some(h) => SshAgentStatus {
            running: true,
            socket_path: Some(h.socket_path.to_string_lossy().into_owned()),
            key_count: h.key_count,
            skipped_count: 0,
        },
        None => SshAgentStatus {
            running: false,
            socket_path: None,
            key_count: 0,
            skipped_count: 0,
        },
    })
}
