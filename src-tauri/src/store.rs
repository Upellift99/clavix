use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::models::KdfType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSession {
    pub server_url: String,
    pub email: String,
    /// Legacy clear-text refresh token. Kept only to migrate old session files
    /// written before refresh-token encryption landed. Always re-saved as `None`
    /// once we've successfully unlocked and re-encrypted the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Refresh token encrypted with the user key (AES-CBC + HMAC-SHA256). Means
    /// the master password is required to reuse the session, so a stolen
    /// `session.json` (e.g. via a backup folder synced to a cloud service)
    /// no longer hands the attacker a working refresh credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_refresh_token: Option<String>,
    pub kdf: KdfType,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub encrypted_user_key: String,
    pub encrypted_private_key: Option<String>,
    /// Optional Yubikey re-unlock material. Present only when the user
    /// has explicitly enrolled a FIDO2 token. `skip_serializing_if`
    /// means session files written before this feature shipped stay
    /// byte-identical until the user opts in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yubikey_unlock: Option<YubikeyUnlockBlock>,
}

/// On-disk material that lets a FIDO2 token release the cached user key
/// without re-typing the master password. Schema documented in
/// `YUBIKEY_UNLOCK.md`. The wrap key never touches disk: only the
/// ciphertext, the per-credential salt, the credential id, and a
/// non-secret HKDF fingerprint of the user key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeyUnlockBlock {
    /// Schema version. Bumped on any wire change.
    pub version: u32,
    /// Stable Relying Party identifier for the credential. We use a
    /// fixed local string — the credential is bound to Clavix on this
    /// machine, not to a domain.
    pub rp_id: String,
    /// CTAP2 credential id, base64-standard. Stored client-side because
    /// we use **non-resident** credentials, which saves the limited
    /// resident-key slots on the user's token.
    pub credential_id: String,
    /// 32 random bytes, fresh per enrolment. Reused at every unlock as
    /// the input to the hmac-secret extension. Base64-standard.
    pub salt: String,
    /// User key (64 raw bytes, enc + mac concatenated) wrapped under
    /// the hmac-secret-derived key. Stored as a Bitwarden-style type-2
    /// `EncString` (AES-256-CBC + HMAC-SHA256) — same primitive used
    /// elsewhere in the app, well-covered by existing proptests.
    pub wrapped_user_key: String,
    /// HKDF-SHA256 derivative of the user key, truncated to 16 bytes,
    /// base64-standard. Lets us detect that the master password was
    /// rotated on another client (which rotates the user key) so we
    /// can drop the stale wrap rather than producing wrong decrypts.
    pub user_key_fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct DeviceFile {
    device_id: String,
}

fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir().ok_or_else(|| Error::Storage {
        reason: "could not locate the local data directory for this platform".into(),
    })?;
    let dir = base.join("clavix");
    fs::create_dir_all(&dir).map_err(|e| Error::Storage {
        reason: format!("create data dir {}: {e}", dir.display()),
    })?;
    Ok(dir)
}

fn session_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("session.json"))
}

fn device_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("device.json"))
}

pub fn load_session() -> Result<Option<PersistedSession>> {
    let path = session_path()?;
    match fs::read_to_string(&path) {
        Ok(json) => {
            let mut session: PersistedSession =
                serde_json::from_str(&json).map_err(|e| Error::Storage {
                    reason: format!("decode {}: {e}", path.display()),
                })?;
            // Proactively strip a *redundant* clear-text refresh token: once the
            // encrypted variant exists, the plaintext is dead weight that only
            // adds disk-read/session-replay risk (a `session.json` synced to a
            // backup folder). Drop it in memory and re-persist without it. When
            // only the plaintext exists (a pre-encryption session not yet
            // unlocked) it can't be re-encrypted without the master key, so it
            // stays until the first unlock migrates it (see `commands::auth::unlock`).
            if session.refresh_token.is_some() && session.encrypted_refresh_token.is_some() {
                session.refresh_token = None;
                let _ = save_session(&session);
            }
            Ok(Some(session))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Storage {
            reason: format!("read {}: {e}", path.display()),
        }),
    }
}

pub fn save_session(session: &PersistedSession) -> Result<()> {
    let path = session_path()?;
    let json = serde_json::to_string_pretty(session).map_err(|e| Error::Storage {
        reason: format!("encode session: {e}"),
    })?;
    atomic_write(&path, &json)
}

pub fn clear_session() -> Result<()> {
    let path = session_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Storage {
            reason: format!("remove {}: {e}", path.display()),
        }),
    }
}

pub fn get_or_create_device_id() -> Result<String> {
    let path = device_path()?;
    match fs::read_to_string(&path) {
        Ok(json) => {
            let file: DeviceFile = serde_json::from_str(&json).map_err(|e| Error::Storage {
                reason: format!("decode {}: {e}", path.display()),
            })?;
            Ok(file.device_id)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let new_id = Uuid::new_v4().to_string();
            let file = DeviceFile {
                device_id: new_id.clone(),
            };
            let json = serde_json::to_string_pretty(&file).map_err(|e| Error::Storage {
                reason: format!("encode device file: {e}"),
            })?;
            atomic_write(&path, &json)?;
            Ok(new_id)
        }
        Err(e) => Err(Error::Storage {
            reason: format!("read {}: {e}", path.display()),
        }),
    }
}

fn atomic_write(path: &Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents).map_err(|e| Error::Storage {
        reason: format!("write {}: {e}", tmp.display()),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp, perms).map_err(|e| Error::Storage {
            reason: format!("chmod {}: {e}", tmp.display()),
        })?;
    }

    fs::rename(&tmp, path).map_err(|e| Error::Storage {
        reason: format!("rename {} -> {}: {e}", tmp.display(), path.display()),
    })?;
    Ok(())
}
