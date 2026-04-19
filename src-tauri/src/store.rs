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
    pub refresh_token: String,
    pub kdf: KdfType,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub encrypted_user_key: String,
    pub encrypted_private_key: Option<String>,
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
            let session: PersistedSession =
                serde_json::from_str(&json).map_err(|e| Error::Storage {
                    reason: format!("decode {}: {e}", path.display()),
                })?;
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
