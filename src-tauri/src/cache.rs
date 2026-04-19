use std::fs;
use std::path::PathBuf;

use rusqlite::{params, Connection};

use crate::error::{Error, Result};

fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir().ok_or_else(|| Error::Storage {
        reason: "could not locate the local data directory".into(),
    })?;
    let dir = base.join("clavix");
    fs::create_dir_all(&dir).map_err(|e| Error::Storage {
        reason: format!("create data dir {}: {e}", dir.display()),
    })?;
    Ok(dir)
}

fn db_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("vault.db"))
}

fn open() -> Result<Connection> {
    let path = db_path()?;
    let conn = Connection::open(&path).map_err(|e| Error::Storage {
        reason: format!("open vault cache db at {}: {e}", path.display()),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&path, perms);
    }

    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault_cache (
            account_key TEXT PRIMARY KEY,
            encrypted_blob TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    )
    .map_err(|e| Error::Storage {
        reason: format!("create vault_cache table: {e}"),
    })?;
    Ok(conn)
}

pub fn account_key(server_url: &str, email: &str) -> String {
    format!(
        "{}|{}",
        server_url.trim(),
        email.trim().to_ascii_lowercase()
    )
}

pub fn save(account_key: &str, encrypted_blob: &str) -> Result<()> {
    let conn = open()?;
    let now = chrono_like_now();
    conn.execute(
        "INSERT INTO vault_cache (account_key, encrypted_blob, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(account_key) DO UPDATE SET
             encrypted_blob = excluded.encrypted_blob,
             updated_at = excluded.updated_at",
        params![account_key, encrypted_blob, now],
    )
    .map_err(|e| Error::Storage {
        reason: format!("save vault cache: {e}"),
    })?;
    Ok(())
}

pub fn load(account_key: &str) -> Result<Option<String>> {
    let conn = open()?;
    let mut stmt = conn
        .prepare("SELECT encrypted_blob FROM vault_cache WHERE account_key = ?1")
        .map_err(|e| Error::Storage {
            reason: format!("prepare load vault cache: {e}"),
        })?;
    let mut rows = stmt
        .query(params![account_key])
        .map_err(|e| Error::Storage {
            reason: format!("query vault cache: {e}"),
        })?;
    if let Some(row) = rows.next().map_err(|e| Error::Storage {
        reason: format!("read vault cache row: {e}"),
    })? {
        let blob: String = row.get(0).map_err(|e| Error::Storage {
            reason: format!("decode vault cache row: {e}"),
        })?;
        Ok(Some(blob))
    } else {
        Ok(None)
    }
}

pub fn clear_all() -> Result<()> {
    let conn = open()?;
    conn.execute("DELETE FROM vault_cache", [])
        .map_err(|e| Error::Storage {
            reason: format!("clear vault cache: {e}"),
        })?;
    Ok(())
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.to_string()
}
