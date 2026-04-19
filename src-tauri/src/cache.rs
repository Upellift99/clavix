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

    // Snapshot of a cipher captured *before* a destructive operation
    // (`share` moves it to another org with re-encryption, `delete` purges
    // it server-side). The blob is the JSON-serialised `Cipher` object,
    // encrypted with the user key. Lets us recover the original entry if
    // the server-side operation half-fails or returns an unexpected error.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cipher_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            cipher_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            encrypted_blob TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )
    .map_err(|e| Error::Storage {
        reason: format!("create cipher_snapshots table: {e}"),
    })?;

    // Per-folder rows for an in-flight `move_folder_path` batch. Each row
    // records the original and target encrypted name; rows are flipped to
    // applied=1 as their PUT succeeds. A crash mid-batch leaves the
    // unflipped rows queryable so we can finish or roll back the rename.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS folder_op_log (
            op_id TEXT NOT NULL,
            folder_id TEXT NOT NULL,
            original_encrypted_name TEXT NOT NULL,
            new_encrypted_name TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            applied INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            PRIMARY KEY (op_id, folder_id)
        )",
        [],
    )
    .map_err(|e| Error::Storage {
        reason: format!("create folder_op_log table: {e}"),
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
    conn.execute("DELETE FROM cipher_snapshots", [])
        .map_err(|e| Error::Storage {
            reason: format!("clear cipher snapshots: {e}"),
        })?;
    conn.execute("DELETE FROM folder_op_log", [])
        .map_err(|e| Error::Storage {
            reason: format!("clear folder op log: {e}"),
        })?;
    Ok(())
}

pub fn save_cipher_snapshot(
    snapshot_id: &str,
    cipher_id: &str,
    operation: &str,
    encrypted_blob: &str,
) -> Result<()> {
    let conn = open()?;
    let now = chrono_like_now();
    conn.execute(
        "INSERT INTO cipher_snapshots
            (snapshot_id, cipher_id, operation, encrypted_blob, created_at, completed)
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![snapshot_id, cipher_id, operation, encrypted_blob, now],
    )
    .map_err(|e| Error::Storage {
        reason: format!("save cipher snapshot: {e}"),
    })?;
    Ok(())
}

pub fn mark_snapshot_completed(snapshot_id: &str) -> Result<()> {
    let conn = open()?;
    conn.execute(
        "UPDATE cipher_snapshots SET completed = 1 WHERE snapshot_id = ?1",
        params![snapshot_id],
    )
    .map_err(|e| Error::Storage {
        reason: format!("mark snapshot completed: {e}"),
    })?;
    Ok(())
}

pub fn save_folder_op_batch(
    op_id: &str,
    operations: &[(String, String, String)], // (folder_id, original_enc, new_enc)
) -> Result<()> {
    let mut conn = open()?;
    let now = chrono_like_now();
    let tx = conn.transaction().map_err(|e| Error::Storage {
        reason: format!("begin folder op tx: {e}"),
    })?;
    for (i, (folder_id, original, new_name)) in operations.iter().enumerate() {
        tx.execute(
            "INSERT INTO folder_op_log
                (op_id, folder_id, original_encrypted_name, new_encrypted_name,
                 sequence, applied, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![op_id, folder_id, original, new_name, i as i64, now],
        )
        .map_err(|e| Error::Storage {
            reason: format!("insert folder op row: {e}"),
        })?;
    }
    tx.commit().map_err(|e| Error::Storage {
        reason: format!("commit folder op tx: {e}"),
    })?;
    Ok(())
}

pub fn mark_folder_op_applied(op_id: &str, folder_id: &str) -> Result<()> {
    let conn = open()?;
    conn.execute(
        "UPDATE folder_op_log SET applied = 1 WHERE op_id = ?1 AND folder_id = ?2",
        params![op_id, folder_id],
    )
    .map_err(|e| Error::Storage {
        reason: format!("mark folder op applied: {e}"),
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
