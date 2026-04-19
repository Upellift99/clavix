//! Clavix SSH agent — Unix-only for now. On Windows, the public API
//! returns `Error::Storage` with a clear reason so the Svelte UI can
//! display the "not supported" message.

#[cfg(not(unix))]
use crate::error::{Error, Result};
#[cfg(not(unix))]
use std::path::PathBuf;

#[cfg(unix)]
pub use unix::*;

#[cfg(not(unix))]
mod stub {
    use super::*;

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        pub key_count: usize,
    }

    impl SshAgentHandle {
        pub async fn stop(self) {}
        pub fn stop_sync(self) {}
    }

    pub struct AgentKey;

    pub fn default_socket_path() -> Result<PathBuf> {
        Err(Error::Storage {
            reason: "SSH agent is only supported on Unix systems for now".into(),
        })
    }

    pub fn try_load_agent_key(_pem: &str, _comment: &str) -> Result<Option<AgentKey>> {
        Ok(None)
    }

    pub async fn start_agent(_path: PathBuf, _keys: Vec<AgentKey>) -> Result<SshAgentHandle> {
        Err(Error::Storage {
            reason: "SSH agent is only supported on Unix systems for now".into(),
        })
    }
}

#[cfg(not(unix))]
pub use stub::*;

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey};
    use ssh_key::{Algorithm, PrivateKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;

    use crate::error::{Error, Result};

    // Agent protocol message types (draft-miller-ssh-agent).
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    const SSH_AGENT_FAILURE: u8 = 5;

    // Cap any single agent request to 256 KB — real traffic is orders smaller.
    const MAX_MESSAGE: usize = 256 * 1024;

    pub struct AgentKey {
        /// SSH wire-format public key blob (what clients compare against).
        pub pub_blob: Vec<u8>,
        pub comment: String,
        /// Ed25519 signer.  RSA/ECDSA to be added later — keys of those
        /// types are filtered out at load time.
        pub signer: SigningKey,
    }

    type KeyStore = Arc<Mutex<Vec<AgentKey>>>;

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        pub key_count: usize,
        task: JoinHandle<()>,
        #[allow(dead_code)]
        keys: KeyStore,
    }

    impl SshAgentHandle {
        pub async fn stop(self) {
            self.task.abort();
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }

        /// Non-async best-effort stop, suitable for `lock` / `logout` commands
        /// that don't want to be async just for this cleanup.
        pub fn stop_sync(self) {
            self.task.abort();
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    pub fn default_socket_path() -> Result<PathBuf> {
        let dir = dirs::runtime_dir()
            .or_else(dirs::cache_dir)
            .ok_or_else(|| Error::Storage {
                reason: "no runtime or cache dir available for agent socket".into(),
            })?;
        let mut path = dir;
        path.push("clavix");
        std::fs::create_dir_all(&path).map_err(|e| Error::Storage {
            reason: format!("cannot create agent dir {}: {e}", path.display()),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
        }
        path.push("agent.sock");
        Ok(path)
    }

    /// Parse an OpenSSH private key and wrap it as an `AgentKey` if we can sign
    /// with it today (Ed25519 only for this pass).  Returns `Ok(None)` for key
    /// types we intentionally skip, `Err` for malformed / encrypted input.
    pub fn try_load_agent_key(
        private_key_pem: &str,
        public_comment: &str,
    ) -> Result<Option<AgentKey>> {
        let pk = PrivateKey::from_openssh(private_key_pem).map_err(|e| Error::Crypto {
            reason: format!("ssh key parse: {e}"),
        })?;
        if pk.is_encrypted() {
            return Err(Error::Crypto {
                reason: "SSH private key is passphrase-protected — decrypt it first".into(),
            });
        }
        match pk.algorithm() {
            Algorithm::Ed25519 => {
                let keypair = pk.key_data().ed25519().ok_or_else(|| Error::Crypto {
                    reason: "ed25519 keypair extraction failed".into(),
                })?;
                let secret_bytes: &[u8; 32] = keypair.private.as_ref();
                let signer = SigningKey::from_bytes(secret_bytes);
                let pub_blob = pk.public_key().to_bytes().map_err(|e| Error::Crypto {
                    reason: format!("ssh public blob: {e}"),
                })?;
                let comment = if !pk.comment().is_empty() {
                    pk.comment().to_string()
                } else {
                    public_comment.to_string()
                };
                Ok(Some(AgentKey {
                    pub_blob,
                    comment,
                    signer,
                }))
            }
            _ => Ok(None),
        }
    }

    pub async fn start_agent(socket_path: PathBuf, keys: Vec<AgentKey>) -> Result<SshAgentHandle> {
        // Remove any stale socket file.
        let _ = tokio::fs::remove_file(&socket_path).await;
        let listener = UnixListener::bind(&socket_path).map_err(|e| Error::Storage {
            reason: format!("bind {}: {e}", socket_path.display()),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
        }

        let key_count = keys.len();
        let store: KeyStore = Arc::new(Mutex::new(keys));
        let store_task = store.clone();
        let path_for_task = socket_path.clone();

        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let store = store_task.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve(stream, store).await {
                                eprintln!("[clavix agent] connection error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!(
                            "[clavix agent] accept failed on {}: {e}",
                            path_for_task.display()
                        );
                        break;
                    }
                }
            }
        });

        Ok(SshAgentHandle {
            socket_path,
            key_count,
            task,
            keys: store,
        })
    }

    async fn serve(mut stream: UnixStream, keys: KeyStore) -> std::io::Result<()> {
        loop {
            let len = match stream.read_u32().await {
                Ok(n) => n as usize,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            };
            if len == 0 || len > MAX_MESSAGE {
                return Ok(());
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let msg_type = buf[0];
            let payload = &buf[1..];

            let response = match msg_type {
                SSH_AGENTC_REQUEST_IDENTITIES => handle_list(&keys).await,
                SSH_AGENTC_SIGN_REQUEST => handle_sign(&keys, payload).await,
                _ => vec![SSH_AGENT_FAILURE],
            };

            let len_bytes = u32::to_be_bytes(response.len() as u32);
            stream.write_all(&len_bytes).await?;
            stream.write_all(&response).await?;
            stream.flush().await?;
        }
    }

    async fn handle_list(keys: &KeyStore) -> Vec<u8> {
        let guard = keys.lock().await;
        let mut out = Vec::with_capacity(64);
        out.push(SSH_AGENT_IDENTITIES_ANSWER);
        out.extend_from_slice(&u32::to_be_bytes(guard.len() as u32));
        for k in guard.iter() {
            write_string(&mut out, &k.pub_blob);
            write_string(&mut out, k.comment.as_bytes());
        }
        out
    }

    async fn handle_sign(keys: &KeyStore, payload: &[u8]) -> Vec<u8> {
        let mut reader = SshReader::new(payload);
        let Ok(key_blob) = reader.read_string() else {
            return vec![SSH_AGENT_FAILURE];
        };
        let Ok(data) = reader.read_string() else {
            return vec![SSH_AGENT_FAILURE];
        };
        // We ignore `flags`; Ed25519 has no per-request hash choice.
        let _flags = reader.read_u32().unwrap_or(0);

        let guard = keys.lock().await;
        let Some(key) = guard.iter().find(|k| k.pub_blob == key_blob) else {
            return vec![SSH_AGENT_FAILURE];
        };

        let signature = key.signer.sign(data);
        let mut sig_blob = Vec::with_capacity(96);
        write_string(&mut sig_blob, b"ssh-ed25519");
        write_string(&mut sig_blob, &signature.to_bytes());

        let mut out = Vec::with_capacity(sig_blob.len() + 5);
        out.push(SSH_AGENT_SIGN_RESPONSE);
        write_string(&mut out, &sig_blob);
        out
    }

    fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&u32::to_be_bytes(s.len() as u32));
        buf.extend_from_slice(s);
    }

    struct SshReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> SshReader<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn read_u32(&mut self) -> std::io::Result<u32> {
            if self.pos + 4 > self.buf.len() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let n = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;
            Ok(n)
        }

        fn read_string(&mut self) -> std::io::Result<&'a [u8]> {
            let len = self.read_u32()? as usize;
            if self.pos + len > self.buf.len() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let slice = &self.buf[self.pos..self.pos + len];
            self.pos += len;
            Ok(slice)
        }
    }
} // mod unix
