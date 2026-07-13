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

    #[derive(Debug, Clone)]
    pub struct KeyInfo {
        pub comment: String,
        pub algorithm: String,
        pub fingerprint: String,
    }

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        pub keys: Vec<KeyInfo>,
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

    use ed25519_dalek::{Signer as _, SigningKey};
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::RsaPrivateKey;
    use sha2::{Sha256, Sha512};
    use ssh_key::{Algorithm, HashAlg, PrivateKey};
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

    // Flags on `SSH_AGENTC_SIGN_REQUEST`: which SHA variant for RSA.
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    // Cap any single agent request to 256 KB — real traffic is orders smaller.
    const MAX_MESSAGE: usize = 256 * 1024;

    pub enum SignerKind {
        Ed25519(SigningKey),
        Rsa(RsaPrivateKey),
    }

    pub struct AgentKey {
        /// SSH wire-format public key blob (what clients compare against).
        pub pub_blob: Vec<u8>,
        pub comment: String,
        /// Wire-format SSH algorithm name, e.g. `"ssh-ed25519"` or `"ssh-rsa"`.
        pub algorithm: String,
        /// `"SHA256:…"` fingerprint of the public key, matches what
        /// `ssh-add -l` would print.
        pub fingerprint: String,
        pub kind: SignerKind,
    }

    /// Slim, signing-material-free summary of an exposed key — what the
    /// agent status surface returns to the front-end. Mirrors the rows
    /// you'd see from `ssh-add -l`.
    #[derive(Debug, Clone)]
    pub struct KeyInfo {
        pub comment: String,
        pub algorithm: String,
        pub fingerprint: String,
    }

    impl From<&AgentKey> for KeyInfo {
        fn from(k: &AgentKey) -> Self {
            Self {
                comment: k.comment.clone(),
                algorithm: k.algorithm.clone(),
                fingerprint: k.fingerprint.clone(),
            }
        }
    }

    type KeyStore = Arc<Mutex<Vec<AgentKey>>>;

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        /// Public-only summary of every key currently exposed by the agent.
        /// The signing material itself stays in the keystore guarded by the
        /// task; this list is safe to clone into a status response.
        pub keys: Vec<KeyInfo>,
        task: JoinHandle<()>,
        #[allow(dead_code)]
        key_store: KeyStore,
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

    /// Parse an OpenSSH private key and wrap it as an `AgentKey` if we can
    /// sign with it. Today: Ed25519 and RSA. Returns `Ok(None)` for key
    /// types we intentionally skip (ECDSA, DSA), `Err` for malformed or
    /// encrypted input.
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
        let pub_blob = pk.public_key().to_bytes().map_err(|e| Error::Crypto {
            reason: format!("ssh public blob: {e}"),
        })?;
        let comment = if !pk.comment().is_empty() {
            pk.comment().to_string()
        } else {
            public_comment.to_string()
        };
        let algorithm = pk.algorithm().to_string();
        let fingerprint = pk.fingerprint(HashAlg::Sha256).to_string();
        let kind = match pk.algorithm() {
            Algorithm::Ed25519 => {
                let keypair = pk.key_data().ed25519().ok_or_else(|| Error::Crypto {
                    reason: "ed25519 keypair extraction failed".into(),
                })?;
                let secret_bytes: &[u8; 32] = keypair.private.as_ref();
                SignerKind::Ed25519(SigningKey::from_bytes(secret_bytes))
            }
            Algorithm::Rsa { .. } => {
                let keypair = pk.key_data().rsa().ok_or_else(|| Error::Crypto {
                    reason: "rsa keypair extraction failed".into(),
                })?;
                let n = rsa::BigUint::from_bytes_be(keypair.public.n.as_bytes());
                let e = rsa::BigUint::from_bytes_be(keypair.public.e.as_bytes());
                let d = rsa::BigUint::from_bytes_be(keypair.private.d.as_bytes());
                let p = rsa::BigUint::from_bytes_be(keypair.private.p.as_bytes());
                let q = rsa::BigUint::from_bytes_be(keypair.private.q.as_bytes());
                let rsa_key =
                    RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|err| {
                        Error::Crypto {
                            reason: format!("rsa key import: {err}"),
                        }
                    })?;
                SignerKind::Rsa(rsa_key)
            }
            _ => return Ok(None),
        };
        Ok(Some(AgentKey {
            pub_blob,
            comment,
            algorithm,
            fingerprint,
            kind,
        }))
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

        let key_summaries: Vec<KeyInfo> = keys.iter().map(KeyInfo::from).collect();
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
            keys: key_summaries,
            task,
            key_store: store,
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
        let flags = reader.read_u32().unwrap_or(0);

        let guard = keys.lock().await;
        let Some(key) = guard.iter().find(|k| k.pub_blob == key_blob) else {
            return vec![SSH_AGENT_FAILURE];
        };

        let (algo_name, sig_bytes): (&'static [u8], Vec<u8>) = match &key.kind {
            SignerKind::Ed25519(signer) => (b"ssh-ed25519", signer.sign(data).to_bytes().to_vec()),
            SignerKind::Rsa(rsa_key) => {
                // flags=4 → SHA-512, flags=2 → SHA-256, legacy flags=0
                // (SHA-1 / ssh-rsa) is deprecated — we degrade it to SHA-256
                // since modern servers no longer accept SHA-1 signatures.
                let mut rng = rand::thread_rng();
                match flags {
                    SSH_AGENT_RSA_SHA2_512 => {
                        let signing_key = RsaSigningKey::<Sha512>::new(rsa_key.clone());
                        let sig: RsaSignature = signing_key.sign_with_rng(&mut rng, data);
                        (b"rsa-sha2-512", sig.to_bytes().to_vec())
                    }
                    _ => {
                        // flags=0 (legacy ssh-rsa/SHA-1) or flags=2 (SHA-256)
                        let _ = SSH_AGENT_RSA_SHA2_256; // name retained for clarity
                        let signing_key = RsaSigningKey::<Sha256>::new(rsa_key.clone());
                        let sig: RsaSignature = signing_key.sign_with_rng(&mut rng, data);
                        (b"rsa-sha2-256", sig.to_bytes().to_vec())
                    }
                }
            }
        };

        let mut sig_blob = Vec::with_capacity(96);
        write_string(&mut sig_blob, algo_name);
        write_string(&mut sig_blob, &sig_bytes);

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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn write_string_prepends_big_endian_length() {
            let mut out = Vec::new();
            write_string(&mut out, b"abc");
            assert_eq!(out, vec![0, 0, 0, 3, b'a', b'b', b'c']);
            write_string(&mut out, &[]);
            assert_eq!(&out[7..], &[0, 0, 0, 0]);
        }

        #[test]
        fn ssh_reader_roundtrip_matches_write_string() {
            let mut buf = Vec::new();
            write_string(&mut buf, b"ssh-ed25519");
            write_string(&mut buf, &[0xDE, 0xAD, 0xBE, 0xEF]);
            buf.extend_from_slice(&u32::to_be_bytes(42));

            let mut r = SshReader::new(&buf);
            assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
            assert_eq!(r.read_string().unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            assert_eq!(r.read_u32().unwrap(), 42);
        }

        #[test]
        fn ssh_reader_rejects_truncated_length() {
            let buf = [0, 0, 0, 10, b'x']; // claims 10 bytes but only 1 available
            let mut r = SshReader::new(&buf);
            assert!(r.read_string().is_err());
        }

        #[test]
        fn ssh_reader_rejects_short_u32() {
            let buf = [0, 0, 0];
            let mut r = SshReader::new(&buf);
            assert!(r.read_u32().is_err());
        }

        #[test]
        fn handle_list_frames_empty_identities_answer() {
            use tokio::runtime::Runtime;
            let rt = Runtime::new().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            let out = rt.block_on(handle_list(&keys));
            assert_eq!(out[0], SSH_AGENT_IDENTITIES_ANSWER);
            assert_eq!(&out[1..5], &[0, 0, 0, 0]); // zero identities
            assert_eq!(out.len(), 5);
        }

        #[test]
        fn handle_sign_fails_on_unknown_key_blob() {
            use tokio::runtime::Runtime;
            let rt = Runtime::new().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            // Build a valid sign_request frame for a blob nobody has.
            let mut payload = Vec::new();
            write_string(&mut payload, b"unknown-blob");
            write_string(&mut payload, b"data-to-sign");
            payload.extend_from_slice(&u32::to_be_bytes(0)); // flags

            let out = rt.block_on(handle_sign(&keys, &payload));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
        }

        /// RFC 8032 §7.1 "TEST 2" Ed25519 vector. Pins the two things a
        /// `ed25519-dalek` major bump could silently change under us: that
        /// `SigningKey::from_bytes` reads its input as the 32-byte *seed*
        /// (not an expanded secret scalar), and that the signature we put on
        /// the wire is the standard 64-byte R‖S encoding. Both are wrong-but-
        /// compiling failure modes — every SSH auth would break with no type
        /// error to catch it.
        #[test]
        fn handle_sign_matches_rfc8032_ed25519_vector() {
            use tokio::runtime::Runtime;

            fn unhex(s: &str) -> Vec<u8> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect()
            }

            let seed: [u8; 32] =
                unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                    .try_into()
                    .unwrap();
            let expected_public =
                unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
            let message = unhex("72");
            let expected_sig = unhex(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            );

            let signer = SigningKey::from_bytes(&seed);
            assert_eq!(
                signer.verifying_key().to_bytes().as_slice(),
                expected_public,
                "seed did not derive the RFC 8032 public key"
            );

            let pub_blob = b"rfc8032-test-2".to_vec();
            let keys: KeyStore = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: pub_blob.clone(),
                comment: "rfc8032".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:test".into(),
                kind: SignerKind::Ed25519(signer),
            }]));

            let mut payload = Vec::new();
            write_string(&mut payload, &pub_blob);
            write_string(&mut payload, &message);
            payload.extend_from_slice(&u32::to_be_bytes(0)); // flags

            let rt = Runtime::new().unwrap();
            let out = rt.block_on(handle_sign(&keys, &payload));

            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            let mut reader = SshReader::new(&out[1..]);
            let sig_blob = reader.read_string().unwrap();

            let mut inner = SshReader::new(sig_blob);
            assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
            assert_eq!(inner.read_string().unwrap(), expected_sig.as_slice());
        }
    }
} // mod unix
