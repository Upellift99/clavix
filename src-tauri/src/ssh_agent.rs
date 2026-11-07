//! Clavix SSH agent — one wire protocol (draft-miller-ssh-agent: 4-byte
//! big-endian length + message), three transports:
//!
//! - **Unix socket** (`SSH_AUTH_SOCK`): `ssh` and friends on Linux/macOS.
//! - **Windows OpenSSH named pipe** `\\.\pipe\openssh-ssh-agent`:
//!   ssh.exe / ssh-add / git-for-windows probe that pipe automatically —
//!   no environment variable involved.
//! - **Windows PuTTY Pageant IPC**: a hidden `Pageant`-class window plus
//!   the `PageantRequest%08x` shared-memory channel, so plink / pscp /
//!   putty can use the vault keys too.
//!
//! Everything platform-neutral lives in `proto`; `unix` and `windows` only
//! differ in how connections arrive and how the caller is identified.

mod proto {
    //! Platform-neutral core: the key store, the sign-approval policy, the
    //! message handlers and the framing shared by every transport.

    use std::collections::HashSet;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use ed25519_dalek::{Signer as _, SigningKey};
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::RsaPrivateKey;
    use sha2::{Sha256, Sha512};
    use ssh_key::{Algorithm, HashAlg, PrivateKey};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::Mutex;

    use clavix_core::error::{Error, Result};

    // Agent protocol message types (draft-miller-ssh-agent).
    pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    pub const SSH_AGENT_FAILURE: u8 = 5;
    pub const SSH_AGENT_SUCCESS: u8 = 6;
    pub const SSH_AGENTC_EXTENSION: u8 = 27;

    /// OpenSSH >= 8.9 binds each agent connection to the SSH session it
    /// serves (PROTOCOL.agent, "session-bind@openssh.com").
    pub const EXT_SESSION_BIND: &[u8] = b"session-bind@openssh.com";
    /// Same cap as OpenSSH's `AGENT_MAX_SESSION_IDS`: a forwarding chain
    /// deeper than this is not a real use case, only a memory sink.
    pub const MAX_SESSION_BINDS: usize = 16;
    /// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252), the byte that follows the
    /// session identifier in the data a client asks us to sign for
    /// public-key authentication.
    const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

    // Flags on `SSH_AGENTC_SIGN_REQUEST`: which SHA variant for RSA.
    pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    // Cap any single agent request to 256 KB — real traffic is orders smaller.
    pub const MAX_MESSAGE: usize = 256 * 1024;

    pub enum SignerKind {
        Ed25519(SigningKey),
        Rsa(RsaPrivateKey),
        /// NIST P-256/384/521. Signed through `ssh-key`, which picks the
        /// curve's hash (SHA-256/384/512) and encodes the `(r, s)` pair the
        /// way RFC 5656 wants it.
        Ecdsa(Box<PrivateKey>),
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

    /// Best-effort identity of the process on the other end of an agent
    /// connection, shown in the confirmation prompt so the user can tell a
    /// `git push` they just ran from a signature they never asked for.
    ///
    /// This is INDICATIVE, NOT A SECURITY BOUNDARY. The OS vouches for the
    /// pid at connect time, but pids are recycled and process names are
    /// unauthenticated labels the process itself can change. Never gate a
    /// trust decision on it — it exists to help a human recognise their
    /// own action.
    ///
    /// Some transports cannot identify the caller at all (PuTTY's Pageant
    /// IPC carries no client identity): those connections get `None`.
    #[derive(Debug, Clone)]
    pub struct CallerInfo {
        pub pid: u32,
        /// Process name, when it can be read. `None` on platforms or
        /// transports where it is unavailable.
        pub name: Option<String>,
    }

    /// One `session-bind@openssh.com` binding: a server host key whose
    /// signature over the session identifier we verified, so we know the
    /// SSH client really holds a session with that host.
    ///
    /// Unlike `CallerInfo`, the host key IS authenticated — but a host key
    /// is not a host name. The name shown to the user comes from matching
    /// the key against `known_hosts`, i.e. from what the user already
    /// accepted for that key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HostHop {
        /// SSH wire-format public host key.
        pub key_blob: Vec<u8>,
        /// `"SHA256:…"` fingerprint of the host key.
        pub fingerprint: String,
        /// `true` when this hop carries a forwarded agent (`ssh -A`),
        /// `false` when the binding is for authenticating to that host.
        pub forwarded: bool,
        /// Exchange hash of the bound session.
        pub session_id: Vec<u8>,
    }

    /// What the user is being asked to approve: the key, plus whoever asked.
    #[derive(Debug, Clone)]
    pub struct SignRequest {
        pub key: KeyInfo,
        pub caller: Option<CallerInfo>,
        /// Session bindings of the requesting connection, outermost first:
        /// `[host1 (forwarded), host2 (auth)]` means "authenticate to
        /// host2 from host1, through the agent forwarded to host1". Empty
        /// for clients that don't bind (OpenSSH < 8.9, git signing, PuTTY).
        pub hops: Vec<HostHop>,
    }

    /// Per-connection agent state. `session-bind` is scoped to the
    /// connection it arrives on, so every transport creates one of these
    /// per client connection (Pageant, which has no connections, uses a
    /// fresh one per message).
    #[derive(Debug, Default)]
    pub struct ConnState {
        pub hops: Vec<HostHop>,
    }

    impl ConnState {
        /// The last binding, if it was for authentication. OpenSSH treats
        /// such a connection as spent for further binds, and expects any
        /// user-auth signature on it to be for that very session.
        fn bound_for_auth(&self) -> Option<&HostHop> {
            self.hops.last().filter(|h| !h.forwarded)
        }
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

    pub type KeyStore = Arc<Mutex<Vec<AgentKey>>>;

    /// When the agent asks the user to approve a signature.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SignPolicy {
        /// Sign silently (historical behaviour).
        Never,
        /// Ask once per key per agent run, then remember that key.
        PerSession,
        /// Ask before every signature.
        Always,
    }

    /// Async "ask the user to approve this signature" callback. Returns
    /// `true` to allow. Kept as a boxed future so `ssh_agent` stays free
    /// of any Tauri dependency — `commands::ssh` supplies the real
    /// implementation that drives the confirmation dialog.
    pub type ConfirmFn =
        Arc<dyn Fn(SignRequest) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

    /// Signature-authorization policy for a running agent, plus the
    /// per-run set of keys already approved under `PerSession`.
    #[derive(Clone)]
    pub struct SignGuard {
        policy: SignPolicy,
        confirm: Option<ConfirmFn>,
        /// Fingerprints approved during this agent run (PerSession only).
        approved: Arc<Mutex<HashSet<String>>>,
        /// Set when the agent starts stopping: every parked authorization
        /// resolves to "denied" immediately instead of waiting out the
        /// confirmation timeout. This is what keeps `stop()` from ever
        /// blocking on a prompt the user can no longer see — it must not
        /// depend on the *caller* remembering to clear the prompts first.
        cancelled: Arc<std::sync::atomic::AtomicBool>,
        cancel_notify: Arc<tokio::sync::Notify>,
    }

    impl SignGuard {
        pub fn new(policy: SignPolicy, confirm: Option<ConfirmFn>) -> Self {
            Self {
                policy,
                confirm,
                approved: Arc::new(Mutex::new(HashSet::new())),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                cancel_notify: Arc::new(tokio::sync::Notify::new()),
            }
        }

        /// Deny every parked (and every later) authorization. Idempotent;
        /// called by the agent's stop paths.
        pub fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.cancel_notify.notify_waiters();
        }

        /// Decide whether a signature with `key` may proceed. Awaits the
        /// user only when the policy requires it; the caller must NOT hold
        /// the key-store lock across this call (it can block on a human).
        async fn authorize(
            &self,
            key: &KeyInfo,
            caller: Option<&CallerInfo>,
            hops: &[HostHop],
        ) -> bool {
            match self.policy {
                SignPolicy::Never => true,
                SignPolicy::Always => self.ask(key, caller, hops).await,
                SignPolicy::PerSession => {
                    // Keyed on the fingerprint alone, deliberately: the
                    // documented contract is "ask once per key per agent
                    // run". Keying on (key, caller) would re-prompt for
                    // every new `ssh` process, which is the behaviour
                    // `Always` already provides.
                    if self.approved.lock().await.contains(&key.fingerprint) {
                        return true;
                    }
                    let ok = self.ask(key, caller, hops).await;
                    if ok {
                        self.approved.lock().await.insert(key.fingerprint.clone());
                    }
                    ok
                }
            }
        }

        async fn ask(&self, key: &KeyInfo, caller: Option<&CallerInfo>, hops: &[HostHop]) -> bool {
            use std::sync::atomic::Ordering;

            // A confirming policy with no callback wired can't be
            // satisfied — deny rather than silently sign.
            let Some(confirm) = &self.confirm else {
                return false;
            };
            if self.cancelled.load(Ordering::SeqCst) {
                return false;
            }
            let answer = confirm(SignRequest {
                key: key.clone(),
                caller: caller.cloned(),
                hops: hops.to_vec(),
            });
            // Register the cancellation waiter *before* the second flag
            // check (`enable` closes the create-vs-notify race), so a
            // `cancel()` landing between the two loads still wins.
            let notified = self.cancel_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.cancelled.load(Ordering::SeqCst) {
                return false;
            }
            tokio::select! {
                approved = answer => approved,
                _ = notified => false,
            }
        }
    }

    /// Reduce an OS-supplied process label (Linux `/proc/<pid>/comm`, a
    /// Windows image file name) to a short, printable, single-line string:
    /// it is headed for a confirmation dialog and the process itself
    /// controls parts of it. Shared by both platforms' `process_name` —
    /// and compiled only where one of those callers exists (macOS resolves
    /// no label at all, so an unconditional copy here would be dead code).
    #[cfg(any(target_os = "linux", windows))]
    pub fn sanitize_process_label(raw: &str) -> Option<String> {
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_control())
            .take(32)
            .collect::<String>()
            .trim()
            .to_string();
        (!cleaned.is_empty()).then_some(cleaned)
    }

    /// Parse an OpenSSH private key and wrap it as an `AgentKey` if we can
    /// sign with it. Today: Ed25519, RSA and ECDSA (NIST P-256/384/521).
    /// Returns `Ok(None)` for key types we intentionally skip (DSA, FIDO
    /// `sk-*` keys, which need the hardware token), `Err` for malformed or
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
            Algorithm::Ecdsa { .. } => SignerKind::Ecdsa(Box::new(pk)),
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

    /// Run one agent message (type byte + body — what a socket would carry
    /// after its length prefix) and return the response *without* framing.
    /// Shared by every transport so the three endpoints cannot drift apart.
    pub async fn process_message(
        msg: &[u8],
        keys: &KeyStore,
        guard: &SignGuard,
        caller: Option<&CallerInfo>,
        conn: &mut ConnState,
    ) -> Vec<u8> {
        let Some((&msg_type, body)) = msg.split_first() else {
            return vec![SSH_AGENT_FAILURE];
        };
        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => handle_list(keys).await,
            SSH_AGENTC_SIGN_REQUEST => handle_sign(keys, guard, body, caller, conn).await,
            SSH_AGENTC_EXTENSION => handle_extension(body, conn),
            _ => vec![SSH_AGENT_FAILURE],
        }
    }

    /// `SSH_AGENTC_EXTENSION`. Only `session-bind@openssh.com` is
    /// understood; anything else gets the generic failure, which is what
    /// PROTOCOL.agent prescribes for an unsupported extension.
    fn handle_extension(body: &[u8], conn: &mut ConnState) -> Vec<u8> {
        let mut reader = SshReader::new(body);
        match reader.read_string() {
            Ok(EXT_SESSION_BIND) => match session_bind(&mut reader, conn) {
                Some(()) => vec![SSH_AGENT_SUCCESS],
                None => vec![SSH_AGENT_FAILURE],
            },
            _ => vec![SSH_AGENT_FAILURE],
        }
    }

    /// Parse, verify and record one session binding:
    ///
    /// ```text
    /// string  hostkey
    /// string  session identifier
    /// string  signature (by hostkey, over the session identifier)
    /// bool    is_forwarding
    /// ```
    ///
    /// The rules mirror OpenSSH's `process_ext_session_bind`, so a client
    /// sees the same answers from Clavix as from `ssh-agent`. `None` means
    /// "refuse".
    fn session_bind(reader: &mut SshReader<'_>, conn: &mut ConnState) -> Option<()> {
        use rsa::signature::Verifier;
        use ssh_key::{PublicKey, Signature};

        let key_blob = reader.read_string().ok()?;
        let session_id = reader.read_string().ok()?;
        let sig_blob = reader.read_string().ok()?;
        let forwarded = match reader.read_u8().ok()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        if !reader.is_empty() {
            return None;
        }

        // The signature is what turns "the client says it talks to this
        // host" into "the client holds a session that this host key
        // signed". Without it a binding would be an unverified label.
        let host_key = PublicKey::from_bytes(key_blob).ok()?;
        let signature = Signature::try_from(sig_blob).ok()?;
        // Fully qualified: `PublicKey` also has an inherent `verify` for
        // SSHSIG (namespace + message), which is not this.
        Verifier::verify(&host_key, session_id, &signature).ok()?;

        // Re-binding a session already seen is fine (OpenSSH re-sends the
        // forwarding bind on every forwarded channel) as long as it names
        // the same host key; a different key for the same session is a lie.
        if let Some(existing) = conn.hops.iter().find(|h| h.session_id == session_id) {
            return (existing.key_blob == key_blob).then_some(());
        }
        // A connection bound for authentication is spent: nothing may be
        // chained after it.
        if conn.bound_for_auth().is_some() || conn.hops.len() >= MAX_SESSION_BINDS {
            return None;
        }
        conn.hops.push(HostHop {
            key_blob: key_blob.to_vec(),
            fingerprint: host_key.fingerprint(HashAlg::Sha256).to_string(),
            forwarded,
            session_id: session_id.to_vec(),
        });
        Some(())
    }

    /// If `data` is a public-key user-auth request (RFC 4252 §7, plus
    /// OpenSSH's `publickey-hostbound-v00@openssh.com`), return its session
    /// identifier and, for the host-bound variant, the server host key it
    /// names. `None` for anything else (git's `SSHSIG`, arbitrary data).
    pub fn parse_userauth_request(data: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
        let mut r = SshReader::new(data);
        let session_id = r.read_string().ok()?;
        if r.read_u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
            return None;
        }
        let _user = r.read_string().ok()?;
        let _service = r.read_string().ok()?;
        let hostbound = match r.read_string().ok()? {
            b"publickey" => false,
            b"publickey-hostbound-v00@openssh.com" => true,
            _ => return None,
        };
        if r.read_u8().ok()? != 1 {
            return None;
        }
        let _alg = r.read_string().ok()?;
        let _key = r.read_string().ok()?;
        let host_key = if hostbound {
            Some(r.read_string().ok()?)
        } else {
            None
        };
        r.is_empty().then_some((session_id, host_key))
    }

    /// Serve one connection: read length-prefixed requests until the peer
    /// disconnects, answering each with a length-prefixed response. The
    /// transport object (Unix socket, named pipe, …) is generic — framing
    /// and message handling are identical for every client.
    pub async fn serve<S>(
        mut stream: S,
        keys: KeyStore,
        guard: SignGuard,
        caller: Option<CallerInfo>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn = ConnState::default();
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

            let response = process_message(&buf, &keys, &guard, caller.as_ref(), &mut conn).await;

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

    async fn handle_sign(
        keys: &KeyStore,
        guard: &SignGuard,
        payload: &[u8],
        caller: Option<&CallerInfo>,
        conn: &ConnState,
    ) -> Vec<u8> {
        let mut reader = SshReader::new(payload);
        let Ok(key_blob) = reader.read_string() else {
            return vec![SSH_AGENT_FAILURE];
        };
        let Ok(data) = reader.read_string() else {
            return vec![SSH_AGENT_FAILURE];
        };
        let flags = reader.read_u32().unwrap_or(0);

        // On a connection bound for authentication, a user-auth signature
        // must be for THAT session (and, host-bound, that host): otherwise
        // a hostile server holding a forwarded agent could relay another
        // session's challenge through a connection whose binding the user
        // is looking at. Same check as OpenSSH's ssh-agent. Data that
        // isn't a user-auth request (git commit signing) is left alone.
        if let Some(bound) = conn.bound_for_auth() {
            if let Some((sid, host_key)) = parse_userauth_request(data) {
                if sid != bound.session_id.as_slice()
                    || host_key.is_some_and(|hk| hk != bound.key_blob.as_slice())
                {
                    return vec![SSH_AGENT_FAILURE];
                }
            }
        }

        // Identify the key (and grab its public summary for the prompt)
        // under the lock, then release it: `authorize` can block on a
        // human for up to the confirmation timeout, and holding the store
        // lock across that would freeze every other agent request.
        let key_info = {
            let store = keys.lock().await;
            let Some(k) = store.iter().find(|k| k.pub_blob == key_blob) else {
                return vec![SSH_AGENT_FAILURE];
            };
            KeyInfo::from(k)
        };

        if !guard.authorize(&key_info, caller, &conn.hops).await {
            return vec![SSH_AGENT_FAILURE];
        }

        let store = keys.lock().await;
        // The key set can't change while the agent runs, but re-find
        // defensively rather than carrying a reference across the await.
        let Some(key) = store.iter().find(|k| k.pub_blob == key_blob) else {
            return vec![SSH_AGENT_FAILURE];
        };

        let (algo_name, sig_bytes): (&'static [u8], Vec<u8>) = match &key.kind {
            SignerKind::Ecdsa(pk) => {
                // `ssh-key` emits the complete wire signature (algorithm
                // name + RFC 5656 `(r, s)` blob) — answer with it as is.
                use rsa::signature::Signer as _;
                let Some(sig_blob) = pk
                    .try_sign(data)
                    .ok()
                    .and_then(|sig| Vec::<u8>::try_from(sig).ok())
                else {
                    return vec![SSH_AGENT_FAILURE];
                };
                let mut out = Vec::with_capacity(sig_blob.len() + 5);
                out.push(SSH_AGENT_SIGN_RESPONSE);
                write_string(&mut out, &sig_blob);
                return out;
            }
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

    pub fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&u32::to_be_bytes(s.len() as u32));
        buf.extend_from_slice(s);
    }

    pub struct SshReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> SshReader<'a> {
        pub fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        pub fn read_u32(&mut self) -> std::io::Result<u32> {
            if self.pos + 4 > self.buf.len() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let n = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;
            Ok(n)
        }

        pub fn read_u8(&mut self) -> std::io::Result<u8> {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or(std::io::ErrorKind::UnexpectedEof)?;
            self.pos += 1;
            Ok(b)
        }

        /// `true` once every byte has been consumed.
        pub fn is_empty(&self) -> bool {
            self.pos >= self.buf.len()
        }

        pub fn read_string(&mut self) -> std::io::Result<&'a [u8]> {
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

            let guard = SignGuard::new(SignPolicy::Never, None);
            let out = rt.block_on(handle_sign(
                &keys,
                &guard,
                &payload,
                None,
                &ConnState::default(),
            ));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
        }

        #[test]
        fn process_message_answers_failure_for_unknown_types() {
            use tokio::runtime::Runtime;
            let rt = Runtime::new().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            let guard = SignGuard::new(SignPolicy::Never, None);
            let mut conn = ConnState::default();
            let out = rt.block_on(process_message(&[0x42], &keys, &guard, None, &mut conn));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
            // A truncated message (no type byte) must fail, not panic.
            let out = rt.block_on(process_message(&[], &keys, &guard, None, &mut conn));
            assert_eq!(out, vec![SSH_AGENT_FAILURE]);
        }

        fn dummy_key(fp: &str) -> KeyInfo {
            KeyInfo {
                comment: "k".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: fp.into(),
            }
        }

        fn counting_confirm(answer: bool, calls: Arc<Mutex<u32>>) -> ConfirmFn {
            Arc::new(move |_req: SignRequest| {
                let calls = calls.clone();
                Box::pin(async move {
                    *calls.lock().await += 1;
                    answer
                })
            })
        }

        #[test]
        fn authorize_never_signs_without_asking() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::Never,
                Some(counting_confirm(false, calls.clone())),
            );
            assert!(rt.block_on(g.authorize(&dummy_key("SHA256:a"), None, &[])));
            assert_eq!(rt.block_on(async { *calls.lock().await }), 0);
        }

        #[test]
        fn authorize_always_asks_every_time() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::Always,
                Some(counting_confirm(true, calls.clone())),
            );
            let k = dummy_key("SHA256:a");
            assert!(rt.block_on(g.authorize(&k, None, &[])));
            assert!(rt.block_on(g.authorize(&k, None, &[])));
            assert_eq!(rt.block_on(async { *calls.lock().await }), 2);
        }

        #[test]
        fn authorize_always_denies_on_reject() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(SignPolicy::Always, Some(counting_confirm(false, calls)));
            assert!(!rt.block_on(g.authorize(&dummy_key("SHA256:a"), None, &[])));
        }

        #[test]
        fn authorize_per_session_asks_once_per_key() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::PerSession,
                Some(counting_confirm(true, calls.clone())),
            );
            let a = dummy_key("SHA256:a");
            let b = dummy_key("SHA256:b");
            assert!(rt.block_on(g.authorize(&a, None, &[])));
            assert!(rt.block_on(g.authorize(&a, None, &[]))); // remembered — no second ask
            assert!(rt.block_on(g.authorize(&b, None, &[]))); // different key — asks again
            assert_eq!(rt.block_on(async { *calls.lock().await }), 2);
        }

        #[test]
        fn authorize_per_session_reject_is_not_remembered() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let calls = Arc::new(Mutex::new(0u32));
            let g = SignGuard::new(
                SignPolicy::PerSession,
                Some(counting_confirm(false, calls.clone())),
            );
            let a = dummy_key("SHA256:a");
            assert!(!rt.block_on(g.authorize(&a, None, &[])));
            assert!(!rt.block_on(g.authorize(&a, None, &[])));
            assert_eq!(rt.block_on(async { *calls.lock().await }), 2); // re-asked
        }

        #[test]
        fn authorize_confirming_policy_without_callback_denies() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let g = SignGuard::new(SignPolicy::Always, None);
            assert!(!rt.block_on(g.authorize(&dummy_key("SHA256:a"), None, &[])));
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
            let guard = SignGuard::new(SignPolicy::Never, None);
            let out = rt.block_on(handle_sign(
                &keys,
                &guard,
                &payload,
                None,
                &ConnState::default(),
            ));

            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            let mut reader = SshReader::new(&out[1..]);
            let sig_blob = reader.read_string().unwrap();

            let mut inner = SshReader::new(sig_blob);
            assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
            assert_eq!(inner.read_string().unwrap(), expected_sig.as_slice());
        }

        // ---- ECDSA -------------------------------------------------------

        fn sign_with(keys: &KeyStore, pub_blob: &[u8], data: &[u8], conn: &ConnState) -> Vec<u8> {
            let mut payload = Vec::new();
            write_string(&mut payload, pub_blob);
            write_string(&mut payload, data);
            payload.extend_from_slice(&u32::to_be_bytes(0));
            let guard = SignGuard::new(SignPolicy::Never, None);
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(handle_sign(keys, &guard, &payload, None, conn))
        }

        /// Every NIST curve OpenSSH generates must load and produce a
        /// signature that verifies against the key's public half, with the
        /// algorithm name ssh expects. A verification against the public
        /// key (not a byte comparison) is the right oracle here: ECDSA
        /// signatures are not reproducible byte for byte.
        #[test]
        fn ecdsa_keys_load_and_sign_verifiably_on_every_curve() {
            use rsa::signature::Verifier;
            for (pem, algo) in [
                (
                    include_str!("../tests/fixtures/ssh/ecdsa-p256"),
                    "ecdsa-sha2-nistp256",
                ),
                (
                    include_str!("../tests/fixtures/ssh/ecdsa-p384"),
                    "ecdsa-sha2-nistp384",
                ),
                (
                    include_str!("../tests/fixtures/ssh/ecdsa-p521"),
                    "ecdsa-sha2-nistp521",
                ),
            ] {
                let key = try_load_agent_key(pem, "fallback")
                    .unwrap()
                    .expect("ECDSA must no longer be skipped");
                assert_eq!(key.algorithm, algo);
                assert!(key.comment.starts_with("clavix-test-p"));
                let pub_blob = key.pub_blob.clone();
                let keys: KeyStore = Arc::new(Mutex::new(vec![key]));

                let out = sign_with(&keys, &pub_blob, b"challenge", &ConnState::default());
                assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE, "{algo}");
                let sig_blob = SshReader::new(&out[1..]).read_string().unwrap();
                assert_eq!(
                    SshReader::new(sig_blob).read_string().unwrap(),
                    algo.as_bytes()
                );

                let public = ssh_key::PublicKey::from_bytes(&pub_blob).unwrap();
                let sig = ssh_key::Signature::try_from(sig_blob).unwrap();
                Verifier::verify(&public, b"challenge", &sig).expect(algo);
                assert!(
                    Verifier::verify(&public, b"something else", &sig).is_err(),
                    "{algo}: signature must be bound to the data"
                );
            }
        }

        /// Known-answer test: RFC 6979 appendix A.2.5 (P-256, SHA-256,
        /// message "sample"). `ssh-key` signs ECDSA deterministically, so
        /// the agent's answer must be exactly the RFC's `(r, s)`. Run it
        /// on any `ssh-key` / `p256` / `ecdsa` bump: a verifying-but-wrong
        /// nonce derivation would still pass the round-trip test above.
        #[test]
        fn ecdsa_p256_matches_rfc6979_vector() {
            fn unhex(s: &str) -> Vec<u8> {
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect()
            }
            let x = unhex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
            let secret = p256::SecretKey::from_slice(&x).unwrap();
            let keypair = ssh_key::private::EcdsaKeypair::NistP256 {
                public: secret.public_key().into(),
                private: secret.into(),
            };
            let pk = PrivateKey::from(keypair);
            let pub_blob = pk.public_key().to_bytes().unwrap();
            let keys: KeyStore = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: pub_blob.clone(),
                comment: "rfc6979".into(),
                algorithm: "ecdsa-sha2-nistp256".into(),
                fingerprint: "SHA256:rfc6979".into(),
                kind: SignerKind::Ecdsa(Box::new(pk)),
            }]));

            let out = sign_with(&keys, &pub_blob, b"sample", &ConnState::default());
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            let sig_blob = SshReader::new(&out[1..]).read_string().unwrap();
            let mut sig = SshReader::new(sig_blob);
            assert_eq!(sig.read_string().unwrap(), b"ecdsa-sha2-nistp256");
            // RFC 5656: the signature is `mpint r, mpint s`; an mpint
            // with its top bit set carries a leading zero byte.
            let mut rs = SshReader::new(sig.read_string().unwrap());
            let strip = |m: &[u8]| m.strip_prefix(&[0]).unwrap_or(m).to_vec();
            let r = strip(rs.read_string().unwrap());
            let s = strip(rs.read_string().unwrap());
            assert!(rs.is_empty());
            assert_eq!(
                r,
                unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
            );
            assert_eq!(
                s,
                unhex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
            );
        }

        // ---- session-bind@openssh.com ------------------------------------

        /// A fake server host key (Ed25519, fixed seed) able to sign
        /// session identifiers the way sshd does during key exchange.
        struct HostKey(SigningKey);

        impl HostKey {
            fn new(seed: u8) -> Self {
                Self(SigningKey::from_bytes(&[seed; 32]))
            }
            fn blob(&self) -> Vec<u8> {
                let mut b = Vec::new();
                write_string(&mut b, b"ssh-ed25519");
                write_string(&mut b, self.0.verifying_key().as_bytes());
                b
            }
            fn sign(&self, sid: &[u8]) -> Vec<u8> {
                let mut b = Vec::new();
                write_string(&mut b, b"ssh-ed25519");
                write_string(&mut b, &self.0.sign(sid).to_bytes());
                b
            }
        }

        fn bind_msg(host_blob: &[u8], sid: &[u8], sig: &[u8], forwarded: bool) -> Vec<u8> {
            let mut m = vec![SSH_AGENTC_EXTENSION];
            write_string(&mut m, EXT_SESSION_BIND);
            write_string(&mut m, host_blob);
            write_string(&mut m, sid);
            write_string(&mut m, sig);
            m.push(forwarded as u8);
            m
        }

        fn bind(conn: &mut ConnState, host: &HostKey, sid: &[u8], forwarded: bool) -> Vec<u8> {
            let msg = bind_msg(&host.blob(), sid, &host.sign(sid), forwarded);
            run(&msg, conn)
        }

        fn run(msg: &[u8], conn: &mut ConnState) -> Vec<u8> {
            let keys: KeyStore = Arc::new(Mutex::new(Vec::new()));
            let guard = SignGuard::new(SignPolicy::Never, None);
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(process_message(msg, &keys, &guard, None, conn))
        }

        fn userauth(sid: &[u8], hostbound: Option<&[u8]>) -> Vec<u8> {
            let mut d = Vec::new();
            write_string(&mut d, sid);
            d.push(SSH_MSG_USERAUTH_REQUEST);
            write_string(&mut d, b"git");
            write_string(&mut d, b"ssh-connection");
            match hostbound {
                Some(_) => write_string(&mut d, b"publickey-hostbound-v00@openssh.com"),
                None => write_string(&mut d, b"publickey"),
            }
            d.push(1);
            write_string(&mut d, b"ssh-ed25519");
            write_string(&mut d, b"client-key-blob");
            if let Some(hk) = hostbound {
                write_string(&mut d, hk);
            }
            d
        }

        #[test]
        fn session_bind_records_a_verified_binding() {
            let host = HostKey::new(7);
            let mut conn = ConnState::default();
            assert_eq!(
                bind(&mut conn, &host, b"sid-1", false),
                vec![SSH_AGENT_SUCCESS]
            );
            assert_eq!(conn.hops.len(), 1);
            let hop = &conn.hops[0];
            assert_eq!(hop.key_blob, host.blob());
            assert!(!hop.forwarded);
            assert!(hop.fingerprint.starts_with("SHA256:"));
        }

        #[test]
        fn session_bind_rejects_a_signature_from_another_key() {
            let (host, impostor) = (HostKey::new(7), HostKey::new(8));
            let mut conn = ConnState::default();
            let msg = bind_msg(&host.blob(), b"sid-1", &impostor.sign(b"sid-1"), false);
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            // Signed by the right key but over another session id.
            let msg = bind_msg(&host.blob(), b"sid-1", &host.sign(b"sid-2"), false);
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            assert!(conn.hops.is_empty());
        }

        #[test]
        fn session_bind_rejects_malformed_bodies() {
            let host = HostKey::new(7);
            let mut conn = ConnState::default();
            let mut msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
            msg.push(0); // trailing garbage
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            let mut msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
            *msg.last_mut().unwrap() = 2; // not a boolean
            assert_eq!(run(&msg, &mut conn), vec![SSH_AGENT_FAILURE]);
            let msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
            assert_eq!(
                run(&msg[..msg.len() - 1], &mut conn),
                vec![SSH_AGENT_FAILURE]
            );
            assert!(conn.hops.is_empty());
        }

        #[test]
        fn unknown_extensions_fail() {
            let mut m = vec![SSH_AGENTC_EXTENSION];
            write_string(&mut m, b"query");
            assert_eq!(run(&m, &mut ConnState::default()), vec![SSH_AGENT_FAILURE]);
        }

        #[test]
        fn forwarding_chain_is_recorded_outermost_first() {
            let (jump, dest) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            assert_eq!(
                bind(&mut conn, &jump, b"sid-jump", true),
                vec![SSH_AGENT_SUCCESS]
            );
            // OpenSSH re-sends the forwarding bind per channel: idempotent.
            assert_eq!(
                bind(&mut conn, &jump, b"sid-jump", true),
                vec![SSH_AGENT_SUCCESS]
            );
            assert_eq!(
                bind(&mut conn, &dest, b"sid-dest", false),
                vec![SSH_AGENT_SUCCESS]
            );
            let shape: Vec<_> = conn
                .hops
                .iter()
                .map(|h| (h.key_blob.clone(), h.forwarded))
                .collect();
            assert_eq!(shape, vec![(jump.blob(), true), (dest.blob(), false)]);
        }

        #[test]
        fn same_session_with_another_host_key_is_refused() {
            let (a, b) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            assert_eq!(bind(&mut conn, &a, b"sid", true), vec![SSH_AGENT_SUCCESS]);
            assert_eq!(bind(&mut conn, &b, b"sid", true), vec![SSH_AGENT_FAILURE]);
            assert_eq!(conn.hops.len(), 1);
        }

        #[test]
        fn a_connection_bound_for_auth_accepts_no_further_binding() {
            let (a, b) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            assert_eq!(
                bind(&mut conn, &a, b"sid-a", false),
                vec![SSH_AGENT_SUCCESS]
            );
            assert_eq!(bind(&mut conn, &b, b"sid-b", true), vec![SSH_AGENT_FAILURE]);
            assert_eq!(conn.hops.len(), 1);
        }

        #[test]
        fn binding_count_is_capped() {
            let host = HostKey::new(3);
            let mut conn = ConnState::default();
            for i in 0..MAX_SESSION_BINDS {
                let sid = format!("sid-{i}");
                assert_eq!(
                    bind(&mut conn, &host, sid.as_bytes(), true),
                    vec![SSH_AGENT_SUCCESS]
                );
            }
            assert_eq!(
                bind(&mut conn, &host, b"one-too-many", true),
                vec![SSH_AGENT_FAILURE]
            );
        }

        fn ed25519_store() -> (KeyStore, Vec<u8>) {
            let pub_blob = b"client-key-blob".to_vec();
            let keys = Arc::new(Mutex::new(vec![AgentKey {
                pub_blob: pub_blob.clone(),
                comment: "c".into(),
                algorithm: "ssh-ed25519".into(),
                fingerprint: "SHA256:c".into(),
                kind: SignerKind::Ed25519(SigningKey::from_bytes(&[9; 32])),
            }]));
            (keys, pub_blob)
        }

        #[test]
        fn auth_bound_connection_only_signs_its_own_session() {
            let host = HostKey::new(4);
            let mut conn = ConnState::default();
            bind(&mut conn, &host, b"sid-ok", false);
            let (keys, blob) = ed25519_store();

            let ok = sign_with(&keys, &blob, &userauth(b"sid-ok", None), &conn);
            assert_eq!(ok[0], SSH_AGENT_SIGN_RESPONSE);
            let relayed = sign_with(&keys, &blob, &userauth(b"sid-other", None), &conn);
            assert_eq!(relayed, vec![SSH_AGENT_FAILURE]);

            // Host-bound variant: the named host key must be the bound one.
            let ok = sign_with(
                &keys,
                &blob,
                &userauth(b"sid-ok", Some(&host.blob())),
                &conn,
            );
            assert_eq!(ok[0], SSH_AGENT_SIGN_RESPONSE);
            let wrong = HostKey::new(5).blob();
            let bad = sign_with(&keys, &blob, &userauth(b"sid-ok", Some(&wrong)), &conn);
            assert_eq!(bad, vec![SSH_AGENT_FAILURE]);

            // Data that is not a user-auth request (e.g. SSHSIG for git
            // commit signing) is not subject to the session check.
            let other = sign_with(&keys, &blob, b"SSHSIG\0\0\0\x01", &conn);
            assert_eq!(other[0], SSH_AGENT_SIGN_RESPONSE);
        }

        #[test]
        fn forwarded_binding_does_not_restrict_the_session() {
            // The last hop being a forwarding bind means "a process on that
            // host is using the forwarded agent" — its own sessions are
            // unknown to us, so the session check must not fire.
            let host = HostKey::new(6);
            let mut conn = ConnState::default();
            bind(&mut conn, &host, b"sid-fwd", true);
            let (keys, blob) = ed25519_store();
            let out = sign_with(&keys, &blob, &userauth(b"sid-elsewhere", None), &conn);
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
        }

        #[test]
        fn parse_userauth_request_accepts_only_publickey_requests() {
            assert_eq!(
                parse_userauth_request(&userauth(b"s", None)),
                Some((&b"s"[..], None))
            );
            let hb = userauth(b"s", Some(b"hk"));
            assert_eq!(
                parse_userauth_request(&hb),
                Some((&b"s"[..], Some(&b"hk"[..])))
            );
            let mut trailing = userauth(b"s", None);
            trailing.push(0);
            assert_eq!(parse_userauth_request(&trailing), None);
            assert_eq!(parse_userauth_request(b"SSHSIG"), None);
            assert_eq!(parse_userauth_request(&[]), None);
        }

        #[test]
        fn confirmation_receives_the_bindings() {
            let seen: Arc<std::sync::Mutex<Vec<HostHop>>> = Arc::default();
            let seen2 = seen.clone();
            let confirm: ConfirmFn = Arc::new(move |req: SignRequest| {
                *seen2.lock().unwrap() = req.hops.clone();
                Box::pin(async { true })
            });
            let guard = SignGuard::new(SignPolicy::Always, Some(confirm));
            let (jump, dest) = (HostKey::new(1), HostKey::new(2));
            let mut conn = ConnState::default();
            bind(&mut conn, &jump, b"sid-j", true);
            bind(&mut conn, &dest, b"sid-d", false);
            let (keys, blob) = ed25519_store();

            let mut payload = Vec::new();
            write_string(&mut payload, &blob);
            write_string(&mut payload, &userauth(b"sid-d", None));
            payload.extend_from_slice(&u32::to_be_bytes(0));
            let out = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(handle_sign(&keys, &guard, &payload, None, &conn));
            assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
            assert_eq!(*seen.lock().unwrap(), conn.hops);
        }
    }
} // mod proto

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::net::{UnixListener, UnixStream};
    use tokio::task::JoinHandle;

    use super::proto::{serve, AgentKey, CallerInfo, KeyInfo, KeyStore, SignGuard};
    use clavix_core::error::{Error, Result};

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        /// Public-only summary of every key currently exposed by the agent.
        /// The signing material itself stays in the keystore guarded by the
        /// task; this list is safe to clone into a status response.
        pub keys: Vec<KeyInfo>,
        task: JoinHandle<()>,
        #[allow(dead_code)]
        key_store: KeyStore,
        /// Used to deny parked confirmations on stop, so stopping never
        /// waits on a prompt nobody can answer.
        guard: SignGuard,
    }

    impl SshAgentHandle {
        pub async fn stop(self) {
            self.guard.cancel();
            self.task.abort();
            let _ = tokio::fs::remove_file(&self.socket_path).await;
        }

        /// Non-async best-effort stop, suitable for `lock` / `logout` commands
        /// that don't want to be async just for this cleanup.
        pub fn stop_sync(self) {
            self.guard.cancel();
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
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
        }
        path.push("agent.sock");
        Ok(path)
    }

    /// Read the peer's credentials off an accepted connection.
    ///
    /// Returns `None` rather than failing the connection: an unidentifiable
    /// caller must still be able to request a signature (the user then sees
    /// "unknown", which is itself useful information).
    fn peer_caller(stream: &UnixStream) -> Option<CallerInfo> {
        let cred = stream.peer_cred().ok()?;
        // `pid()` is `Option` because not every Unix exposes it.
        let pid = cred.pid()?;
        if pid <= 0 {
            return None;
        }
        let pid = pid as u32;
        Some(CallerInfo {
            pid,
            name: process_name(pid),
        })
    }

    /// Resolve a pid to a process name. Linux-only via `/proc`; other Unixes
    /// get `None` and the prompt falls back to showing the bare pid.
    fn process_name(pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
            // `comm` is attacker-controlled text heading for a dialog.
            super::proto::sanitize_process_label(comm.trim())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            None
        }
    }

    pub async fn start_agent(
        socket_path: PathBuf,
        keys: Vec<AgentKey>,
        guard: SignGuard,
    ) -> Result<SshAgentHandle> {
        // Remove any stale socket file.
        let _ = tokio::fs::remove_file(&socket_path).await;
        let listener = UnixListener::bind(&socket_path).map_err(|e| Error::Storage {
            reason: format!("bind {}: {e}", socket_path.display()),
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
        }

        let key_summaries: Vec<KeyInfo> = keys.iter().map(KeyInfo::from).collect();
        let store: KeyStore = Arc::new(tokio::sync::Mutex::new(keys));
        let store_task = store.clone();
        let path_for_task = socket_path.clone();
        let guard_for_handle = guard.clone();

        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let store = store_task.clone();
                        let guard = guard.clone();
                        // Resolve the peer at accept time: the pid is only
                        // guaranteed meaningful while the connection is
                        // open, and the process may exit mid-request.
                        let caller = peer_caller(&stream);
                        tokio::spawn(async move {
                            if let Err(e) = serve(stream, store, guard, caller).await {
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
            guard: guard_for_handle,
        })
    }

    #[cfg(test)]
    mod tests {
        // Both tests below are Linux-only (peer credentials + /proc), so
        // the glob import must be gated the same way or it is unused —
        // an error under `-D warnings` — on macOS.
        #[cfg(target_os = "linux")]
        use super::*;

        /// Both ends of a socketpair live in this test process, so the
        /// credentials the agent reads must resolve to our own pid — which
        /// makes the expected value exactly known rather than "some pid".
        #[cfg(target_os = "linux")]
        #[test]
        fn peer_caller_resolves_the_connecting_process() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let dir = std::env::temp_dir().join(format!("clavix-peer-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let sock = dir.join("agent.sock");

            let caller = rt.block_on(async {
                let listener = UnixListener::bind(&sock).unwrap();
                let connect = tokio::spawn({
                    let sock = sock.clone();
                    async move { UnixStream::connect(&sock).await.unwrap() }
                });
                let (server_side, _) = listener.accept().await.unwrap();
                let _client = connect.await.unwrap();
                peer_caller(&server_side)
            });

            let caller = caller.expect("peer credentials available on Linux");
            assert_eq!(caller.pid, std::process::id());
            // The name comes from /proc/<pid>/comm — the test binary's own.
            let name = caller.name.expect("comm readable for a live process");
            assert!(!name.is_empty());
            assert!(!name.contains('\n'), "name must be a single line: {name:?}");

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A pid that cannot exist yields no name rather than a bogus one.
        #[cfg(target_os = "linux")]
        #[test]
        fn process_name_is_none_for_an_unknown_pid() {
            assert_eq!(process_name(u32::MAX), None);
        }
    }
} // mod unix

#[cfg(windows)]
mod windows {
    //! Windows endpoints for the agent: the OpenSSH named pipe
    //! (`\\.\pipe\openssh-ssh-agent`, used by ssh.exe / ssh-add /
    //! git-for-windows) and the PuTTY Pageant IPC window (`pageant`).

    use std::path::PathBuf;
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::ServerOptions;
    use tokio::runtime::Runtime;
    use tokio::task::JoinHandle;

    use super::proto::{serve, AgentKey, CallerInfo, KeyInfo, KeyStore, SignGuard};
    use clavix_core::error::{Error, Result};

    /// How many accepts in a row may fail before the endpoint gives up.
    /// A single failure says nothing — a client can die between connect
    /// and handshake — but a run of them means the pipe itself is gone,
    /// and spinning on it forever would burn a core.
    const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 5;

    /// A stop still in flight looks exactly like a competing agent: the
    /// previous instance's handles are released by a background runtime
    /// shutdown, so they can outlive the call that replaces them by a few
    /// milliseconds. `start_agent` runs right after a stop whenever the
    /// confirmation policy changes, and blaming the Windows OpenSSH
    /// service for our own not-yet-closed handles would send the user
    /// looking in the wrong place. Retry quietly for up to a second first.
    const FIRST_INSTANCE_RETRIES: u32 = 20;
    const FIRST_INSTANCE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    /// Test-only switch: create our own Pageant window even when an
    /// incumbent "Pageant" window exists. Production always yields to the
    /// incumbent (see `pageant::spawn_if_free`), but tests must be able to
    /// exercise our own window on machines where a Pageant-compatible
    /// agent (e.g. ssh-pageant) happens to be running.
    #[cfg(test)]
    pub static TEST_FORCE_PAGEANT: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    mod pageant {
        //! PuTTY Pageant IPC: a hidden top-level window whose class *and*
        //! title are `"Pageant"`, answering agent requests over the
        //! WM_COPYDATA + `PageantRequest%08x` shared-memory channel.
        //!
        //! Wire details (as implemented by PuTTY's winpgntc.c / pageant.c
        //! since 0.61; constants verified against upstream source):
        //!
        //! 1. Clients find us with `FindWindow("Pageant", "Pageant")`.
        //! 2. They create a file mapping named `PageantRequest%08x` (their
        //!    own thread id) and write the standard framed agent message —
        //!    the same 4-byte big-endian length + body used on sockets —
        //!    at offset 0 of the mapping.
        //! 3. They `SendMessage(hwnd, WM_COPYDATA, NULL, &cds)` with
        //!    `cds.dwData == 0x804e50ba` (AGENT_COPYDATA_ID) and
        //!    `cds.lpData` = the mapping name (length in `cbData`).
        //! 4. The agent opens the mapping, verifies its owner SID matches
        //!    the current user (PuTTY's cross-user guard — with signature
        //!    confirmations off it is the whole protection), processes the
        //!    request *synchronously* and writes the framed response back
        //!    at offset 0.
        //! 5. The window procedure returns non-zero on success, zero on
        //!    failure; the client is blocked on `SendMessage` either way.
        //!
        //! The sender is unknowable (wParam is NULL), so Pageant requests
        //! carry no caller identity for the confirmation prompt.
        //!
        //! The exchange is strictly synchronous — the answer must be in the
        //! mapping before the window procedure returns — so a signature
        //! confirmation parks this thread on the agent runtime, exactly as
        //! PuTTY's own modal confirmation blocks its message loop.

        use std::ffi::c_void;
        use std::sync::Arc;

        use tokio::runtime::Handle;
        use windows_sys::core::w;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, ERROR_CLASS_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER,
            HANDLE, HWND, LPARAM, LRESULT, WPARAM,
        };
        use windows_sys::Win32::Security::{PSID, TOKEN_QUERY};
        use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::Memory::{
            MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualQuery, FILE_MAP_ALL_ACCESS,
            FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_BASIC_INFORMATION,
        };
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentThreadId, OpenProcessToken,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, FindWindowW,
            GetMessageW, GetWindowLongPtrW, PostThreadMessageW, RegisterClassExW,
            SetWindowLongPtrW, TranslateMessage, CREATESTRUCTW, GWLP_USERDATA, MSG, WM_COPYDATA,
            WM_NCCREATE, WM_NCDESTROY, WM_QUIT, WNDCLASSEXW,
        };

        use super::super::proto::{
            process_message, ConnState, KeyStore, SignGuard, MAX_MESSAGE, SSH_AGENT_FAILURE,
        };

        /// Class and window name PuTTY clients search for. (`w!` yields
        /// the NUL-terminated wide pointer directly.)
        const CLASS_AND_TITLE: *const u16 = w!("Pageant");
        /// `dwData` marker of Pageant WM_COPYDATA messages (PuTTY's
        /// AGENT_COPYDATA_ID, "random goop" per their comment).
        const AGENT_COPYDATA_ID: usize = 0x804e50ba;
        /// Mapping names from real clients are always `PageantRequest` +
        /// hex thread id; requiring the prefix keeps a hostile caller from
        /// pointing us at arbitrary shared objects.
        const MAP_PREFIX: &[u8] = b"PageantRequest";
        const MAX_MAP_NAME: usize = 64;

        pub struct PageantThread {
            thread: std::thread::JoinHandle<()>,
            /// Needed to post WM_QUIT into the window thread's queue.
            thread_id: u32,
        }

        impl PageantThread {
            pub fn request_quit(&self) {
                unsafe {
                    PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0);
                }
            }

            pub fn join(self) {
                let _ = self.thread.join();
            }
        }

        enum PageantMsg {
            /// The window thread is alive; carries its id so `stop` can
            /// post WM_QUIT even while setup is still running.
            Started(u32),
            /// The hidden window exists — or setup failed, with the reason
            /// (the agent carries on with the pipe alone).
            Ready(Result<(), String>),
        }

        /// Where the last skipped endpoint left its reason, for the tests:
        /// a silently skipped endpoint is indistinguishable from a bug.
        #[cfg(test)]
        static LAST_UNAVAILABLE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

        /// The window handle the last run created, and where its message
        /// loop ended — test-only forensics for "the endpoint started but
        /// no window is findable".
        #[cfg(test)]
        static LAST_WINDOW: std::sync::Mutex<Option<isize>> = std::sync::Mutex::new(None);
        #[cfg(test)]
        static LAST_LOOP_EXIT: std::sync::Mutex<Option<(i32, u32)>> = std::sync::Mutex::new(None);

        /// The reason the most recent `spawn_if_free` returned `None`,
        /// when that was recorded (tests only).
        #[cfg(test)]
        pub fn user_sid_for_test() -> Option<Vec<u8>> {
            current_user_sid()
        }

        #[cfg(test)]
        pub fn last_unavailable_reason() -> Option<String> {
            LAST_UNAVAILABLE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// Forensics for a window that was created but cannot be found
        /// afterwards: handle, liveness, and — if alive — its parent,
        /// style, visibility and owning thread, plus how many same-named
        /// top-level windows `FindWindow` can see at all.
        #[cfg(test)]
        pub fn last_window_forensics() -> String {
            use std::cell::RefCell;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                EnumWindows, GetClassNameW, GetParent, GetWindowLongPtrW, GetWindowTextW,
                GetWindowThreadProcessId, IsWindowVisible, GWL_STYLE,
            };

            let window = *LAST_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
            let exit = *LAST_LOOP_EXIT.lock().unwrap_or_else(|e| e.into_inner());
            let Some(h) = window else {
                return format!("created=None, loop_exit={exit:?}");
            };

            thread_local! {
                /// Every top-level window the enumeration yields, as
                /// (hwnd, pid, class, title) — truncated in the report.
                static SEEN: RefCell<Vec<(isize, u32, String, String)>> =
                    const { RefCell::new(Vec::new()) };
            }

            unsafe extern "system" fn collect(hwnd: *mut std::ffi::c_void, _: isize) -> i32 {
                unsafe {
                    let mut class = [0u16; 64];
                    let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
                    let mut title = [0u16; 64];
                    let m = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    SEEN.with(|seen| {
                        seen.borrow_mut().push((
                            hwnd as isize,
                            pid,
                            String::from_utf16_lossy(&class[..n.max(0) as usize]),
                            String::from_utf16_lossy(&title[..m.max(0) as usize]),
                        ))
                    });
                    1
                }
            }

            SEEN.with(|seen| seen.borrow_mut().clear());
            let enumerated = unsafe { EnumWindows(Some(collect), 0) };
            let enum_err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            let seen = SEEN.with(|seen| seen.borrow().clone());

            unsafe {
                let hwnd = h as HWND;
                let mut owner_tid = 0u32;
                GetWindowThreadProcessId(hwnd, &mut owner_tid);
                let own_seen = seen.iter().any(|(w, ..)| *w == h);
                let candidates: Vec<String> = seen
                    .iter()
                    .filter(|(w, _, class, title)| {
                        *w == h || class == "Pageant" || title == "Pageant"
                    })
                    .take(4)
                    .map(|(w, pid, class, title)| format!("{w:#x}/pid {pid}/{class}/{title}"))
                    .collect();
                format!(
                    "hwnd={h:#x} alive={} parent={:?} style={:#x} visible={} owner_tid={owner_tid} \
                     enum_ok={enumerated} enum_err={enum_err}, seen_total={}, own_seen={own_seen}, \
                     matching=[{}], loop_exit={exit:?}",
                    windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) != 0,
                    GetParent(hwnd),
                    GetWindowLongPtrW(hwnd, GWL_STYLE),
                    IsWindowVisible(hwnd) != 0,
                    seen.len(),
                    candidates.join("; "),
                )
            }
        }

        /// The PuTTY endpoint is best-effort by design — the named pipe
        /// keeps serving without it — but skipping must never be silent:
        /// log the reason, and record it for the tests.
        fn unavailable(reason: String) -> Option<PageantThread> {
            eprintln!("[clavix agent] Pageant endpoint unavailable: {reason}");
            #[cfg(test)]
            {
                *LAST_UNAVAILABLE.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
            }
            None
        }

        /// What the window procedure needs to answer a request.
        struct Ctx {
            keys: KeyStore,
            guard: SignGuard,
            rt: Handle,
        }

        /// Start the PuTTY endpoint — unless an incumbent `Pageant` window
        /// already exists (real Pageant, KeePassXC, another agent), in
        /// which case PuTTY clients would be served by *that* agent anyway
        /// and two windows would only split them unpredictably.
        pub fn spawn_if_free(
            keys: KeyStore,
            guard: SignGuard,
            rt: Handle,
        ) -> Option<PageantThread> {
            #[cfg(test)]
            {
                *LAST_UNAVAILABLE.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *LAST_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = None;
                *LAST_LOOP_EXIT.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }

            // Tests set this to exercise our own window even when a
            // Pageant-compatible agent (ssh-pageant, KeePassXC, PuTTY)
            // already owns the "Pageant" name on the machine — the
            // production path deliberately yields to that incumbent.
            #[cfg(test)]
            let force = super::TEST_FORCE_PAGEANT.load(std::sync::atomic::Ordering::Relaxed);
            #[cfg(not(test))]
            let force = false;

            if !force {
                unsafe {
                    let incumbent = FindWindowW(CLASS_AND_TITLE, CLASS_AND_TITLE);
                    if !incumbent.is_null() {
                        return unavailable(
                            "another Pageant window is already running; the OpenSSH \
                             named pipe still serves ssh.exe"
                                .into(),
                        );
                    }
                }
            }

            let ctx = Arc::new(Ctx { keys, guard, rt });
            let (tx, rx) = std::sync::mpsc::channel::<PageantMsg>();
            let thread = match std::thread::Builder::new()
                .name("clavix-pageant".into())
                .spawn(move || run_thread(ctx, tx))
            {
                Ok(t) => t,
                Err(e) => return unavailable(format!("cannot spawn the window thread: {e}")),
            };
            // The thread announces its id first, then whether the window
            // came up. A window that failed to appear means the endpoint
            // is dead before it served anything — report None (the thread
            // exits on its own).
            let thread_id = match rx.recv() {
                Ok(PageantMsg::Started(id)) => id,
                _ => return unavailable("window thread exited before announcing its id".into()),
            };
            match rx.recv() {
                Ok(PageantMsg::Ready(Ok(()))) => Some(PageantThread { thread, thread_id }),
                Ok(PageantMsg::Ready(Err(reason))) => unavailable(reason),
                _ => unavailable("window thread exited before reporting the window state".into()),
            }
        }

        fn run_thread(ctx: Arc<Ctx>, tx: std::sync::mpsc::Sender<PageantMsg>) {
            unsafe {
                // Announce before anything fallible: stop() may post
                // WM_QUIT from this moment on.
                let _ = tx.send(PageantMsg::Started(GetCurrentThreadId()));

                let hinst = GetModuleHandleW(std::ptr::null());
                if hinst.is_null() {
                    let _ = tx.send(PageantMsg::Ready(Err(format!(
                        "GetModuleHandleW failed (err {})",
                        GetLastError()
                    ))));
                    return;
                }

                // A previous agent run in this process may already have
                // registered the class; that registration is exactly what
                // we want, so ERROR_CLASS_ALREADY_EXISTS is not an error.
                let mut wc: WNDCLASSEXW = std::mem::zeroed();
                wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
                wc.lpfnWndProc = Some(pageant_wnd_proc);
                wc.hInstance = hinst;
                wc.lpszClassName = CLASS_AND_TITLE;
                let atom = RegisterClassExW(&wc);
                if atom == 0 {
                    let err = GetLastError();
                    if err != ERROR_CLASS_ALREADY_EXISTS {
                        let _ = tx.send(PageantMsg::Ready(Err(format!(
                            "RegisterClassExW failed (err {err})"
                        ))));
                        return;
                    }
                }

                // The window owns a Box<Arc<Ctx>> (freed on WM_NCDESTROY).
                let ctx_box = Box::new(ctx.clone());
                let hwnd = CreateWindowExW(
                    0,
                    CLASS_AND_TITLE,
                    CLASS_AND_TITLE,
                    0, // style 0: a bare hidden top-level window, never shown
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    hinst,
                    Box::into_raw(ctx_box) as *const c_void,
                );
                if hwnd.is_null() {
                    let _ = tx.send(PageantMsg::Ready(Err(format!(
                        "CreateWindowExW failed (err {})",
                        GetLastError()
                    ))));
                    return;
                }
                #[cfg(test)]
                {
                    *LAST_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = Some(hwnd as isize);
                }
                let _ = tx.send(PageantMsg::Ready(Ok(())));

                let mut msg: MSG = std::mem::zeroed();
                let mut rc;
                loop {
                    // 0 = WM_QUIT, -1 = error: leave the loop either way.
                    rc = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
                    if rc <= 0 {
                        break;
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                #[cfg(test)]
                {
                    *LAST_LOOP_EXIT.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some((rc, GetLastError()));
                }
                let _ = DestroyWindow(hwnd);
            }
        }

        unsafe extern "system" fn pageant_wnd_proc(
            hwnd: HWND,
            msg: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            match msg {
                WM_NCCREATE => {
                    // Stash the owning Arc (passed via CreateWindowExW's
                    // lpParam) in the window's user data; WM_NCDESTROY
                    // frees the box.
                    let create = lparam as *const CREATESTRUCTW;
                    if create.is_null() {
                        return 0;
                    }
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*create).lpCreateParams as isize);
                    // DefWindowProc must still see WM_NCCREATE: its handling
                    // is what actually *sets the window caption* from the
                    // CREATESTRUCT. A WndProc that swallows this message
                    // leaves the window nameless — `FindWindow("Pageant",
                    // "Pageant")` then never finds it, so no PuTTY client
                    // ever reaches us (measured: title length 0, not
                    // findable). The return value is still TRUE so the
                    // window is created.
                    DefWindowProcW(hwnd, msg, wparam, lparam);
                    1
                }
                WM_NCDESTROY => {
                    let p = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Arc<Ctx>;
                    if !p.is_null() {
                        drop(Box::from_raw(p));
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    }
                    DefWindowProcW(hwnd, msg, wparam, lparam)
                }
                WM_COPYDATA => handle_copydata(hwnd, lparam),
                _ => DefWindowProcW(hwnd, msg, wparam, lparam),
            }
        }

        /// A client is synchronously waiting for our answer, so any path
        /// that cannot produce one must return zero *now* rather than
        /// letting the send hang.
        unsafe fn handle_copydata(hwnd: HWND, lparam: LPARAM) -> LRESULT {
            let ctx_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Arc<Ctx>;
            if ctx_ptr.is_null() {
                return 0;
            }
            let ctx = (*ctx_ptr).clone();

            let cds = lparam as *const COPYDATASTRUCT;
            if cds.is_null() {
                return 0;
            }
            let cds = &*cds;
            if cds.dwData != AGENT_COPYDATA_ID {
                return 0;
            }
            if cds.lpData.is_null() || cds.cbData == 0 || cds.cbData as usize > MAX_MAP_NAME {
                return 0;
            }

            // The mapping name is ASCII by construction ("PageantRequest" +
            // hex digits); check that and widen per byte, so no codepage
            // conversion ambiguity ever applies.
            let raw = std::slice::from_raw_parts(cds.lpData as *const u8, cds.cbData as usize);
            let raw = match raw.strip_suffix(&[0]) {
                Some(r) => r, // clients include the trailing NUL; tolerate
                None => raw,
            };
            if !raw.starts_with(MAP_PREFIX) || raw.len() == MAP_PREFIX.len() {
                return 0;
            }
            if !raw.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                return 0;
            }
            let mut name: Vec<u16> = raw.iter().map(|&b| b as u16).collect();
            name.push(0);

            // FILE_MAP_ALL_ACCESS rather than READ|WRITE, exactly like
            // PuTTY's pageant: the owner check needs READ_CONTROL, which
            // READ|WRITE does not request.
            let map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, name.as_ptr());
            if map.is_null() {
                return 0;
            }
            let ok = serve_mapping(&ctx, map);
            CloseHandle(map);
            if ok {
                1
            } else {
                0
            }
        }

        /// Process the request sitting in `map` and write the framed
        /// response back at offset 0.
        unsafe fn serve_mapping(ctx: &Ctx, map: HANDLE) -> bool {
            if !mapping_belongs_to_current_user(map) {
                return false;
            }
            let view = MapViewOfFile(map, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
            if view.Value.is_null() {
                return false;
            }

            // VirtualQuery reports the mapped region (the section size
            // rounded up to page granularity); never read or write past it.
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let written = VirtualQuery(
                view.Value,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            let bound = if written != 0 { mbi.RegionSize } else { 0 };
            if bound < 5 {
                UnmapViewOfFile(view);
                return false;
            }

            let bytes = std::slice::from_raw_parts_mut(view.Value as *mut u8, bound);
            let msglen = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            let msg = if msglen == 0 || msglen > MAX_MESSAGE || 4 + msglen > bound {
                None
            } else {
                Some(&bytes[4..4 + msglen])
            };

            // A request that cannot be read (junk length, too big for the
            // mapping) gets a failure response rather than silence: the
            // client is parked on SendMessage and must see *something*.
            let response = match msg {
                Some(msg) => ctx.rt.block_on(process_message(
                    msg,
                    &ctx.keys,
                    &ctx.guard,
                    None,
                    // Pageant has no connection to bind; PuTTY doesn't
                    // send session-bind anyway.
                    &mut ConnState::default(),
                )),
                None => vec![SSH_AGENT_FAILURE],
            };
            if 4 + response.len() > bound {
                UnmapViewOfFile(view);
                return false;
            }
            bytes[..4].copy_from_slice(&u32::to_be_bytes(response.len() as u32));
            bytes[4..4 + response.len()].copy_from_slice(&response);
            UnmapViewOfFile(view);
            true
        }

        /// Copy of this process's user SID (raw bytes as returned by the
        /// OS), computed once and reused for every request.
        fn current_user_sid() -> Option<Vec<u8>> {
            use windows_sys::Win32::Security::{
                GetTokenInformation, TokenUser, SID_AND_ATTRIBUTES,
            };

            // Successful lookups only: caching a failure would disable
            // the Pageant endpoint for the rest of the run after one
            // transient error.
            static CACHE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
            if let Some(sid) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Some(sid);
            }
            let computed = unsafe {
                let mut token = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return None;
                }
                let result = (|| {
                    // First call sizes the buffer (fails with
                    // ERROR_INSUFFICIENT_BUFFER by design).
                    let mut needed = 0u32;
                    let rc =
                        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
                    if rc == 0 {
                        let err = GetLastError();
                        if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
                            return None;
                        }
                    }
                    let mut buf = vec![0u8; needed as usize];
                    if GetTokenInformation(
                        token,
                        TokenUser,
                        buf.as_mut_ptr() as *mut c_void,
                        needed,
                        &mut needed,
                    ) == 0
                    {
                        return None;
                    }
                    // TOKEN_USER begins with a SID_AND_ATTRIBUTES whose
                    // Sid points *into* the buffer; copy the SID out so
                    // the pointer cannot dangle.
                    let attrs = buf.as_ptr() as *const SID_AND_ATTRIBUTES;
                    copy_sid((*attrs).Sid)
                })();
                CloseHandle(token);
                result
            }?;
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(computed.clone());
            Some(computed)
        }

        /// Copy a SID out of OS-owned memory into a plain byte buffer.
        unsafe fn copy_sid(sid: PSID) -> Option<Vec<u8>> {
            use windows_sys::Win32::Security::{CopySid, GetLengthSid};

            if sid.is_null() {
                return None;
            }
            let len = GetLengthSid(sid);
            if len == 0 {
                return None;
            }
            let mut copy = vec![0u8; len as usize];
            (CopySid(len, copy.as_mut_ptr() as *mut c_void, sid) != 0).then_some(copy)
        }

        /// Owner SID of `handle`, copied out of OS-owned memory.
        ///
        /// `ppSecurityDescriptor` is not optional, however tempting it is
        /// to pass NULL when the owner is all we want: `GetSecurityInfo`
        /// allocates a self-relative descriptor on every successful call
        /// and the SID it returns points *into* that allocation — which is
        /// exactly why the SID has to be copied out at all. Passing NULL
        /// does not skip the allocation, it only throws away the one
        /// pointer that could free it, once per Pageant request. MSDN
        /// documents the argument as required whenever any of the
        /// `ppsid*` / `ppDacl` / `ppSacl` outputs is non-NULL.
        unsafe fn owner_sid_of(handle: HANDLE) -> Option<Vec<u8>> {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
            use windows_sys::Win32::Security::{
                OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            };

            let mut owner: PSID = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let rc = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if rc != 0 {
                return None;
            }
            // Copy first, free second: `owner` dangles the moment the
            // descriptor is released.
            let copied = copy_sid(owner);
            if !sd.is_null() {
                LocalFree(sd);
            }
            copied
        }

        /// The SID this process's token uses as the *default owner* for
        /// objects created without an explicit security descriptor: the
        /// Administrators group for an elevated token, the user otherwise.
        ///
        /// PuTTY's pageant accepts either this or the user SID as a valid
        /// request-mapping owner (its `get_default_sid` / `get_user_sid`
        /// pair) — clients that pass no descriptor at all, and clients on
        /// an elevated token, produce exactly this owner.
        fn current_default_owner_sid() -> Option<Vec<u8>> {
            use windows_sys::Win32::System::Threading::{
                GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            };

            /// `READ_CONTROL` — what GetSecurityInfo needs on the handle.
            /// (Only exported by windows-sys as a file-access constant;
            /// the access mask itself is generic.)
            const READ_CONTROL: u32 = 0x0002_0000;

            // Successful lookups only, as in `current_user_sid`.
            static CACHE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
            if let Some(sid) = CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                return Some(sid);
            }
            let computed = unsafe {
                // PuTTY asks for MAXIMUM_ALLOWED, which includes
                // READ_CONTROL.
                let proc = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | READ_CONTROL,
                    0,
                    GetCurrentProcessId(),
                );
                if proc.is_null() {
                    return None;
                }
                let result = owner_sid_of(proc);
                CloseHandle(proc);
                result
            }?;
            *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some(computed.clone());
            Some(computed)
        }

        /// True when the request mapping's owner is this user (or this
        /// token's default owner) — PuTTY's pageant check against a
        /// different user borrowing the agent's keys.
        fn mapping_belongs_to_current_user(map: HANDLE) -> bool {
            use windows_sys::Win32::Security::{EqualSid, PSID};

            // Two acceptable owners, exactly like PuTTY's pageant: the
            // user's own SID (clients that set an explicit security
            // descriptor — winpgntc does) or the token's default owner
            // (clients that pass no descriptor at all).
            let (Some(ours), Some(default_owner)) =
                (current_user_sid(), current_default_owner_sid())
            else {
                return false; // fail closed
            };
            let Some(owned) = (unsafe { owner_sid_of(map) }) else {
                return false;
            };
            unsafe {
                EqualSid(ours.as_ptr() as PSID, owned.as_ptr() as PSID) != 0
                    || EqualSid(default_owner.as_ptr() as PSID, owned.as_ptr() as PSID) != 0
            }
        }
    } // mod pageant

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        /// Public-only summary of every key currently exposed by the agent.
        pub keys: Vec<KeyInfo>,
        shared: AgentShared,
    }

    struct AgentShared {
        /// The agent's own multi-thread runtime. The pipe's accept loop and
        /// connection tasks live here; the Pageant window thread also parks
        /// `block_on` calls on it while a signature approval is pending.
        /// Deliberately not the Tauri runtime — the Pageant thread must be
        /// able to synchronously wait on confirmations without depending on
        /// how the host app's runtime is threaded.
        rt: Runtime,
        /// `None` only after a stop has taken it; see `SshAgentHandle::stop`.
        accept_loop: Option<JoinHandle<()>>,
        pageant: Option<pageant::PageantThread>,
        /// Denies parked confirmations on stop - a Pageant request can be
        /// sitting in the window thread's `block_on`, and joining it must
        /// not wait out the confirmation timeout.
        guard: SignGuard,
    }

    impl SshAgentHandle {
        pub async fn stop(mut self) {
            // Abort *and wait*: the aborted task owns the listening pipe
            // instance, and the next `start_agent` — which is what a
            // confirmation-policy change does — asks the OS for a *first*
            // instance, a request that fails for as long as ours is open.
            // Only the async path can wait; `start_agent` retries for the
            // benefit of the sync one.
            if let Some(loop_task) = self.shared.accept_loop.take() {
                loop_task.abort();
                let _ = loop_task.await;
            }
            self.shutdown();
        }

        /// Non-async best-effort stop, suitable for `lock` / `logout`
        /// commands that don't want to be async just for this cleanup.
        pub fn stop_sync(self) {
            self.shutdown();
        }

        fn shutdown(mut self) {
            self.shared.guard.cancel();
            if let Some(loop_task) = self.shared.accept_loop.take() {
                loop_task.abort();
            }
            // Quit the Pageant window thread, then wait for it: it can be
            // parked on a signature confirmation (bounded by the 30 s
            // confirm timeout), and the runtime must outlive any `block_on`
            // still driving it. `guard.cancel()` above is what keeps that
            // join short; `commands::ssh::stop_agent_sync` separately
            // closes the dialog the confirmation belongs to.
            if let Some(pg) = self.shared.pageant.as_ref() {
                pg.request_quit();
            }
            if let Some(pg) = self.shared.pageant.take() {
                pg.join();
            }
            // Shut the runtime down without waiting (`shutdown_background`
            // consumes it): a blocking runtime drop is not allowed from an
            // async context, and `stop()`/`stop_sync()` are both reachable
            // from inside a runtime. The background shutdown cancels any
            // still-serving connection task; the remaining fields drop
            // with `self`.
            self.shared.rt.shutdown_background();
        }
    }

    /// OpenSSH on Windows expects exactly this pipe name; no env var is
    /// involved, clients probe it automatically.
    pub fn default_socket_path() -> Result<PathBuf> {
        Ok(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
    }

    /// Accept either a full `\\.\pipe\name` path or a bare name and return
    /// the canonical pipe name.
    fn full_pipe_name(path: &std::path::Path) -> String {
        let s = path.to_string_lossy();
        if s.starts_with(r"\\.\pipe\") || s.starts_with(r"\\?\pipe\") || s.starts_with("//./pipe/")
        {
            s.into_owned()
        } else {
            format!(r"\\.\pipe\{s}")
        }
    }

    /// Best-effort identity of the process connected to `server`.
    ///
    /// `GetNamedPipeClientProcessId` works on the server handle while the
    /// client is connected, so it is resolved right after `connect()`.
    fn peer_caller(
        server: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> Option<CallerInfo> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as _, &mut pid) };
        if ok == 0 || pid == 0 {
            return None;
        }
        Some(CallerInfo {
            pid,
            name: process_name(pid),
        })
    }

    /// Resolve a pid to a process name via the image file name. Returns the
    /// bare executable name (e.g. `ssh.exe`), cleaned the same way as the
    /// Unix `/proc/<pid>/comm` label.
    fn process_name(pid: u32) -> Option<String> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        // A process may exit (or be a protected process) between the pid
        // read and this open — any failure just means "unknown caller".
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let mut name = String::with_capacity(260);
        // Grow the buffer if the path is longer than the initial guess.
        let mut len = 260u32;
        let mut ok = false;
        loop {
            let mut wide = vec![0u16; len as usize];
            let mut needed = len;
            let rc =
                unsafe { QueryFullProcessImageNameW(process, 0, wide.as_mut_ptr(), &mut needed) };
            if rc != 0 {
                wide.truncate(needed as usize);
                name = String::from_utf16_lossy(&wide);
                ok = true;
                break;
            }
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER && len < 64 * 1024 {
                len = (len.saturating_mul(2)).min(64 * 1024);
                continue;
            }
            break;
        }
        unsafe { windows_sys::Win32::Foundation::CloseHandle(process) };

        if !ok {
            return None;
        }
        // The image path is attacker-influenced text heading for a dialog:
        // keep just the file name, printable, short, single-line.
        let file = name.rsplit(['\\', '/']).next().unwrap_or(&name);
        super::proto::sanitize_process_label(file)
    }

    pub async fn start_agent(
        path: PathBuf,
        keys: Vec<AgentKey>,
        guard: SignGuard,
    ) -> Result<SshAgentHandle> {
        let rt = Runtime::new().map_err(|e| Error::Storage {
            reason: format!("cannot create agent runtime: {e}"),
        })?;
        let pipe_name = full_pipe_name(&path);

        let store: KeyStore = Arc::new(tokio::sync::Mutex::new(keys));
        let key_summaries: Vec<KeyInfo> = {
            let store = store.lock().await;
            store.iter().map(KeyInfo::from).collect()
        };

        // First pipe instance, declared as such so that any *other* agent
        // holding `\\.\pipe\openssh-ssh-agent` (the Windows OpenSSH
        // ssh-agent service, another Pageant-compatible app, a second
        // Clavix) makes this call fail instead of silently coexisting and
        // splitting clients between two agents.
        //
        // Named-pipe handles bind to the reactor that created them, and
        // everything below runs on the agent's own runtime — so the first
        // instance is created there too, with the outcome reported back
        // through a oneshot. Creating it on the caller's runtime (e.g.
        // Tauri's) and connecting it on ours would cross reactor
        // registrations and fail at the first accept.
        let first = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let name = pipe_name.clone();
            rt.spawn(async move {
                let mut attempt = 0u32;
                let result = loop {
                    let result = ServerOptions::new()
                        .first_pipe_instance(true)
                        .access_inbound(true)
                        .access_outbound(true)
                        .create(&name);
                    // tokio maps ERROR_ACCESS_DENIED — both a competing
                    // agent and our own previous instance still closing —
                    // to PermissionDenied. Only the second one clears up
                    // on its own, so retry before believing it.
                    let retryable = matches!(&result, Err(e)
                        if e.kind() == std::io::ErrorKind::PermissionDenied)
                        && attempt < FIRST_INSTANCE_RETRIES;
                    if !retryable {
                        break result;
                    }
                    attempt += 1;
                    tokio::time::sleep(FIRST_INSTANCE_RETRY_DELAY).await;
                };
                let _ = tx.send(result);
            });
            match rx.await {
                Ok(Ok(server)) => server,
                Ok(Err(e)) => {
                    // tokio maps ERROR_ACCESS_DENIED from a competing
                    // first instance to PermissionDenied.
                    let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        " — is the Windows OpenSSH ssh-agent service running \
                         (`Get-Service ssh-agent`), or another Pageant-compatible \
                         program running? Stop it and retry"
                    } else {
                        ""
                    };
                    // This whole function runs inside a runtime; a bare
                    // drop of our runtime here would panic.
                    rt.shutdown_background();
                    return Err(Error::Storage {
                        reason: format!("bind {pipe_name}: {e}{hint}"),
                    });
                }
                Err(_) => {
                    rt.shutdown_background();
                    return Err(Error::Storage {
                        reason: "agent runtime stopped while creating the pipe".into(),
                    });
                }
            }
        };

        let accept_loop = {
            let store_loop = store.clone();
            let guard_loop = guard.clone();
            let rt_handle = rt.handle().clone();
            let pipe_name_loop = pipe_name.clone();
            rt.spawn(async move {
                // One instance listening at a time; accepted connections
                // are served concurrently by their own tasks. Windows
                // OpenSSH clients connect once per request and don't
                // expect a pool.
                let mut listening = first;
                let mut consecutive_errors = 0u32;
                loop {
                    let accepted = listening.connect().await;

                    // Replenish before the accepted connection is handed
                    // off, and whatever the accept returned. A client that
                    // opens the pipe while no instance is listening is
                    // told it is busy rather than queued, so the ordering
                    // keeps that window as short as it can be — and, more
                    // to the point, keeps it independent of whatever else
                    // ends up between the accept and the hand-off later.
                    // No first-instance flag here: ours is already in.
                    let next = match ServerOptions::new()
                        .access_inbound(true)
                        .access_outbound(true)
                        .create(&pipe_name_loop)
                    {
                        Ok(next) => next,
                        Err(e) => {
                            eprintln!(
                                "[clavix agent] cannot recreate a listening instance on \
                                 {pipe_name_loop}, the endpoint stops here: {e}"
                            );
                            return;
                        }
                    };
                    let server = std::mem::replace(&mut listening, next);

                    if let Err(e) = accepted {
                        eprintln!("[clavix agent] pipe connect failed on {pipe_name_loop}: {e}");
                        consecutive_errors += 1;
                        if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                            eprintln!(
                                "[clavix agent] {consecutive_errors} accepts in a row failed on \
                                 {pipe_name_loop}, the endpoint stops here"
                            );
                            return;
                        }
                        continue;
                    }
                    consecutive_errors = 0;

                    let store = store_loop.clone();
                    let guard = guard_loop.clone();
                    rt_handle.spawn(async move {
                        // Resolve the caller right after accept: the pid is
                        // only meaningful while the client is connected.
                        let caller = peer_caller(&server);
                        if let Err(e) = serve(server, store, guard, caller).await {
                            eprintln!("[clavix agent] connection error: {e}");
                        }
                    });
                }
            })
        };

        // The PuTTY endpoint is best-effort: when a real Pageant (or any
        // other Pageant-compatible agent) is already running, clients will
        // find it anyway — serving alongside would split plink traffic
        // between two agents, so we simply don't start.
        let pageant_thread =
            pageant::spawn_if_free(store.clone(), guard.clone(), rt.handle().clone());

        Ok(SshAgentHandle {
            socket_path: path,
            keys: key_summaries,
            shared: AgentShared {
                rt,
                accept_loop: Some(accept_loop),
                pageant: pageant_thread,
                guard,
            },
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use super::super::proto::SignPolicy;

        /// Pageant window class + title are process-global: two agents (or
        /// two tests) would make `FindWindow` pick an arbitrary one. Every
        /// test that starts an agent serializes on this lock.
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

        /// Find OUR agent's Pageant window, ignoring any incumbent owned
        /// by another process (ssh-pageant, PuTTY's Pageant, …).
        /// `FindWindowW` would return an arbitrary match; this walks the
        /// top-level windows with `FindWindowExW` and filters by owning
        /// process id.
        unsafe fn find_own_pageant_window() -> *mut std::ffi::c_void {
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId,
            };

            thread_local! {
                /// Set by `visit` when our window is found.
                static MATCH: std::cell::Cell<isize> = const { std::cell::Cell::new(0) };
            }

            unsafe extern "system" fn visit(hwnd: *mut std::ffi::c_void, _: isize) -> i32 {
                // "Pageant", as UTF-16 code units.
                const NAME: [u16; 7] = [80, 97, 103, 101, 97, 110, 116];

                unsafe {
                    let mut class = [0u16; 32];
                    let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
                    if n as usize != NAME.len() || class[..NAME.len()] != NAME {
                        return 1;
                    }
                    let mut title = [0u16; 32];
                    let m = GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32);
                    if m as usize != NAME.len() || title[..NAME.len()] != NAME {
                        return 1;
                    }
                    let mut pid = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut pid);
                    if pid == std::process::id() {
                        MATCH.with(|cell| cell.set(hwnd as isize));
                        return 0; // stop enumerating
                    }
                    1
                }
            }

            MATCH.with(|cell| cell.set(0));
            EnumWindows(Some(visit), 0);
            MATCH.with(|cell| cell.get()) as *mut std::ffi::c_void
        }

        /// A fresh unencrypted Ed25519 key, loaded through the same path
        /// the real start command uses.
        fn make_key(comment: &str) -> AgentKey {
            use ssh_key::{Algorithm, LineEnding, PrivateKey};

            let mut rng = rand::thread_rng();
            let pk = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
            let pem = pk.to_openssh(LineEnding::LF).unwrap().to_string();
            super::super::proto::try_load_agent_key(&pem, comment)
                .unwrap()
                .expect("ed25519 keys always load")
        }

        fn unique_pipe(suffix: &str) -> String {
            format!(
                r"\\.\pipe\clavix-agent-test-{}-{suffix}",
                std::process::id()
            )
        }

        fn frame(message: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(4 + message.len());
            out.extend_from_slice(&u32::to_be_bytes(message.len() as u32));
            out.extend_from_slice(message);
            out
        }

        /// Read one framed response ([u32 BE length][payload]) off a
        /// client connection.
        async fn read_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
            use tokio::io::AsyncReadExt;

            let mut hdr = [0u8; 4];
            stream.read_exact(&mut hdr).await.unwrap();
            let len = u32::from_be_bytes(hdr) as usize;
            let mut resp = vec![0u8; len];
            stream.read_exact(&mut resp).await.unwrap();
            resp
        }

        #[test]
        fn named_pipe_serves_list_and_sign() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use tokio::io::AsyncWriteExt as _;

            let key = make_key("pipe-test");
            let blob = key.pub_blob.clone();
            let name = unique_pipe("pipe");
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                let handle = start_agent(
                    PathBuf::from(&name),
                    vec![key],
                    SignGuard::new(SignPolicy::Never, None),
                )
                .await
                .unwrap();

                let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(&name)
                    .unwrap();

                // REQUEST_IDENTITIES -> exactly our one key.
                client.write_all(&frame(&[11])).await.unwrap();
                let resp = read_frame(&mut client).await;
                assert_eq!(resp[0], 12); // SSH_AGENT_IDENTITIES_ANSWER
                assert_eq!(u32::from_be_bytes(resp[1..5].try_into().unwrap()), 1);
                let mut r = super::super::proto::SshReader::new(&resp[5..]);
                assert_eq!(r.read_string().unwrap(), blob.as_slice());

                // SIGN_REQUEST on the same connection -> ssh-ed25519 sig.
                let mut req = vec![13]; // SSH_AGENTC_SIGN_REQUEST
                super::super::proto::write_string(&mut req, &blob);
                super::super::proto::write_string(&mut req, b"data-to-sign");
                req.extend_from_slice(&u32::to_be_bytes(0));
                client.write_all(&frame(&req)).await.unwrap();
                let resp = read_frame(&mut client).await;
                assert_eq!(resp[0], 14); // SSH_AGENT_SIGN_RESPONSE
                let mut r = super::super::proto::SshReader::new(&resp[1..]);
                let sig_blob = r.read_string().unwrap();
                let mut inner = super::super::proto::SshReader::new(sig_blob);
                assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
                assert_eq!(inner.read_string().unwrap().len(), 64);

                handle.stop().await;
            });
        }

        /// A stop must never wait on a parked confirmation: a Pageant
        /// request under the "always ask" policy whose prompt never answers
        /// has the window thread parked in `block_on`, and `stop()` itself
        /// must deny it — not leave the caller waiting on a timeout.
        #[test]
        fn stopping_denies_a_parked_pageant_confirmation() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
            };
            use windows_sys::Win32::System::Threading::GetCurrentThreadId;
            use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageW, WM_COPYDATA};

            let key = make_key("cancel-test");
            let blob = key.pub_blob.clone();
            let name = unique_pipe("cancel");

            // The prompt never answers; cancellation is what ends the wait.
            // The channel tells the test the request is parked inside the
            // agent before it calls stop.
            let (parked_tx, parked_rx) = std::sync::mpsc::channel::<()>();
            let confirm: super::super::proto::ConfirmFn = Arc::new(move |_req| {
                let _ = parked_tx.send(());
                Box::pin(std::future::pending::<bool>())
            });
            let guard = SignGuard::new(SignPolicy::Always, Some(confirm));

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                super::TEST_FORCE_PAGEANT.store(true, std::sync::atomic::Ordering::Relaxed);
                let handle = start_agent(PathBuf::from(&name), vec![key], guard)
                    .await
                    .unwrap();
                super::TEST_FORCE_PAGEANT.store(false, std::sync::atomic::Ordering::Relaxed);

                let hwnd = unsafe { find_own_pageant_window() };
                assert!(
                    !hwnd.is_null(),
                    "start_agent should create a Pageant window"
                );

                // The client blocks in SendMessage until the agent answers.
                let hwnd_addr = hwnd as isize;
                let blob_for_thread = blob.clone();
                let client = std::thread::spawn(move || unsafe {
                    let map_name = format!("PageantRequest{:08x}", GetCurrentThreadId());
                    let mut name_wide: Vec<u16> = map_name.encode_utf16().collect();
                    name_wide.push(0);
                    let mut name_bytes = map_name.into_bytes();
                    name_bytes.push(0);

                    let hmap = CreateFileMappingW(
                        INVALID_HANDLE_VALUE,
                        std::ptr::null(),
                        PAGE_READWRITE,
                        0,
                        256 * 1024,
                        name_wide.as_ptr(),
                    );
                    assert!(!hmap.is_null(), "client mapping");
                    let view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
                    assert!(!view.Value.is_null(), "client view");
                    let bytes = std::slice::from_raw_parts_mut(view.Value as *mut u8, 256 * 1024);

                    let mut req = vec![13u8]; // SSH_AGENTC_SIGN_REQUEST
                    super::super::proto::write_string(&mut req, &blob_for_thread);
                    super::super::proto::write_string(&mut req, b"cancel-test-data");
                    req.extend_from_slice(&u32::to_be_bytes(0));
                    let framed = frame(&req);
                    bytes[..framed.len()].copy_from_slice(&framed);

                    let cds = COPYDATASTRUCT {
                        dwData: 0x804e50ba, // AGENT_COPYDATA_ID
                        cbData: name_bytes.len() as u32,
                        lpData: name_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                    };
                    let result = SendMessageW(
                        hwnd_addr as *mut std::ffi::c_void,
                        WM_COPYDATA,
                        0,
                        (&cds as *const COPYDATASTRUCT) as isize,
                    );
                    let first = if result > 0 {
                        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                        Some(bytes[4..4 + len][0])
                    } else {
                        None
                    };
                    UnmapViewOfFile(view);
                    CloseHandle(hmap);
                    first
                });

                parked_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("the agent should park on the confirmation");
                let started = std::time::Instant::now();
                handle.stop().await;
                let elapsed = started.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_secs(2),
                    "stop must cancel a parked confirmation, took {elapsed:?}"
                );
                assert_eq!(
                    client.join().expect("client thread"),
                    Some(5), // SSH_AGENT_FAILURE: the parked request was denied
                );
            });
        }

        #[test]
        fn peer_caller_reports_the_connecting_process() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use tokio::net::windows::named_pipe::ClientOptions;

            let name = unique_pipe("peer");
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let server = ServerOptions::new().create(&name).unwrap();
                let connect =
                    tokio::spawn(async move { ClientOptions::new().open(&name).unwrap() });
                server.connect().await.unwrap();
                let client = connect.await.unwrap();

                let caller = peer_caller(&server).expect("caller resolvable");
                assert_eq!(caller.pid, std::process::id());
                let caller_name = caller.name.expect("image name readable for a live process");
                assert!(!caller_name.is_empty());
                assert!(
                    !caller_name.contains('\n'),
                    "name must be a single line: {caller_name:?}"
                );
                drop(client);
            });
        }

        #[test]
        fn process_name_is_none_for_an_unknown_pid() {
            assert_eq!(process_name(u32::MAX), None);
        }

        #[test]
        fn a_competing_first_instance_yields_a_clear_error() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            let name = unique_pipe("conflict");
            let rt = tokio::runtime::Runtime::new().unwrap();
            let blocker = rt.block_on(async {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&name)
                    .unwrap()
            });

            let err = match rt.block_on(start_agent(
                PathBuf::from(&name),
                Vec::new(),
                SignGuard::new(SignPolicy::Never, None),
            )) {
                Err(e) => e,
                Ok(h) => {
                    rt.block_on(h.stop());
                    panic!("a competing first instance must be refused");
                }
            };
            match err {
                Error::Storage { reason } => {
                    assert!(
                        reason.contains("ssh-agent"),
                        "error should point at the likely owner: {reason}"
                    );
                }
                other => panic!("expected Storage error, got {other:?}"),
            }
            drop(blocker);
        }

        /// A stop hands the agent's runtime to `shutdown_background()`, so
        /// the instance it was listening on can still be open when the
        /// next start asks the OS for a *first* instance. Changing the
        /// confirmation policy does exactly this — stop, then start again
        /// on the same name — and the OS's ACCESS_DENIED used to surface
        /// as "is the Windows OpenSSH ssh-agent service running?", with no
        /// agent left behind to contradict it.
        #[test]
        fn restarting_immediately_after_a_stop_succeeds() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use tokio::io::AsyncWriteExt as _;

            let name = unique_pipe("restart");
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                let mut handle = start_agent(
                    PathBuf::from(&name),
                    vec![make_key("restart")],
                    SignGuard::new(SignPolicy::Never, None),
                )
                .await
                .unwrap();

                // Three in a row: one restart could get lucky on timing.
                for _ in 0..3 {
                    handle.stop().await;
                    handle = start_agent(
                        PathBuf::from(&name),
                        vec![make_key("restart")],
                        SignGuard::new(SignPolicy::Never, None),
                    )
                    .await
                    .expect("a restart must not be taken for a competing agent");
                }

                // ...and the endpoint the last start returned actually
                // serves, rather than merely having been created.
                let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(&name)
                    .unwrap();
                client.write_all(&frame(&[11])).await.unwrap();
                let resp = read_frame(&mut client).await;
                assert_eq!(resp[0], 12); // SSH_AGENT_IDENTITIES_ANSWER

                handle.stop().await;
            });
        }

        /// Full PuTTY-client emulation against our own Pageant window:
        /// FindWindow, shared `PageantRequest%08x` mapping, WM_COPYDATA,
        /// response read back from the mapping.
        #[test]
        fn pageant_ipc_serves_list_and_sign() {
            let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            use windows_sys::core::w;
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
            };
            use windows_sys::Win32::System::Threading::GetCurrentThreadId;
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                CreateWindowExW, DestroyWindow, SendMessageW, WM_COPYDATA,
            };

            let key = make_key("pageant-test");
            let blob = key.pub_blob.clone();
            let name = unique_pipe("pageant");
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                // Force our own window even when an incumbent agent (e.g.
                // ssh-pageant) owns the "Pageant" name on this machine —
                // production yields to the incumbent, the test wants ours.
                super::TEST_FORCE_PAGEANT.store(true, std::sync::atomic::Ordering::Relaxed);
                let handle = start_agent(
                    PathBuf::from(&name),
                    vec![key],
                    SignGuard::new(SignPolicy::Never, None),
                )
                .await
                .unwrap();
                super::TEST_FORCE_PAGEANT.store(false, std::sync::atomic::Ordering::Relaxed);

                unsafe {
                    let mut hwnd = find_own_pageant_window();
                    if hwnd.is_null() {
                        // Rules out a visibility/publication race before the
                        // environment probe below — cheap, and turns a
                        // would-be flake into a pass with a note.
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        hwnd = find_own_pageant_window();
                        if !hwnd.is_null() {
                            eprintln!("[test] Pageant window appeared after a short retry");
                        }
                    }
                    if hwnd.is_null() {
                        // The endpoint is best-effort, so a missing window
                        // can mean either "this environment cannot create
                        // windows at all" (locked-down CI sessions) or a
                        // real regression. Probe with a system class to
                        // tell them apart, and in the second case carry
                        // the recorded reason into the failure.
                        let probe = CreateWindowExW(
                            0,
                            w!("STATIC"),
                            w!("clavix-probe"),
                            0,
                            0,
                            0,
                            0,
                            0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null(),
                        );
                        let can_create_windows = !probe.is_null();
                        if can_create_windows {
                            DestroyWindow(probe);
                        }
                        let reason = super::pageant::last_unavailable_reason()
                            .unwrap_or_else(|| "no reason recorded".into());
                        if !can_create_windows {
                            eprintln!(
                                "[test] this environment cannot create windows - skipping \
                                 Pageant protocol checks (endpoint: {reason})"
                            );
                            handle.stop().await;
                            return;
                        }
                        let forensics = super::pageant::last_window_forensics();
                        panic!(
                            "start_agent should create a Pageant window, but none is \
                             findable: {reason}; {forensics}"
                        );
                    }
                    let map_name = format!("PageantRequest{:08x}", GetCurrentThreadId());
                    let mut name_wide: Vec<u16> = map_name.encode_utf16().collect();
                    name_wide.push(0);
                    let mut name_bytes = map_name.into_bytes();
                    name_bytes.push(0);

                    // One mapping per request, exactly like winpgntc. The
                    // agent must accept both owner shapes a client can
                    // produce: no security descriptor (owner = the token's
                    // default owner) and an explicit one owned by the user
                    // SID (what winpgntc itself passes when advapi is
                    // available). Exercise each in turn below.
                    let user_sid = super::pageant::user_sid_for_test().expect("token user SID");
                    let mut run_request = |msg: &[u8], with_sd: bool| -> Vec<u8> {
                        let mut sd: windows_sys::Win32::Security::SECURITY_DESCRIPTOR =
                            std::mem::zeroed();
                        let mut sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES =
                            std::mem::zeroed();
                        let attrs: *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES =
                            if with_sd {
                                windows_sys::Win32::Security::InitializeSecurityDescriptor(
                                    &mut sd as *mut _ as *mut std::ffi::c_void,
                                    1, // SECURITY_DESCRIPTOR_REVISION
                                );
                                windows_sys::Win32::Security::SetSecurityDescriptorOwner(
                                    &mut sd as *mut _ as *mut std::ffi::c_void,
                                    user_sid.as_ptr() as windows_sys::Win32::Security::PSID,
                                    0,
                                );
                                sa.nLength = std::mem::size_of_val(&sa) as u32;
                                sa.lpSecurityDescriptor =
                                    &mut sd as *mut _ as *mut std::ffi::c_void;
                                &sa
                            } else {
                                std::ptr::null()
                            };
                        let hmap = CreateFileMappingW(
                            INVALID_HANDLE_VALUE,
                            attrs,
                            PAGE_READWRITE,
                            0,
                            256 * 1024,
                            name_wide.as_ptr(),
                        );
                        assert!(!hmap.is_null(), "client mapping creation");
                        let view = MapViewOfFile(hmap, FILE_MAP_WRITE, 0, 0, 0);
                        assert!(!view.Value.is_null(), "client view mapping");
                        let bytes =
                            std::slice::from_raw_parts_mut(view.Value as *mut u8, 256 * 1024);
                        let framed = frame(msg);
                        bytes[..framed.len()].copy_from_slice(&framed);

                        let cds = COPYDATASTRUCT {
                            dwData: 0x804e50ba, // AGENT_COPYDATA_ID
                            cbData: name_bytes.len() as u32,
                            lpData: name_bytes.as_mut_ptr() as *mut std::ffi::c_void,
                        };
                        let result = SendMessageW(
                            hwnd,
                            WM_COPYDATA,
                            0,
                            (&cds as *const COPYDATASTRUCT) as isize,
                        );
                        assert!(result > 0, "the agent should answer this request");
                        // Response is written at the mapping start,
                        // length-prefixed like the socket protocol.
                        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                        let resp = bytes[4..4 + len].to_vec();
                        UnmapViewOfFile(view);
                        CloseHandle(hmap);
                        resp
                    };

                    let resp = run_request(&[11], false); // no SD: default-owner path
                    assert_eq!(resp[0], 12);
                    let mut r = super::super::proto::SshReader::new(&resp[5..]);
                    assert_eq!(r.read_string().unwrap(), blob.as_slice());

                    let mut req = vec![13];
                    super::super::proto::write_string(&mut req, &blob);
                    super::super::proto::write_string(&mut req, b"data-for-pageant");
                    req.extend_from_slice(&u32::to_be_bytes(0));
                    let resp = run_request(&req, true); // explicit user-SID SD: winpgntc's shape
                    assert_eq!(resp[0], 14);
                    let mut r = super::super::proto::SshReader::new(&resp[1..]);
                    let sig_blob = r.read_string().unwrap();
                    let mut inner = super::super::proto::SshReader::new(sig_blob);
                    assert_eq!(inner.read_string().unwrap(), b"ssh-ed25519");
                    assert_eq!(inner.read_string().unwrap().len(), 64);

                    handle.stop().await;
                }
            });
        }
    }
} // mod windows

#[cfg(not(any(unix, windows)))]
mod stub {
    use std::path::PathBuf;

    use super::proto::{AgentKey, KeyInfo, SignGuard};
    use clavix_core::error::{Error, Result};

    pub struct SshAgentHandle {
        pub socket_path: PathBuf,
        pub keys: Vec<KeyInfo>,
    }

    impl SshAgentHandle {
        pub async fn stop(self) {}
        pub fn stop_sync(self) {}
    }

    pub fn default_socket_path() -> Result<PathBuf> {
        Err(Error::Storage {
            reason: "SSH agent is only supported on Unix and Windows for now".into(),
        })
    }

    pub async fn start_agent(
        _path: PathBuf,
        _keys: Vec<AgentKey>,
        _guard: SignGuard,
    ) -> Result<SshAgentHandle> {
        Err(Error::Storage {
            reason: "SSH agent is only supported on Unix and Windows for now".into(),
        })
    }
}

pub use proto::{try_load_agent_key, ConfirmFn, HostHop, SignGuard, SignPolicy, SignRequest};

#[cfg(not(any(unix, windows)))]
pub use stub::{default_socket_path, start_agent, SshAgentHandle};
#[cfg(unix)]
pub use unix::{default_socket_path, start_agent, SshAgentHandle};
#[cfg(windows)]
pub use windows::{default_socket_path, start_agent, SshAgentHandle};
