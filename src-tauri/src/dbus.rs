//! Session and system bus connections that also work inside Flatpak.
//!
//! Inside the sandbox the buses are not the real daemons but
//! `xdg-dbus-proxy`, which filters traffic per the manifest's
//! `--talk-name`s. The proxy mis-parses the SASL handshake whenever more
//! than one auth command reaches it in a single read: it then treats the
//! leftover text as a message header, logs "Invalid message header read"
//! and drops the connection. zbus pipelines the whole handshake
//! (`AUTH`, `NEGOTIATE_UNIX_FD`, `BEGIN`, then `Hello`) in one write, so
//! every zbus connection from the sandbox fails, and the screen-lock
//! probe reported "this session doesn't signal its lock".
//!
//! Inside Flatpak we therefore do the handshake ourselves, one command at
//! a time (`AUTH`, wait for `OK`, `BEGIN`), hand the authenticated socket
//! to zbus, and send `Hello` as an ordinary call. We never pass file
//! descriptors, so `NEGOTIATE_UNIX_FD` is skipped. Outside Flatpak
//! nothing changes: zbus connects as usual.

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use zbus::connection::socket::{BoxedSplit, ReadHalf, Split, WriteHalf};
use zbus::Connection;

/// Ceiling on connect + handshake + `Hello`. A wedged proxy must not hang
/// the caller, which polls every few seconds and retries anyway.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Longest SASL line we accept from the server (`OK <32 hex>\r\n` in
/// practice). Bounds the byte-by-byte read below.
const MAX_SASL_LINE: usize = 256;

const SYSTEM_BUS_DEFAULT: &str = "/var/run/dbus/system_bus_socket";

pub async fn session() -> zbus::Result<Connection> {
    if !in_flatpak() {
        return Connection::session().await;
    }
    let path = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .and_then(|a| unix_path(&a))
        .ok_or_else(|| zbus::Error::Address("no unix session bus address".into()))?;
    connect_sequential(&path).await
}

pub async fn system() -> zbus::Result<Connection> {
    if !in_flatpak() {
        return Connection::system().await;
    }
    let path = match std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
        Ok(addr) => unix_path(&addr)
            .ok_or_else(|| zbus::Error::Address("no unix system bus address".into()))?,
        Err(_) => PathBuf::from(SYSTEM_BUS_DEFAULT),
    };
    connect_sequential(&path).await
}

pub fn in_flatpak() -> bool {
    Path::new("/.flatpak-info").exists()
}

/// The socket path of the first `unix:path=` entry in a D-Bus address
/// list (`;`-separated, `key=value` pairs separated by `,`, values
/// %-escaped). Abstract sockets and other transports return `None`: the
/// Flatpak proxy always listens on a path.
fn unix_path(address: &str) -> Option<PathBuf> {
    address.split(';').find_map(|entry| {
        let params = entry.strip_prefix("unix:")?;
        params
            .split(',')
            .find_map(|kv| kv.strip_prefix("path="))
            .and_then(unescape)
            .map(PathBuf::from)
    })
}

fn unescape(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

async fn connect_sequential(path: &Path) -> zbus::Result<Connection> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut stream = UnixStream::connect(path).await?;
        let guid = sasl_external(&mut stream).await?;
        let (read, write) = stream.into_split();
        let split: BoxedSplit = Split::new(Box::new(NoFdRead(read)), Box::new(NoFdWrite(write)));
        let conn = zbus::connection::Builder::authenticated_socket(split, guid.as_str())
            .build()
            .await?;
        // An authenticated socket skips zbus' own `Hello`; the bus
        // refuses every other call until we have sent it.
        conn.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "Hello",
            &(),
        )
        .await?;
        Ok(conn)
    })
    .await
    .map_err(|_| zbus::Error::InputOutput(io::Error::from(io::ErrorKind::TimedOut).into()))?
}

/// `AUTH EXTERNAL <uid>`, wait for `OK <guid>`, then `BEGIN`: each
/// command in its own write, the next one only after the answer.
async fn sasl_external(stream: &mut UnixStream) -> zbus::Result<String> {
    let uid = current_uid()?;
    let hex: String = uid
        .to_string()
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    stream
        .write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())
        .await?;
    let reply = read_line(stream).await?;
    let guid = reply
        .strip_prefix("OK ")
        .ok_or_else(|| zbus::Error::Handshake(format!("bus refused EXTERNAL auth: {reply}")))?
        .to_owned();
    stream.write_all(b"BEGIN\r\n").await?;
    Ok(guid)
}

/// One `\r\n`-terminated line, read a byte at a time so nothing past it
/// (the server sends nothing before `BEGIN`, but still) is consumed.
async fn read_line(stream: &mut UnixStream) -> zbus::Result<String> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        if line.len() >= MAX_SASL_LINE {
            return Err(zbus::Error::Handshake("SASL line too long".into()));
        }
        line.push(stream.read_u8().await?);
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| zbus::Error::Handshake("SASL line not UTF-8".into()))
}

/// Our own uid without `unsafe`: `/proc/self` is owned by it.
fn current_uid() -> io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata("/proc/self")?.uid())
}

/// A plain socket half that never carries file descriptors, so zbus
/// doesn't advertise them either.
#[derive(Debug)]
struct NoFdRead(OwnedReadHalf);

#[derive(Debug)]
struct NoFdWrite(OwnedWriteHalf);

#[async_trait::async_trait]
impl ReadHalf for NoFdRead {
    async fn recvmsg(&mut self, buf: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
        Ok((self.0.read(buf).await?, Vec::new()))
    }
}

#[async_trait::async_trait]
impl WriteHalf for NoFdWrite {
    async fn sendmsg(&mut self, buf: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
        if !fds.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.0.write(buf).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_path_picks_the_first_unix_path_entry() {
        assert_eq!(
            unix_path("unix:path=/run/flatpak/bus"),
            Some(PathBuf::from("/run/flatpak/bus"))
        );
        assert_eq!(
            unix_path("tcp:host=x,port=1;unix:guid=ab,path=/run/user/1000/bus"),
            Some(PathBuf::from("/run/user/1000/bus"))
        );
        assert_eq!(
            unix_path("unix:path=/tmp/with%20space"),
            Some(PathBuf::from("/tmp/with space"))
        );
    }

    /// The regression itself: a real `dbus-daemon` behind a real
    /// `xdg-dbus-proxy`, as in the sandbox. zbus' own connect fails there
    /// ("Invalid message header read"); ours must get a unique name and a
    /// routed reply. Skipped locally when either binary is missing.
    #[tokio::test]
    async fn sequential_handshake_passes_xdg_dbus_proxy() {
        use std::process::{Command, Stdio};

        let have = |bin: &str| {
            Command::new(bin)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
        };
        if !have("dbus-daemon") || !have("xdg-dbus-proxy") {
            // CI installs both (see ci.yml), so a skip there would hide
            // the regression this test exists for.
            assert!(
                std::env::var_os("CI").is_none(),
                "dbus-daemon and xdg-dbus-proxy are required on CI"
            );
            eprintln!("skipped: dbus-daemon or xdg-dbus-proxy not installed");
            return;
        }
        // Short path: unix socket paths are capped at 108 bytes.
        let dir = PathBuf::from(format!("/tmp/clavix-dbus-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bus = dir.join("bus");
        let proxied = dir.join("proxy");

        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile"])
            .arg(format!("--address=unix:path={}", bus.display()))
            .spawn()
            .unwrap();
        wait_for(&bus).await;
        let mut proxy = Command::new("xdg-dbus-proxy")
            .arg(format!("unix:path={}", bus.display()))
            .arg(&proxied)
            .args(["--filter", "--talk=org.gnome.ScreenSaver"])
            .spawn()
            .unwrap();
        wait_for(&proxied).await;

        let result = connect_sequential(&proxied).await;
        let reply = match &result {
            Ok(conn) => Some(
                conn.call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "GetId",
                    &(),
                )
                .await,
            ),
            Err(_) => None,
        };

        let _ = proxy.kill();
        let _ = daemon.kill();
        let _ = proxy.wait();
        let _ = daemon.wait();
        let _ = std::fs::remove_dir_all(&dir);

        if let Err(e) = result {
            panic!("connect through xdg-dbus-proxy: {e}");
        }
        reply.unwrap().expect("a call routed through the proxy");
    }

    async fn wait_for(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{} never appeared", path.display());
    }

    #[test]
    fn unix_path_rejects_abstract_and_malformed_addresses() {
        assert_eq!(unix_path("unix:abstract=/tmp/dbus-x"), None);
        assert_eq!(unix_path("unix:path=/bad%2"), None);
        assert_eq!(unix_path(""), None);
    }
}
