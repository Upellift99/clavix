//! Single-instance guard for the Flatpak build.
//!
//! Everywhere else `tauri-plugin-single-instance` does this with a session
//! D-Bus name, but inside Flatpak that can't work: the sandbox may only own
//! names under its app id (ours is the legacy identifier, kept for
//! upgrades), and the plugin's zbus 5 connection doesn't get through older
//! `xdg-dbus-proxy` versions at all (see `dbus.rs`). The plugin ignores
//! both failures, so a second launch would start a second instance, and a
//! second SSH agent that takes over the socket.
//!
//! Instead: an exclusive lock on a file in `$XDG_RUNTIME_DIR/app/<app id>`,
//! a directory every instance of this Flatpak shares and nothing else can
//! write to. The instance that holds the lock listens on a unix socket
//! next to it; a later launch finds the lock taken, sends its arguments
//! over the socket (so the running instance can raise its window) and
//! exits. The kernel drops the lock when the holder dies, so a crash never
//! leaves a stale guard behind.

use std::fs::{File, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const LOCK_FILE: &str = "instance.lock";
const SOCKET_FILE: &str = "instance.sock";

/// Cap on what a second launch may send: its argv, NUL-separated.
const MAX_MESSAGE: u64 = 64 * 1024;

/// The lock holder may still be between taking the lock and binding the
/// socket when a second launch arrives; give it this long.
const CONNECT_ATTEMPTS: u32 = 20;
const CONNECT_INTERVAL: Duration = Duration::from_millis(50);

/// What [`acquire`] found.
pub enum Instance {
    /// We are the only instance. Keep this alive for the life of the
    /// process and hand it to [`Primary::serve`] once the app is up.
    Primary(Primary),
    /// Another instance is running and has our arguments. Exit.
    Forwarded,
}

pub struct Primary {
    // Held, never read: dropping it releases the lock.
    _lock: File,
    listener: UnixListener,
}

/// `$XDG_RUNTIME_DIR/app/$FLATPAK_ID`, which Flatpak creates and shares
/// between all instances of the app.
pub fn runtime_dir() -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    let app_id = std::env::var_os("FLATPAK_ID")?;
    Some(PathBuf::from(runtime).join("app").join(app_id))
}

pub fn acquire(dir: &Path, args: &[String]) -> io::Result<Instance> {
    std::fs::create_dir_all(dir)?;
    let lock = File::create(dir.join(LOCK_FILE))?;
    let socket = dir.join(SOCKET_FILE);
    match lock.try_lock() {
        Ok(()) => {
            // We hold the lock, so whatever socket is there belongs to a
            // dead instance.
            match std::fs::remove_file(&socket) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let listener = UnixListener::bind(&socket)?;
            Ok(Instance::Primary(Primary {
                _lock: lock,
                listener,
            }))
        }
        Err(TryLockError::WouldBlock) => {
            forward(&socket, args)?;
            Ok(Instance::Forwarded)
        }
        Err(TryLockError::Error(e)) => Err(e),
    }
}

fn forward(socket: &Path, args: &[String]) -> io::Result<()> {
    let mut last_err = None;
    for _ in 0..CONNECT_ATTEMPTS {
        match UnixStream::connect(socket) {
            Ok(mut stream) => {
                stream.write_all(args.join("\0").as_bytes())?;
                return Ok(());
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(CONNECT_INTERVAL);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::ErrorKind::TimedOut.into()))
}

impl Primary {
    /// Call `on_launch` with the arguments of every later launch, on a
    /// thread of its own, for as long as the process lives.
    pub fn serve(self, on_launch: impl Fn(Vec<String>) + Send + 'static) {
        let Primary { _lock, listener } = self;
        std::thread::spawn(move || {
            // Moved in so the lock lives exactly as long as the listener.
            let _lock = _lock;
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let mut message = Vec::new();
                if stream.take(MAX_MESSAGE).read_to_end(&mut message).is_err() {
                    continue;
                }
                let args = String::from_utf8_lossy(&message)
                    .split('\0')
                    .map(str::to_owned)
                    .collect();
                on_launch(args);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn second_launch_is_forwarded_to_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let Instance::Primary(primary) = acquire(dir.path(), &args(&["clavix"])).unwrap() else {
            panic!("first launch must be primary");
        };
        let (tx, rx) = mpsc::channel();
        primary.serve(move |argv| tx.send(argv).unwrap());

        let second = acquire(dir.path(), &args(&["clavix", "--tray"])).unwrap();
        assert!(matches!(second, Instance::Forwarded));
        let received = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(received, args(&["clavix", "--tray"]));
    }

    #[test]
    fn a_stale_socket_from_a_dead_instance_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        // A crashed instance leaves its socket file behind, but no lock.
        drop(UnixListener::bind(dir.path().join(SOCKET_FILE)).unwrap());
        assert!(dir.path().join(SOCKET_FILE).exists());

        let first = acquire(dir.path(), &args(&["clavix"])).unwrap();
        assert!(matches!(first, Instance::Primary(_)));
    }

    #[test]
    fn the_lock_is_released_when_the_primary_goes_away() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire(dir.path(), &args(&["clavix"])).unwrap();
        drop(first);
        let again = acquire(dir.path(), &args(&["clavix"])).unwrap();
        assert!(matches!(again, Instance::Primary(_)));
    }
}
