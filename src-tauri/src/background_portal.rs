//! "Launch at login" for the Flatpak build, through the Background portal.
//!
//! `tauri-plugin-autostart` writes `~/.config/autostart/clavix.desktop`,
//! but inside the sandbox `~/.config` is the app's private
//! `~/.var/app/<id>/config`, which the desktop never reads: the toggle
//! would silently do nothing. The portal is the supported way: it writes
//! the host's autostart entry itself, after asking the user if the desktop
//! wants to.
//!
//! The portal has no "is autostart on?" query, so we remember the last
//! answer it gave in a marker file in the app's config directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use zbus::message::Type as MessageType;
use zbus::MessageStream;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

const PORTAL_DEST: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const REQUEST_IFACE: &str = "org.freedesktop.portal.Request";

/// The desktop may show a dialog; leave the user time to read it.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

const MARKER: &str = "autostart-enabled";

pub fn is_enabled(config_dir: &Path) -> bool {
    config_dir.join(MARKER).exists()
}

/// Ask the portal to add (or remove) the host autostart entry, then record
/// the outcome. Errors carry a message fit for the Preferences dialog.
pub async fn set_enabled(config_dir: &Path, enable: bool) -> Result<(), String> {
    let granted = request_background(enable).await?;
    if enable && !granted {
        return Err("The desktop refused to let Clavix start at login. \
                    You can allow it in the system settings, under Apps."
            .into());
    }
    let marker = marker_path(config_dir);
    if enable {
        std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
        std::fs::write(&marker, b"").map_err(|e| e.to_string())?;
    } else {
        match std::fs::remove_file(&marker) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn marker_path(config_dir: &Path) -> PathBuf {
    config_dir.join(MARKER)
}

/// `org.freedesktop.portal.Background.RequestBackground`. Returns whether
/// autostart was granted (for `enable = false`, whether the call went
/// through: the portal then just removes the entry).
async fn request_background(enable: bool) -> Result<bool, String> {
    let conn = crate::dbus::session()
        .await
        .map_err(|e| format!("session bus unavailable: {e}"))?;

    // Subscribe before the call: the answer comes as a signal on a request
    // object, and a fast portal can send it before the call returns.
    let rule = format!(
        "type='signal',sender='{PORTAL_DEST}',interface='{REQUEST_IFACE}',member='Response'"
    );
    conn.call_method(
        Some("org.freedesktop.DBus"),
        "/org/freedesktop/DBus",
        Some("org.freedesktop.DBus"),
        "AddMatch",
        &(rule.as_str(),),
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut stream = MessageStream::from(&conn);

    let commandline = vec!["clavix", "--tray"];
    let mut options: HashMap<&str, Variant<'_>> = HashMap::new();
    options.insert(
        "reason",
        Variant::from("Start Clavix in the tray when you log in"),
    );
    options.insert("autostart", Variant::from(enable));
    options.insert("commandline", Variant::from(commandline));
    options.insert("dbus-activatable", Variant::from(false));

    let reply = conn
        .call_method(
            Some(PORTAL_DEST),
            PORTAL_PATH,
            Some("org.freedesktop.portal.Background"),
            "RequestBackground",
            &("", options),
        )
        .await
        .map_err(|e| format!("Background portal unavailable: {e}"))?;
    let handle: OwnedObjectPath = reply.body().deserialize().map_err(|e| e.to_string())?;

    let wait = async {
        while let Some(msg) = stream.next().await {
            let Ok(msg) = msg else { continue };
            let header = msg.header();
            if header.message_type() != MessageType::Signal
                || header.member().map(|m| m.as_str()) != Some("Response")
                || header.path().map(|p| p.as_str()) != Some(handle.as_str())
            {
                continue;
            }
            let (response, results): (u32, HashMap<String, OwnedVariant>) =
                msg.body().deserialize().map_err(|e| e.to_string())?;
            return Ok(response_granted(response, &results, enable));
        }
        Err("session bus closed while waiting for the portal".to_string())
    };
    tokio::time::timeout(RESPONSE_TIMEOUT, wait)
        .await
        .map_err(|_| "no answer from the Background portal".to_string())?
}

/// Response 0 is success; 1 cancelled, 2 other error. On success the
/// results say whether autostart was actually granted.
fn response_granted(response: u32, results: &HashMap<String, OwnedVariant>, enable: bool) -> bool {
    if response != 0 {
        return false;
    }
    if !enable {
        return true;
    }
    results
        .get("autostart")
        .and_then(|v| bool::try_from(v).ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn results(autostart: Option<bool>) -> HashMap<String, OwnedVariant> {
        let mut map = HashMap::new();
        map.insert("background".to_string(), OwnedVariant::from(true));
        if let Some(a) = autostart {
            map.insert("autostart".to_string(), OwnedVariant::from(a));
        }
        map
    }

    #[test]
    fn granted_only_when_the_portal_says_autostart_true() {
        assert!(response_granted(0, &results(Some(true)), true));
        assert!(!response_granted(0, &results(Some(false)), true));
        assert!(!response_granted(0, &results(None), true));
        assert!(!response_granted(1, &results(Some(true)), true));
    }

    #[test]
    fn disabling_succeeds_on_any_successful_response() {
        assert!(response_granted(0, &results(None), false));
        assert!(!response_granted(2, &results(None), false));
    }

    #[test]
    fn marker_tracks_the_recorded_state() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_enabled(dir.path()));
        std::fs::write(marker_path(dir.path()), b"").unwrap();
        assert!(is_enabled(dir.path()));
    }
}
