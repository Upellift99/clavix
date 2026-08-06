//! Clavix's vault engine: the Bitwarden/Vaultwarden protocol, the
//! cryptography under it, and the vault logic on top — with no window,
//! no tray, no IPC and no Tauri.
//!
//! The split exists so a second front end can be built on the same
//! engine rather than on a reimplementation of it. Nothing in here may
//! reach for a desktop affordance; anything that needs one (the SSH
//! agent socket, the USB security key, the tray, the auto-lock
//! watchdog, the screen-lock probe) belongs in the `clavix` crate that
//! depends on this one.
//!
//! The rule of thumb for adding a module here: it compiles for
//! `aarch64-apple-ios` and it would still make sense to a front end
//! that has no keyboard.

pub mod api;
pub mod audit;
pub mod cache;
pub mod crypto;
pub mod error;
pub mod models;
pub mod services;
pub mod session;
pub mod store;
pub mod strength;
pub mod time;
pub mod totp;

pub use error::{Error, Result};
