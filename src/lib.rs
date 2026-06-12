//! Library surface for `arctracker-sync`.
//!
//! The production entry point is `main.rs`, but the app logic lives in this
//! library target so unit tests run without the Windows `requireAdministrator`
//! manifest embedded into the GUI executable.

// rust-i18n requires `i18n!` to be invoked at the crate root so the generated
// `_rust_i18n_t!` / `_rust_i18n_translate` items live at `crate::`, where the
// `t!` macro expects them. Catalogs are this app's own per-locale files in
// `locales/<locale>.json` (`_version: 1`); `en.json` is the source of truth.
rust_i18n::i18n!("locales", fallback = "en");

pub mod app;
pub mod auth_bridge;
pub mod capture;
pub mod capture_backend;
pub mod config;
pub mod credential_store;
pub mod elevation;
pub mod firewall;
pub mod fonts;
pub mod i18n;
pub mod launch;
pub mod npcap;
pub mod packet;
pub mod process_env;
pub mod rawsock;
pub mod single_instance;
pub mod sync_client;
pub mod theme;
pub mod token;
pub mod tray;
pub mod updater;
pub mod widgets;
