//! The retirement screen: the only thing this final release of ARCTracker Sync
//! shows.
//!
//! ARC Tracker Link replaces ARCTracker Sync. `main.rs` runs [`RetiredApp`]
//! instead of the sync hub (`app::SharedArcTrackerSyncApp`), so none of the
//! hub's startup work runs: no network capture, no launcher preparation or game
//! process checks, no sign-in refresh or sync uploads, no firewall rule, no tray
//! and no self-update check. This is the last release, so there is nothing newer
//! for the updater to find. The hub code stays in the library untouched; it is
//! simply never started by the binary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eframe::egui::{self, Frame, Margin, RichText};

use crate::app::{
    apply_arc_theme, arc_bg, arc_foreground, arc_muted_text, arc_warning, card, primary_button,
    secondary_button,
};
use crate::auth_bridge;
use crate::fonts;
use crate::i18n;
use crate::single_instance;
use crate::tr;

/// Where ARC Tracker Link is downloaded.
pub const LINK_URL: &str = "https://arctracker.io/app#link";

pub struct RetiredApp {
    /// Why the browser could not be opened, shown under the buttons so the user
    /// can still reach the download by hand.
    open_error: Option<String>,
    /// Stops the single-instance listener thread when the app goes away.
    listener_stop: Arc<AtomicBool>,
}

impl RetiredApp {
    pub fn new(cc: &eframe::CreationContext<'_>, primary: single_instance::PrimaryGuard) -> Self {
        // `main` already chose the language (saved preference, else Windows).
        apply_arc_theme(&cc.egui_ctx);
        fonts::apply_locale(&cc.egui_ctx, &i18n::active_locale());

        // A retired app must not start with Windows (each start would show this screen and a UAC
        // prompt at every sign-in). A failure is logged; the screen still says to uninstall.
        if crate::tray::start_with_windows_enabled() {
            if let Err(error) = crate::tray::set_start_with_windows(false) {
                eprintln!("[retired] could not remove Start with Windows: {error:#}");
            }
        }

        // A second launch raises this window instead of opening another copy.
        let listener_stop = Arc::new(AtomicBool::new(false));
        let ctx = cc.egui_ctx.clone();
        primary.spawn_listener(listener_stop.clone(), move || {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
        });

        Self {
            open_error: None,
            listener_stop,
        }
    }

    fn open_link_download(&mut self) {
        self.open_error = match auth_bridge::open_browser(LINK_URL) {
            Ok(()) => None,
            Err(error) => {
                tracing::warn!("opening the ARC Tracker Link download failed: {error:#}");
                Some(tr!("SyncApp.retired.openFailed", url => LINK_URL))
            }
        };
    }
}

impl Drop for RetiredApp {
    fn drop(&mut self) {
        self.listener_stop.store(true, Ordering::Relaxed);
    }
}

impl eframe::App for RetiredApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(Frame::NONE.fill(arc_bg()).inner_margin(Margin::same(24)))
            .show(ctx, |ui| {
                card(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(tr!("SyncApp.retired.title"))
                            .size(22.0)
                            .strong()
                            .color(arc_foreground()),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(tr!("SyncApp.retired.body"))
                            .size(14.0)
                            .color(arc_muted_text()),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(tr!("SyncApp.retired.uninstall"))
                            .size(14.0)
                            .color(arc_muted_text()),
                    );
                    ui.add_space(18.0);
                    ui.horizontal(|ui| {
                        if primary_button(ui, &tr!("SyncApp.retired.getLink")) {
                            self.open_link_download();
                        }
                        if secondary_button(ui, &tr!("SyncApp.retired.quit")) {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    if let Some(error) = &self.open_error {
                        ui.add_space(10.0);
                        ui.label(RichText::new(error).size(13.0).color(arc_warning()));
                    }
                });
            });
    }
}

#[cfg(test)]
mod tests {
    use crate::i18n::UI_LOCALES;

    const RETIRED_KEYS: &[&str] = &[
        "SyncApp.retired.title",
        "SyncApp.retired.body",
        "SyncApp.retired.uninstall",
        "SyncApp.retired.getLink",
        "SyncApp.retired.quit",
        "SyncApp.retired.openFailed",
    ];

    /// Every locale carries its own retirement copy (rust-i18n would otherwise
    /// fall back to English without a word), keeps the `%{url}` placeholder and
    /// the product name, and uses no em dash.
    #[test]
    fn retired_copy_exists_in_every_locale() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
        for locale in UI_LOCALES {
            let path = dir.join(format!("{locale}.json"));
            let text = std::fs::read_to_string(&path).expect("locale file readable");
            let catalog: serde_json::Value = serde_json::from_str(&text).expect("locale is JSON");
            for key in RETIRED_KEYS {
                let value = catalog[key]
                    .as_str()
                    .unwrap_or_else(|| panic!("{locale} is missing {key}"));
                assert!(!value.trim().is_empty(), "{locale} has an empty {key}");
                assert!(
                    !value.contains('\u{2014}'),
                    "{locale} {key} uses an em dash"
                );
            }
            assert!(
                catalog["SyncApp.retired.openFailed"]
                    .as_str()
                    .is_some_and(|value| value.contains("%{url}")),
                "{locale} openFailed lost the %{{url}} placeholder"
            );
            assert!(
                catalog["SyncApp.retired.getLink"]
                    .as_str()
                    .is_some_and(|value| value.contains("ARC Tracker Link")),
                "{locale} getLink lost the product name"
            );
        }
    }
}
