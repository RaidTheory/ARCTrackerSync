// Always use the GUI subsystem so no console window opens alongside the app.
// (If logs are needed for debugging, route tracing to a file instead.)
#![windows_subsystem = "windows"]

use arctracker_sync::{app, config, i18n, single_instance};

fn main() -> eframe::Result<()> {
    let _ = tracing_subscriber::fmt().try_init();

    // One window per session: if an instance is already running, wake its window
    // and exit instead of opening a second copy. The updater's freshly-installed
    // process passes `--relaunched` so it takes over from the exiting old one
    // rather than bouncing off it.
    let relaunched = std::env::args().any(|arg| arg == "--relaunched");
    let primary = match single_instance::acquire(relaunched) {
        single_instance::Acquisition::Primary(guard) => guard,
        single_instance::Acquisition::AlreadyRunning => {
            single_instance::signal_existing();
            return Ok(());
        }
    };

    // Resolve the display language before building the window so the title
    // (and any early strings) use the right locale. The app re-resolves and may
    // override this from persisted config inside `ArcTrackerSyncApp::new`.
    let config = config::load();
    let locale = i18n::resolve_locale(config.language.as_deref());
    i18n::set_active_locale(locale);

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([760.0, 500.0])
            .with_min_inner_size([700.0, 460.0])
            .with_icon(app_icon())
            .with_title(i18n::__translate("SyncApp.appName", &[])),
        ..Default::default()
    };

    // `primary` is moved into the app so it can spawn the listener once it has a
    // window handle and egui context; holding it keeps the named objects alive.
    let mut primary = Some(primary);
    eframe::run_native(
        "ARCTracker Sync",
        native_options,
        Box::new(move |cc| {
            let guard = primary.take().expect("app factory called once");
            Ok(Box::new(app::SharedArcTrackerSyncApp::new(cc, guard)))
        }),
    )
}

/// The ARC chevron mark as the window / taskbar icon, baked to raw RGBA by
/// `build.rs` from `assets/arc-mark.png`.
fn app_icon() -> eframe::egui::IconData {
    eframe::egui::IconData {
        rgba: include_bytes!(concat!(env!("OUT_DIR"), "/icon_256.rgba")).to_vec(),
        width: 256,
        height: 256,
    }
}
