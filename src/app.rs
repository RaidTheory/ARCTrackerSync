use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, CornerRadius, Frame, Margin, RichText, Stroke, Vec2};

use crate::auth_bridge;
use crate::capture::{self, CaptureEvent, CaptureHandle, CaptureStats, InterfaceInfo};
use crate::config::{self, AppConfig};
use crate::credential_store;
use crate::elevation;
use crate::fonts;
use crate::i18n;
use crate::launch::{self, LauncherPlatform, LauncherStatus};
use crate::single_instance;
use crate::sync_client::{self, SubmitError, SubmitResponse, BASE_URL};
use crate::token::TokenObservation;
use crate::tr;
use crate::tray::{self, TrayCommand, TrayCommandHandler, TrayController};
use crate::updater::{self, InstallProgress, ReleaseInfo};

type AuthResult = Result<String, String>;
type SubmitResult = Result<(String, SubmitResponse), SubmitError>;
type RefreshResult = Result<String, SubmitError>;

/// ARC Raiders processes — used to detect whether the user is playing. The Steam
/// launcher runs as `PioneerGame.exe`; once it hands off, the running game is
/// `PioneerGame-e.exe` (EAC) or `PioneerGame-d.exe`.
const GAME_PROCESS_NAMES: &[&str] = &["PioneerGame.exe", "PioneerGame-e.exe", "PioneerGame-d.exe"];
/// General help / troubleshooting destination.
const HELP_URL: &str = "https://arctracker.io/help/sync";
/// Refresh the bridge token when fewer than this many days remain.
const REFRESH_THRESHOLD_DAYS: i64 = 7;
/// How often to proactively refresh the bridge token while running.
const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How often to check GitHub for a newer release while running (a check also
/// runs once on startup). The 750ms worker loop only *notices* this interval
/// elapsing — it never makes a network call every tick.
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The single adaptive hub state (spec §4). The hero card is a pure function of
/// this value; it is recomputed every frame from the app's booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HubState {
    NeedsAdmin,
    SignedOut,
    SigningIn,
    SelectGame,
    PrepareLauncher,
    PreparingLauncher,
    CloseLauncher,
    LauncherReady,
    Connecting,
    Updating,
    Synced,
    SyncedIdle,
    NeedsLauncher,
    NeedsAttention,
}

/// Which screen the window is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Hub,
    Settings,
}

/// Lifecycle of the in-app self-updater, driving the header pill and the
/// changelog/install dialog. The release details themselves live in
/// `current_release`; this enum only tracks where in the flow we are.
#[derive(Debug, Clone)]
enum UpdateState {
    /// No newer release known (or we're between checks).
    Idle,
    /// A newer release is available; the pill is shown and the dialog offers it.
    Available,
    /// Downloading the release package.
    Downloading { received: u64, total: Option<u64> },
    /// Validating the download.
    Verifying,
    /// Swapping the executable in place.
    Installing,
    /// Install done; relaunching on the new version.
    Relaunching,
    /// Download/verify/install failed; the dialog shows the reason + Retry.
    Failed(String),
}

pub struct SharedArcTrackerSyncApp {
    inner: Arc<Mutex<ArcTrackerSyncApp>>,
}

impl SharedArcTrackerSyncApp {
    pub fn new(cc: &eframe::CreationContext<'_>, primary: single_instance::PrimaryGuard) -> Self {
        let app = Arc::new(Mutex::new(ArcTrackerSyncApp::new(cc)));
        {
            let weak = Arc::downgrade(&app);
            app.lock()
                .expect("app mutex poisoned during tray init")
                .init_tray(weak, cc.egui_ctx.clone());
        }
        Self::start_background_worker(&app, cc.egui_ctx.clone());
        Self::start_single_instance_listener(&app, cc.egui_ctx.clone(), primary);
        Self { inner: app }
    }

    /// Listen for a second launch waking us, and raise the window when it does.
    /// Reuses the tray "Open" path so behavior is identical to the tray menu
    /// (switch to the hub and bring the window to the foreground).
    fn start_single_instance_listener(
        app: &Arc<Mutex<ArcTrackerSyncApp>>,
        ctx: egui::Context,
        primary: single_instance::PrimaryGuard,
    ) {
        let weak = Arc::downgrade(app);
        let stop = app
            .lock()
            .expect("app mutex poisoned during single-instance init")
            .waker_stop
            .clone();

        primary.spawn_listener(stop, move || {
            if let Some(app) = weak.upgrade() {
                if let Ok(mut app) = app.lock() {
                    app.handle_tray_command(TrayCommand::Open);
                }
            }
            ctx.request_repaint();
        });
    }

    fn start_background_worker(app: &Arc<Mutex<ArcTrackerSyncApp>>, ctx: egui::Context) {
        let weak = Arc::downgrade(app);
        let stop = app
            .lock()
            .expect("app mutex poisoned during background init")
            .waker_stop
            .clone();

        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(750));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Some(app) = weak.upgrade() else {
                break;
            };
            if let Ok(mut app) = app.lock() {
                app.run_background_work();
            } else {
                break;
            }
            ctx.request_repaint();
        });
    }
}

#[derive(Clone, Copy)]
struct WindowControl {
    #[cfg(windows)]
    hwnd: isize,
}

impl WindowControl {
    #[cfg(windows)]
    fn from_creation_context(cc: &eframe::CreationContext<'_>) -> Option<Self> {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};

        match cc.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(handle) => Some(Self {
                hwnd: handle.hwnd.get(),
            }),
            _ => None,
        }
    }

    #[cfg(not(windows))]
    fn from_creation_context(_cc: &eframe::CreationContext<'_>) -> Option<Self> {
        None
    }

    fn show_and_focus(&self) {
        #[cfg(windows)]
        unsafe {
            const SW_SHOW: i32 = 5;
            const SW_RESTORE: i32 = 9;

            ShowWindowAsync(self.hwnd, SW_RESTORE);
            ShowWindowAsync(self.hwnd, SW_SHOW);
            SetForegroundWindow(self.hwnd);
        }
    }
}

#[cfg(windows)]
#[link(name = "User32")]
extern "system" {
    fn ShowWindowAsync(hwnd: isize, ncmdshow: i32) -> i32;
    fn SetForegroundWindow(hwnd: isize) -> i32;
}

pub struct ArcTrackerSyncApp {
    config: AppConfig,
    locale: String,
    screen: Screen,
    show_activity_log: bool,
    show_explainer: bool,

    interfaces: Vec<InterfaceInfo>,
    selected_interface_index: usize,
    sync_key_source: Option<launch::SyncKeySource>,
    launcher_readiness: launch::LauncherReadiness,
    last_launcher_check: Instant,
    force_close_available: bool,
    preparing_launcher: bool,
    launcher_was_ready: bool,
    /// Stores with ARC Raiders installed, detected once at startup. Gate the
    /// hub's Steam|Epic toggle so it only offers a launcher the user actually has.
    detected_steam: bool,
    detected_epic_exe: Option<PathBuf>,
    game_path_text: String,
    game_running: bool,
    last_game_check: Instant,

    capture: Option<CaptureHandle>,
    capture_blocked: bool,
    stats: CaptureStats,
    latest_token: Option<TokenObservation>,
    auth_token: Option<String>,
    account_name: Option<String>,
    last_synced_label: Option<String>,

    auth_rx: Option<Receiver<AuthResult>>,
    submit_rx: Option<Receiver<SubmitResult>>,
    refresh_rx: Option<Receiver<RefreshResult>>,
    last_refresh_attempt: Instant,
    refresh_after_unauthorized: bool,

    /// True after at least one successful game-account sync this session.
    token_submitted: bool,
    /// Fingerprint of the latest captured game token that was successfully
    /// submitted. This is separate from `token_submitted` so token rotation can
    /// be posted quietly without resetting the user-facing synced state.
    submitted_token_fingerprint: Option<String>,
    sync_enabled: bool,
    messages: Vec<String>,

    tray: Option<TrayController>,
    tray_tooltip: String,
    sync_paused: bool,
    pending_close: bool,
    /// Set when a graceful quit is in progress: the next `update()` drains
    /// finished work, stops capture, and asks eframe to close.
    pending_quit: bool,
    /// Shared stop flag for the background worker; flipped during graceful
    /// shutdown so the loop breaks instead of running forever.
    waker_stop: Arc<AtomicBool>,
    window_control: Option<WindowControl>,

    update_state: UpdateState,
    current_release: Option<ReleaseInfo>,
    show_update_modal: bool,
    update_check_rx: Option<Receiver<Result<ReleaseInfo, String>>>,
    update_progress_rx: Option<Receiver<InstallProgress>>,
    update_done_rx: Option<Receiver<Result<(), String>>>,
    last_update_check: Instant,
}

impl ArcTrackerSyncApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut config = config::load();
        // Which stores actually have ARC Raiders installed (one scan, reused for
        // first-run auto-select below and the hub's Steam|Epic toggle).
        let (detected_steam, detected_epic_exe) = launch::detect_installed_launchers();
        // First run with no explicit launcher choice: pick the store that has the
        // game so the hub immediately speaks the right launcher's name (and Epic
        // owners skip the manual file picker). Steam first — it launches by app id
        // with no exe path. An explicit Settings choice is respected (only `Auto`).
        if config.platform == LauncherPlatform::Auto && config.game_executable_path.is_none() {
            if detected_steam {
                config.platform = LauncherPlatform::Steam;
                let _ = config::save(&config);
            } else if let Some(exe) = detected_epic_exe.clone() {
                config.platform = LauncherPlatform::Epic;
                config.game_executable_path = Some(exe);
                let _ = config::save(&config);
            }
        }
        let locale = i18n::resolve_locale(config.language.as_deref()).to_string();
        i18n::set_active_locale(&locale);

        apply_arc_theme(&cc.egui_ctx);
        fonts::apply_locale(&cc.egui_ctx, &locale);

        // Shared stop flag for the background worker. The worker owns hidden-tray
        // maintenance because eframe may stop calling update() for hidden windows.
        let waker_stop = Arc::new(AtomicBool::new(false));
        let window_control = WindowControl::from_creation_context(cc);

        let sync_key_result = launch::resolve_current_sync_key_source();
        let game_path_text = config
            .game_executable_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default();

        let (auth_token, auth_message) = match credential_store::load_auth_token() {
            Ok(Some(token)) if auth_bridge::token_is_current(&token) => {
                (Some(token), Some("Sign-in restored.".to_string()))
            }
            Ok(Some(token)) => {
                let _ = credential_store::clear_auth_token();
                let detail = match auth_bridge::token_days_remaining(&token) {
                    Some(days) => {
                        format!("Saved sign-in not current ({days} days left). Sign in again.")
                    }
                    None => "Saved sign-in couldn't be read. Sign in again.".to_string(),
                };
                (None, Some(detail))
            }
            Ok(None) => (None, Some("No saved sign-in found.".to_string())),
            Err(error) => (
                None,
                Some(format!("Could not read saved sign-in: {error:#}")),
            ),
        };

        let launcher_readiness = sync_key_result
            .as_ref()
            .ok()
            .map(|source| {
                launch::launcher_readiness(
                    config.platform,
                    config.game_executable_path.as_deref(),
                    &source.path,
                )
            })
            .unwrap_or_else(|| launch::LauncherReadiness {
                platform: launch::resolve_platform(
                    config.platform,
                    config.game_executable_path.as_deref(),
                ),
                status: LauncherStatus::Unknown,
                process_count: 0,
                detail: "Launch setup unavailable".to_string(),
            });

        let launcher_was_ready = launcher_readiness.status == LauncherStatus::Ready;

        let mut app = Self {
            config,
            locale,
            screen: Screen::Hub,
            show_activity_log: false,
            show_explainer: false,
            interfaces: Vec::new(),
            selected_interface_index: 0,
            sync_key_source: sync_key_result.as_ref().ok().cloned(),
            launcher_readiness,
            last_launcher_check: Instant::now(),
            force_close_available: false,
            preparing_launcher: false,
            launcher_was_ready,
            detected_steam,
            detected_epic_exe,
            game_path_text,
            game_running: false,
            last_game_check: Instant::now()
                .checked_sub(Duration::from_secs(10))
                .unwrap_or_else(Instant::now),
            capture: None,
            capture_blocked: false,
            stats: CaptureStats::default(),
            latest_token: None,
            auth_token,
            account_name: None,
            last_synced_label: None,
            auth_rx: None,
            submit_rx: None,
            refresh_rx: None,
            last_refresh_attempt: Instant::now(),
            refresh_after_unauthorized: false,
            token_submitted: false,
            submitted_token_fingerprint: None,
            sync_enabled: false,
            messages: Vec::new(),
            tray: None,
            tray_tooltip: tray::tooltip_for(None),
            sync_paused: false,
            pending_close: false,
            pending_quit: false,
            waker_stop,
            window_control,
            update_state: UpdateState::Idle,
            current_release: None,
            show_update_modal: false,
            update_check_rx: None,
            update_progress_rx: None,
            update_done_rx: None,
            // Backdated so the first worker tick triggers a check immediately.
            last_update_check: Instant::now()
                .checked_sub(UPDATE_CHECK_INTERVAL)
                .unwrap_or_else(Instant::now),
        };

        match sync_key_result {
            Ok(source) => app.push_message(source.label().to_string()),
            Err(error) => app.push_message(format!("Local sync setup unavailable: {error:#}")),
        }
        if let Some(message) = auth_message {
            app.push_message(message);
        }

        // Trust the actual HKCU Run entry for the toggle's displayed state.
        let registered = tray::start_with_windows_enabled();
        if registered != app.config.start_with_windows {
            app.config.start_with_windows = registered;
            app.save_config();
        }

        app.refresh_game_running();
        app.refresh_interfaces();
        app.maybe_refresh_auth_on_launch();
        app
    }

    // ----- tray / window lifecycle -------------------------------------------------

    fn init_tray(&mut self, app: Weak<Mutex<ArcTrackerSyncApp>>, ctx: egui::Context) {
        let handler: TrayCommandHandler = Arc::new(move |command| {
            let Some(app) = app.upgrade() else {
                return;
            };
            let Ok(mut app) = app.lock() else {
                return;
            };
            app.handle_tray_command(command);
            ctx.request_repaint();
        });

        match TrayController::new(&self.tray_tooltip, handler) {
            Ok(controller) => self.tray = Some(controller),
            Err(error) => self.push_message(format!("Tray unavailable: {error:#}")),
        }
    }

    fn handle_tray_command(&mut self, command: TrayCommand) {
        match command {
            TrayCommand::Open => {
                self.screen = Screen::Hub;
                if let Some(window) = self.window_control {
                    window.show_and_focus();
                }
            }
            TrayCommand::TogglePause => self.toggle_sync_paused(),
            TrayCommand::SignOut => self.sign_out(),
            TrayCommand::Quit => self.quit_from_tray(),
        }
    }

    fn handle_close_request(&mut self, ctx: &egui::Context) {
        let close_requested = ctx.input(|input| input.viewport().close_requested());
        if !close_requested {
            return;
        }

        if self.config.keep_in_tray && self.tray.is_some() && !self.pending_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    fn hide_to_tray(&self, ctx: &egui::Context) {
        if self.tray.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    /// Fully quit — reliable from both the tray menu and the in-app button.
    /// Routes through the graceful shutdown path so Drop runs (capture stops,
    /// the tray icon is removed) and any just-finished work is persisted.
    fn quit(&mut self) {
        self.begin_graceful_quit();
    }

    /// Flag a graceful shutdown; `update()` completes it next frame when the UI
    /// is visible. Tray quit uses `quit_from_tray` because hidden windows may not
    /// receive another redraw.
    fn begin_graceful_quit(&mut self) {
        self.pending_quit = true;
        self.waker_stop.store(true, Ordering::Relaxed);
    }

    fn quit_from_tray(&mut self) {
        self.poll_submit();
        self.poll_refresh();
        self.shutdown_cleanup();
        std::process::exit(0);
    }

    fn shutdown_cleanup(&mut self) {
        self.waker_stop.store(true, Ordering::Relaxed);
        if let Some(capture) = self.capture.take() {
            capture.stop();
            drop(capture);
        }
        crate::firewall::remove_capture_rule();
        let _ = config::clear_app_owned_sync_key();
    }

    fn toggle_sync_paused(&mut self) {
        self.sync_paused = !self.sync_paused;
        if self.sync_paused {
            if let Some(capture) = self.capture.take() {
                capture.stop();
                drop(capture);
            }
        } else {
            self.maybe_start_background_capture();
        }
        if let Some(tray) = self.tray.as_mut() {
            tray.set_paused(self.sync_paused);
        }
    }

    fn update_tray_tooltip(&mut self) {
        let tooltip = if self.token_submitted {
            tray::tooltip_for(self.account_name.as_deref())
        } else {
            tray::tooltip_for(None)
        };
        if tooltip != self.tray_tooltip {
            self.tray_tooltip = tooltip.clone();
            if let Some(tray) = self.tray.as_ref() {
                tray.set_tooltip(&tooltip);
            }
        }
    }

    // ----- locale ------------------------------------------------------------------

    fn change_language(&mut self, ctx: &egui::Context, language: Option<String>) {
        let resolved = i18n::resolve_locale(language.as_deref()).to_string();
        if resolved == self.locale && language == self.config.language {
            return;
        }
        self.config.language = language;
        self.save_config();
        self.locale = resolved;
        i18n::set_active_locale(&self.locale);
        fonts::apply_locale(ctx, &self.locale);
        self.tray_tooltip = String::new();
        self.update_tray_tooltip();
    }

    // ----- silent refresh ----------------------------------------------------------

    fn maybe_refresh_auth_on_launch(&mut self) {
        let Some(token) = self.auth_token.clone() else {
            return;
        };
        if auth_bridge::token_days_remaining(&token)
            .map(|days| days < REFRESH_THRESHOLD_DAYS)
            .unwrap_or(true)
        {
            self.start_refresh(token);
        }
    }

    fn maybe_refresh_auth_on_timer(&mut self) {
        if self.refresh_rx.is_some() || self.auth_token.is_none() {
            return;
        }
        if self.last_refresh_attempt.elapsed() >= REFRESH_INTERVAL {
            if let Some(token) = self.auth_token.clone() {
                self.start_refresh(token);
            }
        }
    }

    fn run_background_work(&mut self) {
        if self.pending_quit {
            return;
        }

        self.poll_auth();
        self.poll_capture();
        self.poll_submit();
        self.poll_refresh();
        self.refresh_launcher_readiness_if_needed();
        self.refresh_game_running_if_needed();
        self.maybe_refresh_auth_on_timer();
        self.maybe_check_for_update();
        self.poll_update_check();
        self.poll_update_install();
        if !self.sync_paused {
            self.maybe_start_background_capture();
        }
        self.update_tray_tooltip();
    }

    // ----- self-update -------------------------------------------------------------

    /// Whether the header "update available" pill should show: any time there's
    /// something to act on (available, installing, or a failure to retry).
    fn update_indicator_visible(&self) -> bool {
        !matches!(self.update_state, UpdateState::Idle)
    }

    /// Kick off a background release check, throttled to `UPDATE_CHECK_INTERVAL`.
    /// No-ops while a check/install is in flight or an update is already known,
    /// so it only re-checks from `Idle` (or after a failed attempt).
    fn maybe_check_for_update(&mut self) {
        if self.update_check_rx.is_some() || self.update_progress_rx.is_some() {
            return;
        }
        if !matches!(
            self.update_state,
            UpdateState::Idle | UpdateState::Failed(_)
        ) {
            return;
        }
        if self.last_update_check.elapsed() < UPDATE_CHECK_INTERVAL {
            return;
        }
        self.last_update_check = Instant::now();
        let (tx, rx) = mpsc::channel();
        self.update_check_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send(updater::fetch_latest());
        });
    }

    fn poll_update_check(&mut self) {
        let Some(rx) = self.update_check_rx.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(release)) => {
                if updater::is_newer(&release.version) {
                    self.current_release = Some(release);
                    self.update_state = UpdateState::Available;
                }
                // Already current: stay Idle and check again next interval.
            }
            Ok(Err(error)) => {
                // A failed check is routine (offline, rate-limited) — log quietly
                // and retry next cycle rather than surfacing it to the user.
                tracing::debug!(error = %error, "update check failed");
            }
            Err(mpsc::TryRecvError::Empty) => self.update_check_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {}
        }
    }

    fn start_update_install(&mut self, release: ReleaseInfo) {
        if self.update_progress_rx.is_some() {
            return;
        }
        self.update_state = UpdateState::Downloading {
            received: 0,
            total: Some(release.size).filter(|n| *n > 0),
        };
        let (progress_tx, progress_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        self.update_progress_rx = Some(progress_rx);
        self.update_done_rx = Some(done_rx);
        thread::spawn(move || {
            let result = updater::download_and_install(&release, |progress| {
                let _ = progress_tx.send(progress);
            });
            let _ = done_tx.send(result);
        });
    }

    fn poll_update_install(&mut self) {
        if let Some(rx) = self.update_progress_rx.as_ref() {
            // Coalesce buffered progress; only the latest matters for rendering.
            let mut latest = None;
            while let Ok(progress) = rx.try_recv() {
                latest = Some(progress);
            }
            if let Some(progress) = latest {
                self.update_state = match progress {
                    InstallProgress::Downloading { received, total } => {
                        UpdateState::Downloading { received, total }
                    }
                    InstallProgress::Verifying => UpdateState::Verifying,
                    InstallProgress::Installing => UpdateState::Installing,
                };
            }
        }

        let Some(rx) = self.update_done_rx.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(())) => {
                self.update_progress_rx = None;
                self.update_state = UpdateState::Relaunching;
                match updater::relaunch() {
                    Ok(()) => {
                        // Hand off to the new version: stop capture cleanly (Drop
                        // won't run after exit) and quit so the child takes over.
                        self.shutdown_cleanup();
                        std::process::exit(0);
                    }
                    Err(error) => {
                        self.push_message(
                            "Update installed, but the app couldn't restart automatically."
                                .to_string(),
                        );
                        self.update_state = UpdateState::Failed(error);
                    }
                }
            }
            Ok(Err(error)) => {
                self.update_progress_rx = None;
                self.push_message("Update could not be installed.".to_string());
                self.update_state = UpdateState::Failed(error);
            }
            Err(mpsc::TryRecvError::Empty) => self.update_done_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.update_progress_rx = None;
                self.update_state =
                    UpdateState::Failed("The update stopped unexpectedly.".to_string());
            }
        }
    }

    fn start_refresh(&mut self, token: String) {
        if self.refresh_rx.is_some() {
            return;
        }
        self.last_refresh_attempt = Instant::now();
        let (tx, rx) = mpsc::channel();
        self.refresh_rx = Some(rx);
        thread::spawn(move || {
            let result = sync_client::submit_refresh(&token);
            let _ = tx.send(result);
        });
    }

    fn poll_refresh(&mut self) {
        let Some(rx) = self.refresh_rx.take() else {
            return;
        };

        match rx.try_recv() {
            Ok(Ok(token)) => {
                if let Err(error) = credential_store::save_auth_token(&token) {
                    self.push_message(format!("Could not remember ARCTracker sign-in: {error:#}"));
                }
                self.auth_token = Some(token);
                if self.refresh_after_unauthorized {
                    self.refresh_after_unauthorized = false;
                    self.submit_latest_token_if_ready();
                }
            }
            Ok(Err(error)) => {
                if self.refresh_after_unauthorized {
                    // The refresh genuinely failed (expired/revoked) — only now sign out.
                    self.refresh_after_unauthorized = false;
                    self.clear_auth_session();
                }
                self.push_message(error.to_string());
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.refresh_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                if self.refresh_after_unauthorized {
                    self.refresh_after_unauthorized = false;
                    self.clear_auth_session();
                }
            }
        }
    }

    // ----- state machine -----------------------------------------------------------

    /// Raw-socket capture needs Administrator to read inbound traffic.
    fn capture_ready(&self) -> bool {
        elevation::is_elevated()
    }

    fn hub_state(&self) -> HubState {
        if !self.capture_ready() {
            return HubState::NeedsAdmin;
        }
        // A pending sign-in takes precedence over SignedOut — during sign-in the
        // token isn't stored yet, so `auth_token` is still None.
        if self.auth_rx.is_some() {
            return HubState::SigningIn;
        }
        if self.auth_token.is_none() {
            return HubState::SignedOut;
        }
        if self.capture_blocked {
            return HubState::NeedsAttention;
        }
        if self.token_submitted {
            return if self.game_running {
                HubState::Synced
            } else {
                HubState::SyncedIdle
            };
        }
        if self.submit_rx.is_some() {
            return HubState::Updating;
        }
        // Epic (and Direct) need a known game executable before we can prepare
        // the launcher; surface the picker when one is required but missing.
        if !self.game_ready_for_platform() {
            return HubState::SelectGame;
        }
        if self.force_close_available {
            return HubState::CloseLauncher;
        }
        if self.preparing_launcher {
            return HubState::PreparingLauncher;
        }

        if self.launcher_ready() {
            return if self.game_running || self.latest_token.is_some() {
                HubState::Connecting
            } else {
                HubState::LauncherReady
            };
        }

        // Launcher not ready. If it was prepared earlier this session and lost
        // that state, surface the dedicated "needs preparing again" copy.
        if self.launcher_was_ready {
            HubState::NeedsLauncher
        } else {
            HubState::PrepareLauncher
        }
    }

    /// Title + body for the current state, fully localized.
    fn hub_copy(&self, state: HubState) -> (String, String) {
        let account = self.account_name.clone().unwrap_or_default();
        let time = self.last_synced_label.clone().unwrap_or_default();
        match state {
            HubState::NeedsAdmin => (
                tr!("SyncApp.state.needsAdmin.title"),
                tr!("SyncApp.state.needsAdmin.body"),
            ),
            HubState::SignedOut => (
                tr!("SyncApp.state.signedOut.title"),
                tr!("SyncApp.state.signedOut.body"),
            ),
            HubState::SigningIn => (
                tr!("SyncApp.state.signingIn.title"),
                tr!("SyncApp.state.signingIn.body"),
            ),
            HubState::SelectGame => (
                tr!("SyncApp.state.selectGame.title"),
                tr!("SyncApp.state.selectGame.body", launcher => self.effective_platform().label()),
            ),
            HubState::PrepareLauncher => (
                tr!("SyncApp.state.prepareLauncher.title", launcher => self.effective_platform().label()),
                tr!("SyncApp.state.prepareLauncher.body", launcher => self.effective_platform().label()),
            ),
            HubState::PreparingLauncher => (
                tr!("SyncApp.state.preparingLauncher.title", launcher => self.effective_platform().label()),
                tr!("SyncApp.state.preparingLauncher.body", launcher => self.effective_platform().label()),
            ),
            HubState::CloseLauncher => (
                tr!("SyncApp.state.closeLauncher.title", launcher => self.effective_platform().label()),
                tr!("SyncApp.state.closeLauncher.body", launcher => self.effective_platform().label()),
            ),
            HubState::LauncherReady => (
                tr!("SyncApp.state.launcherReady.title", launcher => self.effective_platform().label()),
                tr!("SyncApp.state.launcherReady.body", launcher => self.effective_platform().label()),
            ),
            HubState::Connecting => (
                tr!("SyncApp.state.connecting.title"),
                tr!("SyncApp.state.connecting.body"),
            ),
            HubState::Updating => (
                tr!("SyncApp.state.updating.title"),
                tr!("SyncApp.state.updating.body"),
            ),
            HubState::Synced => (
                tr!("SyncApp.state.synced.title"),
                tr!("SyncApp.state.synced.body", account => account, time => time),
            ),
            HubState::SyncedIdle => (
                tr!("SyncApp.state.synced.title"),
                tr!("SyncApp.state.syncedIdle.body"),
            ),
            HubState::NeedsLauncher => (
                tr!("SyncApp.state.needsLauncher.title", launcher => self.effective_platform().label()),
                tr!("SyncApp.state.needsLauncher.body", launcher => self.effective_platform().label()),
            ),
            HubState::NeedsAttention => (
                tr!("SyncApp.state.needsAttention.title"),
                tr!("SyncApp.state.needsAttention.body"),
            ),
        }
    }

    /// Local "HH:MM" that the current Embark session stays synced until, decoded
    /// from the captured token's `exp`. `None` if there's no live token (or it
    /// has already expired).
    fn session_expiry_label(&self) -> Option<String> {
        let exp = self.latest_token.as_ref()?.expires_at()?;
        let now = chrono::Local::now();
        // Only surface a genuinely-future expiry; a near-now value is just the
        // current token about to rotate and reads as "expires right now".
        if exp <= now + chrono::Duration::minutes(2) {
            return None;
        }
        let format = if exp.date_naive() == now.date_naive() {
            "%H:%M"
        } else {
            "%b %-d, %H:%M"
        };
        Some(exp.format(format).to_string())
    }

    fn state_accent(state: HubState) -> Color32 {
        match state {
            HubState::Synced | HubState::SyncedIdle => arc_success(),
            HubState::NeedsAttention | HubState::NeedsLauncher | HubState::CloseLauncher => {
                arc_warning()
            }
            _ => arc_primary(),
        }
    }

    /// The 4-stage progress strip status (done / current / pending).
    fn progress_stages(&self, state: HubState) -> [(String, StageState); 4] {
        let signed_in = self.auth_token.is_some();
        let steam_ready = self.launcher_ready();
        let playing = self.game_running || self.latest_token.is_some();
        let synced = self.token_submitted;

        let signed = stage(
            signed_in,
            matches!(state, HubState::SignedOut | HubState::SigningIn),
        );
        let steam = if !signed_in {
            StageState::Pending
        } else {
            stage(
                steam_ready,
                matches!(
                    state,
                    HubState::SelectGame
                        | HubState::PrepareLauncher
                        | HubState::PreparingLauncher
                        | HubState::CloseLauncher
                        | HubState::NeedsLauncher
                ),
            )
        };
        let play = if !steam_ready {
            StageState::Pending
        } else {
            stage(
                playing,
                matches!(state, HubState::LauncherReady | HubState::Connecting),
            )
        };
        let sync = if !playing {
            StageState::Pending
        } else {
            stage(synced, matches!(state, HubState::Updating))
        };

        [
            (tr!("SyncApp.progress.signedIn"), signed),
            (tr!("SyncApp.progress.launcherReady"), steam),
            (tr!("SyncApp.progress.playing"), play),
            (tr!("SyncApp.progress.synced"), sync),
        ]
    }

    // ----- existing wiring (preserved) ---------------------------------------------

    fn refresh_interfaces(&mut self) {
        let previous_name = self.selected_interface().map(|iface| iface.name.clone());
        let mut scan_succeeded = false;

        match capture::list_interfaces() {
            Ok(interfaces) => {
                scan_succeeded = true;
                self.interfaces = interfaces;
                let remembered_index =
                    self.config.selected_interface.as_ref().and_then(|name| {
                        self.interfaces.iter().position(|iface| &iface.name == name)
                    });
                self.selected_interface_index = remembered_index
                    .or_else(|| self.best_interface_index())
                    .unwrap_or(0);
            }
            Err(error) => {
                if let Some(capture) = self.capture.take() {
                    capture.stop();
                    drop(capture);
                }
                self.interfaces.clear();
                self.selected_interface_index = 0;
                self.capture_blocked = true;
                self.stats = CaptureStats::default();
                self.push_message(format!("Connection setup failed: {error:#}"));
            }
        }

        let current_name = self.selected_interface().map(|iface| iface.name.clone());
        if scan_succeeded && previous_name != current_name {
            self.capture_settings_changed();
        }
    }

    fn refresh_sync_key_source(&mut self) {
        let previous = self.sync_key_source.clone();

        match launch::resolve_current_sync_key_source() {
            Ok(source) => {
                if previous.as_ref() == Some(&source) {
                    return;
                }
                self.sync_key_source = Some(source.clone());
                self.push_message(source.label().to_string());
                self.capture_settings_changed();
            }
            Err(error) => {
                self.sync_key_source = None;
                self.capture_settings_changed();
                self.push_message(format!("Local sync setup unavailable: {error:#}"));
            }
        }
        self.refresh_launcher_readiness();
    }

    fn refresh_launcher_readiness(&mut self) {
        if let Some(path) = self.active_sync_key_path() {
            self.launcher_readiness = launch::launcher_readiness(
                self.config.platform,
                self.selected_game_path().as_deref(),
                &path,
            );
        } else {
            self.launcher_readiness = launch::LauncherReadiness {
                platform: self.effective_platform(),
                status: LauncherStatus::Unknown,
                process_count: 0,
                detail: "Launch setup unavailable".to_string(),
            };
        }
        if self.launcher_ready() {
            self.launcher_was_ready = true;
        }
        self.last_launcher_check = Instant::now();
    }

    fn refresh_launcher_readiness_if_needed(&mut self) {
        if self.last_launcher_check.elapsed() >= Duration::from_secs(2) {
            self.refresh_launcher_readiness();
        }
    }

    fn refresh_game_running(&mut self) {
        self.game_running = GAME_PROCESS_NAMES.iter().any(|name| {
            crate::process_env::find_processes(name)
                .map(|processes| !processes.is_empty())
                .unwrap_or(false)
        });
        self.last_game_check = Instant::now();
    }

    fn refresh_game_running_if_needed(&mut self) {
        if self.last_game_check.elapsed() >= Duration::from_secs(3) {
            self.refresh_game_running();
        }
    }

    fn selected_interface(&self) -> Option<&InterfaceInfo> {
        self.interfaces.get(self.selected_interface_index)
    }

    fn active_sync_key_path(&self) -> Option<PathBuf> {
        self.sync_key_source
            .as_ref()
            .map(|source| source.path.clone())
    }

    fn effective_platform(&self) -> LauncherPlatform {
        launch::resolve_platform(self.config.platform, self.selected_game_path().as_deref())
    }

    /// Whether `state` is part of the launcher-prep phase, where offering a quick
    /// Steam|Epic switch makes sense.
    fn is_launcher_phase(state: HubState) -> bool {
        matches!(
            state,
            HubState::SelectGame
                | HubState::PrepareLauncher
                | HubState::NeedsLauncher
                | HubState::LauncherReady
        )
    }

    /// The launcher the toggle would switch *to*, if a Steam|Epic switch should be
    /// offered: the current platform is Steam/Epic and the other store also has the
    /// game installed. `None` hides the toggle (single-store users get no dead
    /// option; `Direct` is never offered a toggle).
    fn launcher_switch_target(&self) -> Option<LauncherPlatform> {
        match self.effective_platform() {
            LauncherPlatform::Steam if self.detected_epic_exe.is_some() => {
                Some(LauncherPlatform::Epic)
            }
            LauncherPlatform::Epic if self.detected_steam => Some(LauncherPlatform::Steam),
            _ => None,
        }
    }

    /// Right-aligned Steam|Epic segmented toggle for the hero card. The active
    /// segment is the current launcher; clicking the other switches to it.
    fn launcher_toggle(&mut self, ui: &mut egui::Ui) {
        let current = self.effective_platform();
        let mut switch_to = None;
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            // right_to_left adds trailing-first, so place Epic then Steam to read
            // "Steam | Epic" left-to-right.
            if launcher_segment(
                ui,
                LauncherPlatform::Epic.label(),
                current == LauncherPlatform::Epic,
            ) {
                switch_to = Some(LauncherPlatform::Epic);
            }
            if launcher_segment(
                ui,
                LauncherPlatform::Steam.label(),
                current == LauncherPlatform::Steam,
            ) {
                switch_to = Some(LauncherPlatform::Steam);
            }
        });
        if let Some(platform) = switch_to.filter(|p| *p != current) {
            self.set_launcher(platform);
        }
    }

    fn game_ready_for_platform(&self) -> bool {
        matches!(self.effective_platform(), LauncherPlatform::Steam) || self.game_path_is_valid()
    }

    fn launcher_ready(&self) -> bool {
        self.launcher_readiness.status == LauncherStatus::Ready
            || self.effective_platform() == LauncherPlatform::Direct
    }

    fn selected_setup_plan(&self) -> Result<launch::LauncherSetupPlan, String> {
        let Some(source) = self.sync_key_source.clone() else {
            return Err("Launch setup unavailable".to_string());
        };

        launch::LauncherSetupPlan::build(
            self.config.platform,
            self.selected_game_path().as_deref(),
            source,
        )
        .map_err(|error| format!("{error:#}"))
    }

    fn selected_game_path(&self) -> Option<PathBuf> {
        let trimmed = self.game_path_text.trim();
        (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
    }

    fn game_path_is_valid(&self) -> bool {
        self.selected_game_path()
            .as_deref()
            .is_some_and(|path| launch::validate_game_executable(path).is_ok())
    }

    fn browse_game_executable(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Choose ARC Raiders")
            .add_filter("Game file", &["exe"])
            .pick_file()
        {
            self.game_path_text = path.display().to_string();
            self.config.game_executable_path = Some(path.clone());
            if self.config.platform == LauncherPlatform::Auto {
                self.config.platform =
                    launch::resolve_platform(LauncherPlatform::Auto, Some(&path));
            }
            self.save_config();
            self.refresh_launcher_readiness();
        }
    }

    /// Switch the active launcher (from Settings or the hub toggle). Switching to
    /// Epic with no game path set auto-fills it from the Epic manifests (preferring
    /// the install detected at startup) so it's immediately ready, not stuck on the
    /// "Choose ARC Raiders" picker.
    fn set_launcher(&mut self, platform: LauncherPlatform) {
        self.config.platform = platform;
        self.force_close_available = false;
        if platform == LauncherPlatform::Epic && self.selected_game_path().is_none() {
            if let Some(exe) = self
                .detected_epic_exe
                .clone()
                .or_else(launch::find_epic_game_executable)
            {
                self.game_path_text = exe.display().to_string();
                self.config.game_executable_path = Some(exe);
            }
        }
        self.save_config();
        self.refresh_launcher_readiness();
    }

    fn persist_game_path(&mut self) {
        let next = self.selected_game_path();
        if next == self.config.game_executable_path {
            return;
        }
        self.config.game_executable_path = next;
        self.save_config();
    }

    fn prepare_launcher(&mut self, force_close: bool) {
        self.persist_game_path();

        if !self.game_ready_for_platform() {
            return;
        }

        let plan = match self.selected_setup_plan() {
            Ok(plan) => plan,
            Err(error) => {
                self.push_message(format!("Launcher setup failed: {error}"));
                return;
            }
        };

        self.preparing_launcher = true;
        match launch::prepare_launcher(&plan, force_close) {
            Ok(launch::PrepareOutcome::Ready) => {
                self.preparing_launcher = false;
                self.force_close_available = false;
                self.sync_key_source = Some(plan.setup_source.clone());
                self.refresh_launcher_readiness();
                self.launcher_was_ready = true;
                self.push_message(format!("{} is ready", plan.platform.label()));
                if !self.sync_paused {
                    self.maybe_start_background_capture();
                }
            }
            Ok(launch::PrepareOutcome::StillRunning) => {
                self.preparing_launcher = false;
                self.force_close_available = true;
                self.push_message(format!("{} needs to close", plan.platform.label()));
                self.refresh_launcher_readiness();
            }
            Err(error) => {
                self.preparing_launcher = false;
                self.push_message(format!("Launcher setup failed: {error:#}"));
                self.refresh_launcher_readiness();
            }
        }
    }

    fn start_sign_in(&mut self) {
        if self.auth_rx.is_some() {
            return;
        }

        match auth_bridge::start(BASE_URL) {
            Ok(attempt) => {
                self.auth_rx = Some(attempt.rx);
                if let Err(error) = auth_bridge::open_browser(&attempt.url) {
                    self.push_message(format!("Open this URL: {}", attempt.url));
                    self.push_message(format!("Could not open browser: {error:#}"));
                }
            }
            Err(error) => {
                self.push_message(format!("Could not start sign-in: {error:#}"));
            }
        }
    }

    fn cancel_sign_in(&mut self) {
        self.auth_rx = None;
    }

    fn sign_out(&mut self) {
        self.cancel_sign_in();
        self.clear_auth_session();
        self.token_submitted = false;
        self.submitted_token_fingerprint = None;
        self.sync_enabled = false;
        self.latest_token = None;
        self.account_name = None;
        self.last_synced_label = None;
        self.update_tray_tooltip();
    }

    fn maybe_start_background_capture(&mut self) {
        if self.capture.is_some() || self.capture_blocked || self.sync_paused {
            return;
        }
        if !self.capture_ready() {
            return;
        }

        let Some(interface_name) = self
            .selected_interface()
            .map(|interface| interface.name.clone())
        else {
            return;
        };

        let Some(sync_key_source) = self.sync_key_source.clone() else {
            return;
        };
        let sync_key_path = sync_key_source.path;

        if !sync_key_path.exists() {
            return;
        }

        self.stats = CaptureStats::default();
        self.latest_token = None;
        self.capture = Some(capture::start_capture(interface_name, sync_key_path));
    }

    fn capture_settings_changed(&mut self) {
        self.capture_blocked = false;
        if let Some(capture) = self.capture.take() {
            capture.stop();
            drop(capture);
        }
        self.stats = CaptureStats::default();
        self.latest_token = None;
        self.token_submitted = false;
        self.submitted_token_fingerprint = None;
        self.sync_enabled = false;
    }

    fn poll_auth(&mut self) {
        let Some(rx) = self.auth_rx.take() else {
            return;
        };

        match rx.try_recv() {
            Ok(Ok(token)) => {
                if let Err(error) = credential_store::save_auth_token(&token) {
                    self.push_message(format!("Could not remember ARCTracker sign-in: {error:#}"));
                }
                self.auth_token = Some(token);
                self.push_message("ARCTracker sign-in complete".to_string());
                self.submit_latest_token_if_ready();
            }
            Ok(Err(error)) => {
                self.push_message(error);
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.auth_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.push_message("Sign-in callback stopped unexpectedly".to_string());
            }
        }
    }

    fn poll_capture(&mut self) {
        let Some(capture) = &self.capture else {
            return;
        };

        let events = capture.rx.try_iter().collect::<Vec<_>>();
        let mut stopped = false;
        let mut errored = false;
        for event in events {
            match event {
                CaptureEvent::Status(status) => {
                    self.push_message(status);
                }
                CaptureEvent::Stats(stats) => {
                    self.stats = stats;
                }
                CaptureEvent::Token(observation) => {
                    let already_submitted = self
                        .submitted_token_fingerprint
                        .as_deref()
                        .is_some_and(|fingerprint| fingerprint == observation.fingerprint);
                    let was_synced = self.token_submitted;
                    self.latest_token = Some(observation);
                    if !already_submitted {
                        if !was_synced {
                            self.token_submitted = false;
                            self.sync_enabled = false;
                            self.push_message("Game account connected".to_string());
                        }
                        self.submit_latest_token_if_ready();
                    }
                }
                CaptureEvent::Error(error) => {
                    self.capture_blocked = true;
                    self.push_message(error);
                    errored = true;
                }
                CaptureEvent::Stopped => {
                    stopped = true;
                }
            }
        }

        if stopped || errored {
            self.capture = None;
        }
    }

    fn poll_submit(&mut self) {
        let Some(rx) = self.submit_rx.take() else {
            return;
        };

        match rx.try_recv() {
            Ok(Ok((fingerprint, response))) => {
                if response.success {
                    self.token_submitted = true;
                    self.submitted_token_fingerprint = Some(fingerprint);
                    self.sync_enabled = response.sync_enabled;
                    let account =
                        match (&response.display_name, &response.display_name_discriminator) {
                            (Some(name), Some(discriminator)) => format!("{name}#{discriminator}"),
                            (Some(name), None) => name.clone(),
                            _ => tr!("SyncApp.tray.tooltipIdle"),
                        };
                    self.account_name = Some(account.clone());
                    self.last_synced_label = Some(current_time_label());
                    self.push_message(format!("{account} connected"));
                    self.update_tray_tooltip();
                    self.submit_latest_token_if_ready();
                } else if !self.token_submitted {
                    self.sync_enabled = response.sync_enabled;
                    self.push_message(
                        "ARCTracker did not enable sync for this account".to_string(),
                    );
                }
            }
            Ok(Err(error)) => {
                if Self::is_auth_submission_error(&error) {
                    // The 401 footgun fix: try a refresh before signing out.
                    if let Some(token) = self.auth_token.clone() {
                        self.refresh_after_unauthorized = true;
                        self.start_refresh(token);
                    } else {
                        self.clear_auth_session();
                    }
                }
                self.push_message(error.to_string());
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.submit_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.push_message("Submission worker stopped unexpectedly".to_string());
            }
        }
    }

    fn submit_latest_token_if_ready(&mut self) {
        if self.submit_rx.is_some() {
            return;
        }
        let Some(auth_token) = self.auth_token.clone() else {
            return;
        };
        let Some(observation) = self.latest_token.clone() else {
            return;
        };
        if self
            .submitted_token_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| fingerprint == observation.fingerprint)
        {
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.submit_rx = Some(rx);
        thread::spawn(move || {
            let fingerprint = observation.fingerprint.clone();
            let result = sync_client::submit_embark_token(&auth_token, &observation)
                .map(|response| (fingerprint, response));
            let _ = tx.send(result);
        });
    }

    fn clear_auth_session(&mut self) {
        self.auth_token = None;
        self.token_submitted = false;
        self.submitted_token_fingerprint = None;
        self.sync_enabled = false;
        self.account_name = None;
        self.last_synced_label = None;
        if let Err(error) = credential_store::clear_auth_token() {
            self.push_message(format!("Could not clear ARCTracker sign-in: {error:#}"));
        }
    }

    fn is_auth_submission_error(error: &SubmitError) -> bool {
        error.status == Some(401)
    }

    fn save_config(&mut self) {
        if let Err(error) = config::save(&self.config) {
            self.push_message(format!("Could not save settings: {error:#}"));
        }
    }

    fn push_message(&mut self, message: String) {
        self.messages
            .insert(0, Self::support_event_message(&message));
        self.messages.truncate(20);
    }

    fn copy_diagnostics(&self, ctx: &egui::Context) {
        let mut lines = vec![
            format!("ARCTracker Sync v{}", env!("CARGO_PKG_VERSION")),
            format!("Locale: {}", self.locale),
            format!("Platform: {}", self.launcher_readiness.platform.label()),
            format!("Launcher: {}", self.launcher_readiness.status.label()),
            format!("Launcher detail: {}", self.launcher_readiness.detail),
            format!("Game running: {}", self.game_running),
            format!("Capture ready: {}", self.capture_ready()),
            format!("Account synced: {}", self.token_submitted),
            format!("Inventory sync enabled: {}", self.sync_enabled),
            format!("Connection active: {}", self.capture.is_some()),
            format!("Activity: {}", self.stats.packets_seen),
            format!("Connection activity: {}", self.stats.tls_segments_processed),
            format!("Game sessions: {}", self.stats.tls_embark_sni_hellos),
            format!("Account matches: {}", self.stats.http1_bearer_headers),
            format!("Setup entries: {}", self.stats.sync_key_entries),
            format!(
                "TLS hellos client/server: {} / {}",
                self.stats.tls_client_hellos, self.stats.tls_server_hellos
            ),
            format!("TLS keys established: {}", self.stats.tls_keys_established),
            format!("TLS missing keys: {}", self.stats.tls_missing_keys),
            format!(
                "Embark missing-key sessions: {} (last: {})",
                self.stats.embark_missing_key_sessions,
                self.stats.last_embark_missing_key.as_deref().unwrap_or("-")
            ),
            format!(
                "Encrypted but not decrypted: {}",
                self.stats.tls_encrypted_no_decrypt
            ),
            format!("Decrypted records: {}", self.stats.decrypted_records),
            format!(
                "Decrypt errors: {} (last: {})",
                self.stats.tls_decrypt_errors,
                self.stats.last_tls_decrypt_error.as_deref().unwrap_or("-")
            ),
            format!(
                "App data to-server / to-client: {} / {}",
                self.stats.tls_inner_app_data_to_server, self.stats.tls_inner_app_data_to_client
            ),
            format!(
                "HTTP candidates / embark hosts: {} / {}",
                self.stats.http1_candidates, self.stats.http1_embark_hosts
            ),
            format!(
                "Last HTTP: {} {} {}",
                self.stats.last_http1_method.as_deref().unwrap_or("-"),
                self.stats.last_http1_host.as_deref().unwrap_or("-"),
                self.stats.last_http1_path.as_deref().unwrap_or("-")
            ),
            format!(
                "Token expires: {}",
                self.latest_token
                    .as_ref()
                    .and_then(|token| token.expires_at())
                    .map(|exp| exp.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".to_string())
            ),
            format!(
                "Packet truncations: {} ({} bytes)",
                self.stats.packet_truncations, self.stats.packet_truncated_bytes
            ),
            "Events:".to_string(),
        ];
        for message in &self.messages {
            lines.push(format!("  {message}"));
        }
        // Scrub any \Users\<name>\ paths (e.g. launcher detail / error lines) so
        // the copied blob doesn't leak the Windows account name.
        ctx.copy_text(Self::scrub_paths(&lines.join("\n")));
    }

    fn support_event_message(message: &str) -> String {
        let lower = message.to_ascii_lowercase();
        if lower.contains("authorization")
            || lower.contains("bearer")
            || lower.contains("token")
            || lower.contains("http")
            || lower.contains("tls")
            || lower.contains("ssl")
            || lower.contains("keylog")
            || lower.contains("secret")
            || lower.contains("random=")
        {
            return if lower.contains("fail")
                || lower.contains("error")
                || lower.contains("reject")
                || lower.contains("unavailable")
                || lower.contains("not readable")
            {
                "Local sync needs attention.".to_string()
            } else {
                "Local sync setup updated.".to_string()
            };
        }

        let cleaned = message
            .replace("capture", "connection")
            .replace("Capture", "Connection")
            .replace("adapter", "network option")
            .replace("Adapter", "Network option")
            .replace("Embark", "Game");
        Self::scrub_paths(&cleaned)
    }

    /// Replace the username component in any `…\Users\<name>\…` path with
    /// `<user>` so the activity log and copied diagnostics (shared with support)
    /// don't leak the Windows account name or install layout. Handles both
    /// slash styles; the `Users` match is case-insensitive.
    fn scrub_paths(text: &str) -> String {
        let lower = text.to_ascii_lowercase();
        let needle = "\\users\\";
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while let Some(rel) = lower[i..].find(needle) {
            let after = i + rel + needle.len();
            out.push_str(&text[i..after]);
            let rest = &text[after..];
            let end = rest.find(['\\', '/']).unwrap_or(rest.len());
            if end > 0 {
                out.push_str("<user>");
            }
            i = after + end;
        }
        out.push_str(&text[i..]);
        out
    }

    fn interface_label(interface: &InterfaceInfo) -> String {
        match &interface.description {
            Some(desc) if !desc.is_empty() => format!("{desc} ({})", interface.name),
            _ => interface.name.clone(),
        }
    }

    fn best_interface_index(&self) -> Option<usize> {
        self.interfaces
            .iter()
            .enumerate()
            .max_by_key(|(_, interface)| Self::interface_score(interface))
            .map(|(index, _)| index)
    }

    fn interface_score(interface: &InterfaceInfo) -> i32 {
        let text = format!(
            "{} {}",
            interface.name,
            interface.description.as_deref().unwrap_or_default()
        )
        .to_ascii_lowercase();

        let mut score = 0;
        for preferred in [
            "ethernet", "wi-fi", "wifi", "wireless", "gigabit", "realtek", "intel", "asix",
        ] {
            if text.contains(preferred) {
                score += 20;
            }
        }
        for virtualized in [
            "loopback",
            "bluetooth",
            "virtual",
            "vmware",
            "hyper-v",
            "wintun",
            "tap",
            "zerotier",
            "docker",
            "vethernet",
        ] {
            if text.contains(virtualized) {
                score -= 100;
            }
        }

        score
    }

    // ----- rendering ---------------------------------------------------------------

    fn render_hub(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let state = self.hub_state();
        self.render_header(ui);
        ui.add_space(16.0);
        self.render_progress_strip(ui, state);
        ui.add_space(14.0);
        self.render_hero(ui, ctx, state);
        ui.add_space(12.0);
        self.render_footer(ui);
        self.render_explainer_modal(ctx);
        self.render_update_modal(ctx);
    }

    /// Bundled, localized, launcher-aware explanation shown when the user clicks
    /// "What does this do?" — replaces the old jump to the website.
    fn render_explainer_modal(&mut self, ctx: &egui::Context) {
        if !self.show_explainer {
            return;
        }
        let launcher = self.effective_platform().label();
        let modal = egui::Modal::new(egui::Id::new("arc_explainer")).show(ctx, |ui| {
            ui.set_max_width(440.0);
            ui.label(
                RichText::new(tr!("SyncApp.explain.title", launcher => launcher))
                    .size(18.0)
                    .strong()
                    .color(arc_foreground()),
            );
            ui.add_space(10.0);
            ui.label(
                RichText::new(tr!("SyncApp.explain.body", launcher => launcher))
                    .size(13.5)
                    .color(arc_muted_text()),
            );
            ui.add_space(18.0);
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if primary_button(ui, &tr!("SyncApp.action.gotIt")) {
                    self.show_explainer = false;
                }
            });
        });
        if modal.should_close() {
            self.show_explainer = false;
        }
    }

    /// The changelog + install dialog. Renders the current `update_state`: the
    /// changelog with Install/Later, a progress bar while downloading, a spinner
    /// while verifying/installing/restarting, or an error with Retry. It cannot
    /// be dismissed once an install is under way.
    fn render_update_modal(&mut self, ctx: &egui::Context) {
        if !self.show_update_modal {
            return;
        }
        let state = self.update_state.clone();
        let release = self.current_release.clone();
        let mut install_clicked = false;
        let mut close_clicked = false;

        let modal = egui::Modal::new(egui::Id::new("arc_update")).show(ctx, |ui| {
            ui.set_max_width(480.0);
            match &state {
                UpdateState::Available | UpdateState::Failed(_) => {
                    let Some(release) = release.as_ref() else {
                        close_clicked = true;
                        return;
                    };
                    ui.label(
                        RichText::new(tr!("SyncApp.update.title", version => release.tag.clone()))
                            .size(18.0)
                            .strong()
                            .color(arc_foreground()),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(tr!("SyncApp.update.changelogHeading"))
                            .size(13.0)
                            .strong()
                            .color(arc_primary()),
                    );
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(release.notes.as_str())
                                        .size(13.0)
                                        .color(arc_muted_text()),
                                )
                                .selectable(true),
                            );
                        });
                    if let UpdateState::Failed(error) = &state {
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(tr!("SyncApp.update.failed", error => error.clone()))
                                .size(12.5)
                                .color(arc_warning()),
                        );
                    }
                    ui.add_space(16.0);
                    ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                        let install_label = if matches!(state, UpdateState::Failed(_)) {
                            tr!("SyncApp.update.retry")
                        } else {
                            tr!("SyncApp.update.install")
                        };
                        if primary_button(ui, &install_label) {
                            install_clicked = true;
                        }
                        if secondary_button(ui, &tr!("SyncApp.update.later")) {
                            close_clicked = true;
                        }
                    });
                }
                UpdateState::Downloading { received, total } => {
                    ui.label(
                        RichText::new(tr!("SyncApp.update.downloading"))
                            .size(16.0)
                            .strong()
                            .color(arc_foreground()),
                    );
                    ui.add_space(12.0);
                    match total {
                        Some(total) if *total > 0 => {
                            let fraction = (*received as f32 / *total as f32).clamp(0.0, 1.0);
                            ui.add(egui::ProgressBar::new(fraction).show_percentage());
                        }
                        _ => {
                            ui.add(egui::ProgressBar::new(0.0).animate(true));
                        }
                    }
                }
                UpdateState::Verifying => spinner_row(ui, &tr!("SyncApp.update.verifying")),
                UpdateState::Installing => spinner_row(ui, &tr!("SyncApp.update.installing")),
                UpdateState::Relaunching => spinner_row(ui, &tr!("SyncApp.update.restarting")),
                UpdateState::Idle => close_clicked = true,
            }
        });

        if install_clicked {
            if let Some(release) = self.current_release.clone() {
                self.start_update_install(release);
            }
        } else if close_clicked {
            self.show_update_modal = false;
        } else if modal.should_close()
            && matches!(
                self.update_state,
                UpdateState::Available | UpdateState::Failed(_)
            )
        {
            // Backdrop/Esc only closes when idle-ish; locked mid-install.
            self.show_update_modal = false;
        }
    }

    fn render_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(tr!("SyncApp.appName"))
                    .size(20.0)
                    .strong()
                    .color(arc_foreground()),
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let signed_in = self.auth_token.is_some();
                pill(
                    ui,
                    &if signed_in {
                        tr!("SyncApp.header.signedIn")
                    } else {
                        tr!("SyncApp.header.signedOut")
                    },
                    if signed_in {
                        arc_success()
                    } else {
                        arc_muted_text()
                    },
                );
                if self.update_indicator_visible() {
                    ui.add_space(6.0);
                    if clickable_pill(ui, &tr!("SyncApp.update.pill"), arc_primary()).clicked() {
                        self.show_update_modal = true;
                    }
                }
            });
        });
    }

    fn render_progress_strip(&mut self, ui: &mut egui::Ui, state: HubState) {
        let stages = self.progress_stages(state);
        Frame::NONE
            .fill(arc_card())
            .stroke(Stroke::new(1.0, arc_border()))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(14, 12))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let count = stages.len();
                    for (index, (label, stage_state)) in stages.into_iter().enumerate() {
                        progress_stage(ui, &label, stage_state);
                        if index + 1 < count {
                            ui.add_space(6.0);
                            ui.label(RichText::new("›").size(14.0).color(arc_muted_text()));
                            ui.add_space(6.0);
                        }
                    }
                });
            });
    }

    fn render_hero(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, state: HubState) {
        let (title, body) = self.hub_copy(state);
        let accent = Self::state_accent(state);

        card(ui, |ui| {
            ui.horizontal(|ui| {
                status_dot(ui, accent);
                ui.add_space(4.0);
                ui.label(
                    RichText::new(title)
                        .size(22.0)
                        .strong()
                        .color(arc_foreground()),
                );
                // Quick Steam|Epic switch, only in the launcher phase and only when
                // the other store also has the game.
                if Self::is_launcher_phase(state) && self.launcher_switch_target().is_some() {
                    self.launcher_toggle(ui);
                }
            });
            ui.add_space(8.0);
            ui.label(RichText::new(body).size(14.0).color(arc_muted_text()));

            if state == HubState::Synced {
                if let Some(until) = self.session_expiry_label() {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(tr!("SyncApp.state.synced.session", time => until))
                            .size(13.5)
                            .strong()
                            .color(arc_foreground()),
                    );
                }
                ui.add_space(8.0);
                ui.label(
                    RichText::new(tr!("SyncApp.state.synced.canClose"))
                        .size(12.5)
                        .color(arc_muted_text()),
                );
            }

            ui.add_space(18.0);
            self.render_hero_actions(ui, ctx, state);
        });
    }

    fn render_hero_actions(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, state: HubState) {
        ui.horizontal(|ui| match state {
            HubState::NeedsAdmin => {
                if primary_button(ui, &tr!("SyncApp.action.restartAsAdmin")) {
                    match elevation::relaunch_elevated() {
                        Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(error) => self.push_message(format!("{error:#}")),
                    }
                }
                if secondary_button(ui, &tr!("SyncApp.action.getHelp")) {
                    let _ = auth_bridge::open_browser(HELP_URL);
                }
            }
            HubState::SignedOut => {
                if primary_button(ui, &tr!("SyncApp.action.signIn")) {
                    self.start_sign_in();
                }
            }
            HubState::SigningIn => {
                if secondary_button(ui, &tr!("SyncApp.action.cancel")) {
                    self.cancel_sign_in();
                }
            }
            HubState::SelectGame => {
                if primary_button(ui, &tr!("SyncApp.action.chooseGame")) {
                    self.browse_game_executable();
                }
                if secondary_button(ui, &tr!("SyncApp.action.whatDoesThisDo")) {
                    self.show_explainer = true;
                }
            }
            HubState::PrepareLauncher => {
                if primary_button(
                    ui,
                    &tr!("SyncApp.action.prepareLauncher", launcher => self.effective_platform().label()),
                ) {
                    self.prepare_launcher(false);
                }
                if secondary_button(ui, &tr!("SyncApp.action.whatDoesThisDo")) {
                    self.show_explainer = true;
                }
            }
            HubState::PreparingLauncher => {
                ui.spinner();
            }
            HubState::CloseLauncher => {
                if primary_button(
                    ui,
                    &tr!("SyncApp.action.closeLauncher", launcher => self.effective_platform().label()),
                ) {
                    self.prepare_launcher(true);
                }
            }
            HubState::LauncherReady => {
                if secondary_button(ui, &tr!("SyncApp.action.hideToTray")) {
                    self.hide_to_tray(ctx);
                }
            }
            HubState::Connecting | HubState::Updating => {
                ui.spinner();
            }
            HubState::Synced | HubState::SyncedIdle => {
                if secondary_button(ui, &tr!("SyncApp.action.hideToTray")) {
                    self.hide_to_tray(ctx);
                }
            }
            HubState::NeedsLauncher => {
                if primary_button(
                    ui,
                    &tr!("SyncApp.action.prepareLauncher", launcher => self.effective_platform().label()),
                ) {
                    self.prepare_launcher(false);
                }
                if secondary_button(ui, &tr!("SyncApp.action.getHelp")) {
                    let _ = auth_bridge::open_browser(HELP_URL);
                }
            }
            HubState::NeedsAttention => {
                if primary_button(ui, &tr!("SyncApp.action.tryAgain")) {
                    self.capture_blocked = false;
                    self.refresh_interfaces();
                    self.refresh_sync_key_source();
                    self.maybe_start_background_capture();
                }
                if secondary_button(ui, &tr!("SyncApp.action.getHelp")) {
                    let _ = auth_bridge::open_browser(HELP_URL);
                }
            }
        });
    }

    fn render_footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let identity = match &self.account_name {
                Some(account) if self.token_submitted => {
                    tr!("SyncApp.footer.signedInAs", account => account)
                }
                _ if self.auth_token.is_some() => tr!("SyncApp.header.signedIn"),
                _ => tr!("SyncApp.footer.notSignedIn"),
            };
            ui.label(RichText::new(identity).size(12.0).color(arc_muted_text()));

            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if link_button(ui, &tr!("SyncApp.footer.settings")) {
                    self.screen = Screen::Settings;
                }
            });
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            if link_button(ui, "←") {
                self.screen = Screen::Hub;
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new(tr!("SyncApp.settings.title"))
                    .size(20.0)
                    .strong()
                    .color(arc_foreground()),
            );
        });
        ui.add_space(14.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            self.render_settings_account(ui);
            ui.add_space(10.0);
            self.render_settings_game(ui);
            ui.add_space(10.0);
            self.render_settings_startup(ui);
            ui.add_space(10.0);
            self.render_settings_language(ui, ctx);
            ui.add_space(10.0);
            self.render_settings_network(ui);
            ui.add_space(10.0);
            self.render_settings_troubleshooting(ui, ctx);
            ui.add_space(14.0);
            self.render_settings_footer(ui);
            ui.add_space(14.0);
            if secondary_button(ui, &tr!("SyncApp.tray.quit")) {
                self.quit();
            }

            if self.show_activity_log {
                ui.add_space(12.0);
                self.render_activity_log(ui);
            }
        });
    }

    fn render_settings_account(&mut self, ui: &mut egui::Ui) {
        settings_section(ui, &tr!("SyncApp.settings.account"), |ui| {
            let account = self
                .account_name
                .clone()
                .filter(|_| self.token_submitted)
                .map(|account| tr!("SyncApp.footer.signedInAs", account => account))
                .unwrap_or_else(|| {
                    if self.auth_token.is_some() {
                        tr!("SyncApp.header.signedIn")
                    } else {
                        tr!("SyncApp.footer.notSignedIn")
                    }
                });
            ui.label(RichText::new(account).color(arc_foreground()));
            ui.label(
                RichText::new(tr!("SyncApp.settings.staysSignedIn"))
                    .size(12.0)
                    .color(arc_muted_text()),
            );
            ui.add_space(8.0);
            if ui
                .add_enabled(
                    self.auth_token.is_some(),
                    egui::Button::new(tr!("SyncApp.settings.signOut")),
                )
                .clicked()
            {
                self.sign_out();
            }
        });
    }

    fn render_settings_game(&mut self, ui: &mut egui::Ui) {
        settings_section(ui, &tr!("SyncApp.settings.gameLauncher"), |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(tr!("SyncApp.settings.launcher")).color(arc_foreground()));
                let mut platform = self.config.platform;
                egui::ComboBox::from_id_salt("settings_platform_combo")
                    .selected_text(platform.label())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut platform, LauncherPlatform::Auto, "Auto");
                        ui.selectable_value(&mut platform, LauncherPlatform::Steam, "Steam");
                        ui.selectable_value(&mut platform, LauncherPlatform::Epic, "Epic Games");
                        ui.selectable_value(&mut platform, LauncherPlatform::Direct, "Direct");
                    });
                if platform != self.config.platform {
                    self.set_launcher(platform);
                }
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.arcLocation")).color(arc_foreground()),
                    );
                    let location = self
                        .selected_game_path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| tr!("SyncApp.settings.autoDetected"));
                    ui.label(RichText::new(location).size(12.0).color(arc_muted_text()));
                });
                if ui.button(tr!("SyncApp.settings.change")).clicked() {
                    self.browse_game_executable();
                }
            });
        });
    }

    fn render_settings_startup(&mut self, ui: &mut egui::Ui) {
        settings_section(ui, &tr!("SyncApp.settings.startup"), |ui| {
            let mut start_with_windows = self.config.start_with_windows;
            if toggle_row(
                ui,
                &tr!("SyncApp.settings.startWithWindows"),
                &tr!("SyncApp.settings.startWithWindowsSub"),
                &mut start_with_windows,
            ) {
                match tray::set_start_with_windows(start_with_windows) {
                    Ok(()) => {
                        self.config.start_with_windows = start_with_windows;
                        self.save_config();
                    }
                    Err(error) => self.push_message(format!("{error:#}")),
                }
            }

            ui.add_space(6.0);
            let mut keep_in_tray = self.config.keep_in_tray;
            if toggle_row(
                ui,
                &tr!("SyncApp.settings.keepInTray"),
                &tr!("SyncApp.settings.keepInTraySub"),
                &mut keep_in_tray,
            ) {
                self.config.keep_in_tray = keep_in_tray;
                self.save_config();
            }
        });
    }

    fn render_settings_language(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        settings_section(ui, &tr!("SyncApp.settings.language"), |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(tr!("SyncApp.settings.displayLanguage")).color(arc_foreground()),
                );

                let current_label = match self.config.language.as_deref() {
                    Some(code) => i18n::native_name(code).to_string(),
                    None => tr!("SyncApp.settings.matchesWindows"),
                };
                let mut chosen: Option<Option<String>> = None;

                egui::ComboBox::from_id_salt("settings_language_combo")
                    .selected_text(current_label)
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(
                                self.config.language.is_none(),
                                tr!("SyncApp.settings.matchesWindows"),
                            )
                            .clicked()
                        {
                            chosen = Some(None);
                        }
                        for locale in i18n::UI_LOCALES.iter().copied() {
                            let selected = self.config.language.as_deref() == Some(locale);
                            if ui
                                .selectable_label(selected, i18n::native_name(locale))
                                .clicked()
                            {
                                chosen = Some(Some(locale.to_string()));
                            }
                        }
                    });

                if let Some(language) = chosen {
                    self.change_language(ctx, language);
                }
            });
        });
    }

    fn render_settings_network(&mut self, ui: &mut egui::Ui) {
        settings_section(ui, &tr!("SyncApp.settings.network"), |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.networkAdapter"))
                            .color(arc_foreground()),
                    );
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.networkAdapterSub"))
                            .size(12.0)
                            .color(arc_muted_text()),
                    );
                });

                let selected_label = self
                    .selected_interface()
                    .map(Self::interface_label)
                    .unwrap_or_else(|| "Auto".to_string());
                let mut selected_name = None;

                egui::ComboBox::from_id_salt("settings_interface_combo")
                    .selected_text(selected_label)
                    .width(360.0)
                    .show_ui(ui, |ui| {
                        for (index, interface) in self.interfaces.iter().enumerate() {
                            let label = Self::interface_label(interface);
                            if ui
                                .selectable_value(&mut self.selected_interface_index, index, label)
                                .changed()
                            {
                                selected_name = Some(interface.name.clone());
                            }
                        }
                    });

                if let Some(name) = selected_name {
                    self.config.selected_interface = Some(name);
                    self.save_config();
                    self.capture_settings_changed();
                }

                if ui.button(tr!("SyncApp.settings.refresh")).clicked() {
                    self.refresh_interfaces();
                    self.refresh_sync_key_source();
                }
            });
        });
    }

    fn render_settings_troubleshooting(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        settings_section(ui, &tr!("SyncApp.settings.troubleshooting"), |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.activityLog")).color(arc_foreground()),
                    );
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.activityLogSub"))
                            .size(12.0)
                            .color(arc_muted_text()),
                    );
                });
                if ui.button(tr!("SyncApp.settings.view")).clicked() {
                    self.show_activity_log = !self.show_activity_log;
                }
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.copyDiagnostics"))
                            .color(arc_foreground()),
                    );
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.copyDiagnosticsSub"))
                            .size(12.0)
                            .color(arc_muted_text()),
                    );
                });
                if ui.button(tr!("SyncApp.settings.copy")).clicked() {
                    self.copy_diagnostics(ctx);
                }
            });
        });
    }

    fn render_settings_footer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(
                    tr!("SyncApp.settings.version", version => env!("CARGO_PKG_VERSION")),
                )
                .size(12.0)
                .color(arc_muted_text()),
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if link_button(ui, &tr!("SyncApp.settings.checkForUpdates")) {
                    let _ = auth_bridge::open_browser(BASE_URL);
                }
            });
        });
    }

    fn render_activity_log(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(
                RichText::new(tr!("SyncApp.settings.activityLog"))
                    .strong()
                    .color(arc_foreground()),
            );
            ui.add_space(6.0);
            if self.messages.is_empty() {
                ui.label(RichText::new("—").color(arc_muted_text()));
            } else {
                for message in &self.messages {
                    ui.label(RichText::new(message).size(12.0).color(arc_muted_text()));
                }
            }
        });
    }
}

impl Drop for ArcTrackerSyncApp {
    fn drop(&mut self) {
        self.shutdown_cleanup();
    }
}

impl ArcTrackerSyncApp {
    fn update_frame(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.pending_quit {
            // Graceful shutdown: drain only ALREADY-finished submit/refresh
            // results so a just-refreshed token is persisted (these poll calls
            // never block on in-flight network work), stop capture cleanly, then
            // ask eframe to close so its loop exits and runs Drop.
            self.poll_submit();
            self.poll_refresh();
            self.shutdown_cleanup();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        self.run_background_work();
        self.handle_close_request(ctx);

        ctx.request_repaint_after(Duration::from_millis(750));

        egui::CentralPanel::default()
            .frame(Frame::NONE.fill(arc_bg()).inner_margin(Margin::same(24)))
            .show(ctx, |ui| {
                ui.set_min_width(640.0);
                match self.screen {
                    Screen::Hub => {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.render_hub(ui, ctx));
                    }
                    Screen::Settings => self.render_settings(ui, ctx),
                }
            });
    }
}

impl eframe::App for SharedArcTrackerSyncApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if let Ok(mut app) = self.inner.lock() {
            app.update_frame(ctx, frame);
        }
    }
}

// ----- shared widgets & theme ------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageState {
    Done,
    Current,
    Pending,
}

fn stage(done: bool, current: bool) -> StageState {
    if done {
        StageState::Done
    } else if current {
        StageState::Current
    } else {
        StageState::Pending
    }
}

fn current_time_label() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

pub(crate) fn primary_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(
        RichText::new(label)
            .strong()
            .color(arc_primary_foreground()),
    )
    .fill(arc_primary())
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(6));
    ui.add(button).clicked()
}

pub(crate) fn secondary_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(RichText::new(label).color(arc_foreground()))
        .fill(arc_input())
        .stroke(Stroke::new(1.0, arc_border()))
        .corner_radius(CornerRadius::same(6));
    ui.add(button).clicked()
}

fn link_button(ui: &mut egui::Ui, label: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(label).color(arc_primary())).frame(false))
        .clicked()
}

/// One segment of the Steam|Epic toggle: filled when it's the active launcher,
/// outlined otherwise.
fn launcher_segment(ui: &mut egui::Ui, label: &str, selected: bool) -> bool {
    let (fill, text, stroke) = if selected {
        (arc_primary(), arc_primary_foreground(), Stroke::NONE)
    } else {
        (
            arc_input(),
            arc_foreground(),
            Stroke::new(1.0, arc_border()),
        )
    };
    let button = egui::Button::new(RichText::new(label).size(12.0).color(text))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(6));
    ui.add(button).clicked()
}

fn toggle_row(ui: &mut egui::Ui, label: &str, sub: &str, value: &mut bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).color(arc_foreground()));
            ui.label(RichText::new(sub).size(12.0).color(arc_muted_text()));
        });
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            changed = ui.add(egui::Checkbox::without_text(value)).changed();
        });
    });
    changed
}

fn settings_section<R>(
    ui: &mut egui::Ui,
    title: &str,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    card(ui, |ui| {
        ui.label(
            RichText::new(title)
                .size(14.0)
                .strong()
                .color(arc_primary()),
        );
        ui.add_space(10.0);
        add_contents(ui)
    })
}

pub(crate) fn apply_arc_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = arc_bg();
    visuals.window_fill = arc_card();
    visuals.extreme_bg_color = arc_input();
    visuals.faint_bg_color = arc_muted();
    visuals.hyperlink_color = arc_primary();
    visuals.selection.bg_fill = arc_primary();
    visuals.selection.stroke = Stroke::new(1.0, arc_primary_foreground());
    visuals.widgets.inactive.bg_fill = arc_input();
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, arc_foreground());
    visuals.widgets.hovered.bg_fill = arc_muted();
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, arc_foreground());
    visuals.widgets.active.bg_fill = arc_primary();
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, arc_primary_foreground());

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 7.0);
    style.spacing.combo_width = 220.0;
    ctx.set_style(style);
}

pub(crate) fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    Frame::NONE
        .fill(arc_card())
        .stroke(Stroke::new(1.0, arc_border()))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(16))
        .show(ui, add_contents)
        .inner
}

fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::NONE
        .fill(color.linear_multiply(0.16))
        .stroke(Stroke::new(1.0, color.linear_multiply(0.55)))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).strong().color(color));
        });
}

/// Like [`pill`], but the whole chip is a click target — used for the header
/// "update available" indicator that opens the changelog dialog.
fn clickable_pill(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    let inner = Frame::NONE
        .fill(color.linear_multiply(0.16))
        .stroke(Stroke::new(1.0, color.linear_multiply(0.55)))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).strong().color(color));
        });
    ui.interact(
        inner.response.rect,
        egui::Id::new("arc_update_pill"),
        egui::Sense::click(),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn progress_stage(ui: &mut egui::Ui, label: &str, state: StageState) {
    let (color, marker) = match state {
        StageState::Done => (arc_success(), "●"),
        StageState::Current => (arc_primary(), "◆"),
        StageState::Pending => (arc_muted_text(), "○"),
    };
    ui.label(RichText::new(marker).size(12.0).color(color));
    ui.add_space(4.0);
    let text_color = if state == StageState::Pending {
        arc_muted_text()
    } else {
        arc_foreground()
    };
    let mut text = RichText::new(label).size(12.0).color(text_color);
    if state == StageState::Current {
        text = text.strong();
    }
    ui.label(text);
}

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 14.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 7.0, color);
}

/// A spinner followed by a status line — the body of the update dialog while an
/// install is in progress.
fn spinner_row(ui: &mut egui::Ui, label: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.add_space(8.0);
        ui.label(RichText::new(label).size(15.0).color(arc_foreground()));
    });
}

pub(crate) fn arc_bg() -> Color32 {
    Color32::from_rgb(18, 24, 31)
}

fn arc_card() -> Color32 {
    Color32::from_rgb(26, 33, 42)
}

fn arc_input() -> Color32 {
    Color32::from_rgb(22, 29, 37)
}

fn arc_muted() -> Color32 {
    Color32::from_rgb(36, 44, 55)
}

fn arc_border() -> Color32 {
    Color32::from_rgb(52, 61, 74)
}

pub(crate) fn arc_foreground() -> Color32 {
    Color32::from_rgb(237, 240, 244)
}

pub(crate) fn arc_muted_text() -> Color32 {
    Color32::from_rgb(156, 164, 176)
}

fn arc_primary() -> Color32 {
    Color32::from_rgb(255, 198, 1)
}

fn arc_primary_foreground() -> Color32 {
    Color32::from_rgb(24, 25, 28)
}

fn arc_success() -> Color32 {
    Color32::from_rgb(80, 220, 150)
}

pub(crate) fn arc_warning() -> Color32 {
    Color32::from_rgb(248, 165, 80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn customer_copy_avoids_technical_terms() {
        let mut copy = customer_visible_copy_samples().join("\n");
        copy.push('\n');
        copy.push_str(include_str!("../README.md"));
        let copy = copy.to_ascii_lowercase();

        for term in blocked_customer_terms() {
            assert!(
                !copy.contains(&term),
                "customer-visible copy contains blocked term: {term}"
            );
        }
    }

    #[test]
    fn support_event_message_redacts_sensitive_details() {
        let event = ArcTrackerSyncApp::support_event_message(
            "Authorization: Bearer abc.def.ghi over HTTP failed",
        );
        assert_eq!(event, "Local sync needs attention.");
    }

    #[test]
    fn support_event_message_keeps_the_account_deletion_reason() {
        // The reason arctracker.io gives for a sign-in into an account scheduled for deletion
        // names no token or HTTP, so the event log shows it as it is.
        let message = "ARCTracker sign-in failed: This account is scheduled for deletion on 2026-10-04. Cancel the deletion in your arctracker.io settings, then sign in again.";
        assert_eq!(ArcTrackerSyncApp::support_event_message(message), message);
    }

    fn blocked_customer_terms() -> Vec<String> {
        [
            "authorization",
            "bearer",
            "capture",
            "http/",
            "keylog",
            "key log",
            "packet",
            "protocol",
            "secret",
            "ssl",
            "tls",
            "token",
            "tshark",
            "wireshark",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    /// The full set of user-visible strings — pulled straight from the active
    /// (English) catalog so the jargon check tracks the real copy.
    fn customer_visible_copy_samples() -> Vec<String> {
        i18n::set_active_locale("en");
        let keys = [
            "SyncApp.appName",
            "SyncApp.header.signedIn",
            "SyncApp.header.signedOut",
            "SyncApp.progress.signedIn",
            "SyncApp.progress.launcherReady",
            "SyncApp.progress.playing",
            "SyncApp.progress.synced",
            "SyncApp.footer.notSignedIn",
            "SyncApp.footer.settings",
            "SyncApp.state.needsAdmin.title",
            "SyncApp.state.needsAdmin.body",
            "SyncApp.state.signedOut.title",
            "SyncApp.state.signedOut.body",
            "SyncApp.state.signingIn.title",
            "SyncApp.state.signingIn.body",
            "SyncApp.state.selectGame.title",
            "SyncApp.state.selectGame.body",
            "SyncApp.state.prepareLauncher.title",
            "SyncApp.state.prepareLauncher.body",
            "SyncApp.state.preparingLauncher.title",
            "SyncApp.state.preparingLauncher.body",
            "SyncApp.state.closeLauncher.title",
            "SyncApp.state.closeLauncher.body",
            "SyncApp.state.launcherReady.title",
            "SyncApp.state.launcherReady.body",
            "SyncApp.state.connecting.title",
            "SyncApp.state.connecting.body",
            "SyncApp.state.updating.title",
            "SyncApp.state.updating.body",
            "SyncApp.state.synced.title",
            "SyncApp.state.synced.body",
            "SyncApp.state.synced.session",
            "SyncApp.state.synced.canClose",
            "SyncApp.state.syncedIdle.body",
            "SyncApp.state.needsLauncher.title",
            "SyncApp.state.needsLauncher.body",
            "SyncApp.state.needsAttention.title",
            "SyncApp.state.needsAttention.body",
            "SyncApp.action.signIn",
            "SyncApp.action.cancel",
            "SyncApp.action.chooseGame",
            "SyncApp.action.prepareLauncher",
            "SyncApp.action.whatDoesThisDo",
            "SyncApp.action.closeLauncher",
            "SyncApp.action.hideToTray",
            "SyncApp.action.getHelp",
            "SyncApp.action.tryAgain",
            "SyncApp.action.restartAsAdmin",
            "SyncApp.action.gotIt",
            "SyncApp.explain.title",
            "SyncApp.explain.body",
            "SyncApp.settings.title",
            "SyncApp.settings.account",
            "SyncApp.settings.staysSignedIn",
            "SyncApp.settings.signOut",
            "SyncApp.settings.gameLauncher",
            "SyncApp.settings.launcher",
            "SyncApp.settings.arcLocation",
            "SyncApp.settings.autoDetected",
            "SyncApp.settings.change",
            "SyncApp.settings.startup",
            "SyncApp.settings.startWithWindows",
            "SyncApp.settings.startWithWindowsSub",
            "SyncApp.settings.keepInTray",
            "SyncApp.settings.keepInTraySub",
            "SyncApp.settings.language",
            "SyncApp.settings.displayLanguage",
            "SyncApp.settings.matchesWindows",
            "SyncApp.settings.network",
            "SyncApp.settings.networkAdapter",
            "SyncApp.settings.networkAdapterSub",
            "SyncApp.settings.refresh",
            "SyncApp.settings.troubleshooting",
            "SyncApp.settings.activityLog",
            "SyncApp.settings.activityLogSub",
            "SyncApp.settings.view",
            "SyncApp.settings.copyDiagnostics",
            "SyncApp.settings.copyDiagnosticsSub",
            "SyncApp.settings.copy",
            "SyncApp.settings.checkForUpdates",
            "SyncApp.tray.open",
            "SyncApp.tray.pause",
            "SyncApp.tray.resume",
            "SyncApp.tray.signOut",
            "SyncApp.tray.quit",
            "SyncApp.tray.tooltipIdle",
            "SyncApp.bridge.successTitle",
            "SyncApp.bridge.successBody",
            "SyncApp.bridge.errorTitle",
            "SyncApp.bridge.errorBody",
            "SyncApp.update.pill",
            "SyncApp.update.title",
            "SyncApp.update.changelogHeading",
            "SyncApp.update.install",
            "SyncApp.update.later",
            "SyncApp.update.retry",
            "SyncApp.update.downloading",
            "SyncApp.update.verifying",
            "SyncApp.update.installing",
            "SyncApp.update.restarting",
            "SyncApp.update.failed",
            "SyncApp.retired.title",
            "SyncApp.retired.body",
            "SyncApp.retired.uninstall",
            "SyncApp.retired.getLink",
            "SyncApp.retired.quit",
            "SyncApp.retired.openFailed",
        ];
        keys.into_iter().map(|key| tr!(key)).collect()
    }
}
