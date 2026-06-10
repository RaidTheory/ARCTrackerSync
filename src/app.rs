use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, CornerRadius, Frame, Margin, RichText, Stroke};

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
use crate::theme::{
    self, apply_arc_theme, arc_bg, arc_border, arc_card, arc_foreground, arc_muted_text,
    arc_primary, arc_success, arc_warning,
};
use crate::token::TokenObservation;
use crate::tr;
use crate::tray::{self, TrayCommand, TrayCommandHandler, TrayController};
use crate::updater::{self, InstallProgress, ReleaseInfo};
use crate::widgets::{
    card, clickable_pill, launcher_segment, link_button, pill, primary_button, progress_stage,
    screen_header, secondary_button, settings_section, spinner_row, stage, status_dot, toggle_row,
    StageState,
};

type AuthResult = Result<String, String>;
type SubmitResult = Result<(String, SubmitResponse), SubmitError>;
type RefreshResult = Result<String, SubmitError>;

/// ARC Raiders processes — used to detect whether the user is playing. The Steam
/// launcher runs as `PioneerGame.exe`; once it hands off, the running game is
/// `PioneerGame-e.exe` (EAC) or `PioneerGame-d.exe`.
const GAME_PROCESS_NAMES: &[&str] = &["PioneerGame.exe", "PioneerGame-e.exe", "PioneerGame-d.exe"];
const HELP_URL: &str = "https://arctracker.io/help/sync";
/// Where a synced user goes to view their inventory on the web app.
const STASH_URL: &str = "https://arctracker.io/stash";
/// Refresh the bridge token when fewer than this many days remain.
const REFRESH_THRESHOLD_DAYS: i64 = 7;
const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How often to check GitHub for a newer release; one check also runs on
/// startup. The 750ms worker loop only notices this interval elapsing — it
/// never makes a network call every tick.
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The adaptive hub state (spec §4). The hero card is a pure function of this
/// value, recomputed every frame.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Hub,
    Settings,
}

/// Self-updater lifecycle, driving the header pill and the changelog/install
/// dialog. Release details live in `current_release`.
#[derive(Debug, Clone)]
enum UpdateState {
    /// No newer release known (or we're between checks).
    Idle,
    Available,
    Downloading { received: u64, total: Option<u64> },
    Verifying,
    Installing,
    Relaunching,
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

    /// Raise the window when a second launch wakes us. Goes through the tray
    /// "Open" path so behavior matches the tray menu.
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
    /// User-set SSLKEYLOGFILE overrides that were ignored because they don't
    /// point at a usable file (kept for the diagnostics dump).
    sync_key_skipped: Vec<launch::SkippedSyncKey>,
    /// Token submissions started this session (kept for the diagnostics dump,
    /// to distinguish "never attempted" from "attempted and failed").
    submit_attempts: u32,
    /// Last token-submission failure, path-scrubbed but unredacted (the
    /// activity log entry for it may be collapsed to customer copy).
    last_sync_error: Option<String>,
    /// When the last submission failed; drives the backoff retry. `None` while
    /// idle, synced, or hard-stopped (see `submit_gave_up`).
    submit_failed_at: Option<Instant>,
    /// Consecutive failed submissions for the current token; indexes the
    /// `submit_backoff` schedule and resets on success or a new token.
    consecutive_submit_failures: u32,
    /// Whether we've already refreshed the ARCTracker sign-in for the current
    /// failure episode — bounds `/api/auth/bridge/refresh` to one call per
    /// episode instead of one per retry (the 401 ping-pong).
    refreshed_for_current_failure: bool,
    /// Set when backoff is exhausted: automatic retries stop until the user
    /// hits "Try again" or a new token arrives. Surfaces `NeedsAttention`.
    submit_gave_up: bool,
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
    mark_texture: Option<egui::TextureHandle>,

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
    /// Stop flag for the background worker, flipped during graceful shutdown.
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
        let (detected_steam, detected_epic_exe) = launch::detect_installed_launchers();
        // First run with no explicit launcher choice: pick the store that has
        // the game. Steam first — it launches by app id with no exe path.
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

        // The worker owns hidden-tray maintenance because eframe may stop
        // calling update() for hidden windows.
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
            .map(|resolution| {
                launch::launcher_readiness(
                    config.platform,
                    config.game_executable_path.as_deref(),
                    &resolution.source.path,
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
            sync_key_source: sync_key_result
                .as_ref()
                .ok()
                .map(|resolution| resolution.source.clone()),
            sync_key_skipped: sync_key_result
                .as_ref()
                .ok()
                .map(|resolution| resolution.skipped.clone())
                .unwrap_or_default(),
            submit_attempts: 0,
            last_sync_error: None,
            submit_failed_at: None,
            consecutive_submit_failures: 0,
            refreshed_for_current_failure: false,
            submit_gave_up: false,
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
            mark_texture: None,
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
            Ok(resolution) => {
                for skipped in &resolution.skipped {
                    app.push_message(skipped_sync_key_notice(&skipped.path));
                }
                app.push_message(resolution.source.label().to_string());
            }
            Err(error) => app.push_message(format!("Local sync setup unavailable: {error:#}")),
        }
        if let Some(message) = auth_message {
            app.push_message(message);
        }

        // Best-effort cleanup of the Run entry older releases wrote for the
        // removed "Start with Windows" feature.
        let _ = tray::remove_startup_entry();

        app.refresh_game_running();
        app.refresh_interfaces();
        app.maybe_refresh_auth_on_launch();

        // Debug aid: `--screen-settings` opens directly on the settings screen
        // so UI work can be verified without clicking through elevation.
        #[cfg(debug_assertions)]
        if std::env::args().any(|arg| arg == "--screen-settings") {
            app.screen = Screen::Settings;
        }

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

    /// Routes through the graceful shutdown path so Drop runs and any
    /// just-finished work is persisted.
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
        self.maybe_retry_token_submission();
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

    fn update_indicator_visible(&self) -> bool {
        !matches!(self.update_state, UpdateState::Idle)
    }

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
                // Failed checks are routine (offline, rate-limited); don't
                // surface them to the user.
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
        // Submission backoff exhausted: surface attention (with Try again)
        // instead of a perpetual "Connecting…", and stop retrying in the
        // background until the user acts.
        if self.submit_gave_up {
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

    fn hub_copy(&self, state: HubState) -> (String, String) {
        let account = self.account_name.clone().unwrap_or_default();
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
                tr!("SyncApp.state.synced.body", account => account),
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

    /// Local "Mon D, HH:MM" the current Embark session stays synced until,
    /// decoded from the captured token's `exp`. `None` without a live token.
    fn session_expiry_label(&self) -> Option<String> {
        let exp = self.latest_token.as_ref()?.expires_at()?;
        expiry_label(exp, chrono::Local::now())
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

    // ----- capture / launcher wiring -------------------------------------------------

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
            Ok(resolution) => {
                self.sync_key_skipped = resolution.skipped.clone();
                if previous.as_ref() == Some(&resolution.source) {
                    return;
                }
                self.sync_key_source = Some(resolution.source.clone());
                for skipped in &resolution.skipped {
                    self.push_message(skipped_sync_key_notice(&skipped.path));
                }
                self.push_message(resolution.source.label().to_string());
                self.capture_settings_changed();
            }
            Err(error) => {
                self.sync_key_skipped = Vec::new();
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

    /// States where offering a quick Steam|Epic switch makes sense.
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

    /// Switching to Epic with no game path set auto-fills it from the Epic
    /// manifests so the user isn't stuck on the "Choose ARC Raiders" picker.
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

        // `is_file`, not `exists`: a directory path (e.g. a stale SSLKEYLOGFILE
        // override) would open with "access denied" and block capture.
        if !sync_key_path.is_file() {
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
        self.reset_submit_retry_state();
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
                        // A genuinely new token gets a clean retry budget, and
                        // resumes submission if a prior episode hard-stopped.
                        self.reset_submit_retry_state();
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
                    self.last_sync_error = None;
                    self.reset_submit_retry_state();
                    let account =
                        match (&response.display_name, &response.display_name_discriminator) {
                            (Some(name), Some(discriminator)) => format!("{name}#{discriminator}"),
                            (Some(name), None) => name.clone(),
                            _ => tr!("SyncApp.tray.tooltipIdle"),
                        };
                    self.account_name = Some(account.clone());
                    self.push_message(format!("{account} connected"));
                    self.update_tray_tooltip();
                    self.submit_latest_token_if_ready();
                } else if !self.token_submitted {
                    self.sync_enabled = response.sync_enabled;
                    // Authoritative server answer — no retry until a new token.
                    self.last_sync_error =
                        Some("ARCTracker answered success=false for the submitted token".to_string());
                    self.submit_failed_at = None;
                    self.push_message(
                        "ARCTracker did not enable sync for this account".to_string(),
                    );
                }
            }
            Ok(Err(error)) => {
                self.note_submit_failure(&error.to_string());
                // A 401 means the ARCTracker sign-in may have expired: refresh
                // once per failure episode and let that resubmit. Not on every
                // 401 — a persistent server-side error masked as 401 (e.g. a
                // stale Embark manifest) would loop refresh→resubmit→401 with
                // no delay, hammering the backend.
                if Self::is_auth_submission_error(&error) && !self.refreshed_for_current_failure {
                    if let Some(token) = self.auth_token.clone() {
                        self.refreshed_for_current_failure = true;
                        self.refresh_after_unauthorized = true;
                        self.start_refresh(token);
                    } else {
                        self.clear_auth_session();
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.submit_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.push_message("Submission worker stopped unexpectedly".to_string());
                self.note_submit_failure("Submission worker stopped unexpectedly");
            }
        }
    }

    /// Backoff delay after `failures` consecutive failed submissions; `None`
    /// gives up for good, so an outage can't keep hammering the backend (and
    /// Embark behind it).
    fn submit_backoff(failures: u32) -> Option<Duration> {
        match failures {
            0 => None,
            1 => Some(Duration::from_secs(30)),
            2 => Some(Duration::from_secs(60)),
            3 => Some(Duration::from_secs(120)),
            4 => Some(Duration::from_secs(300)),
            5 => Some(Duration::from_secs(600)),
            _ => None,
        }
    }

    /// The error is pushed to the log once per distinct message.
    fn note_submit_failure(&mut self, error: &str) {
        self.consecutive_submit_failures = self.consecutive_submit_failures.saturating_add(1);
        let detail = Self::scrub_paths(error);
        if self.last_sync_error.as_deref() != Some(detail.as_str()) {
            self.push_message(error.to_string());
        }
        self.last_sync_error = Some(detail);

        if Self::submit_backoff(self.consecutive_submit_failures).is_some() {
            self.submit_failed_at = Some(Instant::now());
        } else {
            // Schedule exhausted — stop until the user acts or a new token arrives.
            self.submit_failed_at = None;
            self.submit_gave_up = true;
            self.push_message(
                "Sync paused after repeated failures. Use Try again once it's resolved."
                    .to_string(),
            );
        }
    }

    fn reset_submit_retry_state(&mut self) {
        self.consecutive_submit_failures = 0;
        self.refreshed_for_current_failure = false;
        self.submit_gave_up = false;
        self.submit_failed_at = None;
    }

    /// Retry a failed submission once its backoff window elapses. Capture emits
    /// each distinct token only once, so without this a transient blip would
    /// lose sync for the whole session.
    fn maybe_retry_token_submission(&mut self) {
        if self.token_submitted || self.submit_rx.is_some() {
            return;
        }
        let Some(failed_at) = self.submit_failed_at else {
            return;
        };
        let Some(delay) = Self::submit_backoff(self.consecutive_submit_failures) else {
            self.submit_failed_at = None;
            self.submit_gave_up = true;
            return;
        };
        if failed_at.elapsed() >= delay {
            self.submit_failed_at = Some(Instant::now());
            self.submit_latest_token_if_ready();
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

        self.submit_attempts += 1;
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
            .insert(0, Self::stored_event_message(&message));
        self.messages.truncate(20);
    }

    /// What the activity log stores: the raw message with usernames scrubbed.
    /// Keyword redaction happens at render time (`support_event_message`), so
    /// the copied diagnostics keep full failure detail for support.
    fn stored_event_message(message: &str) -> String {
        Self::scrub_paths(message)
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
            format!(
                "Sync key source: {}",
                self.sync_key_source
                    .as_ref()
                    .map(|source| format!("{:?} ({})", source.kind, source.path.display()))
                    .unwrap_or_else(|| "-".to_string())
            ),
            format!("Sync key reloads: {}", self.stats.sync_key_reloads),
            format!("Signed in: {}", self.auth_token.is_some()),
            format!(
                "Token host: {}",
                self.latest_token
                    .as_ref()
                    .map(|token| token.host.as_str())
                    .unwrap_or("-")
            ),
            format!(
                "Sync submit attempts: {} (in flight: {})",
                self.submit_attempts,
                self.submit_rx.is_some()
            ),
            format!(
                "Sync retry: {} consecutive failures{}",
                self.consecutive_submit_failures,
                if self.submit_gave_up {
                    " (paused — Try again to resume)"
                } else {
                    ""
                }
            ),
            format!(
                "Last sync error: {}",
                self.last_sync_error.as_deref().unwrap_or("-")
            ),
        ];
        for skipped in &self.sync_key_skipped {
            lines.push(format!(
                "Skipped SSLKEYLOGFILE (not a file): {}",
                skipped.path.display()
            ));
        }
        lines.push("Events:".to_string());
        for message in &self.messages {
            lines.push(format!("  {message}"));
        }
        // Scrub any \Users\<name>\ paths (e.g. launcher detail / error lines) so
        // the copied blob doesn't leak the Windows account name.
        ctx.copy_text(Self::scrub_paths(&lines.join("\n")));
    }

    /// What the on-screen activity log shows. The app's networking is described
    /// openly (README, source), so the real event text is kept as-is — we only
    /// redact the one genuine secret that could appear, the access-token value,
    /// plus usernames in paths. Full detail still reaches "Copy diagnostics".
    fn support_event_message(message: &str) -> String {
        Self::scrub_paths(&Self::redact_token_values(message))
    }

    /// Replace an access-token value with `<redacted>` wherever one could show
    /// up — the value right after a `Bearer` marker, or a bare JWT-looking token
    /// (three long base64url segments). Everything else, including mechanism
    /// words like "TLS" or "keylog", is left intact.
    fn redact_token_values(message: &str) -> String {
        fn is_jwt_like(word: &str) -> bool {
            let parts: Vec<&str> = word.split('.').collect();
            parts.len() == 3
                && parts.iter().all(|part| {
                    part.len() >= 10
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
        }

        // After a `Bearer` marker, the next word is the secret value.
        fn flush(word: &mut String, out: &mut String, after_marker: &mut bool) {
            if word.is_empty() {
                return;
            }
            if *after_marker || is_jwt_like(word) {
                out.push_str("<redacted>");
            } else {
                out.push_str(word);
            }
            let bare = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            *after_marker = bare.eq_ignore_ascii_case("bearer");
            word.clear();
        }

        let mut out = String::with_capacity(message.len());
        let mut word = String::new();
        let mut after_marker = false;
        for ch in message.chars() {
            if ch.is_whitespace() {
                flush(&mut word, &mut out, &mut after_marker);
                out.push(ch);
            } else {
                word.push(ch);
            }
        }
        flush(&mut word, &mut out, &mut after_marker);
        out
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
        self.render_header(ui, ctx);
        ui.add_space(theme::SPACE_LG);
        self.render_progress_strip(ui, state);
        ui.add_space(theme::SPACE_LG);
        self.render_hero(ui, ctx, state);
        ui.add_space(theme::SPACE_MD);
        self.render_footer(ui);
        self.render_explainer_modal(ctx);
        self.render_update_modal(ctx);
    }

    fn render_explainer_modal(&mut self, ctx: &egui::Context) {
        if !self.show_explainer {
            return;
        }
        let launcher = self.effective_platform().label();
        let modal = egui::Modal::new(egui::Id::new("arc_explainer")).show(ctx, |ui| {
            ui.set_max_width(theme::MODAL_WIDTH);
            ui.label(
                RichText::new(tr!("SyncApp.explain.title", launcher => launcher))
                    .size(theme::TEXT_SUBTITLE)
                    .strong()
                    .color(arc_foreground()),
            );
            ui.add_space(theme::SPACE_MD);
            ui.label(
                RichText::new(tr!("SyncApp.explain.body", launcher => launcher))
                    .size(theme::TEXT_SECONDARY)
                    .color(arc_muted_text()),
            );
            ui.add_space(theme::SPACE_LG);
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

    /// Changelog + install dialog. Cannot be dismissed once an install is
    /// under way.
    fn render_update_modal(&mut self, ctx: &egui::Context) {
        if !self.show_update_modal {
            return;
        }
        let state = self.update_state.clone();
        let release = self.current_release.clone();
        let mut install_clicked = false;
        let mut close_clicked = false;

        let modal = egui::Modal::new(egui::Id::new("arc_update")).show(ctx, |ui| {
            ui.set_max_width(theme::MODAL_WIDTH);
            match &state {
                UpdateState::Available | UpdateState::Failed(_) => {
                    let Some(release) = release.as_ref() else {
                        close_clicked = true;
                        return;
                    };
                    ui.label(
                        RichText::new(tr!("SyncApp.update.title", version => release.tag.clone()))
                            .size(theme::TEXT_SUBTITLE)
                            .strong()
                            .color(arc_foreground()),
                    );
                    ui.add_space(theme::SPACE_MD);
                    ui.label(
                        RichText::new(tr!("SyncApp.update.changelogHeading"))
                            .size(theme::TEXT_SECONDARY)
                            .strong()
                            .color(arc_primary()),
                    );
                    ui.add_space(theme::SPACE_SM);
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(release.notes.as_str())
                                        .size(theme::TEXT_SECONDARY)
                                        .color(arc_muted_text()),
                                )
                                .selectable(true),
                            );
                        });
                    if let UpdateState::Failed(error) = &state {
                        ui.add_space(theme::SPACE_MD);
                        ui.label(
                            RichText::new(tr!("SyncApp.update.failed", error => error.clone()))
                                .size(theme::TEXT_SECONDARY)
                                .color(arc_warning()),
                        );
                    }
                    ui.add_space(theme::SPACE_LG);
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
                            .size(theme::TEXT_SUBTITLE)
                            .strong()
                            .color(arc_foreground()),
                    );
                    ui.add_space(theme::SPACE_MD);
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

    /// The ARC chevron mark (32×32, baked by `build.rs`), uploaded once on
    /// first use.
    fn arc_mark(&mut self, ctx: &egui::Context) -> egui::TextureHandle {
        self.mark_texture
            .get_or_insert_with(|| {
                const RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/icon_32.rgba"));
                let image = egui::ColorImage::from_rgba_unmultiplied([32, 32], RGBA);
                ctx.load_texture("arc-mark", image, egui::TextureOptions::LINEAR)
            })
            .clone()
    }

    fn render_header(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mark = self.arc_mark(ctx);
        let signed_in = self.auth_token.is_some();
        let update_visible = self.update_indicator_visible();
        let mut open_update = false;
        screen_header(
            ui,
            Some(&mark),
            &tr!("SyncApp.appName"),
            |_| {},
            |ui| {
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
                if update_visible {
                    ui.add_space(theme::SPACE_SM);
                    if clickable_pill(ui, &tr!("SyncApp.update.pill"), arc_primary()).clicked() {
                        open_update = true;
                    }
                }
            },
        );
        if open_update {
            self.show_update_modal = true;
        }
    }

    fn render_progress_strip(&mut self, ui: &mut egui::Ui, state: HubState) {
        let stages = self.progress_stages(state);
        Frame::NONE
            .fill(arc_card())
            .stroke(Stroke::new(1.0, arc_border()))
            .corner_radius(CornerRadius::same(theme::RADIUS_CARD))
            .inner_margin(Margin::symmetric(16, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let count = stages.len();
                    for (index, (label, stage_state)) in stages.into_iter().enumerate() {
                        progress_stage(ui, &label, stage_state);
                        if index + 1 < count {
                            ui.add_space(theme::SPACE_SM);
                            ui.label(
                                RichText::new("›")
                                    .size(theme::TEXT_BODY)
                                    .color(arc_muted_text()),
                            );
                            ui.add_space(theme::SPACE_SM);
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
                ui.add_space(theme::SPACE_XS);
                ui.label(
                    RichText::new(title)
                        .size(theme::TEXT_TITLE)
                        .strong()
                        .color(arc_foreground()),
                );
                if Self::is_launcher_phase(state) && self.launcher_switch_target().is_some() {
                    self.launcher_toggle(ui);
                }
            });
            ui.add_space(theme::SPACE_SM);
            ui.label(
                RichText::new(body)
                    .size(theme::TEXT_BODY)
                    .color(arc_muted_text()),
            );

            if state == HubState::Synced {
                if let Some(until) = self.session_expiry_label() {
                    ui.add_space(theme::SPACE_SM);
                    ui.label(
                        RichText::new(tr!("SyncApp.state.synced.session", time => until))
                            .size(theme::TEXT_SECONDARY)
                            .strong()
                            .color(arc_foreground()),
                    );
                }
                ui.add_space(theme::SPACE_SM);
                ui.label(
                    RichText::new(tr!("SyncApp.state.synced.canClose"))
                        .size(theme::TEXT_SECONDARY)
                        .color(arc_muted_text()),
                );
            }

            ui.add_space(theme::SPACE_LG);
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
                if primary_button(ui, &tr!("SyncApp.action.viewStash")) {
                    let _ = auth_bridge::open_browser(STASH_URL);
                }
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
                    // Resume submission if a prior episode hard-stopped, then
                    // re-attempt with the token we already have.
                    self.reset_submit_retry_state();
                    self.refresh_interfaces();
                    self.refresh_sync_key_source();
                    self.maybe_start_background_capture();
                    self.submit_latest_token_if_ready();
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
            ui.label(
                RichText::new(identity)
                    .size(theme::TEXT_CAPTION)
                    .color(arc_muted_text()),
            );

            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                if link_button(ui, &tr!("SyncApp.footer.settings")) {
                    self.screen = Screen::Settings;
                }
            });
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mark = self.arc_mark(ctx);
        let mut back = false;
        screen_header(
            ui,
            Some(&mark),
            &tr!("SyncApp.settings.title"),
            |ui| {
                if link_button(ui, "←") {
                    back = true;
                }
                ui.add_space(theme::SPACE_SM);
            },
            |_| {},
        );
        if back {
            self.screen = Screen::Hub;
        }
        ui.add_space(theme::SPACE_LG);

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.render_settings_account(ui);
                ui.add_space(theme::SPACE_MD);
                self.render_settings_game(ui);
                ui.add_space(theme::SPACE_MD);
                self.render_settings_startup(ui);
                ui.add_space(theme::SPACE_MD);
                self.render_settings_language(ui, ctx);
                ui.add_space(theme::SPACE_MD);
                self.render_settings_network(ui);
                ui.add_space(theme::SPACE_MD);
                self.render_settings_troubleshooting(ui, ctx);
                ui.add_space(theme::SPACE_LG);
                self.render_settings_footer(ui);
                ui.add_space(theme::SPACE_LG);
                if secondary_button(ui, &tr!("SyncApp.tray.quit")) {
                    self.quit();
                }

                if self.show_activity_log {
                    ui.add_space(theme::SPACE_MD);
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
                    .size(theme::TEXT_CAPTION)
                    .color(arc_muted_text()),
            );
            ui.add_space(theme::SPACE_SM);
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

            ui.add_space(theme::SPACE_SM);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.arcLocation")).color(arc_foreground()),
                    );
                    let location = self
                        .selected_game_path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| tr!("SyncApp.settings.autoDetected"));
                    ui.label(
                        RichText::new(location)
                            .size(theme::TEXT_CAPTION)
                            .color(arc_muted_text()),
                    );
                });
                if ui.button(tr!("SyncApp.settings.change")).clicked() {
                    self.browse_game_executable();
                }
            });
        });
    }

    fn render_settings_startup(&mut self, ui: &mut egui::Ui) {
        settings_section(ui, &tr!("SyncApp.settings.startup"), |ui| {
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
            // Stacked layout: adapter labels can be long (GUIDs) and the row
            // would otherwise push the card past the window edge.
            ui.label(RichText::new(tr!("SyncApp.settings.networkAdapter")).color(arc_foreground()));
            ui.label(
                RichText::new(tr!("SyncApp.settings.networkAdapterSub"))
                    .size(theme::TEXT_CAPTION)
                    .color(arc_muted_text()),
            );
            ui.add_space(theme::SPACE_SM);

            let selected_label = self
                .selected_interface()
                .map(Self::interface_label)
                .unwrap_or_else(|| "Auto".to_string());
            let mut selected_name = None;
            let mut refresh = false;

            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                refresh = ui.button(tr!("SyncApp.settings.refresh")).clicked();
                egui::ComboBox::from_id_salt("settings_interface_combo")
                    .selected_text(selected_label)
                    .width(theme::COMBO_WIDE.min(ui.available_width()))
                    .truncate()
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
            });

            if let Some(name) = selected_name {
                self.config.selected_interface = Some(name);
                self.save_config();
                self.capture_settings_changed();
            }

            if refresh {
                self.refresh_interfaces();
                self.refresh_sync_key_source();
            }
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
                            .size(theme::TEXT_CAPTION)
                            .color(arc_muted_text()),
                    );
                });
                if ui.button(tr!("SyncApp.settings.view")).clicked() {
                    self.show_activity_log = !self.show_activity_log;
                }
            });

            ui.add_space(theme::SPACE_SM);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.copyDiagnostics"))
                            .color(arc_foreground()),
                    );
                    ui.label(
                        RichText::new(tr!("SyncApp.settings.copyDiagnosticsSub"))
                            .size(theme::TEXT_CAPTION)
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
                .size(theme::TEXT_CAPTION)
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
            ui.add_space(theme::SPACE_SM);
            if self.messages.is_empty() {
                ui.label(RichText::new("—").color(arc_muted_text()));
            } else {
                for message in &self.messages {
                    ui.label(
                        RichText::new(Self::support_event_message(message))
                            .size(theme::TEXT_CAPTION)
                            .color(arc_muted_text()),
                    );
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
            // Drain already-finished submit/refresh results (the polls never
            // block on in-flight network work) so a just-refreshed token is
            // persisted, then close so eframe's loop exits and runs Drop.
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
                // The column wraps the scroll areas (not the other way around)
                // so it always works with the panel's finite rect.
                Self::content_column(ui, |ui| match self.screen {
                    Screen::Hub => {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.render_hub(ui, ctx));
                    }
                    Screen::Settings => self.render_settings(ui, ctx),
                });
            });
    }

    /// Center a column capped at [`theme::CONTENT_MAX_WIDTH`] so wide or
    /// maximized windows don't stretch the cards edge-to-edge. Renders into a
    /// child rect directly (not a horizontal/vertical nest, which would starve
    /// nested scroll areas of height).
    fn content_column(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
        let available = ui.available_rect_before_wrap();
        let column = available.width().min(theme::CONTENT_MAX_WIDTH);
        let x = available.left() + ((available.width() - column) / 2.0).max(0.0);
        let rect = egui::Rect::from_x_y_ranges(x..=x + column, available.y_range());
        ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
            ui.set_width(column);
            add_contents(ui);
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

// ----- app-local helpers ------------------------------------------------------

/// Activity-log notice for a user-set SSLKEYLOGFILE that was ignored. Uses the
/// app's "sync key" product term so it reads cleanly in the activity log and
/// doesn't trip `support_event_message`'s secret-value redaction; the username
/// in the path is scrubbed by `push_message` as usual.
fn skipped_sync_key_notice(path: &Path) -> String {
    format!(
        "Ignoring sync key setting that isn't a usable file: {} — using the app-managed sync key instead",
        path.display()
    )
}

/// Session-expiry label, date always included: Embark tokens last exactly 24h,
/// so a bare time-of-day reads as the moment the token was captured. `None`
/// when the expiry isn't genuinely in the future — a near-now value is just
/// the current token about to rotate and reads as "expires right now".
fn expiry_label(
    exp: chrono::DateTime<chrono::Local>,
    now: chrono::DateTime<chrono::Local>,
) -> Option<String> {
    if exp <= now + chrono::Duration::minutes(2) {
        return None;
    }
    Some(exp.format("%b %-d, %H:%M").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_backoff_escalates_then_gives_up() {
        use std::time::Duration;
        assert_eq!(ArcTrackerSyncApp::submit_backoff(0), None);
        assert_eq!(
            ArcTrackerSyncApp::submit_backoff(1),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            ArcTrackerSyncApp::submit_backoff(2),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            ArcTrackerSyncApp::submit_backoff(3),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            ArcTrackerSyncApp::submit_backoff(4),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            ArcTrackerSyncApp::submit_backoff(5),
            Some(Duration::from_secs(600))
        );
        assert_eq!(ArcTrackerSyncApp::submit_backoff(6), None);
        assert_eq!(ArcTrackerSyncApp::submit_backoff(100), None);
    }

    #[test]
    fn events_store_raw_detail_and_redact_only_at_render() {
        // The activity log stores the path-scrubbed raw message so the copied
        // diagnostics keep failure detail (status codes, hosts) ...
        let raw = "ARCTracker rejected token submission with HTTP 503: upstream timeout";
        let stored = ArcTrackerSyncApp::stored_event_message(raw);
        assert!(stored.contains("HTTP 503"), "stored: {stored}");

        // ... and the on-screen log keeps that real detail too; only secret
        // values (an access token) would be redacted, and there is none here.
        let shown = ArcTrackerSyncApp::support_event_message(&stored);
        assert_eq!(
            shown,
            "ARCTracker rejected token submission with HTTP 503: upstream timeout"
        );

        // Username scrubbing still applies at storage time.
        let stored =
            ArcTrackerSyncApp::stored_event_message("loading C:\\Users\\someone\\file.log failed");
        assert!(
            stored.contains("<user>") && !stored.contains("someone"),
            "stored: {stored}"
        );
    }

    #[test]
    fn skipped_sync_key_notice_survives_support_redaction() {
        let notice = skipped_sync_key_notice(Path::new("C:\\Users\\someone\\Documents"));
        let shown = ArcTrackerSyncApp::support_event_message(&notice);

        assert!(
            shown.contains("Ignoring sync key setting"),
            "notice carries no token value, so it shows intact: {shown}"
        );
        assert!(
            shown.contains("<user>") && !shown.contains("someone"),
            "username should be scrubbed: {shown}"
        );
    }

    #[test]
    fn expiry_label_always_includes_the_date() {
        use chrono::TimeZone;

        let now = chrono::Local
            .with_ymd_and_hms(2026, 6, 9, 16, 44, 48)
            .unwrap();

        // A 24h Embark token: same time-of-day tomorrow must carry the date so
        // it can't be misread as the capture time.
        let exp = now + chrono::Duration::hours(24);
        assert_eq!(expiry_label(exp, now).as_deref(), Some("Jun 10, 16:44"));

        // Even a same-day expiry shows the date.
        let exp = now + chrono::Duration::hours(3);
        assert_eq!(expiry_label(exp, now).as_deref(), Some("Jun 9, 19:44"));
    }

    #[test]
    fn expiry_label_hides_near_now_or_past_expiry() {
        use chrono::TimeZone;

        let now = chrono::Local
            .with_ymd_and_hms(2026, 6, 9, 16, 0, 0)
            .unwrap();
        assert_eq!(expiry_label(now + chrono::Duration::minutes(1), now), None);
        assert_eq!(expiry_label(now - chrono::Duration::hours(1), now), None);
    }

    #[test]
    fn support_event_message_redacts_the_token_value_only() {
        // The access token is scrubbed; the rest of the line — including the
        // honest mechanism words — is shown as-is.
        let event = ArcTrackerSyncApp::support_event_message(
            "Authorization: Bearer abc.def.ghi over HTTP failed",
        );
        assert_eq!(event, "Authorization: Bearer <redacted> over HTTP failed");
    }
}
