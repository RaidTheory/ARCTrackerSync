use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config;
use crate::process_env::{self, LauncherProcess};

pub const ARC_RAIDERS_STEAM_APP_ID: u32 = 1808500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LauncherPlatform {
    #[default]
    Auto,
    Steam,
    Epic,
    Direct,
}

impl LauncherPlatform {
    pub fn label(self) -> &'static str {
        match self {
            LauncherPlatform::Auto => "Auto",
            LauncherPlatform::Steam => "Steam",
            LauncherPlatform::Epic => "Epic Games",
            LauncherPlatform::Direct => "Direct",
        }
    }

    pub fn process_name(self) -> Option<&'static str> {
        match self {
            LauncherPlatform::Steam => Some("steam.exe"),
            LauncherPlatform::Epic => Some("EpicGamesLauncher.exe"),
            LauncherPlatform::Auto | LauncherPlatform::Direct => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherStatus {
    NotRunning,
    Ready,
    NeedsRestart,
    Unknown,
}

impl LauncherStatus {
    pub fn label(self) -> &'static str {
        match self {
            LauncherStatus::NotRunning => "Not running",
            LauncherStatus::Ready => "Ready",
            LauncherStatus::NeedsRestart => "Needs restart",
            LauncherStatus::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherReadiness {
    pub platform: LauncherPlatform,
    pub status: LauncherStatus,
    pub process_count: usize,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherSetupPlan {
    pub platform: LauncherPlatform,
    pub setup_source: SyncKeySource,
    pub game_executable: Option<PathBuf>,
    pub steam_exe: Option<PathBuf>,
    pub epic_launcher_exe: Option<PathBuf>,
}

impl LauncherSetupPlan {
    pub fn build(
        selected_platform: LauncherPlatform,
        game_executable: Option<&Path>,
        setup_source: SyncKeySource,
    ) -> Result<Self> {
        let platform = resolve_platform(selected_platform, game_executable);
        let game_executable = game_executable.map(Path::to_path_buf);

        let steam_exe = (platform == LauncherPlatform::Steam)
            .then(find_steam_exe)
            .transpose()?;
        let epic_launcher_exe = (platform == LauncherPlatform::Epic)
            .then(find_epic_launcher_exe)
            .transpose()?;

        Ok(Self {
            platform,
            setup_source,
            game_executable,
            steam_exe,
            epic_launcher_exe,
        })
    }

    pub fn explicit_sync_key_path(&self) -> Option<&Path> {
        self.setup_source
            .needs_explicit_child_env()
            .then_some(self.setup_source.path.as_path())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareOutcome {
    Ready,
    StillRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKeySourceKind {
    ProcessEnv,
    Registry,
    AppOwned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncKeySource {
    pub kind: SyncKeySourceKind,
    pub path: PathBuf,
}

impl SyncKeySource {
    pub fn label(&self) -> &'static str {
        match self.kind {
            SyncKeySourceKind::ProcessEnv | SyncKeySourceKind::Registry => "Sync setup ready",
            SyncKeySourceKind::AppOwned => "Launch from this app",
        }
    }

    pub fn is_app_owned(&self) -> bool {
        self.kind == SyncKeySourceKind::AppOwned
    }

    pub fn needs_explicit_child_env(&self) -> bool {
        matches!(
            self.kind,
            SyncKeySourceKind::Registry | SyncKeySourceKind::AppOwned
        )
    }
}

pub fn launcher_readiness(
    selected_platform: LauncherPlatform,
    game_executable: Option<&Path>,
    setup_path: &Path,
) -> LauncherReadiness {
    let platform = resolve_platform(selected_platform, game_executable);
    if platform == LauncherPlatform::Direct {
        return LauncherReadiness {
            platform,
            status: LauncherStatus::Ready,
            process_count: 0,
            detail: "Direct launch selected".to_string(),
        };
    }

    let Some(process_name) = platform.process_name() else {
        return LauncherReadiness {
            platform,
            status: LauncherStatus::Unknown,
            process_count: 0,
            detail: "Choose Steam or Epic Games".to_string(),
        };
    };

    let processes = match process_env::find_processes(process_name) {
        Ok(processes) => processes,
        Err(error) => {
            return LauncherReadiness {
                platform,
                status: LauncherStatus::Unknown,
                process_count: 0,
                detail: format!("Could not inspect {}: {error:#}", platform.label()),
            };
        }
    };

    if processes.is_empty() {
        return LauncherReadiness {
            platform,
            status: LauncherStatus::NotRunning,
            process_count: 0,
            detail: format!("{} is not running", platform.label()),
        };
    }

    let mut unknown = None;
    for process in &processes {
        match process_env::process_environment_value(process.pid, "SSLKEYLOGFILE") {
            Ok(Some(value)) if same_path_text(&value, setup_path) => {
                return LauncherReadiness {
                    platform,
                    status: LauncherStatus::Ready,
                    process_count: processes.len(),
                    detail: format!("{} is ready", platform.label()),
                };
            }
            Ok(_) => {}
            Err(error) => {
                unknown.get_or_insert_with(|| format!("{error:#}"));
            }
        }
    }

    if let Some(error) = unknown {
        LauncherReadiness {
            platform,
            status: LauncherStatus::Unknown,
            process_count: processes.len(),
            detail: format!("Could not confirm {} setup: {error}", platform.label()),
        }
    } else {
        LauncherReadiness {
            platform,
            status: LauncherStatus::NeedsRestart,
            process_count: processes.len(),
            detail: format!("{} needs to restart", platform.label()),
        }
    }
}

pub fn prepare_launcher(plan: &LauncherSetupPlan, force_close: bool) -> Result<PrepareOutcome> {
    if matches!(
        plan.platform,
        LauncherPlatform::Auto | LauncherPlatform::Direct
    ) {
        prepare_sync_key_for_launch(&plan.setup_source)?;
        return Ok(PrepareOutcome::Ready);
    }

    let process_name = plan
        .platform
        .process_name()
        .context("launcher platform has no process name")?;

    let running = process_env::find_processes(process_name)?;
    if !running.is_empty() {
        if force_close {
            force_close_processes(&running)?;
        } else {
            graceful_close_launcher(plan)?;
        }

        if !wait_until_process_exits(process_name, Duration::from_secs(20))? {
            return Ok(PrepareOutcome::StillRunning);
        }
    }

    prepare_sync_key_for_launch(&plan.setup_source)?;
    start_launcher_with_setup(plan)?;
    Ok(PrepareOutcome::Ready)
}

pub fn resolve_platform(
    selected_platform: LauncherPlatform,
    game_executable: Option<&Path>,
) -> LauncherPlatform {
    if selected_platform != LauncherPlatform::Auto {
        return selected_platform;
    }

    if let Some(path) = game_executable {
        if is_steam_game_path(path) {
            return LauncherPlatform::Steam;
        }
        if is_epic_game_path(path) {
            return LauncherPlatform::Epic;
        }
    }

    LauncherPlatform::Steam
}

pub fn is_steam_game_path(path: &Path) -> bool {
    let text = normalize_path_text(path);
    text.contains("\\steamapps\\common\\")
}

pub fn is_epic_game_path(path: &Path) -> bool {
    let text = normalize_path_text(path);
    if text.contains("\\epic games\\") {
        return true;
    }

    epic_manifest_install_locations()
        .into_iter()
        .any(|location| path_starts_with(path, &location))
}

/// A user-set SSLKEYLOGFILE override (env var or registry) that was ignored
/// because it can't be a usable keylog file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedSyncKey {
    pub kind: SyncKeySourceKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncKeyResolution {
    pub source: SyncKeySource,
    pub skipped: Vec<SkippedSyncKey>,
}

pub fn resolve_current_sync_key_source() -> Result<SyncKeyResolution> {
    let app_owned = config::app_owned_sync_key_path()?;
    Ok(resolve_sync_key_source(
        config::process_sync_key_env(),
        config::registry_sync_key_path(),
        app_owned,
        sync_key_override_usable,
    ))
}

/// Pick the sync key path: the first usable user override (process env, then
/// registry), otherwise the app-owned path. Unusable overrides — e.g. an
/// SSLKEYLOGFILE left pointing at a folder by another tool — are reported in
/// `skipped` instead of blocking sync. The app-owned fallback is never skipped.
pub fn resolve_sync_key_source(
    process_env: Option<PathBuf>,
    registry_env: Option<PathBuf>,
    app_owned: PathBuf,
    is_usable_file: impl Fn(&Path) -> bool,
) -> SyncKeyResolution {
    let mut skipped = Vec::new();
    for (kind, candidate) in [
        (SyncKeySourceKind::ProcessEnv, process_env),
        (SyncKeySourceKind::Registry, registry_env),
    ] {
        let Some(path) = candidate else {
            continue;
        };
        if is_usable_file(&path) {
            return SyncKeyResolution {
                source: SyncKeySource { kind, path },
                skipped,
            };
        }
        skipped.push(SkippedSyncKey { kind, path });
    }

    SyncKeyResolution {
        source: SyncKeySource {
            kind: SyncKeySourceKind::AppOwned,
            path: app_owned,
        },
        skipped,
    }
}

/// An override is honored only when it already points at an existing regular
/// file (an active Wireshark-style keylog). Anything else falls back to the
/// app-owned key, which is injected explicitly into the launcher child env, so
/// a stale system-wide value can't break sync.
fn sync_key_override_usable(path: &Path) -> bool {
    path.is_file()
}

pub fn prepare_sync_key_for_launch(source: &SyncKeySource) -> Result<()> {
    if !source.is_app_owned() {
        return Ok(());
    }

    if let Some(parent) = source.path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    // Truncate fresh on every prepare so the plaintext TLS secrets the game
    // writes here never accumulate across sessions (they decrypt all of the
    // user's port-443 traffic). The capture stop path / app exit deletes it
    // entirely via config::clear_app_owned_sync_key().
    //
    // TODO ACL: restrict this file's DACL to the owning user (best-effort
    // Windows ACL FFI). It currently inherits the LocalAppData default ACL,
    // which is already per-user, but an explicit owner-only ACE would harden it
    // against same-machine actors. Left out for now to avoid heavy unsafe FFI.
    fs::write(&source.path, b"").with_context(|| format!("preparing {}", source.path.display()))?;
    Ok(())
}

pub fn validate_game_executable(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("Select the ARC Raiders PioneerGame.exe file.");
    }
    if !path.is_file() {
        bail!("The selected ARC Raiders path is not a file.");
    }
    if !path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        bail!("Select a Windows .exe file for ARC Raiders.");
    }

    Ok(())
}

fn start_launcher_with_setup(plan: &LauncherSetupPlan) -> Result<()> {
    match plan.platform {
        LauncherPlatform::Steam => {
            let steam_exe = plan
                .steam_exe
                .as_ref()
                .context("Steam path is unavailable")?;
            let mut command = Command::new(steam_exe);
            if let Some(path) = plan.explicit_sync_key_path() {
                command.env("SSLKEYLOGFILE", path);
            }
            command
                .spawn()
                .with_context(|| format!("starting {}", steam_exe.display()))?;
        }
        LauncherPlatform::Epic => {
            let epic_exe = plan
                .epic_launcher_exe
                .as_ref()
                .context("Epic Games Launcher path is unavailable")?;
            let mut command = Command::new(epic_exe);
            if let Some(path) = plan.explicit_sync_key_path() {
                command.env("SSLKEYLOGFILE", path);
            }
            command
                .spawn()
                .with_context(|| format!("starting {}", epic_exe.display()))?;
        }
        LauncherPlatform::Direct | LauncherPlatform::Auto => {}
    }
    Ok(())
}

fn graceful_close_launcher(plan: &LauncherSetupPlan) -> Result<()> {
    match plan.platform {
        LauncherPlatform::Steam => {
            let steam_exe = plan
                .steam_exe
                .as_ref()
                .context("Steam path is unavailable")?;
            Command::new(steam_exe)
                .arg("-shutdown")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("asking {} to close", steam_exe.display()))?;
        }
        LauncherPlatform::Epic => {
            Command::new("taskkill")
                .args(["/IM", "EpicGamesLauncher.exe", "/T"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("asking Epic Games Launcher to close")?;
        }
        LauncherPlatform::Auto | LauncherPlatform::Direct => {}
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn force_close_processes(processes: &[LauncherProcess]) -> Result<()> {
    let Some(process_name) = processes.first().map(|process| process.name.as_str()) else {
        return Ok(());
    };
    Command::new("taskkill")
        .args(["/F", "/IM", process_name, "/T"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("force closing {process_name}"))?;
    Ok(())
}

/// Linux has no `taskkill`; send `SIGKILL` to each matched PID directly.
#[cfg(target_os = "linux")]
fn force_close_processes(processes: &[LauncherProcess]) -> Result<()> {
    for process in processes {
        unsafe {
            libc::kill(process.pid as libc::pid_t, libc::SIGKILL);
        }
    }
    Ok(())
}

fn wait_until_process_exits(process_name: &str, timeout: Duration) -> Result<bool> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if process_env::find_processes(process_name)?.is_empty() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(process_env::find_processes(process_name)?.is_empty())
}

#[cfg(not(target_os = "linux"))]
fn find_steam_exe() -> Result<PathBuf> {
    if let Some(path) = config::steam_install_path().map(|path| path.join("steam.exe")) {
        if path.exists() {
            return Ok(path);
        }
    }

    for path in [
        PathBuf::from("C:\\Program Files (x86)\\Steam\\steam.exe"),
        PathBuf::from("C:\\Program Files\\Steam\\steam.exe"),
    ] {
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow!("Steam was not found"))
}

/// On Linux Steam is the `steam` wrapper script on `PATH`. Returning the bare
/// command lets `Command::new` resolve it, and `steam -shutdown` /
/// `steam steam://...` work the same as the Windows exe path.
#[cfg(target_os = "linux")]
fn find_steam_exe() -> Result<PathBuf> {
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join("steam");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    // Flatpak fallback: no `steam` on PATH, but the app id is launchable.
    if Path::new("/var/lib/flatpak/exports/bin/com.valvesoftware.Steam").exists() {
        return Ok(PathBuf::from(
            "/var/lib/flatpak/exports/bin/com.valvesoftware.Steam",
        ));
    }
    Err(anyhow!("Steam was not found on PATH"))
}

fn find_epic_launcher_exe() -> Result<PathBuf> {
    for path in [
        PathBuf::from(
            "C:\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Binaries\\Win64\\EpicGamesLauncher.exe",
        ),
        PathBuf::from(
            "C:\\Program Files\\Epic Games\\Launcher\\Portal\\Binaries\\Win64\\EpicGamesLauncher.exe",
        ),
    ] {
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow!("Epic Games Launcher was not found"))
}

fn read_epic_manifests() -> Vec<serde_json::Value> {
    let manifest_dir = PathBuf::from("C:\\ProgramData\\Epic\\EpicGamesLauncher\\Data\\Manifests");
    let Ok(entries) = fs::read_dir(manifest_dir) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension()?.to_str()?.eq_ignore_ascii_case("item")).then_some(path)
        })
        .filter_map(|path| fs::read_to_string(path).ok())
        .filter_map(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .collect()
}

fn epic_manifest_install_locations() -> Vec<PathBuf> {
    read_epic_manifests()
        .into_iter()
        .filter_map(|json| json.get("InstallLocation")?.as_str().map(PathBuf::from))
        .collect()
}

/// Auto-detect the ARC Raiders executable from the Epic manifests
/// (`LaunchExecutable` under `InstallLocation`), so Epic owners skip the
/// manual file picker.
pub fn find_epic_game_executable() -> Option<PathBuf> {
    for manifest in read_epic_manifests() {
        let install = manifest
            .get("InstallLocation")
            .and_then(|value| value.as_str());
        let launch_exe = manifest
            .get("LaunchExecutable")
            .and_then(|value| value.as_str());
        let (Some(install), Some(launch_exe)) = (install, launch_exe) else {
            continue;
        };

        let exe_name = Path::new(launch_exe)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let display = manifest
            .get("DisplayName")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if exe_name.starts_with("pioneergame") || display.contains("arc raiders") {
            let full = Path::new(install).join(launch_exe);
            if full.exists() {
                return Some(full);
            }
        }
    }
    None
}

/// Which stores have ARC Raiders installed right now: `(steam, epic_exe)`.
pub fn detect_installed_launchers() -> (bool, Option<PathBuf>) {
    (steam_game_installed(), find_epic_game_executable())
}

fn steam_game_installed() -> bool {
    let manifest = format!("appmanifest_{ARC_RAIDERS_STEAM_APP_ID}.acf");
    steam_library_paths()
        .into_iter()
        .any(|library| library.join("steamapps").join(&manifest).exists())
}

fn steam_library_paths() -> Vec<PathBuf> {
    let Some(steam) = config::steam_install_path() else {
        return Vec::new();
    };
    let mut paths = vec![steam.clone()];

    // Additional libraries are listed in libraryfolders.vdf. The modern format
    // uses `"path"  "<dir>"`; legacy files use a numeric index instead
    // (`"1"  "<dir>"`), so scan every quoted pair and take any `"path"` key
    // plus any numeric-index key rather than matching on line prefix.
    if let Ok(text) = fs::read_to_string(steam.join("steamapps").join("libraryfolders.vdf")) {
        for line in text.lines() {
            let mut tokens = quoted_tokens(line);
            let (Some(key), Some(value)) = (tokens.next(), tokens.next()) else {
                continue;
            };
            if key == "path" || key.bytes().all(|byte| byte.is_ascii_digit()) {
                paths.push(PathBuf::from(value.replace("\\\\", "\\")));
            }
        }
    }
    paths
}

/// Each double-quoted token on a line, in order — enough to read VDF pairs
/// without a VDF crate.
fn quoted_tokens(line: &str) -> impl Iterator<Item = &str> {
    let mut rest = line;
    std::iter::from_fn(move || {
        let open = rest.find('"')? + 1;
        let close = rest[open..].find('"')? + open;
        let token = &rest[open..close];
        rest = &rest[close + 1..];
        Some(token)
    })
}

fn path_starts_with(path: &Path, base: &Path) -> bool {
    normalize_path_text(path).starts_with(&normalize_path_text(base))
}

fn same_path_text(value: &str, expected: &Path) -> bool {
    normalize_slashes(value) == normalize_path_text(expected)
}

fn normalize_path_text(path: &Path) -> String {
    normalize_slashes(&path.display().to_string())
}

fn normalize_slashes(value: &str) -> String {
    value.trim().replace('/', "\\").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn config_platform_default_is_auto() {
        assert_eq!(LauncherPlatform::default(), LauncherPlatform::Auto);
    }

    #[test]
    fn sync_key_resolution_prefers_process_then_registry_then_app_owned() {
        let process = PathBuf::from("C:\\temp\\process.log");
        let registry = PathBuf::from("C:\\temp\\registry.log");
        let app_owned = PathBuf::from("C:\\temp\\app-owned.log");

        let resolution = resolve_sync_key_source(
            Some(process.clone()),
            Some(registry.clone()),
            app_owned.clone(),
            |_| true,
        );
        assert_eq!(resolution.source.kind, SyncKeySourceKind::ProcessEnv);
        assert_eq!(resolution.source.path, process);
        assert!(resolution.skipped.is_empty());

        let resolution =
            resolve_sync_key_source(None, Some(registry.clone()), app_owned.clone(), |_| true);
        assert_eq!(resolution.source.kind, SyncKeySourceKind::Registry);
        assert_eq!(resolution.source.path, registry);
        assert!(resolution.skipped.is_empty());

        let resolution = resolve_sync_key_source(None, None, app_owned.clone(), |_| true);
        assert_eq!(resolution.source.kind, SyncKeySourceKind::AppOwned);
        assert_eq!(resolution.source.path, app_owned);
        assert!(resolution.skipped.is_empty());
    }

    #[test]
    fn sync_key_resolution_skips_unusable_overrides() {
        let process = PathBuf::from("C:\\Users\\someone\\Documents");
        let registry = PathBuf::from("C:\\temp\\registry.log");
        let app_owned = PathBuf::from("C:\\temp\\app-owned.log");

        // Only the process-env value is unusable: fall through to the registry.
        let resolution = resolve_sync_key_source(
            Some(process.clone()),
            Some(registry.clone()),
            app_owned.clone(),
            |path| path != process,
        );
        assert_eq!(resolution.source.kind, SyncKeySourceKind::Registry);
        assert_eq!(resolution.source.path, registry);
        assert_eq!(
            resolution.skipped,
            vec![SkippedSyncKey {
                kind: SyncKeySourceKind::ProcessEnv,
                path: process.clone(),
            }]
        );

        let resolution = resolve_sync_key_source(
            Some(process.clone()),
            Some(registry.clone()),
            app_owned.clone(),
            |_| false,
        );
        assert_eq!(resolution.source.kind, SyncKeySourceKind::AppOwned);
        assert_eq!(resolution.source.path, app_owned);
        assert_eq!(
            resolution.skipped,
            vec![
                SkippedSyncKey {
                    kind: SyncKeySourceKind::ProcessEnv,
                    path: process,
                },
                SkippedSyncKey {
                    kind: SyncKeySourceKind::Registry,
                    path: registry,
                },
            ]
        );
    }

    #[test]
    fn sync_key_resolution_never_skips_app_owned() {
        let app_owned = PathBuf::from("C:\\temp\\app-owned.log");

        // App-owned is selected even when nothing satisfies the predicate.
        let resolution = resolve_sync_key_source(None, None, app_owned.clone(), |_| false);
        assert_eq!(resolution.source.kind, SyncKeySourceKind::AppOwned);
        assert_eq!(resolution.source.path, app_owned);
        assert!(resolution.skipped.is_empty());
    }

    #[test]
    fn sync_key_override_usable_requires_existing_regular_file() {
        let temp_dir = unique_temp_dir("override-usable");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let file_path = temp_dir.join("keys.log");
        fs::write(&file_path, b"CLIENT_RANDOM ...").expect("write file");

        assert!(
            !sync_key_override_usable(&temp_dir),
            "directory is not usable"
        );
        assert!(
            sync_key_override_usable(&file_path),
            "existing file is usable"
        );
        assert!(
            !sync_key_override_usable(&temp_dir.join("missing.log")),
            "nonexistent path is not usable"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn detects_steam_paths() {
        assert!(is_steam_game_path(Path::new(
            "F:\\SteamLibrary\\steamapps\\common\\Arc Raiders\\PioneerGame.exe"
        )));
        assert_eq!(
            resolve_platform(
                LauncherPlatform::Auto,
                Some(Path::new(
                    "F:\\SteamLibrary\\steamapps\\common\\Arc Raiders\\PioneerGame.exe"
                ))
            ),
            LauncherPlatform::Steam
        );
    }

    #[test]
    fn launcher_status_labels_are_stable() {
        assert_eq!(LauncherStatus::Ready.label(), "Ready");
        assert_eq!(LauncherStatus::NeedsRestart.label(), "Needs restart");
        assert_eq!(LauncherStatus::NotRunning.label(), "Not running");
        assert_eq!(LauncherStatus::Unknown.label(), "Unknown");
    }

    #[test]
    fn steam_launch_plan_uses_app_id() {
        assert_eq!(ARC_RAIDERS_STEAM_APP_ID, 1808500);
    }

    #[test]
    fn setup_plan_sets_child_env_only_when_needed() {
        let temp_dir = unique_temp_dir("launch-env");
        let process_plan = LauncherSetupPlan {
            platform: LauncherPlatform::Direct,
            setup_source: SyncKeySource {
                kind: SyncKeySourceKind::ProcessEnv,
                path: temp_dir.join("process.log"),
            },
            game_executable: None,
            steam_exe: None,
            epic_launcher_exe: None,
        };
        assert!(process_plan.explicit_sync_key_path().is_none());

        let app_log = temp_dir.join("app.log");
        let app_plan = LauncherSetupPlan {
            platform: LauncherPlatform::Steam,
            setup_source: SyncKeySource {
                kind: SyncKeySourceKind::AppOwned,
                path: app_log.clone(),
            },
            game_executable: None,
            steam_exe: Some(temp_dir.join("steam.exe")),
            epic_launcher_exe: None,
        };
        assert_eq!(app_plan.explicit_sync_key_path(), Some(app_log.as_path()));
    }

    #[test]
    fn prepare_sync_key_truncates_only_app_owned_file() {
        let temp_dir = unique_temp_dir("prepare-sync-key");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let global_path = temp_dir.join("global.log");
        let app_path = temp_dir.join("app.log");
        fs::write(&global_path, b"keep this").expect("write global file");
        fs::write(&app_path, b"remove this").expect("write app file");

        prepare_sync_key_for_launch(&SyncKeySource {
            kind: SyncKeySourceKind::Registry,
            path: global_path.clone(),
        })
        .expect("prepare global sync key");
        prepare_sync_key_for_launch(&SyncKeySource {
            kind: SyncKeySourceKind::AppOwned,
            path: app_path.clone(),
        })
        .expect("prepare app sync key");

        assert_eq!(fs::read(&global_path).expect("read global"), b"keep this");
        assert_eq!(fs::read(&app_path).expect("read app"), b"");
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("arctracker-sync-{label}-{nanos}"))
    }
}
