//! Self-updater for ARCTracker Sync.
//!
//! Checks the public GitHub releases of `RaidTheory/ARCTrackerSync` via the
//! anonymous Releases API and, when the user opts in, downloads the release
//! `.zip`, verifies it against the release's `SHA256SUMS` asset, and swaps the
//! running executable in place. No backend, token, or CDN in this path — just
//! GitHub. A release without `SHA256SUMS` is rejected; there is no unverified
//! install path.
//!
//! No egui here (mirroring `sync_client`); the app drives this from the
//! background worker thread and reflects progress in the UI.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Public releases repo. Source lives in the internal `arctracker` repo; builds
/// are released here for the updater to read.
const RELEASES_API: &str = "https://api.github.com/repos/RaidTheory/ARCTrackerSync/releases/latest";
/// GitHub returns 403 without a `User-Agent`.
const USER_AGENT: &str = concat!("arctracker-sync/", env!("CARGO_PKG_VERSION"));
const EXE_NAME: &str = "arctracker-sync.exe";
/// Checksum asset published by `.github/workflows/release.yml`. Releases
/// without it are rejected at check time.
const SUMS_ASSET: &str = "SHA256SUMS";

/// Everything the changelog dialog and installer need about the latest release.
#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: Version,
    pub tag: String,
    pub notes: String,
    pub download_url: String,
    /// Matched against `SHA256SUMS` lines when verifying.
    pub asset_name: String,
    /// Progress fallback when the download has no `Content-Length`.
    pub size: u64,
    pub sums_url: String,
}

/// Streamed install progress, sent from the worker thread to the UI.
#[derive(Debug, Clone)]
pub enum InstallProgress {
    Downloading { received: u64, total: Option<u64> },
    Verifying,
    Installing,
}

// ----- GitHub JSON (only the fields we use) ----------------------------------------

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    size: u64,
    browser_download_url: String,
}

/// Short-timeout agent for the small JSON / checksum requests.
fn api_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
}

/// No overall timeout (a multi-MB body would blow a 30s cap), but a per-read
/// timeout so a stalled connection can't wedge the worker.
fn download_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(60))
        .build()
}

pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is valid semver")
}

pub fn is_newer(remote: &Version) -> bool {
    version_is_newer(remote, &current_version())
}

fn version_is_newer(remote: &Version, current: &Version) -> bool {
    remote > current
}

fn parse_tag(tag: &str) -> Result<Version, String> {
    let trimmed = tag.trim();
    let bare = trimmed.strip_prefix('v').unwrap_or(trimmed);
    Version::parse(bare).map_err(|error| format!("release tag '{tag}' is not a version: {error}"))
}

/// Normally the public GitHub endpoint; in debug builds the `ARC_UPDATE_API_URL`
/// env var can redirect it for offline testing. The override is compiled out of
/// release builds, so production can only ever hit GitHub.
fn releases_api_url() -> String {
    #[cfg(debug_assertions)]
    if let Ok(url) = std::env::var("ARC_UPDATE_API_URL") {
        if !url.is_empty() {
            tracing::warn!(url = %url, "ARC_UPDATE_API_URL override active (debug build)");
            return url;
        }
    }
    RELEASES_API.to_string()
}

/// Fetch the latest published (non-draft, non-prerelease) release. Blocking;
/// call from a worker thread.
pub fn fetch_latest() -> Result<ReleaseInfo, String> {
    fetch_latest_from(&releases_api_url())
}

/// `fetch_latest` against an explicit API URL, so integration tests can point
/// it at a local server.
pub fn fetch_latest_from(api_url: &str) -> Result<ReleaseInfo, String> {
    let response = api_agent()
        .get(api_url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|error| format!("checking for updates: {error}"))?;

    let release: GhRelease = response
        .into_json()
        .map_err(|error| format!("reading release information: {error}"))?;

    if release.draft || release.prerelease {
        return Err("latest release is a draft or pre-release".to_string());
    }

    let version = parse_tag(&release.tag_name)?;

    let zip = release
        .assets
        .iter()
        .find(|asset| asset.name.to_ascii_lowercase().ends_with(".zip"))
        .ok_or_else(|| "release has no .zip download".to_string())?;

    // Fail at check time so a mispublished release shows up on every update
    // check, not only when someone tries to install it.
    let sums_url = release
        .assets
        .iter()
        .find(|asset| asset.name.eq_ignore_ascii_case(SUMS_ASSET))
        .map(|asset| asset.browser_download_url.clone())
        .ok_or_else(|| format!("release has no {SUMS_ASSET} checksum asset"))?;

    Ok(ReleaseInfo {
        version,
        tag: release.tag_name,
        notes: release.body.unwrap_or_default(),
        download_url: zip.browser_download_url.clone(),
        asset_name: zip.name.clone(),
        size: zip.size,
        sums_url,
    })
}

/// Download → verify → swap the running executable. On `Ok` the new exe is in
/// place and the caller should relaunch and exit.
pub fn download_and_install(
    release: &ReleaseInfo,
    on_progress: impl Fn(InstallProgress),
) -> Result<(), String> {
    let work_dir = create_work_dir()?;

    let zip_path = work_dir.join("download.zip");
    let digest = download_to_file(release, &zip_path, &on_progress)?;

    on_progress(InstallProgress::Verifying);
    verify_checksum(&release.sums_url, &release.asset_name, &digest)?;
    let new_exe = extract_exe(&zip_path, &work_dir)?;

    on_progress(InstallProgress::Installing);
    self_replace::self_replace(&new_exe)
        .map_err(|error| format!("installing the update: {error}"))?;

    let _ = std::fs::remove_dir_all(&work_dir);
    Ok(())
}

/// Create the temp work directory the update is downloaded and unpacked in.
///
/// This process runs elevated while `%TEMP%` is writable by the same user's
/// non-elevated processes, so a predictable path would let one of them swap
/// the extracted exe between `extract_exe` and `self_replace` (a TOCTOU
/// elevation of privilege). Two defenses, both load-bearing:
/// - the directory name carries a CSPRNG suffix and `create_dir` refuses a
///   pre-existing (pre-planted) directory, and
/// - the directory is labeled High mandatory integrity, so medium-IL processes
///   cannot write into it at all (Windows no-write-up policy).
fn create_work_dir() -> Result<PathBuf, String> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random)
        .map_err(|error| format!("generating the update folder name: {error}"))?;

    let work_dir =
        std::env::temp_dir().join(format!("arctracker-sync-update-{}", hex::encode(random)));
    std::fs::create_dir(&work_dir)
        .map_err(|error| format!("preparing the update folder: {error}"))?;

    raise_dir_integrity(&work_dir)?;
    Ok(work_dir)
}

/// Label `dir` (and everything created inside it) High mandatory integrity via
/// `icacls`. Failure is a hard error — installing through an unprotected folder
/// would defeat the TOCTOU defense above.
#[cfg(windows)]
fn raise_dir_integrity(dir: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let output = Command::new("icacls")
        .arg(dir)
        .args(["/setintegritylevel", "(OI)(CI)High"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("protecting the update folder: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "protecting the update folder: icacls failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn raise_dir_integrity(_dir: &Path) -> Result<(), String> {
    Ok(())
}

/// Stream the asset to `zip_path` and return its hex SHA-256, hashed inline so
/// the bytes are never read twice.
pub fn download_to_file(
    release: &ReleaseInfo,
    zip_path: &Path,
    on_progress: &impl Fn(InstallProgress),
) -> Result<String, String> {
    let response = download_agent()
        .get(&release.download_url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|error| format!("downloading the update: {error}"))?;

    let total = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .or(Some(release.size).filter(|n| *n > 0));

    let mut reader = response.into_reader();
    let mut file = File::create(zip_path).map_err(|error| format!("saving the update: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut received: u64 = 0;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("downloading the update: {error}"))?;
        if read == 0 {
            break;
        }
        file.write_all(&buffer[..read])
            .map_err(|error| format!("saving the update: {error}"))?;
        hasher.update(&buffer[..read]);
        received += read as u64;
        on_progress(InstallProgress::Downloading { received, total });
    }

    file.flush()
        .map_err(|error| format!("saving the update: {error}"))?;
    Ok(hex::encode(hasher.finalize()))
}

/// Download the `SHA256SUMS` sidecar and check the line for `asset_name`
/// against `actual` (hex).
pub fn verify_checksum(sums_url: &str, asset_name: &str, actual: &str) -> Result<(), String> {
    let body = download_agent()
        .get(sums_url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|error| format!("downloading the checksum: {error}"))?
        .into_string()
        .map_err(|error| format!("reading the checksum: {error}"))?;

    match find_expected_hash(&body, asset_name) {
        Some(expected) if expected == actual.to_ascii_lowercase() => Ok(()),
        Some(_) => Err("the update download did not match its checksum".to_string()),
        // Sidecar exists but doesn't list our asset — unverifiable, not trusted.
        None => Err("the update checksum did not cover this download".to_string()),
    }
}

/// Find the lowercase hex hash for `asset_name` in a `SHA256SUMS` body
/// (`<hash>  <name>` per line, as `sha256sum` and the release workflow emit).
fn find_expected_hash(body: &str, asset_name: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        // Filenames may be prefixed with `*` (binary mode) or `./`.
        let name = parts
            .next_back()?
            .trim_start_matches('*')
            .trim_start_matches("./");
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        if base.eq_ignore_ascii_case(asset_name) {
            Some(hash.to_ascii_lowercase())
        } else {
            None
        }
    })
}

pub fn extract_exe(zip_path: &Path, work_dir: &Path) -> Result<PathBuf, String> {
    let file = File::open(zip_path).map_err(|error| format!("opening the update: {error}"))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| format!("the update download is not a valid package: {error}"))?;

    let mut exe_index = None;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("reading the update package: {error}"))?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name();
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        if base.eq_ignore_ascii_case(EXE_NAME) {
            exe_index = Some(index);
            break;
        }
    }

    let exe_index =
        exe_index.ok_or_else(|| format!("the update package does not contain {EXE_NAME}"))?;
    let new_exe = work_dir.join(EXE_NAME);

    let mut entry = archive
        .by_index(exe_index)
        .map_err(|error| format!("reading the update package: {error}"))?;
    let mut out =
        File::create(&new_exe).map_err(|error| format!("unpacking the update: {error}"))?;
    std::io::copy(&mut entry, &mut out)
        .map_err(|error| format!("unpacking the update: {error}"))?;

    Ok(new_exe)
}

/// Launch the freshly-installed executable and let the caller exit. The child
/// inherits this (already-elevated) process's token, so no second UAC prompt.
/// CWD is moved off the install directory so the exiting process doesn't pin it.
///
/// `--relaunched` tells the single-instance guard this is an update takeover, so
/// it becomes the primary instead of bouncing off the still-exiting old process
/// (which would momentarily leave zero instances running).
pub fn relaunch() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| format!("locating the app: {error}"))?;
    std::process::Command::new(exe)
        .arg("--relaunched")
        .current_dir(std::env::temp_dir())
        .spawn()
        .map_err(|error| format!("restarting the app: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags_with_and_without_prefix() {
        assert_eq!(parse_tag("v0.2.0").unwrap(), Version::new(0, 2, 0));
        assert_eq!(parse_tag("0.2.0").unwrap(), Version::new(0, 2, 0));
        assert_eq!(parse_tag("  v1.4.7 ").unwrap(), Version::new(1, 4, 7));
        assert!(parse_tag("not-a-version").is_err());
    }

    #[test]
    fn finds_hash_in_sums_body() {
        // The exact line format .github/workflows/release.yml emits in the
        // public repo: "<lowercase-hex>  <zip name>".
        let body = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  arctracker-sync-0.2.0-windows-x64.zip\n";
        assert_eq!(
            find_expected_hash(body, "arctracker-sync-0.2.0-windows-x64.zip").as_deref(),
            Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
    }

    #[test]
    fn finds_hash_with_prefixes_and_case_differences() {
        assert_eq!(
            find_expected_hash("ABCD12  *app.zip", "app.zip").as_deref(),
            Some("abcd12") // `*` binary-mode prefix stripped, hash lowercased
        );
        assert_eq!(
            find_expected_hash("abcd12  ./app.zip", "app.zip").as_deref(),
            Some("abcd12")
        );
        assert_eq!(
            find_expected_hash("abcd12  dist/release\\App.ZIP", "app.zip").as_deref(),
            Some("abcd12") // path components dropped, name match is case-insensitive
        );
    }

    #[test]
    fn missing_asset_yields_no_hash() {
        assert_eq!(find_expected_hash("abcd12  other.zip", "app.zip"), None);
        assert_eq!(find_expected_hash("", "app.zip"), None);
        assert_eq!(find_expected_hash("just-one-token", "app.zip"), None);
    }

    #[test]
    fn newer_compares_by_semver_not_lexically() {
        let current = Version::new(0, 1, 0);
        assert!(version_is_newer(&Version::new(0, 2, 0), &current));
        assert!(version_is_newer(&Version::new(0, 10, 0), &current)); // 0.10 > 0.1 numerically
        assert!(!version_is_newer(&Version::new(0, 1, 0), &current)); // equal is not newer
        assert!(!version_is_newer(&Version::new(0, 0, 9), &current));
        // A pre-release is older than its release per semver ordering.
        assert!(!version_is_newer(
            &Version::parse("0.2.0-rc.1").unwrap(),
            &Version::new(0, 2, 0)
        ));
    }
}
