use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::launch::LauncherPlatform;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub selected_interface: Option<String>,
    pub game_executable_path: Option<PathBuf>,
    #[serde(default)]
    pub platform: LauncherPlatform,
    /// Persisted display language (a UI locale code). `None` means "match
    /// Windows" — resolution falls back to the system UI language.
    #[serde(default)]
    pub language: Option<String>,
    /// Whether closing the window hides to tray instead of quitting (default on).
    #[serde(default = "default_keep_in_tray")]
    pub keep_in_tray: bool,
}

fn default_keep_in_tray() -> bool {
    true
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            selected_interface: None,
            game_executable_path: None,
            platform: LauncherPlatform::default(),
            language: None,
            keep_in_tray: default_keep_in_tray(),
        }
    }
}

pub fn load() -> AppConfig {
    let Some(path) = config_path() else {
        return AppConfig::default();
    };

    let Ok(bytes) = fs::read(path) else {
        return AppConfig::default();
    };

    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(config: &AppConfig) -> Result<()> {
    let path = config_path().context("could not resolve config path")?;
    let parent = path.parent().context("config path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let bytes = serde_json::to_vec_pretty(config)?;

    // Write to a sibling temp file then rename over the target so a crash or
    // exit mid-write can never leave a half-written config.json (which load()
    // would silently reset to defaults). `rename` is atomic on NTFS when both
    // paths share a directory; clean up the temp file if anything fails.
    let tmp_path = path.with_extension("json.tmp");
    if let Err(error) =
        fs::write(&tmp_path, &bytes).with_context(|| format!("writing {}", tmp_path.display()))
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&tmp_path, &path)
        .with_context(|| format!("replacing {} with {}", path.display(), tmp_path.display()))
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

pub fn process_sync_key_env() -> Option<PathBuf> {
    std::env::var_os("SSLKEYLOGFILE")
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)
}

pub fn registry_sync_key_path() -> Option<PathBuf> {
    read_sync_key_path_from_registry()
}

pub fn app_owned_sync_key_path() -> Result<PathBuf> {
    let dirs = project_dirs().context("could not resolve app data path")?;
    Ok(dirs.data_local_dir().join("sync-key.log"))
}

/// Delete the app-owned TLS sync-key file. The secrets in it can decrypt all
/// of the user's port-443 traffic, so it must not outlive the capture session.
/// User-set Process/Registry SSLKEYLOGFILE sources are never touched. A
/// missing file is success.
pub fn clear_app_owned_sync_key() -> Result<()> {
    let path = app_owned_sync_key_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("deleting sync key {}", path.display())),
    }
}

pub fn steam_install_path() -> Option<PathBuf> {
    read_steam_install_path()
}

fn config_path() -> Option<PathBuf> {
    project_dirs().map(|dirs| dirs.config_dir().join("config.json"))
}

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("io", "ArcTracker", "Sync")
}

#[cfg(not(windows))]
fn read_sync_key_path_from_registry() -> Option<PathBuf> {
    None
}

#[cfg(not(windows))]
fn read_steam_install_path() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn read_sync_key_path_from_registry() -> Option<PathBuf> {
    registry_value(HKEY_CURRENT_USER, "Environment", "SSLKEYLOGFILE")
        .or_else(|| {
            registry_value(
                HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                "SSLKEYLOGFILE",
            )
        })
        .map(PathBuf::from)
}

#[cfg(windows)]
fn read_steam_install_path() -> Option<PathBuf> {
    registry_value(HKEY_CURRENT_USER, "Software\\Valve\\Steam", "SteamPath")
        .or_else(|| {
            registry_value(
                HKEY_LOCAL_MACHINE,
                "SOFTWARE\\WOW6432Node\\Valve\\Steam",
                "InstallPath",
            )
        })
        .map(PathBuf::from)
}

#[cfg(windows)]
fn registry_value(root: Hkey, subkey: &str, value_name: &str) -> Option<std::ffi::OsString> {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    const ERROR_MORE_DATA: i32 = 234;
    const ERROR_SUCCESS: i32 = 0;
    const RRF_RT_REG_EXPAND_SZ: u32 = 0x0000_0004;
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;

    let subkey = std::ffi::OsStr::new(subkey)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let value_name = std::ffi::OsStr::new(value_name)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut value_type = 0u32;
    let mut bytes = 0u32;

    let first = unsafe {
        RegGetValueW(
            root,
            subkey.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            &mut value_type,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };

    if !matches!(first, ERROR_SUCCESS | ERROR_MORE_DATA) || bytes < 2 {
        return None;
    }

    let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
    let result = unsafe {
        RegGetValueW(
            root,
            subkey.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            &mut value_type,
            buffer.as_mut_ptr().cast::<c_void>(),
            &mut bytes,
        )
    };

    if result != ERROR_SUCCESS {
        return None;
    }

    let len = buffer
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(buffer.len());
    if len == 0 {
        return None;
    }

    let value = OsString::from_wide(&buffer[..len]);
    if value_type == REG_EXPAND_SZ {
        expand_environment_string(&value).or(Some(value))
    } else {
        Some(value)
    }
}

#[cfg(windows)]
fn expand_environment_string(value: &std::ffi::OsStr) -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let source = value.encode_wide().chain(Some(0)).collect::<Vec<_>>();
    let needed = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), std::ptr::null_mut(), 0) };
    if needed == 0 {
        return None;
    }

    let mut output = vec![0u16; needed as usize];
    let written = unsafe {
        ExpandEnvironmentStringsW(source.as_ptr(), output.as_mut_ptr(), output.len() as u32)
    };
    if written == 0 || written as usize > output.len() {
        return None;
    }

    let len = output
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(output.len());
    Some(std::ffi::OsString::from_wide(&output[..len]))
}

#[cfg(windows)]
type Hkey = isize;

#[cfg(windows)]
const HKEY_CURRENT_USER: Hkey = 0x8000_0001u32 as i32 as isize;
#[cfg(windows)]
const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002u32 as i32 as isize;
#[cfg(windows)]
const REG_EXPAND_SZ: u32 = 2;

#[cfg(windows)]
#[link(name = "Advapi32")]
extern "system" {
    fn RegGetValueW(
        hkey: Hkey,
        lp_sub_key: *const u16,
        lp_value: *const u16,
        dw_flags: u32,
        pdw_type: *mut u32,
        pv_data: *mut std::ffi::c_void,
        pcb_data: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "Kernel32")]
extern "system" {
    fn ExpandEnvironmentStringsW(lp_src: *const u16, lp_dst: *mut u16, n_size: u32) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrips_game_executable_path() {
        let config = AppConfig {
            selected_interface: Some("iface".to_string()),
            game_executable_path: Some(PathBuf::from("F:\\Games\\PioneerGame.exe")),
            platform: LauncherPlatform::Steam,
            language: Some("de".to_string()),
            keep_in_tray: false,
        };

        let json = serde_json::to_string(&config).expect("serialize config");
        let decoded: AppConfig = serde_json::from_str(&json).expect("deserialize config");

        assert_eq!(
            decoded.game_executable_path,
            Some(PathBuf::from("F:\\Games\\PioneerGame.exe"))
        );
        assert_eq!(decoded.platform, LauncherPlatform::Steam);
        assert_eq!(decoded.language.as_deref(), Some("de"));
        assert!(!decoded.keep_in_tray);
    }

    #[test]
    fn keep_in_tray_defaults_on() {
        assert!(AppConfig::default().keep_in_tray);

        // A legacy config without the new fields keeps the tray on by default.
        let legacy: AppConfig = serde_json::from_str("{}").expect("deserialize legacy config");
        assert!(legacy.keep_in_tray);
        assert!(legacy.language.is_none());
    }
}
