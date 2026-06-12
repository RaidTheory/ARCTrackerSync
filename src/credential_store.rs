use anyhow::Result;

#[cfg(windows)]
const TARGET_NAME: &str = "ARCTracker Sync Desktop Session";

#[cfg(windows)]
pub fn load_auth_token() -> Result<Option<String>> {
    windows_credential_store::load(TARGET_NAME)
}

#[cfg(windows)]
pub fn save_auth_token(token: &str) -> Result<()> {
    windows_credential_store::save(TARGET_NAME, token)
}

#[cfg(windows)]
pub fn clear_auth_token() -> Result<()> {
    windows_credential_store::clear(TARGET_NAME)
}

#[cfg(target_os = "linux")]
pub fn load_auth_token() -> Result<Option<String>> {
    let path = linux_token_store::token_path()?;
    match std::fs::read_to_string(&path) {
        Ok(token) => {
            let token = token.trim();
            Ok((!token.is_empty()).then(|| token.to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display())),
    }
}

#[cfg(target_os = "linux")]
pub fn save_auth_token(token: &str) -> Result<()> {
    linux_token_store::save(token)
}

#[cfg(target_os = "linux")]
pub fn clear_auth_token() -> Result<()> {
    let path = linux_token_store::token_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).map_err(|e| anyhow::anyhow!("deleting {}: {e}", path.display())),
    }
}

/// No OS keyring on Linux without a dbus/secret-service dependency, so the
/// ArcTracker session token is persisted to a `0600` file in the app's data
/// directory — readable only by the owning user, the same trust boundary as
/// Windows Credential Manager's per-user store.
#[cfg(target_os = "linux")]
mod linux_token_store {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use anyhow::{anyhow, Context, Result};
    use directories::ProjectDirs;

    pub fn token_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("io", "ArcTracker", "Sync")
            .ok_or_else(|| anyhow!("could not resolve app data path"))?;
        Ok(dirs.data_local_dir().join("session-token"))
    }

    pub fn save(token: &str) -> Result<()> {
        let path = token_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        file.write_all(token.as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn load_auth_token() -> Result<Option<String>> {
    Ok(None)
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn save_auth_token(_token: &str) -> Result<()> {
    Ok(())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn clear_auth_token() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
mod windows_credential_store {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::slice;

    use anyhow::{anyhow, Context, Result};

    const CRED_TYPE_GENERIC: u32 = 1;
    const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
    const ERROR_NOT_FOUND: u32 = 1168;

    pub fn load(target_name: &str) -> Result<Option<String>> {
        let target_name = wide_null(target_name);
        let mut credential = std::ptr::null_mut();
        let ok = unsafe { CredReadW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };

        if ok == 0 {
            let error = unsafe { GetLastError() };
            if error == ERROR_NOT_FOUND {
                return Ok(None);
            }
            return Err(anyhow!(
                "reading saved sign-in failed with Windows error {error}"
            ));
        }

        let credential = CredentialPtr(credential);
        let credential_ref = unsafe { &*credential.0 };
        if credential_ref.credential_blob.is_null() || credential_ref.credential_blob_size == 0 {
            return Ok(None);
        }

        let bytes = unsafe {
            slice::from_raw_parts(
                credential_ref.credential_blob,
                credential_ref.credential_blob_size as usize,
            )
        };
        let token = String::from_utf8(bytes.to_vec()).context("saved sign-in was not UTF-8")?;
        Ok(Some(token))
    }

    pub fn save(target_name: &str, token: &str) -> Result<()> {
        let target_name = wide_null(target_name);
        let user_name = wide_null("ARCTracker Sync");
        let token_bytes = token.as_bytes();
        if token_bytes.len() > 5120 {
            return Err(anyhow!(
                "saved sign-in is too large for Windows Credential Manager"
            ));
        }

        let credential = CredentialW {
            flags: 0,
            type_: CRED_TYPE_GENERIC,
            target_name: target_name.as_ptr() as *mut u16,
            comment: std::ptr::null_mut(),
            last_written: FileTime {
                low_date_time: 0,
                high_date_time: 0,
            },
            credential_blob_size: token_bytes.len() as u32,
            credential_blob: token_bytes.as_ptr() as *mut u8,
            persist: CRED_PERSIST_LOCAL_MACHINE,
            attribute_count: 0,
            attributes: std::ptr::null_mut(),
            target_alias: std::ptr::null_mut(),
            user_name: user_name.as_ptr() as *mut u16,
        };

        let ok = unsafe { CredWriteW(&credential, 0) };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            return Err(anyhow!("saving sign-in failed with Windows error {error}"));
        }

        Ok(())
    }

    pub fn clear(target_name: &str) -> Result<()> {
        let target_name = wide_null(target_name);
        let ok = unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NOT_FOUND {
                return Err(anyhow!(
                    "clearing saved sign-in failed with Windows error {error}"
                ));
            }
        }
        Ok(())
    }

    fn wide_null(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    struct CredentialPtr(*mut CredentialW);

    impl Drop for CredentialPtr {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CredFree(self.0.cast::<c_void>()) };
            }
        }
    }

    #[repr(C)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    struct CredentialW {
        flags: u32,
        type_: u32,
        target_name: *mut u16,
        comment: *mut u16,
        last_written: FileTime,
        credential_blob_size: u32,
        credential_blob: *mut u8,
        persist: u32,
        attribute_count: u32,
        attributes: *mut c_void,
        target_alias: *mut u16,
        user_name: *mut u16,
    }

    #[link(name = "Advapi32")]
    extern "system" {
        fn CredReadW(
            target_name: *const u16,
            type_: u32,
            flags: u32,
            credential: *mut *mut CredentialW,
        ) -> i32;
        fn CredWriteW(credential: *const CredentialW, flags: u32) -> i32;
        fn CredDeleteW(target_name: *const u16, type_: u32, flags: u32) -> i32;
        fn CredFree(buffer: *mut c_void);
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetLastError() -> u32;
    }
}
