//! Windows elevation helpers for the raw-socket capture backend, which needs
//! Administrator. `is_elevated()` gates the readiness state; `relaunch_elevated()`
//! restarts the app with a UAC prompt on demand.

#[cfg(windows)]
pub use imp::{is_elevated, relaunch_elevated};

#[cfg(not(windows))]
pub use stub::{is_elevated, relaunch_elevated};

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;

    use anyhow::{anyhow, Result};

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: i32 = 20; // TokenElevation
    const SW_SHOWNORMAL: i32 = 1;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    pub fn is_elevated() -> bool {
        unsafe {
            let process = GetCurrentProcess();
            let mut token: isize = 0;
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TokenElevation {
                token_is_elevated: 0,
            };
            let mut returned: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                &mut elevation as *mut TokenElevation as *mut core::ffi::c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            ok != 0 && elevation.token_is_elevated != 0
        }
    }

    pub fn relaunch_elevated() -> Result<()> {
        // Already elevated — nothing to do. Matters if the embedded manifest is
        // ever relaxed from requireAdministrator so a second UAC prompt isn't
        // raised against ourselves.
        if is_elevated() {
            return Ok(());
        }

        let exe = std::env::current_exe()?;
        let operation = wide("runas");
        let file = wide(exe.to_string_lossy().as_ref());
        let result = unsafe {
            ShellExecuteW(
                0,
                operation.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        } as isize;

        if result <= 32 {
            return Err(anyhow!(
                "could not restart with administrator access (code {result})"
            ));
        }
        Ok(())
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn CloseHandle(handle: isize) -> i32;
    }

    #[link(name = "Advapi32")]
    extern "system" {
        fn OpenProcessToken(process: isize, desired_access: u32, token: *mut isize) -> i32;
        fn GetTokenInformation(
            token: isize,
            information_class: i32,
            information: *mut core::ffi::c_void,
            length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    #[link(name = "Shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: isize,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }
}

#[cfg(target_os = "linux")]
mod stub {
    use anyhow::{anyhow, Result};

    /// Capture needs `CAP_NET_RAW`. Root always has it; otherwise probe by
    /// opening an `AF_PACKET` socket, which succeeds only when the capability is
    /// present (e.g. via `setcap cap_net_raw+ep`). This drives the readiness
    /// gate the same way the Windows admin check does.
    pub fn is_elevated() -> bool {
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            true
        } else {
            false
        }
    }

    /// Re-launch the app through `pkexec` so a graphical sudo prompt grants the
    /// capture capability for this run.
    pub fn relaunch_elevated() -> Result<()> {
        if is_elevated() {
            return Ok(());
        }
        let exe = std::env::current_exe()?;
        let status = std::process::Command::new("pkexec")
            .arg(exe)
            .status()
            .map_err(|error| {
                anyhow!("could not run pkexec (install polkit, or run the app with sudo): {error}")
            })?;
        if status.success() {
            // The elevated copy now owns the session; exit this unprivileged one.
            std::process::exit(0);
        }
        Err(anyhow!("pkexec did not grant elevation"))
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
mod stub {
    use anyhow::{bail, Result};

    pub fn is_elevated() -> bool {
        true
    }

    pub fn relaunch_elevated() -> Result<()> {
        bail!("elevation is only supported on Windows")
    }
}
