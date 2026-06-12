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

    /// Grant the capture capability via a single graphical `pkexec` prompt, then
    /// restart as the same user. We do NOT run the GUI itself under `pkexec`:
    /// a root process loses access to the user's Wayland/X session (pkexec
    /// scrubs the environment), so the window would never appear. Instead we
    /// `setcap cap_net_raw+ep` the binary file — that capability is picked up on
    /// the next `exec`, so we re-launch as the normal user and exit this copy.
    pub fn relaunch_elevated() -> Result<()> {
        if is_elevated() {
            return Ok(());
        }
        let exe = std::env::current_exe()?;
        let setcap = find_setcap()
            .ok_or_else(|| anyhow!("setcap not found — install libcap (it provides setcap)"))?;

        let status = std::process::Command::new("pkexec")
            .arg(setcap)
            .arg("cap_net_raw+ep")
            .arg(&exe)
            .status()
            .map_err(|error| {
                anyhow!("could not run pkexec (install polkit, or run `sudo setcap cap_net_raw+ep {}`): {error}", exe.display())
            })?;
        if !status.success() {
            // Non-zero also covers the user cancelling the password dialog.
            return Err(anyhow!(
                "granting the capture capability was cancelled or failed"
            ));
        }

        // The file now carries CAP_NET_RAW; a fresh exec as this same user picks
        // it up and keeps the user's display session.
        std::process::Command::new(&exe)
            .spawn()
            .map_err(|error| anyhow!("restarting after granting capability: {error}"))?;
        std::process::exit(0);
    }

    /// Locate the `setcap` binary. pkexec wants an absolute path, and `setcap`
    /// lives in different places across distros (usr-merged Arch vs split /sbin).
    fn find_setcap() -> Option<std::path::PathBuf> {
        let candidates = [
            "/usr/sbin/setcap",
            "/sbin/setcap",
            "/usr/bin/setcap",
            "/bin/setcap",
        ];
        candidates
            .iter()
            .map(std::path::PathBuf::from)
            .find(|path| path.exists())
            .or_else(|| {
                std::env::var_os("PATH").and_then(|paths| {
                    std::env::split_paths(&paths)
                        .map(|dir| dir.join("setcap"))
                        .find(|path| path.exists())
                })
            })
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
