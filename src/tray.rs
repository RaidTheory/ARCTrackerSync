//! System-tray integration and Windows startup wiring.
//!
//! ARCTracker Sync lives in the tray: closing the window hides it (capture keeps
//! running) and the tray menu exposes Open / Pause-Resume / Sign out / Quit. The
//! "Start with Windows" toggle writes the HKCU `…\Run` value. On non-Windows the
//! whole module degrades to no-ops so the crate keeps compiling.
//!
//! The tray runs on a **dedicated thread with its own Win32 message pump**.
//! tray-icon/muda deliver menu and click events through a message-only window;
//! eframe's event loop does not pump those messages, so polling the event
//! channels from the UI thread never sees anything. Pumping on our own thread
//! makes the menu work.

use crate::tr;
use std::sync::Arc;

/// A command produced by clicking a tray menu entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    Open,
    TogglePause,
    SignOut,
    Quit,
}

pub type TrayCommandHandler = Arc<dyn Fn(TrayCommand) + Send + Sync + 'static>;

/// Registry value name used for the HKCU Run startup entry.
const RUN_VALUE_NAME: &str = "ARCTrackerSync";

#[cfg(windows)]
pub use windows_impl::TrayController;

#[cfg(not(windows))]
pub use stub_impl::TrayController;

/// Whether ARCTracker Sync is registered to start with Windows.
pub fn start_with_windows_enabled() -> bool {
    #[cfg(windows)]
    {
        windows_impl::run_key_matches_current_exe()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Add or remove the HKCU Run entry so the app launches at sign-in.
pub fn set_start_with_windows(enabled: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        if enabled {
            windows_impl::write_run_key()
        } else {
            windows_impl::remove_run_key()
        }
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Ok(())
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    use super::{TrayCommand, TrayCommandHandler, RUN_VALUE_NAME};
    use crate::tr;

    /// What app state asks the tray thread to change.
    enum TrayUpdate {
        Tooltip(String),
        Paused(bool),
        Stop,
    }

    /// Handle to the dedicated tray thread. Dropping it stops the thread, which
    /// removes the tray icon.
    pub struct TrayController {
        updates: Sender<TrayUpdate>,
        handle: Option<JoinHandle<()>>,
    }

    impl TrayController {
        /// Spawn the tray thread and wait for it to report that the icon is up.
        pub fn new(tooltip: &str, handler: TrayCommandHandler) -> Result<Self> {
            let (upd_tx, upd_rx) = std::sync::mpsc::channel();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let tooltip = tooltip.to_string();

            let handle = std::thread::Builder::new()
                .name("arctracker-tray".to_string())
                .spawn(move || tray_thread(tooltip, handler, upd_rx, ready_tx))
                .map_err(|error| anyhow!("spawning tray thread: {error}"))?;

            match ready_rx.recv() {
                Ok(Ok(())) => Ok(Self {
                    updates: upd_tx,
                    handle: Some(handle),
                }),
                Ok(Err(error)) => Err(anyhow!(error)),
                Err(_) => Err(anyhow!("tray thread stopped before it started")),
            }
        }

        /// Update the hover tooltip to reflect the current status.
        pub fn set_tooltip(&self, tooltip: &str) {
            let _ = self.updates.send(TrayUpdate::Tooltip(tooltip.to_string()));
        }

        /// Reflect the paused/running state in the Pause/Resume label.
        pub fn set_paused(&mut self, paused: bool) {
            let _ = self.updates.send(TrayUpdate::Paused(paused));
        }
    }

    impl Drop for TrayController {
        fn drop(&mut self) {
            let _ = self.updates.send(TrayUpdate::Stop);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    /// Body of the dedicated tray thread: build the icon + menu, then pump Win32
    /// messages and translate menu/icon events into [`TrayCommand`]s.
    fn tray_thread(
        tooltip: String,
        handler: TrayCommandHandler,
        updates: Receiver<TrayUpdate>,
        ready: Sender<std::result::Result<(), String>>,
    ) {
        let open = MenuItem::new(tr!("SyncApp.tray.open"), true, None);
        let pause_resume = MenuItem::new(tr!("SyncApp.tray.pause"), true, None);
        let sign_out = MenuItem::new(tr!("SyncApp.tray.signOut"), true, None);
        let quit = MenuItem::new(tr!("SyncApp.tray.quit"), true, None);

        let menu = Menu::new();
        if let Err(error) = menu.append_items(&[
            &open,
            &pause_resume,
            &PredefinedMenuItem::separator(),
            &sign_out,
            &quit,
        ]) {
            let _ = ready.send(Err(format!("building tray menu: {error}")));
            return;
        }

        let open_id = open.id().clone();
        let pause_id = pause_resume.id().clone();
        let sign_out_id = sign_out.id().clone();
        let quit_id = quit.id().clone();

        let tray = match TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip(&tooltip)
            .with_icon(branded_icon())
            .build()
        {
            Ok(tray) => tray,
            Err(error) => {
                let _ = ready.send(Err(format!("creating tray icon: {error}")));
                return;
            }
        };

        let _ = ready.send(Ok(()));

        let menu_channel = MenuEvent::receiver();
        let tray_channel = TrayIconEvent::receiver();

        loop {
            // Pump pending Win32 messages so the menu/icon window procs run and
            // populate the muda / tray-icon event channels.
            pump_thread_messages();

            while let Ok(event) = menu_channel.try_recv() {
                let command = if event.id == open_id {
                    Some(TrayCommand::Open)
                } else if event.id == pause_id {
                    Some(TrayCommand::TogglePause)
                } else if event.id == sign_out_id {
                    Some(TrayCommand::SignOut)
                } else if event.id == quit_id {
                    Some(TrayCommand::Quit)
                } else {
                    None
                };
                if let Some(command) = command {
                    handler(command);
                }
            }

            while let Ok(event) = tray_channel.try_recv() {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    handler(TrayCommand::Open);
                }
            }

            let mut stop = false;
            while let Ok(update) = updates.try_recv() {
                match update {
                    TrayUpdate::Tooltip(text) => {
                        let _ = tray.set_tooltip(Some(&text));
                    }
                    TrayUpdate::Paused(paused) => {
                        pause_resume.set_text(if paused {
                            tr!("SyncApp.tray.resume")
                        } else {
                            tr!("SyncApp.tray.pause")
                        });
                    }
                    TrayUpdate::Stop => stop = true,
                }
            }
            if stop {
                break;
            }

            std::thread::sleep(Duration::from_millis(30));
        }
        // `tray` drops here, which removes the icon from the notification area.
    }

    fn pump_thread_messages() {
        const PM_REMOVE: u32 = 0x0001;
        let mut msg = unsafe { std::mem::zeroed::<Msg>() };
        while unsafe { PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) } != 0 {
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    /// The ARC chevron mark as the tray glyph: 32×32 RGBA baked from
    /// `assets/arc-mark.png` by `build.rs`, so no runtime image decoder is needed.
    fn branded_icon() -> Icon {
        const RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/icon_32.rgba"));
        // 32×32×4 bytes by construction, so this cannot fail.
        Icon::from_rgba(RGBA.to_vec(), 32, 32).expect("tray icon rgba is well-formed")
    }

    pub fn run_key_matches_current_exe() -> bool {
        let Some(current) = current_exe_path() else {
            return false;
        };
        match read_run_value() {
            Some(existing) => paths_match(&existing, &current),
            None => false,
        }
    }

    pub fn write_run_key() -> Result<()> {
        let exe = current_exe_path().ok_or_else(|| anyhow!("could not resolve executable path"))?;
        let value = format!("\"{}\"", exe.display());
        set_run_value(&value)
    }

    pub fn remove_run_key() -> Result<()> {
        delete_run_value()
    }

    fn paths_match(stored: &str, current: &Path) -> bool {
        let stored = stored.trim().trim_matches('"').replace('/', "\\");
        let current = current.display().to_string().replace('/', "\\");
        stored.eq_ignore_ascii_case(&current)
    }

    fn current_exe_path() -> Option<PathBuf> {
        std::env::current_exe().ok()
    }

    const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    fn read_run_value() -> Option<String> {
        use std::ffi::{c_void, OsString};
        use std::os::windows::ffi::OsStringExt;

        const ERROR_SUCCESS: i32 = 0;
        const ERROR_MORE_DATA: i32 = 234;
        const RRF_RT_REG_SZ: u32 = 0x0000_0002;
        const RRF_RT_REG_EXPAND_SZ: u32 = 0x0000_0004;

        let subkey = wide_null(RUN_SUBKEY);
        let value_name = wide_null(RUN_VALUE_NAME);
        let mut value_type = 0u32;
        let mut bytes = 0u32;

        let first = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
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
                HKEY_CURRENT_USER,
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
        Some(
            OsString::from_wide(&buffer[..len])
                .to_string_lossy()
                .into_owned(),
        )
    }

    fn set_run_value(value: &str) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;

        const REG_SZ: u32 = 1;
        const KEY_SET_VALUE: u32 = 0x0002;
        const ERROR_SUCCESS: i32 = 0;

        let subkey = wide_null(RUN_SUBKEY);
        let mut handle: HKey = 0;
        let opened = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut handle,
            )
        };
        if opened != ERROR_SUCCESS {
            return Err(anyhow!(
                "opening Run key failed with Windows error {opened}"
            ));
        }

        let value_name = wide_null(RUN_VALUE_NAME);
        let data: Vec<u16> = std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let byte_len = (data.len() * std::mem::size_of::<u16>()) as u32;
        let result = unsafe {
            RegSetValueExW(
                handle,
                value_name.as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast::<u8>(),
                byte_len,
            )
        };
        unsafe { RegCloseKey(handle) };

        if result != ERROR_SUCCESS {
            return Err(anyhow!(
                "writing Start with Windows entry failed with Windows error {result}"
            ));
        }
        Ok(())
    }

    fn delete_run_value() -> Result<()> {
        const ERROR_SUCCESS: i32 = 0;
        const ERROR_FILE_NOT_FOUND: i32 = 2;

        let subkey = wide_null(RUN_SUBKEY);
        let value_name = wide_null(RUN_VALUE_NAME);
        let result =
            unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, subkey.as_ptr(), value_name.as_ptr()) };
        if result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND {
            return Err(anyhow!(
                "removing Start with Windows entry failed with Windows error {result}"
            ));
        }
        Ok(())
    }

    fn wide_null(value: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    type HKey = isize;
    const HKEY_CURRENT_USER: HKey = 0x8000_0001u32 as i32 as isize;

    #[link(name = "Advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: HKey,
            lp_sub_key: *const u16,
            lp_value: *const u16,
            dw_flags: u32,
            pdw_type: *mut u32,
            pv_data: *mut std::ffi::c_void,
            pcb_data: *mut u32,
        ) -> i32;
        fn RegOpenKeyExW(
            hkey: HKey,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut HKey,
        ) -> i32;
        fn RegSetValueExW(
            hkey: HKey,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> i32;
        fn RegDeleteKeyValueW(hkey: HKey, lp_sub_key: *const u16, lp_value_name: *const u16)
            -> i32;
        fn RegCloseKey(hkey: HKey) -> i32;
    }

    #[repr(C)]
    #[allow(dead_code)] // filled by PeekMessageW; we only forward it to the OS.
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[allow(dead_code)] // filled by PeekMessageW; we only forward it to the OS.
    struct Msg {
        hwnd: isize,
        message: u32,
        w_param: usize,
        l_param: isize,
        time: u32,
        pt: Point,
    }

    #[link(name = "User32")]
    extern "system" {
        fn PeekMessageW(
            msg: *mut Msg,
            hwnd: isize,
            filter_min: u32,
            filter_max: u32,
            remove: u32,
        ) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
    }
}

#[cfg(not(windows))]
mod stub_impl {
    use anyhow::Result;

    use super::TrayCommandHandler;

    /// No-op tray on non-Windows targets so the crate still builds.
    pub struct TrayController;

    impl TrayController {
        pub fn new(_tooltip: &str, _handler: TrayCommandHandler) -> Result<Self> {
            Ok(Self)
        }

        pub fn set_tooltip(&self, _tooltip: &str) {}

        pub fn set_paused(&mut self, _paused: bool) {}
    }
}

/// Tooltip text for the tray icon, derived from the synced account (if any).
pub fn tooltip_for(account: Option<&str>) -> String {
    match account {
        Some(account) => tr!("SyncApp.tray.tooltipSynced", account => account),
        None => tr!("SyncApp.tray.tooltipIdle"),
    }
}
