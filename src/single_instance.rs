//! Single-instance guard.
//!
//! Launching the exe again must not open a second copy: the duplicate signals
//! the running instance to come to the foreground and exits. Two session-local
//! named kernel objects:
//!
//! - a named mutex to detect that an instance already owns this session, and
//! - a named auto-reset event the new launch sets to wake the running one.
//!
//! The app always runs elevated (`RequireAdministrator`), so every launch
//! shares the same session and integrity level and sees the same names.
//!
//! The process the updater spawns with `--relaunched` is special: the old
//! instance is mid-exit and still holds the mutex for a moment, so the
//! relaunched copy takes over as primary instead of treating itself as a
//! duplicate — otherwise an update would momentarily leave zero instances.

#[cfg(windows)]
pub use windows::{acquire, signal_existing, Acquisition, PrimaryGuard};

#[cfg(not(windows))]
pub use stub::{acquire, signal_existing, Acquisition, PrimaryGuard};

#[cfg(windows)]
mod windows {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    /// Session-local: no `Global\` prefix.
    const MUTEX_NAME: &str = "ARCTrackerSync.SingleInstance.Mutex";
    const EVENT_NAME: &str = "ARCTrackerSync.SingleInstance.Event";

    const ERROR_ALREADY_EXISTS: u32 = 183;
    const WAIT_OBJECT_0: u32 = 0;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    /// `AllowSetForegroundWindow(ASFW_ANY)` lets any process take foreground —
    /// how the background instance is permitted to raise its window when signaled.
    const ASFW_ANY: u32 = 0xFFFF_FFFF;
    /// Listener wake cadence; also the responsiveness of the stop check on quit.
    const LISTEN_TICK_MS: u32 = 750;

    pub enum Acquisition {
        /// We own the session. Keep the guard for the process lifetime.
        Primary(PrimaryGuard),
        /// Another instance owns it; the caller should `signal_existing` and exit.
        AlreadyRunning,
    }

    pub struct PrimaryGuard {
        // Never read; an open handle keeps the named mutex alive so peers keep
        // seeing ERROR_ALREADY_EXISTS, and closes it on drop.
        #[allow(dead_code)]
        mutex: Handle,
        event: Handle,
    }

    /// Try to become the sole instance.
    ///
    /// `relaunched` is true only for the updater's freshly-spawned process: the
    /// exiting instance still holds a mutex handle for a moment, so a relaunch
    /// must take over as primary rather than defer. Both holding a handle to the
    /// same named mutex briefly is fine; the old one closes when that process exits.
    pub fn acquire(relaunched: bool) -> Acquisition {
        let mutex = create_mutex();
        // Only a valid handle plus ERROR_ALREADY_EXISTS means a peer owns the
        // session. A creation failure (null) falls through to Primary rather
        // than wrongly exiting as a duplicate.
        let peer_running = !mutex.is_null() && last_error() == ERROR_ALREADY_EXISTS;

        if peer_running && !relaunched {
            return Acquisition::AlreadyRunning;
        }

        // Auto-reset event: each `SetEvent` wakes exactly one `WaitForSingleObject`.
        let event = create_event();
        Acquisition::Primary(PrimaryGuard { mutex, event })
    }

    /// Wake the running instance so it raises its window; the duplicate launch
    /// then exits.
    pub fn signal_existing() {
        // Grant the background instance the right to take foreground first.
        unsafe { AllowSetForegroundWindow(ASFW_ANY) };

        let name = wide_null(EVENT_NAME);
        let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
        if event != 0 {
            unsafe {
                SetEvent(event);
                CloseHandle(event);
            }
        }
    }

    impl PrimaryGuard {
        /// Spawn a thread that waits on the named event and calls `on_signal`
        /// each time a duplicate launch wakes us; exits (closing the handles)
        /// once `stop` is set.
        pub fn spawn_listener(self, stop: Arc<AtomicBool>, on_signal: impl Fn() + Send + 'static) {
            // No event handle means we can't listen; the mutex still guards
            // against duplicates, they just won't raise our window. Forget self
            // so the mutex stays alive for the process lifetime.
            if self.event.is_null() {
                std::mem::forget(self);
                return;
            }

            thread::spawn(move || {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let result = unsafe { WaitForSingleObject(self.event.0, LISTEN_TICK_MS) };
                    if result == WAIT_OBJECT_0 {
                        on_signal();
                    }
                }
                drop(self);
            });
        }
    }

    fn create_mutex() -> Handle {
        let name = wide_null(MUTEX_NAME);
        // initial_owner = 0: we only need to detect the mutex, not own it.
        Handle(unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) })
    }

    fn create_event() -> Handle {
        let name = wide_null(EVENT_NAME);
        // manual_reset = 0 (auto-reset), initial_state = 0 (non-signaled).
        Handle(unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) })
    }

    fn last_error() -> u32 {
        unsafe { GetLastError() }
    }

    fn wide_null(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    /// Owned Win32 HANDLE that closes on drop. `0` is the null/invalid handle.
    struct Handle(isize);

    impl Handle {
        fn is_null(&self) -> bool {
            self.0 == 0
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn CreateMutexW(attributes: *const u8, initial_owner: i32, name: *const u16) -> isize;
        fn CreateEventW(
            attributes: *const u8,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> isize;
        fn OpenEventW(desired_access: u32, inherit_handle: i32, name: *const u16) -> isize;
        fn SetEvent(event: isize) -> i32;
        fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
        fn CloseHandle(handle: isize) -> i32;
        fn GetLastError() -> u32;
    }

    #[link(name = "User32")]
    extern "system" {
        fn AllowSetForegroundWindow(process_id: u32) -> i32;
    }
}

#[cfg(not(windows))]
mod stub {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    pub enum Acquisition {
        Primary(PrimaryGuard),
        #[allow(dead_code)]
        AlreadyRunning,
    }

    pub struct PrimaryGuard;

    /// The app ships Windows-only; the stub keeps the crate cross-compilable.
    pub fn acquire(_relaunched: bool) -> Acquisition {
        Acquisition::Primary(PrimaryGuard)
    }

    pub fn signal_existing() {}

    impl PrimaryGuard {
        pub fn spawn_listener(
            self,
            _stop: Arc<AtomicBool>,
            _on_signal: impl Fn() + Send + 'static,
        ) {
        }
    }
}
