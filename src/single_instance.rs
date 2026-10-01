//! Single-instance guard.
//!
//! ARCTracker Sync should run as one window per session. Launching the exe again
//! must not open a second copy: instead it signals the running instance to come
//! to the foreground and exits. We use two session-local named kernel objects:
//!
//! - a **named mutex** to detect that an instance already owns this session, and
//! - a **named auto-reset event** the new launch sets to wake the running one.
//!
//! Both objects live in the per-session namespace. The app always runs elevated
//! (`RequireAdministrator`), so every launch shares the same session and
//! integrity level and sees the same names.
//!
//! The freshly-installed process the updater spawns (`relaunch`, passing
//! `--relaunched`) is special: the old instance is mid-exit and still holds the
//! mutex for a moment, so the relaunched copy *waits* for the mutex instead of
//! treating itself as a duplicate. That keeps exactly one instance alive across
//! an update rather than leaving zero.

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

    /// Session-local names. The `.` separators keep them distinct from any
    /// global object and out of the `Global\` namespace.
    const MUTEX_NAME: &str = "ARCTrackerSync.SingleInstance.Mutex";
    const EVENT_NAME: &str = "ARCTrackerSync.SingleInstance.Event";

    const ERROR_ALREADY_EXISTS: u32 = 183;
    const WAIT_OBJECT_0: u32 = 0;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    /// `AllowSetForegroundWindow(ASFW_ANY)` lets any process steal foreground,
    /// which is how the (background) running instance is permitted to raise its
    /// window when we signal it.
    const ASFW_ANY: u32 = 0xFFFF_FFFF;
    /// Listener wake cadence; also the responsiveness of the stop check on quit.
    const LISTEN_TICK_MS: u32 = 750;

    /// Outcome of trying to become the session's sole instance.
    pub enum Acquisition {
        /// We own the session. Keep the guard for the process lifetime.
        Primary(PrimaryGuard),
        /// Another instance owns it; the caller should `signal_existing` and exit.
        AlreadyRunning,
    }

    /// Holds the named objects for the lifetime of the primary instance.
    pub struct PrimaryGuard {
        // Held only for its lifetime/Drop effect: an open handle keeps the named
        // mutex alive (so peers keep seeing ERROR_ALREADY_EXISTS) and closes it on
        // drop. Never read directly, hence the allow.
        #[allow(dead_code)]
        mutex: Handle,
        event: Handle,
    }

    /// Try to become the sole instance.
    ///
    /// `relaunched` is true only for the updater's freshly-spawned process. The
    /// old instance is exiting but still holds a mutex handle for a moment, so a
    /// relaunch must take over as primary rather than defer — otherwise an update
    /// could momentarily leave zero instances. Both holding a handle to the same
    /// named mutex briefly is fine; the old handle closes when that process exits.
    pub fn acquire(relaunched: bool) -> Acquisition {
        let mutex = create_mutex();
        // Only a valid handle reporting ERROR_ALREADY_EXISTS means a peer instance
        // owns the session. A creation failure (null) falls through to Primary as
        // a best effort rather than wrongly exiting as a duplicate.
        let peer_running = !mutex.is_null() && last_error() == ERROR_ALREADY_EXISTS;

        if peer_running && !relaunched {
            return Acquisition::AlreadyRunning;
        }

        // Auto-reset event: each `SetEvent` wakes exactly one `WaitForSingleObject`.
        let event = create_event();
        Acquisition::Primary(PrimaryGuard { mutex, event })
    }

    /// Wake the running instance so it raises its window, then return so the
    /// caller (the duplicate launch) can exit.
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
        /// Spawn the listener thread that waits on the named event and calls
        /// `on_signal` each time a duplicate launch wakes us. Stops (closing the
        /// handles) once `stop` is set. The objects are owned by the thread so
        /// they outlive `self` for the rest of the process.
        pub fn spawn_listener(self, stop: Arc<AtomicBool>, on_signal: impl Fn() + Send + 'static) {
            // No event handle (creation failed) means we cannot listen; the mutex
            // still guards against duplicates, they just won't raise our window.
            if self.event.is_null() {
                // Keep the mutex alive for the process lifetime regardless.
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
                // `self` (mutex + event handles) drops here, closing both.
                drop(self);
            });
        }
    }

    fn create_mutex() -> Handle {
        let name = wide_null(MUTEX_NAME);
        // initial_owner = 0: we don't need to own it, only to detect/observe it.
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

    /// Non-Windows builds are always the sole instance (the app ships Windows-only;
    /// this keeps the crate cross-compilable).
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
