//! Optional packet-capture backend using Npcap's `wpcap.dll`, loaded
//! dynamically at runtime. Npcap is never bundled, downloaded, or installed by
//! this app — the user installs it themselves from <https://npcap.com>. The
//! app must start and run normally when Npcap is absent, which is why there is
//! no import-table link against wpcap: every entry point is resolved with
//! `LoadLibraryExW`/`GetProcAddress` on first use.
//!
//! Exists as an alternative to [`crate::rawsock`] for users whose antivirus
//! interferes with raw-socket capture. Delivers link-layer frames (typically
//! `DLT_EN10MB` Ethernet), which `packet.rs` already parses.

#[cfg(windows)]
pub use imp::{Capture, Npcap};

#[cfg(not(windows))]
pub use stub::{Capture, Npcap};

/// True when a pcap device name (e.g. `\Device\NPF_{GUID}`) refers to the
/// adapter with this GetAdaptersAddresses GUID string (e.g. `{GUID}`).
/// Case-insensitive; tolerates the GUID with or without braces. The Npcap
/// loopback device (`\Device\NPF_Loopback`) never matches because the match
/// requires the braced form.
pub fn npf_name_matches_adapter(pcap_name: &str, adapter_guid: &str) -> bool {
    let bare = adapter_guid.trim_matches(|c| c == '{' || c == '}');
    if bare.is_empty() {
        return false;
    }
    let needle = format!("{{{}}}", bare.to_ascii_lowercase());
    pcap_name.to_ascii_lowercase().contains(&needle)
}

/// `pcap_pkthdr`'s timeval → unix microseconds. On 64-bit Windows `timeval`
/// is two 32-bit `long`s, hence the `i32` fields.
pub fn pkthdr_timestamp_us(ts_sec: i32, ts_usec: i32) -> i64 {
    i64::from(ts_sec) * 1_000_000 + i64::from(ts_usec)
}

#[cfg(windows)]
mod imp {
    use std::ffi::CString;
    use std::sync::OnceLock;

    use anyhow::{bail, Context, Result};

    use crate::capture_backend::{Device, Packet};

    const PCAP_ERRBUF_SIZE: usize = 256;
    const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
    // Matches rawsock's 256 KB RECV_BUF so LSO/GRO super-frames are not truncated.
    const SNAPLEN: i32 = 262_144;
    // Matches rawsock's 100 ms select() cadence; pcap_next_ex returns 0 on
    // timeout, so the capture loop keeps honoring the stop flag.
    const READ_TIMEOUT_MS: i32 = 100;
    // Matches rawsock's 8 MB SO_RCVBUF to reduce drops (best-effort).
    const KERNEL_BUFFER_BYTES: i32 = 8 * 1024 * 1024;

    const NOT_INSTALLED: &str = "Npcap is not installed (wpcap.dll could not be loaded). \
        Install Npcap from https://npcap.com, or switch the capture method back to \
        raw sockets in Settings.";

    // ---- LoadLibraryExW search flags ----
    // Lets wpcap.dll's dependency Packet.dll resolve from the directory the
    // DLL itself was loaded from (System32\Npcap).
    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

    /// Opaque `pcap_t`.
    type PcapT = core::ffi::c_void;

    /// `struct pcap_pkthdr` on 64-bit Windows: `timeval` is two 32-bit longs.
    #[repr(C)]
    struct PcapPkthdr {
        ts_sec: i32,
        ts_usec: i32,
        caplen: u32,
        len: u32,
    }

    /// Prefix of `pcap_if_t` up to the fields we read.
    #[repr(C)]
    struct PcapIf {
        next: *mut PcapIf,
        name: *mut u8,        // C string: \Device\NPF_{GUID}
        description: *mut u8, // C string, may be null
        addresses: *mut core::ffi::c_void,
        flags: u32,
    }

    /// `struct bpf_program`.
    #[repr(C)]
    struct BpfProgram {
        bf_len: u32,
        bf_insns: *mut core::ffi::c_void,
    }

    // The wpcap.dll function signatures, named so the GetProcAddress
    // transmutes below state exactly what they produce.
    type FindAllDevsFn = unsafe extern "C" fn(*mut *mut PcapIf, *mut u8) -> i32;
    type FreeAllDevsFn = unsafe extern "C" fn(*mut PcapIf);
    type OpenLiveFn = unsafe extern "C" fn(*const u8, i32, i32, i32, *mut u8) -> *mut PcapT;
    type CompileFn = unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const u8, i32, u32) -> i32;
    type SetFilterFn = unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> i32;
    type FreeCodeFn = unsafe extern "C" fn(*mut BpfProgram);
    type NextExFn = unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> i32;
    type DatalinkFn = unsafe extern "C" fn(*mut PcapT) -> i32;
    type CloseFn = unsafe extern "C" fn(*mut PcapT);
    type GetErrFn = unsafe extern "C" fn(*mut PcapT) -> *mut u8;
    type LibVersionFn = unsafe extern "C" fn() -> *const u8;
    type SetBuffFn = unsafe extern "C" fn(*mut PcapT, i32) -> i32;

    /// wpcap.dll entry points resolved via GetProcAddress. Plain `extern "C"`
    /// function pointers are `Send + Sync`, so the `OnceLock` cache below is
    /// shareable across threads without any unsafe impls.
    struct Api {
        findalldevs: FindAllDevsFn,
        freealldevs: FreeAllDevsFn,
        open_live: OpenLiveFn,
        compile: CompileFn,
        setfilter: SetFilterFn,
        freecode: FreeCodeFn,
        next_ex: NextExFn,
        datalink: DatalinkFn,
        close: CloseFn,
        geterr: GetErrFn,
        lib_version: LibVersionFn,
        /// WinPcap/Npcap-specific kernel buffer resize; absent in some builds.
        setbuff: Option<SetBuffFn>,
    }

    /// Set on successful load only — a failed probe is retried on the next
    /// call, so installing Npcap while the app is running works without a
    /// restart. The module stays loaded for the process lifetime.
    static API: OnceLock<Api> = OnceLock::new();

    // ---- Public surface: Npcap (loader) + Capture (live handle) ----

    pub struct Npcap {
        api: &'static Api,
    }

    impl Npcap {
        pub fn load() -> Result<Self> {
            Ok(Npcap { api: load_api()? })
        }

        /// Cheap when Npcap is present (cached); a failed probe is a couple of
        /// LoadLibraryExW calls.
        pub fn is_installed() -> bool {
            Self::load().is_ok()
        }

        /// The `pcap_lib_version` banner, for diagnostics.
        pub fn lib_version(&self) -> String {
            c_to_string(unsafe { (self.api.lib_version)() })
        }

        /// Open a live capture on the adapter with this GetAdaptersAddresses
        /// GUID by finding the matching `\Device\NPF_{GUID}` pcap device.
        pub fn open_adapter(&self, adapter_guid: &str) -> Result<Capture> {
            let device = self
                .list_devices()?
                .into_iter()
                .find(|device| super::npf_name_matches_adapter(&device.name, adapter_guid))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Npcap did not report a capture device for the selected network \
                         adapter ({adapter_guid}). Press Refresh in Settings, reinstall \
                         Npcap, or switch back to raw sockets."
                    )
                })?;

            let name = CString::new(device.name.clone())
                .with_context(|| format!("capture device name {:?}", device.name))?;
            let mut errbuf = [0u8; PCAP_ERRBUF_SIZE + 1];
            let handle = unsafe {
                (self.api.open_live)(
                    name.as_ptr().cast(),
                    SNAPLEN,
                    0, // promiscuous off — mirrors RCVALL_IPLEVEL; promiscuous
                    // mode drops the host's own inbound traffic on some Wi-Fi
                    // adapters (see rawsock.rs), breaking TLS key establishment.
                    READ_TIMEOUT_MS,
                    errbuf.as_mut_ptr(),
                )
            };
            if handle.is_null() {
                bail!(
                    "pcap_open_live on {} failed: {}",
                    device.name,
                    c_to_string(errbuf.as_ptr())
                );
            }

            // Enlarge the kernel buffer to reduce drops; best-effort, like
            // rawsock's SO_RCVBUF.
            if let Some(setbuff) = self.api.setbuff {
                let _ = unsafe { setbuff(handle, KERNEL_BUFFER_BYTES) };
            }

            let datalink = unsafe { (self.api.datalink)(handle) };
            Ok(Capture {
                api: self.api,
                handle,
                datalink,
            })
        }

        fn list_devices(&self) -> Result<Vec<Device>> {
            let mut list: *mut PcapIf = std::ptr::null_mut();
            let mut errbuf = [0u8; PCAP_ERRBUF_SIZE + 1];
            if unsafe { (self.api.findalldevs)(&mut list, errbuf.as_mut_ptr()) } != 0 {
                bail!(
                    "listing Npcap capture devices failed: {}",
                    c_to_string(errbuf.as_ptr())
                );
            }

            let mut devices = Vec::new();
            let mut current = list;
            while !current.is_null() {
                let entry = unsafe { &*current };
                let name = c_to_string(entry.name);
                if !name.is_empty() {
                    let description = Some(c_to_string(entry.description))
                        .filter(|description| !description.is_empty());
                    devices.push(Device { name, description });
                }
                current = entry.next;
            }
            if !list.is_null() {
                unsafe { (self.api.freealldevs)(list) };
            }
            Ok(devices)
        }
    }

    pub struct Capture {
        api: &'static Api,
        handle: *mut PcapT,
        datalink: i32,
    }

    impl Capture {
        pub fn next_packet(&mut self) -> Result<Option<Packet>> {
            let mut header: *mut PcapPkthdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null();
            let result = unsafe { (self.api.next_ex)(self.handle, &mut header, &mut data) };
            match result {
                // The header and data buffers are only valid until the next
                // pcap call, so copy out immediately.
                1 => {
                    if header.is_null() || data.is_null() {
                        return Ok(None);
                    }
                    let header = unsafe { &*header };
                    let captured = header.caplen as usize;
                    let bytes = unsafe { std::slice::from_raw_parts(data, captured) };
                    Ok(Some(Packet {
                        timestamp_us: super::pkthdr_timestamp_us(header.ts_sec, header.ts_usec),
                        captured_len: header.caplen,
                        original_len: header.len,
                        data: bytes.to_vec(),
                    }))
                }
                0 => Ok(None),  // read timeout — nothing captured this round
                -2 => Ok(None), // pcap_breakloop, not used but harmless
                _ => bail!("Npcap capture read failed: {}", self.last_error()),
            }
        }

        pub fn datalink(&self) -> Result<i32> {
            Ok(self.datalink)
        }

        pub fn set_filter(&mut self, expression: &str) -> Result<()> {
            let filter = CString::new(expression)
                .with_context(|| format!("capture filter {expression:?}"))?;
            let mut program = BpfProgram {
                bf_len: 0,
                bf_insns: std::ptr::null_mut(),
            };
            if unsafe {
                (self.api.compile)(
                    self.handle,
                    &mut program,
                    filter.as_ptr().cast(),
                    1, // optimize
                    PCAP_NETMASK_UNKNOWN,
                )
            } != 0
            {
                bail!(
                    "compiling capture filter {expression:?} failed: {}",
                    self.last_error()
                );
            }
            let result = unsafe { (self.api.setfilter)(self.handle, &mut program) };
            unsafe { (self.api.freecode)(&mut program) };
            if result != 0 {
                bail!(
                    "installing capture filter {expression:?} failed: {}",
                    self.last_error()
                );
            }
            Ok(())
        }

        fn last_error(&self) -> String {
            c_to_string(unsafe { (self.api.geterr)(self.handle) })
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            unsafe { (self.api.close)(self.handle) };
        }
    }

    // ---- wpcap.dll loading ----

    fn load_api() -> Result<&'static Api> {
        if let Some(api) = API.get() {
            return Ok(api);
        }
        let api = probe_wpcap()?;
        // A racing thread may have loaded it too; either Api is equivalent.
        Ok(API.get_or_init(|| api))
    }

    fn probe_wpcap() -> Result<Api> {
        // (1) The standard Npcap install: <System32>\Npcap\wpcap.dll.
        // LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR lets its dependency Packet.dll
        // resolve from that same directory.
        let mut module: isize = 0;
        if let Some(system32) = system_directory() {
            let path = wide(&format!("{system32}\\Npcap\\wpcap.dll"));
            module = unsafe {
                LoadLibraryExW(
                    path.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
                )
            };
        }
        // (2) "WinPcap API-compatible mode" installs place wpcap.dll in
        // System32 itself. Restricting the search to System32 avoids picking
        // up a planted wpcap.dll next to our exe or on PATH.
        if module == 0 {
            let name = wide("wpcap.dll");
            module = unsafe {
                LoadLibraryExW(
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
        }
        if module == 0 {
            bail!("{NOT_INSTALLED}");
        }

        macro_rules! required {
            ($name:literal, $ty:ty) => {{
                let address = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) };
                if address.is_null() {
                    bail!(
                        "wpcap.dll is missing the expected function {} — the Npcap install \
                         may be damaged; reinstall it from https://npcap.com",
                        $name
                    );
                }
                unsafe { std::mem::transmute::<*mut core::ffi::c_void, $ty>(address) }
            }};
        }

        let setbuff_address = unsafe { GetProcAddress(module, c"pcap_setbuff".as_ptr().cast()) };
        Ok(Api {
            findalldevs: required!("pcap_findalldevs", FindAllDevsFn),
            freealldevs: required!("pcap_freealldevs", FreeAllDevsFn),
            open_live: required!("pcap_open_live", OpenLiveFn),
            compile: required!("pcap_compile", CompileFn),
            setfilter: required!("pcap_setfilter", SetFilterFn),
            freecode: required!("pcap_freecode", FreeCodeFn),
            next_ex: required!("pcap_next_ex", NextExFn),
            datalink: required!("pcap_datalink", DatalinkFn),
            close: required!("pcap_close", CloseFn),
            geterr: required!("pcap_geterr", GetErrFn),
            lib_version: required!("pcap_lib_version", LibVersionFn),
            setbuff: if setbuff_address.is_null() {
                None
            } else {
                Some(unsafe {
                    std::mem::transmute::<*mut core::ffi::c_void, SetBuffFn>(setbuff_address)
                })
            },
        })
    }

    fn system_directory() -> Option<String> {
        let mut buffer = [0u16; 260];
        let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if written == 0 || written as usize >= buffer.len() {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..written as usize]))
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn c_to_string(ptr: *const u8) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut core::ffi::c_void, flags: u32) -> isize;
        fn GetProcAddress(module: isize, name: *const u8) -> *mut core::ffi::c_void;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    #[cfg(test)]
    mod tests {
        use super::PcapPkthdr;

        /// Layout guard: `pcap_pkthdr` on 64-bit Windows is `timeval` (two
        /// 32-bit longs) + two `bpf_u_int32`s — 16 bytes, no padding.
        #[test]
        fn pcap_pkthdr_layout_matches_windows_abi() {
            assert_eq!(std::mem::size_of::<PcapPkthdr>(), 16);
            let header = PcapPkthdr {
                ts_sec: 1,
                ts_usec: 2,
                caplen: 3,
                len: 4,
            };
            assert_eq!(
                std::mem::offset_of!(PcapPkthdr, caplen),
                8,
                "caplen must directly follow the 8-byte timeval"
            );
            assert_eq!(header.len, 4);
        }
    }
}

#[cfg(not(windows))]
mod stub {
    use anyhow::{bail, Result};

    use crate::capture_backend::{Device, Packet};

    pub struct Npcap;
    pub struct Capture;

    impl Npcap {
        pub fn load() -> Result<Self> {
            bail!("Npcap capture is only supported on Windows")
        }
        pub fn is_installed() -> bool {
            false
        }
        pub fn lib_version(&self) -> String {
            String::new()
        }
        #[allow(dead_code)]
        pub fn list_devices(&self) -> Result<Vec<Device>> {
            Ok(Vec::new())
        }
        pub fn open_adapter(&self, _adapter_guid: &str) -> Result<Capture> {
            bail!("Npcap capture is only supported on Windows")
        }
    }

    impl Capture {
        pub fn next_packet(&mut self) -> Result<Option<Packet>> {
            Ok(None)
        }
        pub fn datalink(&self) -> Result<i32> {
            Ok(crate::packet::DLT_EN10MB)
        }
        pub fn set_filter(&mut self, _expression: &str) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npf_name_matches_braced_guid_case_insensitively() {
        let pcap_name = r"\Device\NPF_{F3A9B2C1-0D4E-4F56-9A78-1B2C3D4E5F60}";
        assert!(npf_name_matches_adapter(
            pcap_name,
            "{f3a9b2c1-0d4e-4f56-9a78-1b2c3d4e5f60}"
        ));
        assert!(npf_name_matches_adapter(
            pcap_name,
            "{F3A9B2C1-0D4E-4F56-9A78-1B2C3D4E5F60}"
        ));
    }

    #[test]
    fn npf_name_matches_guid_without_braces() {
        assert!(npf_name_matches_adapter(
            r"\Device\NPF_{F3A9B2C1-0D4E-4F56-9A78-1B2C3D4E5F60}",
            "F3A9B2C1-0D4E-4F56-9A78-1B2C3D4E5F60"
        ));
    }

    #[test]
    fn npf_loopback_device_never_matches() {
        assert!(!npf_name_matches_adapter(
            r"\Device\NPF_Loopback",
            "Loopback"
        ));
    }

    #[test]
    fn npf_name_rejects_different_guid() {
        assert!(!npf_name_matches_adapter(
            r"\Device\NPF_{F3A9B2C1-0D4E-4F56-9A78-1B2C3D4E5F60}",
            "{00000000-0000-0000-0000-000000000000}"
        ));
    }

    #[test]
    fn npf_name_rejects_empty_guid() {
        let pcap_name = r"\Device\NPF_{F3A9B2C1-0D4E-4F56-9A78-1B2C3D4E5F60}";
        assert!(!npf_name_matches_adapter(pcap_name, ""));
        assert!(!npf_name_matches_adapter(pcap_name, "{}"));
    }

    #[test]
    fn pkthdr_timestamp_converts_to_unix_micros() {
        assert_eq!(
            pkthdr_timestamp_us(1_700_000_000, 250_000),
            1_700_000_000_250_000
        );
        assert_eq!(pkthdr_timestamp_us(0, 0), 0);
        assert_eq!(pkthdr_timestamp_us(1, 999_999), 1_999_999);
    }
}
