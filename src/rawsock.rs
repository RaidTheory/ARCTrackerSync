//! Packet-capture backend using Windows raw sockets (`SIO_RCVALL`) — no
//! kernel driver to bundle, but the process must run elevated (raw sockets
//! need Administrator).
//!
//! Delivers raw IPv4 packets (no link-layer header), reported as `DLT_RAW`
//! for `packet.rs` — including the Windows quirk where outbound packets are
//! exposed before the IPv4 total-length field is filled in. IPv6 is
//! intentionally not captured: the Embark gateway is reached over IPv4, and
//! raw IPv6 sockets don't deliver the IP header consistently.

#[cfg(windows)]
pub use imp::{Capture, RawSock};

#[cfg(target_os = "linux")]
pub use linux::{Capture, RawSock};

#[cfg(all(not(windows), not(target_os = "linux")))]
pub use stub::{Capture, RawSock};

#[cfg(windows)]
#[allow(dead_code)] // FFI structs carry fields we map for layout but never read.
mod imp {
    use std::os::raw::c_int;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{anyhow, bail, Result};

    use crate::capture_backend::{Device, Packet};
    use crate::packet::DLT_RAW;

    // ---- Winsock constants ----
    const AF_INET: i32 = 2;
    const SOCK_RAW: i32 = 3;
    const IPPROTO_IP: i32 = 0;
    const SOL_SOCKET: i32 = 0xffff;
    const SO_RCVBUF: i32 = 0x1002;
    const SIO_RCVALL: u32 = 0x9800_0001; // _WSAIOW(IOC_VENDOR, 1)
                                         // RCVALL_IPLEVEL: all packets to/from this interface's IP, both directions,
                                         // without promiscuous mode. RCVALL_ON (1, full promiscuous) is unreliable
                                         // for the host's own inbound traffic, notably on Wi-Fi — it drops the
                                         // ServerHello and breaks TLS key establishment.
    const RCVALL_IPLEVEL: u32 = 3;
    const FIONBIO: i32 = 0x8004_667e_u32 as i32;
    const INVALID_SOCKET: usize = usize::MAX;
    const SOCKET_ERROR: i32 = -1;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAEACCES: i32 = 10013;
    // Datagram larger than the buffer; Winsock has already filled the buffer
    // and discarded the rest. Happens with LSO/GRO-offloaded segments that
    // exceed RECV_BUF — treat as truncation, never as a fatal error.
    const WSAEMSGSIZE: i32 = 10040;
    const WINSOCK_VERSION: u16 = 0x0202; // 2.2

    // ---- Iphlpapi / GetAdaptersAddresses constants ----
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
    const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
    const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;
    const IF_OPER_STATUS_UP: i32 = 1;

    // Sized generously so a single offloaded (LSO/GRO) datagram usually fits in
    // one recv; oversized ones still come back as WSAEMSGSIZE (handled below).
    const RECV_BUF: usize = 256 * 1024;
    const ADMIN_HINT: &str =
        "Administrator access is required to capture network traffic with raw sockets.";

    // ---- Public surface: RawSock (loader) + Capture (live handle) ----

    pub struct RawSock;

    impl RawSock {
        pub fn load() -> Result<Self> {
            ensure_winsock()?;
            Ok(RawSock)
        }

        pub fn list_devices(&self) -> Result<Vec<Device>> {
            Ok(enumerate_adapters()?
                .into_iter()
                .map(|adapter| Device {
                    name: adapter.name,
                    description: adapter.friendly,
                })
                .collect())
        }

        pub fn open_live(&self, name: &str) -> Result<Capture> {
            let adapter = enumerate_adapters()?
                .into_iter()
                .find(|adapter| adapter.name == name)
                .ok_or_else(|| anyhow!("network adapter {name} is no longer available"))?;
            let bind_addr = adapter.v4_sockaddr.ok_or_else(|| {
                anyhow!("network adapter {name} has no IPv4 address to capture on")
            })?;
            let socket = open_rcvall_socket(&bind_addr)?;
            Ok(Capture {
                sockets: vec![socket],
                next: 0,
                buf: vec![0u8; RECV_BUF],
                truncations: 0,
            })
        }
    }

    pub struct Capture {
        sockets: Vec<usize>,
        next: usize,
        buf: Vec<u8>,
        /// Count of datagrams larger than `buf` (WSAEMSGSIZE); the returned
        /// packet held only the first `buf.len()` bytes.
        truncations: u64,
    }

    impl Capture {
        pub fn next_packet(&mut self) -> Result<Option<Packet>> {
            if self.sockets.is_empty() {
                return Ok(None);
            }

            let count = self.sockets.len();
            for _ in 0..count {
                let index = self.next % count;
                self.next = self.next.wrapping_add(1);
                let socket = self.sockets[index];

                let read = unsafe { recv(socket, self.buf.as_mut_ptr(), self.buf.len() as i32, 0) };
                if read > 0 {
                    let len = read as usize;
                    return Ok(Some(Packet {
                        timestamp_us: now_micros(),
                        captured_len: len as u32,
                        original_len: len as u32,
                        data: self.buf[..len].to_vec(),
                    }));
                } else if read == SOCKET_ERROR {
                    let error = unsafe { WSAGetLastError() };
                    match error {
                        WSAEWOULDBLOCK => {} // nothing here, try the next socket.
                        WSAEMSGSIZE => {
                            // buf already holds the truncated prefix of an
                            // oversized datagram; deliver it and keep going.
                            self.truncations = self.truncations.wrapping_add(1);
                            let len = self.buf.len();
                            return Ok(Some(Packet {
                                timestamp_us: now_micros(),
                                captured_len: len as u32,
                                original_len: len as u32,
                                data: self.buf[..len].to_vec(),
                            }));
                        }
                        _ => bail!("raw socket recv failed: WSA error {error}"),
                    }
                }
                // read == 0 → nothing here, try the next socket.
            }

            // Nothing ready; block up to 100 ms for a socket to become readable
            // so the capture loop doesn't busy-spin. The next call does the recv.
            wait_readable(&self.sockets, 100);
            Ok(None)
        }

        pub fn datalink(&self) -> Result<c_int> {
            // Raw sockets deliver IPv4 packets with the IP header and no
            // link-layer header — exactly what packet.rs treats as DLT_RAW.
            Ok(DLT_RAW)
        }

        pub fn set_filter(&mut self, _expression: &str) -> Result<()> {
            // No kernel BPF here; packet.rs filters to TCP/443 itself.
            Ok(())
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            for &socket in &self.sockets {
                unsafe { closesocket(socket) };
            }
        }
    }

    // ---- Implementation helpers ----

    fn ensure_winsock() -> Result<()> {
        static STARTED: OnceLock<bool> = OnceLock::new();
        let ok = *STARTED.get_or_init(|| {
            let mut data = WsaData { _bytes: [0u8; 512] };
            unsafe { WSAStartup(WINSOCK_VERSION, &mut data) == 0 }
        });
        if ok {
            Ok(())
        } else {
            bail!("Windows Sockets could not be initialized");
        }
    }

    fn open_rcvall_socket(bind_sockaddr: &[u8]) -> Result<usize> {
        let socket_handle = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_IP) };
        if socket_handle == INVALID_SOCKET {
            let error = unsafe { WSAGetLastError() };
            if error == WSAEACCES {
                bail!("{ADMIN_HINT}");
            }
            bail!("creating raw socket failed: WSA error {error}");
        }

        if unsafe {
            bind(
                socket_handle,
                bind_sockaddr.as_ptr(),
                bind_sockaddr.len() as i32,
            )
        } == SOCKET_ERROR
        {
            let error = unsafe { WSAGetLastError() };
            unsafe { closesocket(socket_handle) };
            bail!("binding raw socket to the interface failed: WSA error {error}");
        }

        // Enlarge the receive buffer to reduce drops, and go non-blocking so the
        // round-robin drain in next_packet never blocks on an idle socket.
        let rcvbuf: u32 = 8 * 1024 * 1024;
        unsafe {
            setsockopt(
                socket_handle,
                SOL_SOCKET,
                SO_RCVBUF,
                &rcvbuf as *const u32 as *const u8,
                4,
            )
        };
        let mut non_blocking: u32 = 1;
        unsafe { ioctlsocket(socket_handle, FIONBIO, &mut non_blocking) };

        let on: u32 = RCVALL_IPLEVEL;
        let mut returned: u32 = 0;
        let result = unsafe {
            WSAIoctl(
                socket_handle,
                SIO_RCVALL,
                &on as *const u32,
                4,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result == SOCKET_ERROR {
            let error = unsafe { WSAGetLastError() };
            unsafe { closesocket(socket_handle) };
            if error == WSAEACCES {
                bail!("{ADMIN_HINT}");
            }
            bail!("enabling raw-socket capture (SIO_RCVALL) failed: WSA error {error}");
        }

        Ok(socket_handle)
    }

    fn wait_readable(sockets: &[usize], timeout_ms: i64) {
        if sockets.is_empty() {
            return;
        }
        let mut fds = FdSet {
            fd_count: 0,
            fd_array: [0usize; 64],
        };
        for &socket in sockets {
            if (fds.fd_count as usize) < fds.fd_array.len() {
                fds.fd_array[fds.fd_count as usize] = socket;
                fds.fd_count += 1;
            }
        }
        let timeout = TimeVal {
            tv_sec: (timeout_ms / 1000) as i32,
            tv_usec: ((timeout_ms % 1000) * 1000) as i32,
        };
        unsafe {
            select(
                0,
                &mut fds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &timeout,
            )
        };
    }

    struct Adapter {
        name: String,
        friendly: Option<String>,
        v4_sockaddr: Option<Vec<u8>>,
    }

    fn enumerate_adapters() -> Result<Vec<Adapter>> {
        ensure_winsock()?;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        // Backed by u64 so the buffer is 8-byte aligned for the adapter structs
        // (a Vec<u8> would only be 1-aligned — UB to read the structs from it).
        let mut buffer: Vec<u64> = Vec::new();
        let mut result = ERROR_BUFFER_OVERFLOW;

        for _ in 0..4 {
            buffer.clear();
            buffer.resize((size as usize).div_ceil(8), 0);
            result = unsafe {
                GetAdaptersAddresses(
                    AF_INET as u32,
                    flags,
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut IpAdapterAddresses,
                    &mut size,
                )
            };
            if result != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }

        if result != ERROR_SUCCESS {
            bail!("listing network adapters (GetAdaptersAddresses) failed with code {result}");
        }

        let mut adapters = Vec::new();
        let mut current = buffer.as_ptr() as *const IpAdapterAddresses;
        while !current.is_null() {
            let entry = unsafe { &*current };
            if entry.oper_status == IF_OPER_STATUS_UP {
                let name = ansi_to_string(entry.adapter_name);
                if !name.is_empty() {
                    if let Some(v4) = first_v4_sockaddr(entry.first_unicast) {
                        adapters.push(Adapter {
                            name,
                            friendly: wide_to_string(entry.friendly_name),
                            v4_sockaddr: Some(v4),
                        });
                    }
                }
            }
            current = entry.next;
        }
        Ok(adapters)
    }

    fn first_v4_sockaddr(mut unicast: *const IpAdapterUnicastAddress) -> Option<Vec<u8>> {
        while !unicast.is_null() {
            let entry = unsafe { &*unicast };
            if !entry.sockaddr.is_null() && entry.sockaddr_len >= 16 {
                let family =
                    unsafe { u16::from_ne_bytes([*entry.sockaddr, *entry.sockaddr.add(1)]) };
                if family as i32 == AF_INET {
                    let bytes = unsafe {
                        std::slice::from_raw_parts(entry.sockaddr, entry.sockaddr_len as usize)
                    };
                    return Some(bytes.to_vec());
                }
            }
            unicast = entry.next;
        }
        None
    }

    fn ansi_to_string(ptr: *const u8) -> String {
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

    fn wide_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        if len == 0 {
            return None;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        Some(String::from_utf16_lossy(slice))
    }

    fn now_micros() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_micros() as i64)
            .unwrap_or(0)
    }

    // ---- FFI types ----

    #[repr(C)]
    struct WsaData {
        _bytes: [u8; 512],
    }

    #[repr(C)]
    struct FdSet {
        fd_count: u32,
        fd_array: [usize; 64],
    }

    #[repr(C)]
    struct TimeVal {
        tv_sec: i32,
        tv_usec: i32,
    }

    /// Prefix of `IP_ADAPTER_ADDRESSES_LH` up to the fields we read (x64 layout).
    #[repr(C)]
    struct IpAdapterAddresses {
        length_ifindex: u64, // union { ULONGLONG Alignment; { ULONG Length; ULONG IfIndex; } }
        next: *const IpAdapterAddresses,
        adapter_name: *const u8, // PCHAR (ANSI GUID string)
        first_unicast: *const IpAdapterUnicastAddress,
        first_anycast: *const u8,
        first_multicast: *const u8,
        first_dns_server: *const u8,
        dns_suffix: *const u16,
        description: *const u16,
        friendly_name: *const u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: i32,
    }

    /// Prefix of `IP_ADAPTER_UNICAST_ADDRESS_LH` up to the embedded
    /// `SOCKET_ADDRESS` (x64 layout).
    #[repr(C)]
    struct IpAdapterUnicastAddress {
        length_flags: u64, // union { ULONGLONG Alignment; { ULONG Length; DWORD Flags; } }
        next: *const IpAdapterUnicastAddress,
        sockaddr: *const u8, // SOCKET_ADDRESS.lpSockaddr
        sockaddr_len: i32,   // SOCKET_ADDRESS.iSockaddrLength
    }

    #[link(name = "Ws2_32")]
    extern "system" {
        fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
        fn socket(af: i32, ty: i32, protocol: i32) -> usize;
        fn bind(s: usize, name: *const u8, namelen: i32) -> i32;
        fn closesocket(s: usize) -> i32;
        fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
        fn ioctlsocket(s: usize, cmd: i32, argp: *mut u32) -> i32;
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        fn WSAIoctl(
            s: usize,
            code: u32,
            in_buffer: *const u32,
            in_len: u32,
            out_buffer: *mut u8,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut core::ffi::c_void,
            completion: *mut core::ffi::c_void,
        ) -> i32;
        fn select(
            nfds: i32,
            readfds: *mut FdSet,
            writefds: *mut FdSet,
            exceptfds: *mut FdSet,
            timeout: *const TimeVal,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    #[link(name = "Iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut core::ffi::c_void,
            addresses: *mut IpAdapterAddresses,
            size: *mut u32,
        ) -> u32;
    }
}

/// Linux capture backend using an `AF_PACKET`/`SOCK_RAW` socket bound to one
/// interface. Delivers full Ethernet frames, reported as `DLT_EN10MB` so
/// `packet.rs` strips the link layer itself. The socket needs `CAP_NET_RAW`
/// (run as root, or `setcap cap_net_raw+ep` on the binary). Both directions are
/// captured: `AF_PACKET` sees outbound frames as well as inbound, which is what
/// the Windows `RCVALL_IPLEVEL` path also relies on.
#[cfg(target_os = "linux")]
mod linux {
    use std::os::raw::c_int;
    use std::os::unix::io::RawFd;

    use anyhow::{anyhow, bail, Context, Result};

    use crate::capture_backend::{Device, Packet};
    use crate::packet::DLT_EN10MB;

    // Generous: a single GRO/LSO-coalesced frame on the wire can far exceed the
    // 1500-byte MTU, and a short read silently truncates the segment.
    const RECV_BUF: usize = 256 * 1024;

    fn eth_p_all() -> u16 {
        (libc::ETH_P_ALL as u16).to_be()
    }

    pub struct RawSock;

    impl RawSock {
        pub fn load() -> Result<Self> {
            Ok(RawSock)
        }

        pub fn list_devices(&self) -> Result<Vec<Device>> {
            let mut devices = Vec::new();
            let entries = std::fs::read_dir("/sys/class/net")
                .context("listing /sys/class/net network interfaces")?;
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == "lo" {
                    continue;
                }
                let operstate = std::fs::read_to_string(entry.path().join("operstate"))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let description = match operstate.as_str() {
                    "" | "unknown" => None,
                    other => Some(format!("link {other}")),
                };
                // Prefer up/unknown links first so the picker's default is live.
                let up = matches!(operstate.as_str(), "up" | "unknown" | "");
                devices.push((up, Device { name, description }));
            }
            devices.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.name.cmp(&b.1.name)));
            Ok(devices.into_iter().map(|(_, device)| device).collect())
        }

        pub fn open_live(&self, name: &str) -> Result<Capture> {
            let ifindex = if_index(name)?;
            let fd =
                unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(eth_p_all())) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    bail!(
                        "opening AF_PACKET socket needs CAP_NET_RAW — run as root, or \
                         `sudo setcap cap_net_raw+ep` on the binary"
                    );
                }
                return Err(err).context("opening AF_PACKET socket");
            }
            let capture = Capture { fd };

            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            addr.sll_family = libc::AF_PACKET as u16;
            addr.sll_protocol = eth_p_all();
            addr.sll_ifindex = ifindex;
            let rc = unsafe {
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("binding capture socket to {name}"));
            }

            // Non-blocking so the capture loop can poll for the stop flag.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("setting capture socket non-blocking");
            }

            Ok(capture)
        }
    }

    pub struct Capture {
        fd: RawFd,
    }

    impl Capture {
        pub fn next_packet(&mut self) -> Result<Option<Packet>> {
            // Wait for a frame with a bounded timeout rather than spinning: the
            // capture loop calls this back-to-back, and the socket is
            // non-blocking, so a bare `recv` would busy-loop at 100% CPU while
            // idle. The 200 ms cap still lets the loop service its 500 ms/1 s
            // housekeeping timers and the stop flag promptly.
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pfd, 1, 200) };
            if ready <= 0 {
                // 0 = timeout; <0 with EINTR = interrupted. Either way, no frame.
                return Ok(None);
            }

            let mut buf = vec![0u8; RECV_BUF];
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(None),
                    _ => Err(err).context("reading from capture socket"),
                };
            }
            let captured = n as usize;
            buf.truncate(captured);
            Ok(Some(Packet {
                timestamp_us: now_micros(),
                captured_len: captured as u32,
                original_len: captured as u32,
                data: buf,
            }))
        }

        pub fn datalink(&self) -> Result<i32> {
            Ok(DLT_EN10MB)
        }

        pub fn set_filter(&mut self, _expression: &str) -> Result<()> {
            // No kernel BPF: the socket captures every frame on the interface and
            // `packet.rs` discards anything that isn't TCP/443. A busy link costs
            // some extra userspace parsing, but keeps the backend dependency-free
            // and correct for VLAN-tagged and offloaded frames.
            Ok(())
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    fn if_index(name: &str) -> Result<c_int> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| anyhow!("interface name {name:?} contains a NUL byte"))?;
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if index == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("resolving interface index for {name}"));
        }
        Ok(index as c_int)
    }

    fn now_micros() -> i64 {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
            return 0;
        }
        ts.tv_sec as i64 * 1_000_000 + ts.tv_nsec as i64 / 1_000
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
mod stub {
    use anyhow::{bail, Result};

    use crate::capture_backend::{Device, Packet};

    pub struct RawSock;
    pub struct Capture;

    impl RawSock {
        pub fn load() -> Result<Self> {
            bail!("raw-socket capture is only supported on Windows")
        }
        pub fn list_devices(&self) -> Result<Vec<Device>> {
            Ok(Vec::new())
        }
        pub fn open_live(&self, _name: &str) -> Result<Capture> {
            bail!("raw-socket capture is only supported on Windows")
        }
    }

    impl Capture {
        pub fn next_packet(&mut self) -> Result<Option<Packet>> {
            Ok(None)
        }
        pub fn datalink(&self) -> Result<i32> {
            Ok(crate::packet::DLT_RAW)
        }
        pub fn set_filter(&mut self, _expression: &str) -> Result<()> {
            Ok(())
        }
    }
}
