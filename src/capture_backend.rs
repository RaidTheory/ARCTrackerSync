//! Types shared by the capture backends ([`crate::rawsock`] and
//! [`crate::npcap`]) and consumed by `capture.rs`.

use serde::{Deserialize, Serialize};

/// Which packet-capture backend drives the live capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CaptureMethod {
    /// Windows raw sockets (`SIO_RCVALL`). Built in, nothing extra to install.
    #[default]
    RawSocket,
    /// Npcap (`wpcap.dll`), installed separately by the user from npcap.com.
    Npcap,
}

impl CaptureMethod {
    /// English label for diagnostics and activity-log status lines (those are
    /// intentionally not localized).
    pub fn label(self) -> &'static str {
        match self {
            CaptureMethod::RawSocket => "raw sockets",
            CaptureMethod::Npcap => "Npcap",
        }
    }
}

/// A capture-able network interface, as shown in the adapter picker.
#[derive(Debug, Clone, Default)]
pub struct Device {
    /// Backend-specific stable identifier (pcap device name, or adapter GUID).
    pub name: String,
    /// Human-friendly label (adapter description / friendly name).
    pub description: Option<String>,
}

/// One captured frame. Whether `data` is Ethernet or raw IP is conveyed by the
/// backend's reported datalink type, which `packet.rs` dispatches on.
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp_us: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}
