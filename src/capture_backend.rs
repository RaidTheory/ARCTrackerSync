//! Shared types for the packet-capture backend.
//!
//! The [`crate::rawsock`] (driver-free Windows raw sockets) backend produces
//! these for `capture.rs` to consume.

/// A capture-able network interface, as shown in the adapter picker.
#[derive(Debug, Clone, Default)]
pub struct Device {
    /// Backend-specific stable identifier (pcap device name, or adapter GUID).
    pub name: String,
    /// Human-friendly label for the picker (adapter description / friendly name).
    pub description: Option<String>,
}

/// One captured frame. `data` is the raw bytes the backend delivered; how to
/// interpret it (Ethernet vs. raw IP) is conveyed separately by the backend's
/// reported datalink type, which `packet.rs` dispatches on.
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp_us: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}
