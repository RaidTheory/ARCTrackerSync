use std::net::IpAddr;

use anyhow::Result;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcapsql_core::stream::TcpFlags;

pub const DLT_NULL: i32 = 0;
pub const DLT_EN10MB: i32 = 1;
pub const DLT_RAW: i32 = 12;
pub const DLT_LINUX_SLL: i32 = 113;
pub const DLT_IPV4: i32 = 228;
pub const DLT_IPV6: i32 = 229;

#[derive(Debug, Clone)]
pub struct CapturedSegment {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub payload: Vec<u8>,
    pub frame_number: u64,
    pub timestamp_us: i64,
}

pub fn parse_tcp_segment(
    frame_number: u64,
    timestamp_us: i64,
    datalink: i32,
    data: &[u8],
) -> Result<Option<CapturedSegment>> {
    if let Some(packet) = slice_packet(datalink, data) {
        let (src_ip, dst_ip) = match packet.net {
            Some(NetSlice::Ipv4(slice)) => (
                IpAddr::V4(slice.header().source_addr()),
                IpAddr::V4(slice.header().destination_addr()),
            ),
            Some(NetSlice::Ipv6(slice)) => (
                IpAddr::V6(slice.header().source_addr()),
                IpAddr::V6(slice.header().destination_addr()),
            ),
            None => return Ok(None),
        };

        let tcp = match packet.transport {
            Some(TransportSlice::Tcp(tcp)) => tcp,
            _ => return Ok(None),
        };

        let src_port = tcp.source_port();
        let dst_port = tcp.destination_port();
        if src_port != 443 && dst_port != 443 {
            return Ok(None);
        }

        return Ok(Some(CapturedSegment {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq: tcp.sequence_number(),
            ack: tcp.acknowledgment_number(),
            flags: TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
            },
            payload: tcp.payload().to_vec(),
            frame_number,
            timestamp_us,
        }));
    }

    Ok(parse_tcp_segment_fallback(
        frame_number,
        timestamp_us,
        datalink,
        data,
    ))
}

pub fn datalink_name(datalink: i32) -> &'static str {
    match datalink {
        DLT_NULL => "DLT_NULL",
        DLT_EN10MB => "DLT_EN10MB",
        DLT_RAW => "DLT_RAW",
        DLT_LINUX_SLL => "DLT_LINUX_SLL",
        DLT_IPV4 => "DLT_IPV4",
        DLT_IPV6 => "DLT_IPV6",
        _ => "unknown",
    }
}

fn slice_packet(datalink: i32, data: &[u8]) -> Option<SlicedPacket<'_>> {
    match datalink {
        DLT_EN10MB => SlicedPacket::from_ethernet(data).ok(),
        DLT_LINUX_SLL => SlicedPacket::from_linux_sll(data).ok(),
        DLT_RAW | DLT_IPV4 | DLT_IPV6 => SlicedPacket::from_ip(data).ok(),
        DLT_NULL => {
            if data.len() < 4 {
                return None;
            }
            SlicedPacket::from_ip(&data[4..]).ok()
        }
        _ => None,
    }
}

fn parse_tcp_segment_fallback(
    frame_number: u64,
    timestamp_us: i64,
    datalink: i32,
    data: &[u8],
) -> Option<CapturedSegment> {
    let ip_offset = ipv4_offset(datalink, data)?;
    if data.len() < ip_offset + 20 {
        return None;
    }

    let version_ihl = data[ip_offset];
    if version_ihl >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(version_ihl & 0x0f) * 4;
    if ihl < 20 || data.len() < ip_offset + ihl {
        return None;
    }
    if data[ip_offset + 9] != 6 {
        return None;
    }

    let total_len = u16::from_be_bytes([data[ip_offset + 2], data[ip_offset + 3]]) as usize;
    let available_ip_len = data.len().saturating_sub(ip_offset);
    let ip_len = if total_len >= ihl {
        total_len.min(available_ip_len)
    } else {
        // Windows/NIC offload can expose outbound packets before the IPv4 total
        // length is filled in. Wireshark infers the length from the capture.
        available_ip_len
    };

    let tcp_offset = ip_offset + ihl;
    if ip_len < ihl + 20 || data.len() < tcp_offset + 20 {
        return None;
    }

    let tcp_header_len = usize::from(data[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 {
        return None;
    }
    let payload_offset = tcp_offset + tcp_header_len;
    let tcp_end = ip_offset + ip_len;
    if payload_offset > tcp_end || tcp_end > data.len() {
        return None;
    }

    let src_port = u16::from_be_bytes([data[tcp_offset], data[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([data[tcp_offset + 2], data[tcp_offset + 3]]);
    if src_port != 443 && dst_port != 443 {
        return None;
    }

    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        data[ip_offset + 12],
        data[ip_offset + 13],
        data[ip_offset + 14],
        data[ip_offset + 15],
    ));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        data[ip_offset + 16],
        data[ip_offset + 17],
        data[ip_offset + 18],
        data[ip_offset + 19],
    ));
    let seq = u32::from_be_bytes([
        data[tcp_offset + 4],
        data[tcp_offset + 5],
        data[tcp_offset + 6],
        data[tcp_offset + 7],
    ]);
    let ack = u32::from_be_bytes([
        data[tcp_offset + 8],
        data[tcp_offset + 9],
        data[tcp_offset + 10],
        data[tcp_offset + 11],
    ]);
    let flags = data[tcp_offset + 13];

    Some(CapturedSegment {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags: TcpFlags {
            syn: flags & 0x02 != 0,
            ack: flags & 0x10 != 0,
            fin: flags & 0x01 != 0,
            rst: flags & 0x04 != 0,
        },
        payload: data[payload_offset..tcp_end].to_vec(),
        frame_number,
        timestamp_us,
    })
}

fn ipv4_offset(datalink: i32, data: &[u8]) -> Option<usize> {
    match datalink {
        DLT_EN10MB => ethernet_ipv4_offset(data),
        DLT_RAW | DLT_IPV4 => Some(0),
        DLT_NULL => (data.len() >= 4).then_some(4),
        _ => None,
    }
}

fn ethernet_ipv4_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 14 {
        return None;
    }

    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    (ethertype == 0x0800).then_some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parses_raw_ipv4_tcp_443_with_offload_zero_total_length() {
        let payload = b"POST / HTTP/1.1\r\n\r\n";
        let packet = ipv4_tcp_packet(0, 50_000, 443, payload);

        let segment = parse_tcp_segment(7, 123_456, DLT_RAW, &packet)
            .expect("parse packet")
            .expect("https tcp segment");

        assert_eq!(segment.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(segment.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(segment.src_port, 50_000);
        assert_eq!(segment.dst_port, 443);
        assert_eq!(segment.seq, 0x0102_0304);
        assert_eq!(segment.ack, 0x0506_0708);
        assert!(segment.flags.ack);
        assert!(!segment.flags.syn);
        assert_eq!(segment.payload, payload);
        assert_eq!(segment.frame_number, 7);
        assert_eq!(segment.timestamp_us, 123_456);
    }

    #[test]
    fn parses_vlan_tagged_ethernet_ipv4_tcp_443() {
        let payload = b"hello";
        let ip = ipv4_tcp_packet((20 + 20 + payload.len()) as u16, 443, 50_000, payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]); // destination MAC
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]); // source MAC
        frame.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN TPID
        frame.extend_from_slice(&100u16.to_be_bytes()); // VLAN TCI
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
        frame.extend_from_slice(&ip);

        let segment = parse_tcp_segment(1, 2, DLT_EN10MB, &frame)
            .expect("parse frame")
            .expect("https tcp segment");

        assert_eq!(segment.src_port, 443);
        assert_eq!(segment.dst_port, 50_000);
        assert_eq!(segment.payload, payload);
    }

    #[test]
    fn ignores_tcp_segments_that_are_not_port_443() {
        let packet = ipv4_tcp_packet(0, 1234, 5678, b"ignored");

        let segment = parse_tcp_segment(1, 2, DLT_RAW, &packet).expect("parse packet");

        assert!(segment.is_none());
    }

    #[test]
    fn ethernet_ipv4_offset_skips_stacked_vlan_tags() {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&0x88a8u16.to_be_bytes());
        frame.extend_from_slice(&2u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        assert_eq!(ethernet_ipv4_offset(&frame), Some(22));
    }

    #[test]
    fn datalink_names_are_stable() {
        assert_eq!(datalink_name(DLT_NULL), "DLT_NULL");
        assert_eq!(datalink_name(DLT_EN10MB), "DLT_EN10MB");
        assert_eq!(datalink_name(DLT_RAW), "DLT_RAW");
        assert_eq!(datalink_name(9999), "unknown");
    }

    fn ipv4_tcp_packet(total_len: u16, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[
            0x45,
            0x00, // version/IHL, DSCP/ECN
            (total_len >> 8) as u8,
            total_len as u8,
            0x00,
            0x01, // identification
            0x00,
            0x00, // flags/fragment offset
            64,
            6, // TTL, TCP
            0x00,
            0x00, // checksum ignored by parser
            10,
            0,
            0,
            1, // source
            10,
            0,
            0,
            2, // destination
        ]);
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        packet.extend_from_slice(&0x0506_0708u32.to_be_bytes());
        packet.extend_from_slice(&[
            0x50, 0x10, // data offset 5, ACK
            0x20, 0x00, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ]);
        packet.extend_from_slice(payload);
        packet
    }
}
