//! Capture smoke test: lists interfaces, opens the first non-loopback one, and
//! reports how many frames and TCP/443 segments arrive over a few seconds.
//!
//! It exercises the live capture backend end to end (interface enumeration,
//! socket open, frame read, link-layer strip, TCP/443 filter) without the GUI
//! or any game, so a non-zero TCP/443 count while browsing HTTPS means capture
//! works on this machine. Needs CAP_NET_RAW (run as root, or after
//! `setcap cap_net_raw+ep` on the binary).
//!
//!   cargo run --release --example capture_smoke [interface] [seconds]

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arctracker_sync::packet::{datalink_name, parse_tcp_segment};
use arctracker_sync::rawsock::RawSock;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let wanted = args.next();
    let seconds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);

    let sock = RawSock::load().context("loading capture backend")?;
    let devices = sock.list_devices().context("listing interfaces")?;
    if devices.is_empty() {
        anyhow::bail!("no capture interfaces found");
    }

    println!("Interfaces:");
    for device in &devices {
        let desc = device.description.as_deref().unwrap_or("");
        println!("  {} {}", device.name, desc);
    }

    let chosen = match &wanted {
        Some(name) => devices
            .iter()
            .find(|d| &d.name == name)
            .with_context(|| format!("interface {name:?} not found"))?,
        None => &devices[0],
    };
    println!("\nOpening {} for {seconds}s ...", chosen.name);

    let mut capture = sock
        .open_live(&chosen.name)
        .with_context(|| format!("opening {}", chosen.name))?;
    let datalink = capture.datalink()?;
    capture.set_filter("tcp port 443").ok();
    println!("Datalink: {} ({datalink})", datalink_name(datalink));

    let started = Instant::now();
    let mut frames = 0u64;
    let mut https = 0u64;
    while started.elapsed() < Duration::from_secs(seconds) {
        if let Some(packet) = capture.next_packet()? {
            frames += 1;
            if parse_tcp_segment(frames, packet.timestamp_us, datalink, &packet.data)?.is_some() {
                https += 1;
            }
        }
    }

    println!("\nframes captured: {frames}");
    println!("TCP/443 segments: {https}");
    if https > 0 {
        println!("OK: live TCP/443 capture works on this interface.");
    } else if frames > 0 {
        println!("Frames seen but no TCP/443 — browse an HTTPS site while this runs.");
    } else {
        println!("No frames — wrong interface, or CAP_NET_RAW is missing.");
    }
    Ok(())
}
