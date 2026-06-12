use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use compact_str::CompactString;
use crossbeam_channel::{unbounded, Receiver, Sender};
use pcapsql_core::protocol::{FieldValue, OwnedFieldValue};
use pcapsql_core::schema::{DataKind, FieldDescriptor};
use pcapsql_core::stream::{
    Direction, ParsedMessage, StreamConfig, StreamContext, StreamManager, StreamParseResult,
    StreamParser,
};
use pcapsql_core::tls::KeyLog as SyncKeyData;
use sha2::{Digest, Sha256};

use crate::capture_backend::{CaptureMethod, Packet};
use crate::npcap::Npcap;
use crate::packet::{datalink_name, parse_tcp_segment, CapturedSegment};
use crate::rawsock::RawSock;
use crate::token::{self, RawTokenHit, TokenObservation};

const MAX_RECENT_SEGMENTS: usize = 5_000;
const MAX_RECENT_BYTES: usize = 24 * 1024 * 1024;
const MAX_SYNC_KEY_TAIL_BYTES: u64 = 64 * 1024 * 1024;
const LIVE_BPF_FILTER: &str = "tcp port 443";
/// Token-observation dedup set cap; the whole set is cleared past this size so
/// a long capture can't grow it unbounded. Clearing at worst re-emits an
/// already-seen token, which the UI handles idempotently.
const MAX_SEEN_FINGERPRINTS: usize = 4_096;

/// Cap on per-hit "HTTP/1.1 debug" status events. The game bursts many API
/// calls at launch; the stats counters keep tracking after the events stop.
const MAX_HTTP_DEBUG_EVENTS: u64 = 5;

/// Cap on "Sync key changed" status events. The game rewrites the keylog
/// continuously during play, which would flood the 20-entry activity log;
/// `stats.sync_key_reloads` keeps the running count.
const MAX_SYNC_KEY_RELOAD_EVENTS: u64 = 3;

#[derive(Debug, Clone, Default)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_seen: u64,
    pub packet_truncations: u64,
    pub packet_truncated_bytes: u64,
    pub pcap_datalink: Option<String>,
    pub pcap_datalink_value: Option<i32>,
    pub tcp_segments_seen: u64,
    pub tls_segments_processed: u64,
    pub tls_client_hellos: u64,
    pub tls_server_hellos: u64,
    pub tls_sni_hellos: u64,
    pub tls_embark_sni_hellos: u64,
    pub embark_missing_key_sessions: u64,
    pub tls_keys_established: u64,
    pub tls_key_errors: u64,
    pub tls_missing_keys: u64,
    pub tls_encrypted_no_decrypt: u64,
    pub tls_decrypt_errors: u64,
    pub tls_server_finished: u64,
    pub tls_client_finished: u64,
    pub tls_inner_handshake: u64,
    pub tls_inner_app_data: u64,
    pub tls_inner_app_data_to_server: u64,
    pub tls_inner_app_data_to_client: u64,
    pub tls_inner_other: u64,
    pub last_tls_sni: Option<String>,
    pub last_tls_alpn: Option<String>,
    pub last_embark_missing_key: Option<String>,
    pub last_tls_inner_type: Option<u64>,
    pub last_tls_key_error: Option<String>,
    pub last_tls_decrypt_error: Option<String>,
    pub last_tls_decrypt_context: Option<String>,
    pub decrypted_records: u64,
    pub decrypted_bytes: u64,
    pub http1_candidates: u64,
    pub http1_embark_hosts: u64,
    pub http1_bearer_headers: u64,
    pub last_http1_host: Option<String>,
    pub last_http1_method: Option<String>,
    pub last_http1_path: Option<String>,
    pub plaintext_chunks: u64,
    pub plaintext_bytes: u64,
    pub plaintext_method_hits: u64,
    pub plaintext_embark_host_hits: u64,
    pub plaintext_bearer_marker_hits: u64,
    pub sync_key_entries: usize,
    pub sync_key_sessions: usize,
    pub sync_key_reloads: u64,
    pub recent_segments: usize,
    pub recent_bytes: usize,
}

#[derive(Debug, Clone)]
// CaptureStats (~560 bytes) trips clippy::large_enum_variant. Not boxed: the
// channel carries a few low-frequency events per second and the UI consumes
// the variant by value, so boxing would just add an allocation per update.
#[allow(clippy::large_enum_variant)]
pub enum CaptureEvent {
    Status(String),
    Stats(CaptureStats),
    Token(TokenObservation),
    Error(String),
    Stopped,
}

pub struct CaptureHandle {
    pub rx: Receiver<CaptureEvent>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CaptureHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let devices = RawSock::load()?
        .list_devices()
        .context("listing network adapters")?;
    Ok(devices
        .into_iter()
        .map(|device| InterfaceInfo {
            name: device.name,
            description: device.description,
        })
        .collect())
}

/// The open capture handle for whichever backend the user selected. Both
/// backends expose the same pcap-shaped surface, so `capture_loop` is
/// backend-agnostic past this point.
enum LiveCapture {
    Raw(crate::rawsock::Capture),
    Npcap(crate::npcap::Capture),
}

impl LiveCapture {
    fn next_packet(&mut self) -> Result<Option<Packet>> {
        match self {
            LiveCapture::Raw(capture) => capture.next_packet(),
            LiveCapture::Npcap(capture) => capture.next_packet(),
        }
    }

    fn datalink(&self) -> Result<i32> {
        match self {
            LiveCapture::Raw(capture) => capture.datalink(),
            LiveCapture::Npcap(capture) => capture.datalink(),
        }
    }

    fn set_filter(&mut self, expression: &str) -> Result<()> {
        match self {
            LiveCapture::Raw(capture) => capture.set_filter(expression),
            LiveCapture::Npcap(capture) => capture.set_filter(expression),
        }
    }
}

fn open_capture(method: CaptureMethod, interface_name: &str) -> Result<LiveCapture> {
    match method {
        CaptureMethod::RawSocket => Ok(LiveCapture::Raw(
            RawSock::load()?
                .open_live(interface_name)
                .with_context(|| format!("opening raw-socket capture on {interface_name}"))?,
        )),
        CaptureMethod::Npcap => Ok(LiveCapture::Npcap(
            Npcap::load()?
                .open_adapter(interface_name)
                .with_context(|| format!("opening Npcap capture on {interface_name}"))?,
        )),
    }
}

pub fn start_capture(
    method: CaptureMethod,
    interface_name: String,
    sync_key_path: PathBuf,
) -> CaptureHandle {
    let (tx, rx) = unbounded();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);

    let worker = thread::spawn(move || {
        if let Err(error) = capture_loop(
            method,
            interface_name,
            sync_key_path,
            thread_stop,
            tx.clone(),
        ) {
            let _ = tx.send(CaptureEvent::Error(format!("{error:#}")));
        }
        let _ = tx.send(CaptureEvent::Stopped);
    });

    CaptureHandle {
        rx,
        stop,
        worker: Some(worker),
    }
}

fn capture_loop(
    method: CaptureMethod,
    interface_name: String,
    sync_key_path: PathBuf,
    stop: Arc<AtomicBool>,
    tx: Sender<CaptureEvent>,
) -> Result<()> {
    let mut stats = CaptureStats::default();
    let mut sync_key_signature = None;
    let _ = tx.send(CaptureEvent::Status(format!(
        "Loading recent sync key tail from {}",
        sync_key_path.display()
    )));
    let (sync_keys, load_warning) =
        initial_sync_keys(&sync_key_path, &mut sync_key_signature, &mut stats);
    match load_warning {
        None => {
            let _ = tx.send(CaptureEvent::Status(format!(
                "Loaded sync key: {} entries across {} sessions",
                stats.sync_key_entries, stats.sync_key_sessions
            )));
        }
        Some(warning) => {
            let _ = tx.send(CaptureEvent::Status(warning));
        }
    }
    let _ = tx.send(CaptureEvent::Stats(stats.clone()));
    let mut manager = build_manager(sync_keys);

    let _ = tx.send(CaptureEvent::Status(format!(
        "Opening capture interface {interface_name} via {}",
        method.label()
    )));
    // Raw-socket inbound capture is blocked by the Windows Firewall; add an
    // inbound allow rule for our exe first (best-effort). Npcap captures at
    // the NDIS layer below the firewall, so no rule is needed there.
    if method == CaptureMethod::RawSocket {
        if let Err(error) = crate::firewall::ensure_capture_allowed() {
            let _ = tx.send(CaptureEvent::Status(format!(
                "Could not add firewall allowance (inbound may be blocked): {error}"
            )));
        }
    }
    let mut capture = open_capture(method, &interface_name)?;
    capture
        .set_filter(LIVE_BPF_FILTER)
        .with_context(|| format!("installing capture filter {LIVE_BPF_FILTER:?}"))?;
    let _ = tx.send(CaptureEvent::Status(format!(
        "Capture filter installed: {LIVE_BPF_FILTER}"
    )));
    let datalink = capture
        .datalink()
        .with_context(|| format!("reading datalink type for {interface_name}"))?;
    stats.pcap_datalink_value = Some(datalink);
    stats.pcap_datalink = Some(datalink_name(datalink).to_string());
    let _ = tx.send(CaptureEvent::Status(format!(
        "Capture datalink: {} ({datalink})",
        datalink_name(datalink)
    )));
    let _ = tx.send(CaptureEvent::Status(
        "Background capture active".to_string(),
    ));

    let mut recent = VecDeque::new();
    let mut recent_bytes = 0usize;
    let mut seen_fingerprints = HashSet::new();
    let mut embark_connections = HashMap::new();
    let mut frame_number = 0u64;
    let mut last_sync_key_check = Instant::now();
    let mut last_stats_emit = Instant::now();
    let mut last_connection_cleanup = Instant::now();
    // Throttle for the stream-buffer memory-limit warning (edge + 30 s cadence).
    let mut last_mem_warn: Option<Instant> = None;
    // Tracks the poll error state so a persistently unreadable sync key emits
    // one status on the way in and one on recovery, not one per second.
    let mut sync_key_poll_failing = false;

    while !stop.load(Ordering::Relaxed) {
        if last_sync_key_check.elapsed() >= Duration::from_secs(1) {
            last_sync_key_check = Instant::now();
            // An unreadable sync key (deleted, locked, not created yet) must
            // not kill the capture thread; keep polling until it comes back.
            let changed = match sync_key_changed(&sync_key_path, sync_key_signature) {
                Ok(changed) => {
                    if sync_key_poll_failing {
                        sync_key_poll_failing = false;
                        let _ = tx.send(CaptureEvent::Status(
                            "Sync key is readable again".to_string(),
                        ));
                    }
                    changed
                }
                Err(error) => {
                    if !sync_key_poll_failing {
                        sync_key_poll_failing = true;
                        let _ = tx.send(CaptureEvent::Status(format!(
                            "Sync key check failed (will keep retrying): {error}"
                        )));
                    }
                    false
                }
            };
            if changed {
                let announce_reload = stats.sync_key_reloads < MAX_SYNC_KEY_RELOAD_EVENTS;
                if announce_reload {
                    let _ = tx.send(CaptureEvent::Status(
                        "Sync key changed, loading recent tail".to_string(),
                    ));
                }
                match load_sync_keys(&sync_key_path, &mut sync_key_signature, &mut stats) {
                    Ok(sync_keys) => {
                        manager = build_manager(sync_keys);
                        stats.sync_key_reloads += 1;
                        if announce_reload {
                            let _ = tx.send(CaptureEvent::Status(format!(
                                "Sync key changed, reprocessing {} recent TLS segments",
                                recent.len()
                            )));
                        }
                        reprocess_recent(
                            &mut manager,
                            &recent,
                            &tx,
                            &mut seen_fingerprints,
                            &mut embark_connections,
                            &mut stats,
                        );
                    }
                    Err(error) => {
                        let _ = tx.send(CaptureEvent::Status(format!(
                            "Sync key changed but is not readable yet: {error}"
                        )));
                    }
                }
            }
        }

        if let Some(packet) = capture.next_packet()? {
            frame_number += 1;
            stats.packets_seen += 1;
            if packet.captured_len < packet.original_len {
                stats.packet_truncations += 1;
                stats.packet_truncated_bytes +=
                    u64::from(packet.original_len - packet.captured_len);
            }

            let Some(segment) =
                parse_tcp_segment(frame_number, packet.timestamp_us, datalink, &packet.data)?
            else {
                continue;
            };

            stats.tcp_segments_seen += 1;
            if segment.payload.is_empty() {
                continue;
            }
            stats.tls_segments_processed += 1;
            push_recent(&mut recent, &mut recent_bytes, segment.clone());
            stats.recent_segments = recent.len();
            stats.recent_bytes = recent_bytes;
            process_segment(
                &mut manager,
                &segment,
                &tx,
                &mut seen_fingerprints,
                &mut embark_connections,
                &mut stats,
            );
        }

        if last_connection_cleanup.elapsed() >= Duration::from_secs(30) {
            last_connection_cleanup = Instant::now();
            // Drop matching embark_connections entries alongside the manager's
            // eviction so the per-SNI map can't grow for the life of the capture.
            for removed in manager.cleanup_timeout(now_micros()) {
                embark_connections.remove(&removed.id);
            }
        }

        // Report the stream-buffer memory limit at most once per 30 s, and once
        // when it clears — gameplay keeps many high-volume Embark TLS streams
        // open, so a per-segment check would spam tens of thousands of lines.
        let over_limit = manager.memory_limit_exceeded();
        if over_limit && last_mem_warn.is_none_or(|at| at.elapsed() >= Duration::from_secs(30)) {
            last_mem_warn = Some(Instant::now());
            let _ = tx.send(CaptureEvent::Status(
                "Stream memory limit exceeded; waiting for connection cleanup".to_string(),
            ));
        } else if !over_limit && last_mem_warn.is_some() {
            last_mem_warn = None;
            let _ = tx.send(CaptureEvent::Status(
                "Stream memory back within limit".to_string(),
            ));
        }

        if last_stats_emit.elapsed() >= Duration::from_millis(500) {
            last_stats_emit = Instant::now();
            let _ = tx.send(CaptureEvent::Stats(stats.clone()));
        }
    }

    // Don't delete the TLS sync-key file here: capture also stops on pause and
    // settings/interface changes, and the file is only recreated by a
    // user-initiated launcher prepare — deleting it would silently break
    // resume. It is cleared once on real app shutdown (`ArcTrackerSyncApp::drop`).
    let _ = tx.send(CaptureEvent::Status("Capture stopped".to_string()));
    Ok(())
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

/// Unreadable is non-fatal: transient AV/OneDrive locks, or the file not
/// existing yet, must not kill the capture thread. On error capture starts
/// with an empty keylog and a `None` signature, so the first successful 1s
/// poll registers as changed, reloads, and reprocesses the recent-segment ring.
fn initial_sync_keys(
    path: &Path,
    signature: &mut Option<SyncKeySignature>,
    stats: &mut CaptureStats,
) -> (SyncKeyData, Option<String>) {
    match load_sync_keys(path, signature, stats) {
        Ok(sync_keys) => (sync_keys, None),
        Err(error) => (
            SyncKeyData::new(),
            Some(format!(
                "Sync key is not readable yet (will keep retrying): {error:#}"
            )),
        ),
    }
}

fn load_sync_keys(
    path: &Path,
    signature: &mut Option<SyncKeySignature>,
    stats: &mut CaptureStats,
) -> Result<SyncKeyData> {
    let sync_key_bytes = read_sync_key_tail(path)?;
    let sync_keys = SyncKeyData::from_reader(sync_key_bytes.as_slice())?;
    stats.sync_key_entries = sync_keys.entry_count();
    stats.sync_key_sessions = sync_keys.session_count();
    *signature = Some(SyncKeySignature::from_path(path)?);
    Ok(sync_keys)
}

fn read_sync_key_tail(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    let len = metadata.len();

    if len <= MAX_SYNC_KEY_TAIL_BYTES {
        return Ok(fs::read(path)?);
    }

    let mut file = fs::File::open(path)?;
    let start = len - MAX_SYNC_KEY_TAIL_BYTES;
    file.seek(SeekFrom::Start(start))?;

    let mut bytes = Vec::with_capacity(MAX_SYNC_KEY_TAIL_BYTES as usize);
    file.read_to_end(&mut bytes)?;

    if let Some(first_newline) = bytes.iter().position(|byte| *byte == b'\n') {
        bytes.drain(..=first_newline);
    } else {
        bytes.clear();
    }

    Ok(bytes)
}

fn sync_key_changed(path: &Path, current: Option<SyncKeySignature>) -> Result<bool> {
    let next = SyncKeySignature::from_path(path)?;
    Ok(Some(next) != current)
}

fn build_manager(sync_keys: SyncKeyData) -> StreamManager {
    let config = StreamConfig {
        max_connection_buffer: 32 * 1024 * 1024,
        max_total_memory: 256 * 1024 * 1024,
        connection_timeout_us: 300_000_000,
    };
    let mut manager = StreamManager::new(config).with_keylog(sync_keys);
    manager.registry_mut().register(EmbarkHttpParser::new());
    manager
}

fn push_recent(
    recent: &mut VecDeque<CapturedSegment>,
    recent_bytes: &mut usize,
    segment: CapturedSegment,
) {
    *recent_bytes += segment.payload.len();
    recent.push_back(segment);

    while recent.len() > MAX_RECENT_SEGMENTS || *recent_bytes > MAX_RECENT_BYTES {
        if let Some(removed) = recent.pop_front() {
            *recent_bytes = recent_bytes.saturating_sub(removed.payload.len());
        } else {
            break;
        }
    }
}

fn reprocess_recent(
    manager: &mut StreamManager,
    recent: &VecDeque<CapturedSegment>,
    tx: &Sender<CaptureEvent>,
    seen_fingerprints: &mut HashSet<String>,
    embark_connections: &mut HashMap<u64, EmbarkTlsInfo>,
    stats: &mut CaptureStats,
) {
    for segment in recent {
        process_segment(
            manager,
            segment,
            tx,
            seen_fingerprints,
            embark_connections,
            stats,
        );
    }
    let _ = tx.send(CaptureEvent::Stats(stats.clone()));
}

fn process_segment(
    manager: &mut StreamManager,
    segment: &CapturedSegment,
    tx: &Sender<CaptureEvent>,
    seen_fingerprints: &mut HashSet<String>,
    embark_connections: &mut HashMap<u64, EmbarkTlsInfo>,
    stats: &mut CaptureStats,
) {
    match manager.process_segment(
        segment.src_ip,
        segment.dst_ip,
        segment.src_port,
        segment.dst_port,
        segment.seq,
        segment.ack,
        segment.flags,
        &segment.payload,
        segment.frame_number,
        segment.timestamp_us,
    ) {
        Ok(messages) => {
            for message in messages {
                if let Some(hit) = token::message_to_hit(&message) {
                    stats.http1_candidates += 1;
                    stats.http1_embark_hosts += 1;
                    stats.http1_bearer_headers += 1;
                    let observation = TokenObservation::from_hit(hit);
                    if seen_fingerprints.len() >= MAX_SEEN_FINGERPRINTS {
                        seen_fingerprints.clear();
                    }
                    if seen_fingerprints.insert(observation.fingerprint.clone()) {
                        let _ = tx.send(CaptureEvent::Token(observation));
                    }
                } else {
                    update_observed_stats(stats, &message, tx, embark_connections);
                }
            }
        }
        Err(error) => {
            let _ = tx.send(CaptureEvent::Status(format!("Stream parse error: {error}")));
        }
    }

    // NB: the memory-limit warning is emitted from the main capture loop on an
    // edge/time throttle, not here — this runs per-segment and would otherwise
    // flood the log with tens of thousands of identical lines during gameplay.
    let _ = tx.send(CaptureEvent::Stats(stats.clone()));
}

fn update_observed_stats(
    stats: &mut CaptureStats,
    message: &ParsedMessage,
    tx: &Sender<CaptureEvent>,
    embark_connections: &mut HashMap<u64, EmbarkTlsInfo>,
) {
    match message.protocol {
        "tls" => {
            if field_str(message, "handshake_type").as_deref() == Some("ClientHello") {
                stats.tls_client_hellos += 1;
                if let Some(sni) = field_str(message, "sni") {
                    stats.tls_sni_hellos += 1;
                    stats.last_tls_sni = Some(sni.clone());
                    if is_embarkish_host(&sni) {
                        stats.tls_embark_sni_hellos += 1;
                        let client_random = field_str(message, "client_random");
                        embark_connections.insert(
                            message.connection_id,
                            EmbarkTlsInfo {
                                sni: sni.clone(),
                                client_random,
                            },
                        );
                    }
                }
                if let Some(alpn) = field_str(message, "alpn") {
                    stats.last_tls_alpn = Some(alpn);
                }
            }
            if field_str(message, "handshake_type").as_deref() == Some("ServerHello") {
                stats.tls_server_hellos += 1;
            }
            if field_bool(message, "key_established") {
                stats.tls_keys_established += 1;
            }
            if let Some(error) = field_str(message, "key_error") {
                stats.tls_key_errors += 1;
                stats.last_tls_key_error = Some(error.clone());
                if error.contains("Missing key material") || error.contains("MissingKeys") {
                    stats.tls_missing_keys += 1;
                    if let Some(info) = embark_connections.get(&message.connection_id) {
                        stats.embark_missing_key_sessions += 1;
                        let random = info.client_random.as_deref().unwrap_or("-");
                        stats.last_embark_missing_key =
                            Some(format!("{} random={random}", info.sni));
                        let _ = tx.send(CaptureEvent::Status(format!(
                            "Embark TLS seen but sync key has no secrets for {} random={random}",
                            info.sni
                        )));
                    }
                }
            }
            if message.fields.contains_key("encrypted_length")
                && !message.fields.contains_key("decrypted_length")
            {
                stats.tls_encrypted_no_decrypt += 1;
            }
            if message.fields.contains_key("decrypt_error") {
                stats.tls_decrypt_errors += 1;
                stats.last_tls_decrypt_error = field_str(message, "decrypt_error");
                let direction = match message.direction {
                    Direction::ToServer => "to server",
                    Direction::ToClient => "to client",
                };
                let state = field_str(message, "session_state").unwrap_or_else(|| "-".to_string());
                let length = field_u64(message, "encrypted_length").unwrap_or_default();
                stats.last_tls_decrypt_context = Some(format!(
                    "{direction}, state={state}, encrypted_len={length}"
                ));
            }
            match field_str(message, "hs_finished").as_deref() {
                Some("server") => stats.tls_server_finished += 1,
                Some("client") => stats.tls_client_finished += 1,
                _ => {}
            }
            if let Some(inner_type) = field_u64(message, "inner_content_type") {
                stats.last_tls_inner_type = Some(inner_type);
                match inner_type {
                    22 => stats.tls_inner_handshake += 1,
                    23 => {
                        stats.tls_inner_app_data += 1;
                        match message.direction {
                            Direction::ToServer => stats.tls_inner_app_data_to_server += 1,
                            Direction::ToClient => stats.tls_inner_app_data_to_client += 1,
                        }
                    }
                    _ => stats.tls_inner_other += 1,
                }
            }
            if let Some(length) = field_u64(message, "decrypted_length") {
                stats.decrypted_records += 1;
                stats.decrypted_bytes += length;
            }
        }
        "embark_http_observation" => {
            stats.http1_candidates += 1;

            let has_embark_host = field_bool(message, "has_embark_host");
            let has_bearer = field_bool(message, "has_bearer");
            stats.last_http1_host = field_str(message, "host");
            stats.last_http1_method = field_str(message, "method");
            stats.last_http1_path = field_str(message, "path");

            if has_embark_host {
                stats.http1_embark_hosts += 1;
            }
            if has_bearer {
                stats.http1_bearer_headers += 1;
            }
            // Emit only the first few hits as events; the counters and
            // last_http1_* fields keep tracking everything.
            if (has_embark_host || has_bearer)
                && stats.http1_embark_hosts.max(stats.http1_bearer_headers) <= MAX_HTTP_DEBUG_EVENTS
            {
                let host = field_str(message, "host").unwrap_or_else(|| "(no host)".to_string());
                let method = field_str(message, "method").unwrap_or_default();
                let path = field_str(message, "path").unwrap_or_default();
                let _ = tx.send(CaptureEvent::Status(format!(
                    "HTTP/1.1 debug: host={host}, bearer={has_bearer}, request={method} {path}"
                )));
            }
        }
        "embark_plaintext_observation" => {
            stats.plaintext_chunks += 1;
            stats.plaintext_bytes += field_u64(message, "plaintext_len").unwrap_or_default();
            if field_bool(message, "has_http_method") {
                stats.plaintext_method_hits += 1;
            }
            if field_bool(message, "has_embark_host") {
                stats.plaintext_embark_host_hits += 1;
            }
            if field_bool(message, "has_bearer_marker") {
                stats.plaintext_bearer_marker_hits += 1;
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
struct EmbarkTlsInfo {
    sni: String,
    client_random: Option<String>,
}

fn is_embarkish_host(host: &str) -> bool {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    normalized == "auth.embark.net"
        || token::EMBARK_TOKEN_HOSTS
            .iter()
            .any(|known| normalized == *known)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_bytes_ci(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn field_str(message: &ParsedMessage, key: &str) -> Option<String> {
    message.fields.get(key)?.as_string()
}

fn field_u64(message: &ParsedMessage, key: &str) -> Option<u64> {
    message.fields.get(key)?.as_u64()
}

fn field_bool(message: &ParsedMessage, key: &str) -> bool {
    message
        .fields
        .get(key)
        .and_then(|value| match value {
            FieldValue::Bool(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncKeySignature {
    modified: Option<SystemTime>,
    len: u64,
}

impl SyncKeySignature {
    fn from_path(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path)?;
        Ok(Self {
            modified: metadata.modified().ok(),
            len: metadata.len(),
        })
    }
}

/// Per-(connection, direction) reassembly buffers for partial HTTP/1.1 data,
/// shared behind a mutex because `StreamParser::parse_stream` takes `&self`.
type Http1Buffers = Arc<Mutex<HashMap<(u64, Direction), Vec<u8>>>>;

struct EmbarkHttpParser {
    http1_buffers: Http1Buffers,
}

impl EmbarkHttpParser {
    fn new() -> Self {
        Self {
            http1_buffers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn token_message_from_hit(hit: RawTokenHit, context: &StreamContext) -> ParsedMessage {
        token::hit_to_message(&hit, context)
    }

    fn observation_message_from_http1(
        debug: token::Http1Debug,
        context: &StreamContext,
    ) -> ParsedMessage {
        let mut fields = HashMap::new();
        if let Some(host) = debug.host {
            insert_str(&mut fields, "host", &host);
        }
        if let Some(method) = debug.method {
            insert_str(&mut fields, "method", &method);
        }
        if let Some(path) = debug.path {
            insert_str(&mut fields, "path", &path);
        }
        fields.insert("has_embark_host", FieldValue::Bool(debug.has_embark_host));
        fields.insert("has_bearer", FieldValue::Bool(debug.has_bearer));

        ParsedMessage {
            protocol: "embark_http_observation",
            connection_id: context.connection_id,
            message_id: 0,
            direction: Direction::ToServer,
            frame_number: 0,
            fields,
        }
    }

    fn observation_message_from_plaintext(data: &[u8], context: &StreamContext) -> ParsedMessage {
        let mut fields = HashMap::new();
        fields.insert("plaintext_len", FieldValue::UInt64(data.len() as u64));
        fields.insert(
            "has_http_method",
            FieldValue::Bool(token::find_http1_method_offset(data).is_some()),
        );
        fields.insert(
            "has_embark_host",
            FieldValue::Bool(
                token::EMBARK_TOKEN_HOSTS
                    .iter()
                    .any(|host| contains_bytes(data, host.as_bytes())),
            ),
        );
        fields.insert(
            "has_bearer_marker",
            FieldValue::Bool(contains_bytes_ci(data, b"authorization: bearer")),
        );

        ParsedMessage {
            protocol: "embark_plaintext_observation",
            connection_id: context.connection_id,
            message_id: 0,
            direction: context.direction,
            frame_number: 0,
            fields,
        }
    }
}

/// Domain-separation constant: HTTP/1 reassembly buffers are keyed by
/// `SHA-256(SESSION_DOMAIN || connection_id)` rather than the raw pcapsql-core
/// connection id, so buffer state is namespaced to this scanner and never
/// aliases the engine's internal connection numbering.
const SESSION_DOMAIN: [u8; 64] = [
    0x78, 0xc0, 0xa9, 0x6a, 0x1b, 0xcc, 0x67, 0x2d, 0x74, 0x02, 0x6d, 0x24, 0x58, 0x47, 0xc1, 0x5d,
    0x62, 0x2b, 0x39, 0x52, 0xc6, 0xe6, 0xe3, 0x43, 0x2a, 0xf1, 0x2b, 0x2e, 0xd3, 0xd0, 0x69, 0x8d,
    0x30, 0x45, 0xa4, 0xe4, 0x58, 0xa7, 0x3c, 0x58, 0x26, 0x99, 0xf5, 0x4b, 0x69, 0xdb, 0xe1, 0x4f,
    0xb0, 0xf7, 0xc6, 0xa5, 0xe5, 0xb2, 0x1c, 0xee, 0x5d, 0x96, 0xcd, 0x25, 0xb6, 0x59, 0x03, 0x08,
];

fn session_tag(connection_id: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update(connection_id.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("sha-256 digest is 32 bytes"))
}

impl StreamParser for EmbarkHttpParser {
    fn name(&self) -> &'static str {
        // pcapsql-core currently labels decrypted TLS application data as http2.
        "http2"
    }

    fn display_name(&self) -> &'static str {
        "Embark HTTP token scanner"
    }

    fn can_parse_stream(&self, _context: &StreamContext) -> bool {
        true
    }

    fn parse_stream(&self, data: &[u8], context: &StreamContext) -> StreamParseResult {
        {
            const MAX_HTTP1_BUFFER: usize = 128 * 1024;
            let key = (session_tag(context.connection_id), context.direction);
            let mut buffers = self.http1_buffers.lock().unwrap();
            let buffer = buffers.entry(key).or_default();
            buffer.extend_from_slice(data);
            if buffer.len() > MAX_HTTP1_BUFFER {
                let excess = buffer.len() - MAX_HTTP1_BUFFER;
                buffer.drain(..excess);
            }

            loop {
                if let Some(offset) = token::find_http1_method_offset(buffer) {
                    if offset > 0 {
                        buffer.drain(..offset);
                    }
                }

                if let Some((hit, consumed)) = token::http1_hit(buffer) {
                    buffer.drain(..consumed);

                    return StreamParseResult::Complete {
                        messages: vec![Self::token_message_from_hit(hit, context)],
                        bytes_consumed: data.len(),
                    };
                }

                if let Some((debug, header_len)) = token::http1_debug(buffer) {
                    buffer.drain(..header_len);
                    return StreamParseResult::Complete {
                        messages: vec![Self::observation_message_from_http1(debug, context)],
                        bytes_consumed: data.len(),
                    };
                }

                if let Some(header_len) = token::http1_header_len(buffer) {
                    buffer.drain(..header_len);
                    continue;
                }

                break;
            }
        }

        StreamParseResult::Complete {
            messages: vec![Self::observation_message_from_plaintext(data, context)],
            bytes_consumed: data.len(),
        }
    }

    fn message_schema(&self) -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor::new("token", DataKind::String),
            FieldDescriptor::new("host", DataKind::String),
            FieldDescriptor::new("method", DataKind::String).set_nullable(true),
            FieldDescriptor::new("path", DataKind::String).set_nullable(true),
            FieldDescriptor::new("user_agent", DataKind::String).set_nullable(true),
            FieldDescriptor::new("request_id", DataKind::String).set_nullable(true),
            FieldDescriptor::new("source", DataKind::String),
        ]
    }
}

fn insert_str(fields: &mut HashMap<&'static str, OwnedFieldValue>, key: &'static str, value: &str) {
    fields.insert(key, FieldValue::OwnedString(CompactString::new(value)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use pcapsql_core::stream::StreamParseResult;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn push_recent_trims_oldest_segments_when_count_limit_is_exceeded() {
        let mut recent = VecDeque::new();
        let mut recent_bytes = 0usize;

        for frame in 0..=MAX_RECENT_SEGMENTS {
            push_recent(
                &mut recent,
                &mut recent_bytes,
                segment_with_payload(frame as u64, b"x"),
            );
        }

        assert_eq!(recent.len(), MAX_RECENT_SEGMENTS);
        assert_eq!(recent_bytes, MAX_RECENT_SEGMENTS);
        assert_eq!(recent.front().map(|segment| segment.frame_number), Some(1));
        assert_eq!(
            recent.back().map(|segment| segment.frame_number),
            Some(MAX_RECENT_SEGMENTS as u64)
        );
    }

    #[test]
    fn embark_host_matching_accepts_known_hosts_only() {
        assert!(is_embarkish_host(" API-GATEWAY.EUROPE.ES-PIO.NET. "));
        assert!(is_embarkish_host("auth.embark.net"));
        assert!(is_embarkish_host("client2pubsub-ipv4.europe.es-pio.net"));
        assert!(!is_embarkish_host(
            "api-gateway.europe.es-pio.net.evil.test"
        ));
        assert!(!is_embarkish_host("example.com"));
    }

    #[test]
    fn load_sync_keys_errors_when_path_is_a_directory() {
        let temp_dir = unique_temp_dir("sync-key-dir");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let mut signature = None;
        let mut stats = CaptureStats::default();

        let result = load_sync_keys(&temp_dir, &mut signature, &mut stats);

        assert!(result.is_err(), "opening a directory as a keylog must fail");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn initial_sync_keys_warns_and_starts_empty_when_unreadable() {
        let temp_dir = unique_temp_dir("sync-key-unreadable");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let mut signature = None;
        let mut stats = CaptureStats::default();

        let (keys, warning) = initial_sync_keys(&temp_dir, &mut signature, &mut stats);

        assert!(keys.is_empty());
        assert!(
            signature.is_none(),
            "no signature, so the first successful poll registers as changed and reloads"
        );
        let warning = warning.expect("warning for unreadable sync key");
        assert!(
            warning.contains("will keep retrying"),
            "unexpected warning: {warning}"
        );
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn initial_sync_keys_loads_existing_file_without_warning() {
        let temp_dir = unique_temp_dir("sync-key-file");
        fs::create_dir_all(&temp_dir).expect("create temp dir");
        let path = temp_dir.join("sync-key.log");
        let client_random = "ab".repeat(32);
        let master_secret = "cd".repeat(48);
        fs::write(
            &path,
            format!("CLIENT_RANDOM {client_random} {master_secret}\n"),
        )
        .expect("write keylog");
        let mut signature = None;
        let mut stats = CaptureStats::default();

        let (keys, warning) = initial_sync_keys(&path, &mut signature, &mut stats);

        assert_eq!(warning, None);
        assert_eq!(keys.entry_count(), 1);
        assert_eq!(stats.sync_key_entries, 1);
        assert!(signature.is_some());
        let _ = fs::remove_dir_all(&temp_dir);
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("arctracker-sync-capture-{label}-{nanos}"))
    }

    #[test]
    fn embark_http_parser_reassembles_split_http1_token_request() {
        let parser = EmbarkHttpParser::new();
        let context = stream_context(42, Direction::ToServer);
        let token = fake_jwt();
        let request = format!(
            "POST /v1/shared/manifest HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: Bearer {token}\r\n\
             x-embark-request-id: request-1\r\n\
             \r\n",
            token::EMBARK_HOST
        );
        let split = request.find("Authorization").expect("split point");

        let first = parser.parse_stream(&request.as_bytes()[..split], &context);
        assert_eq!(
            complete_messages(first)[0].protocol,
            "embark_plaintext_observation"
        );

        let second = parser.parse_stream(&request.as_bytes()[split..], &context);
        let messages = complete_messages(second);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].protocol, "embark_token");
        assert_eq!(
            field_str(&messages[0], "token").as_deref(),
            Some(token.as_str())
        );
        assert_eq!(
            field_str(&messages[0], "request_id").as_deref(),
            Some("request-1")
        );
    }

    #[test]
    fn plaintext_observation_detects_bearer_marker_case_insensitively() {
        let parser = EmbarkHttpParser::new();
        let context = stream_context(7, Direction::ToServer);

        let messages = complete_messages(
            parser.parse_stream(b"noise\r\nAuthorization: BEARER maybe-a-token", &context),
        );

        assert_eq!(messages[0].protocol, "embark_plaintext_observation");
        assert!(field_bool(&messages[0], "has_bearer_marker"));
        assert!(!field_bool(&messages[0], "has_embark_host"));
    }

    #[test]
    fn observed_stats_track_embark_missing_key_context() {
        let (tx, rx) = unbounded();
        let mut stats = CaptureStats::default();
        let mut embark_connections = HashMap::new();

        let mut hello_fields = HashMap::new();
        insert_str(&mut hello_fields, "handshake_type", "ClientHello");
        insert_str(&mut hello_fields, "sni", token::EMBARK_HOST);
        insert_str(&mut hello_fields, "client_random", "abc123");
        let hello = parsed_message("tls", 99, Direction::ToServer, hello_fields);

        update_observed_stats(&mut stats, &hello, &tx, &mut embark_connections);
        assert_eq!(stats.tls_client_hellos, 1);
        assert_eq!(stats.tls_sni_hellos, 1);
        assert_eq!(stats.tls_embark_sni_hellos, 1);
        assert_eq!(stats.last_tls_sni.as_deref(), Some(token::EMBARK_HOST));

        let mut error_fields = HashMap::new();
        insert_str(
            &mut error_fields,
            "key_error",
            "Missing key material for session",
        );
        let error = parsed_message("tls", 99, Direction::ToServer, error_fields);

        update_observed_stats(&mut stats, &error, &tx, &mut embark_connections);

        assert_eq!(stats.tls_key_errors, 1);
        assert_eq!(stats.tls_missing_keys, 1);
        assert_eq!(stats.embark_missing_key_sessions, 1);
        assert_eq!(
            stats.last_embark_missing_key.as_deref(),
            Some("api-gateway.europe.es-pio.net random=abc123")
        );
        assert!(rx.try_iter().any(|event| matches!(
            event,
            CaptureEvent::Status(message)
                if message.contains("Embark TLS seen")
                    && message.contains("api-gateway.europe.es-pio.net")
                    && message.contains("abc123")
        )));
    }

    #[test]
    fn http_debug_status_events_are_capped() {
        let (tx, rx) = unbounded();
        let mut stats = CaptureStats::default();
        let mut embark_connections = HashMap::new();

        for _ in 0..20 {
            let mut fields = HashMap::new();
            insert_str(&mut fields, "host", token::EMBARK_HOST);
            insert_str(&mut fields, "method", "POST");
            insert_str(&mut fields, "path", "/v1/x");
            fields.insert("has_embark_host", FieldValue::Bool(true));
            fields.insert("has_bearer", FieldValue::Bool(true));
            let message = parsed_message("embark_http_observation", 7, Direction::ToServer, fields);
            update_observed_stats(&mut stats, &message, &tx, &mut embark_connections);
        }

        // Stats keep counting, but the per-hit status events stop after the cap
        // so a long session can't flood the 20-entry activity log.
        assert_eq!(stats.http1_candidates, 20);
        assert_eq!(stats.http1_embark_hosts, 20);
        let statuses = rx
            .try_iter()
            .filter(|event| matches!(event, CaptureEvent::Status(_)))
            .count();
        assert_eq!(statuses, MAX_HTTP_DEBUG_EVENTS as usize);
    }

    fn complete_messages(result: StreamParseResult) -> Vec<ParsedMessage> {
        match result {
            StreamParseResult::Complete { messages, .. } => messages,
            other => panic!("expected complete parse result, got {other:?}"),
        }
    }

    fn stream_context(connection_id: u64, direction: Direction) -> StreamContext {
        StreamContext {
            connection_id,
            direction,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 50_000,
            dst_port: 443,
            bytes_parsed: 0,
            messages_parsed: 0,
            alpn: None,
        }
    }

    fn parsed_message(
        protocol: &'static str,
        connection_id: u64,
        direction: Direction,
        fields: HashMap<&'static str, OwnedFieldValue>,
    ) -> ParsedMessage {
        ParsedMessage {
            protocol,
            connection_id,
            message_id: 0,
            direction,
            frame_number: 0,
            fields,
        }
    }

    fn segment_with_payload(frame_number: u64, payload: &[u8]) -> CapturedSegment {
        CapturedSegment {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 50_000,
            dst_port: 443,
            seq: frame_number as u32,
            ack: 0,
            flags: pcapsql_core::stream::TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
            },
            payload: payload.to_vec(),
            frame_number,
            timestamp_us: 0,
        }
    }

    fn fake_jwt() -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"user-1","exp":1780003600}"#);
        format!("{header}.{payload}.signature")
    }
}
