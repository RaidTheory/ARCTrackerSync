//! End-to-end tests for the self-updater pipeline against a local in-process
//! HTTP server — no GitHub, no network, no elevation required.
//!
//! These run as an integration-test target, which (unlike the binary) carries no
//! `requireAdministrator` manifest, so they launch from an ordinary shell.
//!
//! Keep this file's name free of `update`/`install`/`setup`/`patch`: those
//! substrings trip Windows' UAC installer-detection heuristic on the unsigned
//! test exe, which then demands elevation (os error 740) and breaks `cargo test`.
//! That's why this isn't named `updater_e2e`.
//!
//! Covered: release-metadata parsing (incl. the mandatory `SHA256SUMS` gate),
//! streamed download + hashing, checksum verification, and zip extraction.
//! `self_replace`, the `icacls` hardening, and the UAC-inherited relaunch are
//! validated separately in the elevated GUI run.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use arctracker_sync::updater::{self, InstallProgress, ReleaseInfo};

const ZIP_NAME: &str = "arctracker-sync-0.2.0-windows-x64.zip";
const EXE_BYTES: &[u8] = b"NEW-ARCTRACKER-SYNC-BINARY-v0.2.0";

// ----- local test server ---------------------------------------------------------

/// Bind a throwaway loopback server and answer each GET by path. Routes are
/// built from the real base URL so `latest.json` can embed correct asset URLs.
/// Returns the base URL; the server thread runs for the rest of the test.
fn serve(build_routes: impl FnOnce(&str) -> HashMap<String, Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let routes = Arc::new(build_routes(&base));

    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let mut buf = [0u8; 8192];
            let read = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();

            match routes.get(path.as_str()) {
                Some(body) => {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body);
                }
                None => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            }
            let _ = stream.flush();
        }
    });

    base
}

// ----- fixtures ------------------------------------------------------------------

fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            writer.start_file(*name, options).expect("start zip entry");
            writer.write_all(data).expect("write zip entry");
        }
        writer.finish().expect("finish zip");
    }
    cursor.into_inner()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// GitHub-shaped `releases/latest` JSON. `include_sums` toggles the mandatory
/// `SHA256SUMS` asset so a test can prove the updater rejects a release without it.
fn latest_json(base: &str, zip_len: usize, sums_len: usize, include_sums: bool) -> String {
    let sums_asset = if include_sums {
        format!(
            r#",{{"name":"SHA256SUMS","size":{sums_len},"browser_download_url":"{base}/sums"}}"#
        )
    } else {
        String::new()
    };
    format!(
        r#"{{"tag_name":"v0.2.0","draft":false,"prerelease":false,"assets":[{{"name":"{ZIP_NAME}","size":{zip_len},"browser_download_url":"{base}/zip"}}{sums_asset}]}}"#
    )
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("arc-e2e-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// A `ReleaseInfo` pointing at the local server, bypassing `fetch_latest`
/// (whose parsing has its own tests) so download/verify can be exercised directly.
fn release_at(base: &str) -> ReleaseInfo {
    ReleaseInfo {
        version: semver::Version::new(0, 2, 0),
        tag: "v0.2.0".to_string(),
        notes: String::new(),
        download_url: format!("{base}/zip"),
        asset_name: ZIP_NAME.to_string(),
        size: 0,
        sums_url: format!("{base}/sums"),
    }
}

// ----- tests ---------------------------------------------------------------------

#[test]
fn fetch_parses_release_with_zip_and_sums() {
    let zip = make_zip(&[("arctracker-sync.exe", EXE_BYTES)]);
    let sums = format!("{}  {ZIP_NAME}\n", sha256_hex(&zip));

    let base = serve(move |base| {
        let latest = latest_json(base, zip.len(), sums.len(), true);
        HashMap::from([
            ("/latest.json".to_string(), latest.into_bytes()),
            ("/zip".to_string(), zip),
            ("/sums".to_string(), sums.into_bytes()),
        ])
    });

    let release = updater::fetch_latest_from(&format!("{base}/latest.json"))
        .expect("fetch_latest_from should parse the release");
    assert_eq!(release.tag, "v0.2.0");
    assert_eq!(release.version, semver::Version::new(0, 2, 0));
    assert_eq!(release.asset_name, ZIP_NAME);
    assert_eq!(release.download_url, format!("{base}/zip"));
    assert_eq!(release.sums_url, format!("{base}/sums"));
}

#[test]
fn fetch_rejects_release_without_sha256sums() {
    let zip = make_zip(&[("arctracker-sync.exe", EXE_BYTES)]);

    let base = serve(move |base| {
        let latest = latest_json(base, zip.len(), 0, false);
        HashMap::from([
            ("/latest.json".to_string(), latest.into_bytes()),
            ("/zip".to_string(), zip),
        ])
    });

    let err = updater::fetch_latest_from(&format!("{base}/latest.json"))
        .expect_err("a release without SHA256SUMS must be rejected at fetch time");
    assert!(
        err.contains("SHA256SUMS"),
        "error should name the missing checksum asset, got: {err}"
    );
}

#[test]
fn download_streams_and_hashes_correctly() {
    let zip = make_zip(&[("arctracker-sync.exe", EXE_BYTES)]);
    let expected = sha256_hex(&zip);
    let zip_for_server = zip.clone();

    let base = serve(move |_base| HashMap::from([("/zip".to_string(), zip_for_server)]));

    let release = release_at(&base);
    let dir = temp_dir("download");
    let dest = dir.join("download.zip");

    let digest =
        updater::download_to_file(&release, &dest, &|_p: InstallProgress| {}).expect("download");
    assert_eq!(
        digest, expected,
        "streamed SHA-256 must match the served zip"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), zip, "saved bytes must match");
}

#[test]
fn verify_checksum_accepts_match_and_rejects_others() {
    let zip = make_zip(&[("arctracker-sync.exe", EXE_BYTES)]);
    let good = sha256_hex(&zip);
    let sums = format!("{good}  {ZIP_NAME}\n");

    let base = serve(move |_base| HashMap::from([("/sums".to_string(), sums.into_bytes())]));
    let sums_url = format!("{base}/sums");

    updater::verify_checksum(&sums_url, ZIP_NAME, &good).expect("matching checksum should pass");

    let wrong = "0".repeat(64);
    let err = updater::verify_checksum(&sums_url, ZIP_NAME, &wrong).expect_err("mismatch fails");
    assert!(err.to_lowercase().contains("match"), "got: {err}");

    let err = updater::verify_checksum(&sums_url, "some-other.zip", &good)
        .expect_err("uncovered asset fails");
    assert!(err.to_lowercase().contains("cover"), "got: {err}");
}

#[test]
fn extract_exe_finds_binary_and_errors_when_absent() {
    let zip_with = make_zip(&[
        ("nested/arctracker-sync.exe", EXE_BYTES),
        ("README.txt", b"x"),
    ]);
    let dir = temp_dir("extract-ok");
    let zip_path = dir.join("with.zip");
    std::fs::write(&zip_path, &zip_with).unwrap();
    let exe = updater::extract_exe(&zip_path, &dir).expect("should find arctracker-sync.exe");
    assert_eq!(std::fs::read(&exe).unwrap(), EXE_BYTES);

    let zip_without = make_zip(&[("README.txt", b"x"), ("other.exe", b"y")]);
    let dir = temp_dir("extract-missing");
    let zip_path = dir.join("without.zip");
    std::fs::write(&zip_path, &zip_without).unwrap();
    let err = updater::extract_exe(&zip_path, &dir).expect_err("should error without the exe");
    assert!(err.contains("arctracker-sync.exe"), "got: {err}");
}
