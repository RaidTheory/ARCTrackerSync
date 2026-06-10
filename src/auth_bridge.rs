use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;

use crate::tr;

const APP_ID: &str = "arctracker-sync";
const CALLBACK_PORT: u16 = 39876;
const CALLBACK_PATH: &str = "/auth/callback";

const SUCCESS_HTML: &str = include_str!("../assets/bridge/success.html");
const ERROR_HTML: &str = include_str!("../assets/bridge/error.html");

pub struct AuthAttempt {
    pub url: String,
    pub rx: Receiver<Result<String, String>>,
}

pub fn start(base_url: &str) -> Result<AuthAttempt> {
    let state = make_state()?;
    let auth_url = build_authorize_url(base_url, &state);

    let listener = TcpListener::bind(("127.0.0.1", CALLBACK_PORT))
        .with_context(|| format!("binding local auth callback on port {CALLBACK_PORT}"))?;
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let result = accept_callback(listener, &state);
        let _ = tx.send(result.map_err(|error| format!("{error:#}")));
    });

    Ok(AuthAttempt { url: auth_url, rx })
}

pub fn token_is_current(token: &str) -> bool {
    let Some(exp) = token_expires_at(token) else {
        return false;
    };
    let now = unix_time_seconds();
    exp > now + 30
}

/// Whole days until the token's `exp` claim; negative once expired, `None` if
/// the token has no readable expiry.
pub fn token_days_remaining(token: &str) -> Option<i64> {
    let exp = token_expires_at(token)?;
    let now = unix_time_seconds();
    Some((exp - now) / 86_400)
}

fn token_expires_at(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp")?;
    // Some JWT libraries serialize `exp` as a float; accept both forms.
    exp.as_i64()
        .or_else(|| exp.as_f64().map(|value| value as i64))
}

fn build_authorize_url(base_url: &str, state: &str) -> String {
    let return_to = format!(
        "http://127.0.0.1:{CALLBACK_PORT}{CALLBACK_PATH}?state={}",
        percent_encode(state)
    );
    format!(
        "{}/api/auth/bridge/authorize?app={}&returnTo={}&state={}",
        base_url.trim_end_matches('/'),
        APP_ID,
        percent_encode(&return_to),
        percent_encode(state)
    )
}

#[cfg(windows)]
pub fn open_browser(url: &str) -> Result<()> {
    const SW_SHOWNORMAL: i32 = 1;
    let operation = wide_null("open");
    let target = wide_null(url);

    let result = unsafe {
        ShellExecuteW(
            0,
            operation.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;

    if result <= 32 {
        return Err(anyhow!(
            "could not open browser, ShellExecuteW returned {result}"
        ));
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn open_browser(url: &str) -> Result<()> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .context("opening browser")?;
    Ok(())
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn accept_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
    let (mut stream, _) = listener.accept().context("accepting auth callback")?;
    let request = read_http_request(&mut stream)?;
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty auth callback request"))?;
    let target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("auth callback request has no target"))?;

    // Reject anything that reached the socket under a non-loopback Host
    // (e.g. DNS rebinding).
    if !host_is_loopback(&request) {
        write_branded_response(&mut stream, BridgeOutcome::Error)?;
        return Err(anyhow!("auth callback had a non-loopback Host header"));
    }

    let query = target
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default();
    let state = query_value(query, "state").unwrap_or_default();
    let token = query_value(query, "token").unwrap_or_default();
    let error = query_value(query, "error").unwrap_or_default();

    if state != expected_state {
        write_branded_response(&mut stream, BridgeOutcome::Error)?;
        return Err(anyhow!("auth callback state mismatch"));
    }

    if !error.is_empty() {
        write_branded_response(&mut stream, BridgeOutcome::Error)?;
        return Err(anyhow!("ARCTracker sign-in failed: {error}"));
    }

    if token.is_empty() {
        write_branded_response(&mut stream, BridgeOutcome::Error)?;
        return Err(anyhow!("auth callback did not include a token"));
    }

    write_branded_response(&mut stream, BridgeOutcome::Success)?;
    Ok(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BridgeOutcome {
    Success,
    Error,
}

/// Render the branded bridge page in the app's active language.
fn render_bridge_page(outcome: BridgeOutcome) -> String {
    let (template, title, body) = match outcome {
        BridgeOutcome::Success => (
            SUCCESS_HTML,
            tr!("SyncApp.bridge.successTitle"),
            tr!("SyncApp.bridge.successBody"),
        ),
        BridgeOutcome::Error => (
            ERROR_HTML,
            tr!("SyncApp.bridge.errorTitle"),
            tr!("SyncApp.bridge.errorBody"),
        ),
    };

    let locale = crate::i18n::active_locale();
    template
        .replace("{{TITLE}}", &html_escape(&title))
        .replace("{{BODY}}", &html_escape(&body))
        .replace("{{LANG}}", &html_escape(&locale))
        .replace("{{DIR}}", text_direction(&locale))
}

fn write_branded_response(stream: &mut TcpStream, outcome: BridgeOutcome) -> Result<()> {
    let status = match outcome {
        BridgeOutcome::Success => 200,
        BridgeOutcome::Error => 400,
    };
    write_http_response(stream, status, &render_bridge_page(outcome))
}

fn text_direction(locale: &str) -> &'static str {
    // egui renders he LTR (documented limitation), but the bridge page is real
    // HTML, so honour RTL there.
    if locale.starts_with("he") {
        "rtl"
    } else {
        "ltr"
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(windows)]
#[link(name = "Shell32")]
extern "system" {
    fn ShellExecuteW(
        hwnd: isize,
        lp_operation: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show_cmd: i32,
    ) -> isize;
}

/// Read the HTTP request head, looping until the `\r\n\r\n` terminator — the
/// browser may split the request across TCP segments. A read timeout and size
/// cap keep a misbehaving client from blocking the callback thread.
fn read_http_request(stream: &mut TcpStream) -> Result<String> {
    const MAX_REQUEST_BYTES: usize = 16 * 1024;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .context("setting auth callback read timeout")?;

    let mut request = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream.read(&mut chunk).context("reading auth callback")?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if find_header_end(&request).is_some() || request.len() >= MAX_REQUEST_BYTES {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&request).to_string())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

/// True when the request's `Host` header is `127.0.0.1` or `localhost` (with or
/// without a port). A missing Host is rejected.
fn host_is_loopback(request: &str) -> bool {
    let Some(host) = request
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("Host"))
        .map(|(_, value)| value.trim())
    else {
        return false;
    };

    let host_name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    matches!(host_name, "127.0.0.1" | "localhost")
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> Result<()> {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .context("writing auth callback response")
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| percent_decode(value))
    })
}

/// CSRF `state` from the OS CSPRNG. Fails loud if the CSPRNG is unavailable
/// rather than falling back to a predictable value.
fn make_state() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow!("generating CSRF state from the OS CSPRNG: {error}"))?;
    Ok(hex::encode(bytes)[..32].to_string())
}

fn unix_time_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect::<Vec<_>>(),
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(byte);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn authorize_url_includes_encoded_return_to_and_state() {
        let state = "abc&state=bad";
        let url = build_authorize_url("https://arctracker.io/", state);

        assert!(url.starts_with("https://arctracker.io/api/auth/bridge/authorize?"));
        assert!(url.contains("app=arctracker-sync"));
        assert!(url.contains("returnTo=http%3A%2F%2F127.0.0.1%3A39876%2Fauth%2Fcallback%3Fstate%3Dabc%2526state%253Dbad"));
        assert!(url.contains("state=abc%26state%3Dbad"));
    }

    #[test]
    fn callback_error_returns_sign_in_failure() {
        crate::i18n::set_active_locale("en");
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let worker =
            thread::spawn(move || accept_callback(listener, "state-123").expect_err("callback"));

        let mut stream = TcpStream::connect(address).expect("connect callback");
        stream
            .write_all(
                b"GET /auth/callback?state=state-123&error=sign_in_unavailable HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .expect("write request");

        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        let error = worker.join().expect("worker result");

        assert!(response.contains("400 Bad Request"));
        // The branded page carries the localized error title from SyncApp.bridge.*.
        assert!(response.contains(&tr!("SyncApp.bridge.errorTitle")));
        assert_eq!(
            error.to_string(),
            "ARCTracker sign-in failed: sign_in_unavailable"
        );
    }

    #[test]
    fn token_current_check_uses_jwt_expiry() {
        let valid = fake_jwt(unix_time_seconds() + 120);
        let expired = fake_jwt(unix_time_seconds() - 1);

        assert!(token_is_current(&valid));
        assert!(!token_is_current(&expired));
        assert!(!token_is_current("not-a-jwt"));
    }

    fn fake_jwt(exp: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"user-1","exp":{exp}}}"#));
        format!("{header}.{payload}.signature")
    }
}
