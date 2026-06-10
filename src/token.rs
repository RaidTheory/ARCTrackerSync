use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Local};
use compact_str::CompactString;
use pcapsql_core::protocol::{FieldValue, OwnedFieldValue};
use pcapsql_core::stream::{Direction, ParsedMessage, StreamContext};
use sha2::{Digest, Sha256};

pub const EMBARK_HOST: &str = "api-gateway.europe.es-pio.net";

/// Hosts the game presents its Embark access token to. The api-gateway request
/// only happens around login, so token capture must also accept the pubsub
/// hosts that fire continuously during gameplay — otherwise starting the app
/// mid-session never syncs. `auth.embark.net` is deliberately excluded:
/// requests there can carry auth-flow credentials that aren't the gameplay
/// access token.
pub const EMBARK_TOKEN_HOSTS: &[&str] = &[
    EMBARK_HOST,
    "client2pubsub.europe.es-pio.net",
    "client2pubsub-ipv4.europe.es-pio.net",
];

#[derive(Debug, Clone, Default)]
pub struct RawTokenHit {
    pub token: String,
    pub host: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Http1Debug {
    pub host: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub has_embark_host: bool,
    pub has_bearer: bool,
}

#[derive(Debug, Clone)]
pub struct TokenObservation {
    pub token: String,
    pub fingerprint: String,
    pub observed_at: DateTime<Local>,
    pub host: String,
    pub path: Option<String>,
    pub request_id: Option<String>,
}

impl TokenObservation {
    pub fn from_hit(hit: RawTokenHit) -> Self {
        let fingerprint = fingerprint(&hit.token);
        Self {
            token: hit.token,
            fingerprint,
            observed_at: Local::now(),
            host: hit.host,
            path: hit.path,
            request_id: hit.request_id,
        }
    }

    /// Expiry from the JWT `exp` claim; `None` if the token isn't a readable
    /// JWT with a numeric `exp`.
    pub fn expires_at(&self) -> Option<DateTime<Local>> {
        let payload = self.token.split('.').nth(1)?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let exp_value = claims.get("exp")?;
        let exp = exp_value
            .as_i64()
            .or_else(|| exp_value.as_f64().map(|value| value as i64))?;
        Some(DateTime::from_timestamp(exp, 0)?.with_timezone(&Local))
    }
}

pub fn http1_hit(data: &[u8]) -> Option<(RawTokenHit, usize)> {
    let header_len = http1_header_len(data)?;
    let header_bytes = &data[..header_len - 4];
    let header_text = std::str::from_utf8(header_bytes).ok()?;

    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?.to_string();
    let path = request_parts.next()?.to_string();
    let version = request_parts.next().unwrap_or_default();

    if !is_http_method(&method) || !version.starts_with("HTTP/1.") {
        return None;
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let host = headers.get("host")?.to_string();
    if !is_embark_host(&host) {
        return None;
    }

    let token = bearer_from_header(headers.get("authorization")?)?;
    Some((
        RawTokenHit {
            token,
            host,
            method: Some(method),
            path: Some(path),
            user_agent: headers.get("user-agent").cloned(),
            request_id: headers.get("x-embark-request-id").cloned(),
            source: "http/1.1".to_string(),
        },
        header_len,
    ))
}

pub fn http1_debug(data: &[u8]) -> Option<(Http1Debug, usize)> {
    let header_len = http1_header_len(data)?;
    let header_bytes = &data[..header_len - 4];
    let header_text = std::str::from_utf8(header_bytes).ok()?;

    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?.to_string();
    let path = request_parts.next()?.to_string();
    let version = request_parts.next().unwrap_or_default();

    if !is_http_method(&method) || !version.starts_with("HTTP/1.") {
        return None;
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let host = headers.get("host").cloned();
    let has_embark_host = host.as_deref().map(is_embark_host).unwrap_or(false);
    let has_bearer = headers
        .get("authorization")
        .and_then(|value| bearer_from_header(value))
        .is_some();

    Some((
        Http1Debug {
            host,
            method: Some(method),
            path: Some(path),
            has_embark_host,
            has_bearer,
        },
        header_len,
    ))
}

pub fn http1_header_len(data: &[u8]) -> Option<usize> {
    find_subslice(data, b"\r\n\r\n").map(|index| index + 4)
}

pub fn find_http1_method_offset(data: &[u8]) -> Option<usize> {
    const METHODS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
    ];
    METHODS
        .iter()
        .filter_map(|method| find_subslice(data, method))
        .min()
}

pub fn hit_to_message(hit: &RawTokenHit, context: &StreamContext) -> ParsedMessage {
    let mut fields = HashMap::new();
    insert_str(&mut fields, "token", &hit.token);
    insert_str(&mut fields, "host", &hit.host);
    insert_str(&mut fields, "source", &hit.source);

    if let Some(method) = &hit.method {
        insert_str(&mut fields, "method", method);
    }
    if let Some(path) = &hit.path {
        insert_str(&mut fields, "path", path);
    }
    if let Some(user_agent) = &hit.user_agent {
        insert_str(&mut fields, "user_agent", user_agent);
    }
    if let Some(request_id) = &hit.request_id {
        insert_str(&mut fields, "request_id", request_id);
    }

    ParsedMessage {
        protocol: "embark_token",
        connection_id: context.connection_id,
        message_id: 0,
        direction: Direction::ToServer,
        frame_number: 0,
        fields,
    }
}

pub fn message_to_hit(message: &ParsedMessage) -> Option<RawTokenHit> {
    if message.protocol != "embark_token" {
        return None;
    }

    Some(RawTokenHit {
        token: field_str(message, "token")?,
        host: field_str(message, "host")?,
        method: field_str(message, "method"),
        path: field_str(message, "path"),
        user_agent: field_str(message, "user_agent"),
        request_id: field_str(message, "request_id"),
        source: field_str(message, "source").unwrap_or_else(|| "http/1.1".to_string()),
    })
}

fn insert_str(fields: &mut HashMap<&'static str, OwnedFieldValue>, key: &'static str, value: &str) {
    fields.insert(key, FieldValue::OwnedString(CompactString::new(value)));
}

fn field_str(message: &ParsedMessage, key: &str) -> Option<String> {
    message.fields.get(key)?.as_string()
}

fn bearer_from_header(value: &str) -> Option<String> {
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = parts.next()?.trim();
    if token.matches('.').count() != 2 {
        return None;
    }

    Some(token.to_string())
}

fn is_embark_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.');
    let host_without_port = host.split_once(':').map(|(h, _)| h).unwrap_or(host);
    EMBARK_TOKEN_HOSTS
        .iter()
        .any(|known| host_without_port.eq_ignore_ascii_case(known))
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Domain-separation prefix for observation fingerprints: the dedup key is
/// `SHA-256(DEDUP_DOMAIN || token)` rather than bare `SHA-256(token)`, so the
/// stored/loggable fingerprint can't be precomputed against candidate bearers.
const DEDUP_DOMAIN: [u8; 64] = [
    0xf5, 0x27, 0x21, 0x48, 0x72, 0x93, 0x63, 0xf9, 0xda, 0xb0, 0xd7, 0x1b, 0x24, 0x9d, 0x13, 0xf2,
    0xce, 0xe1, 0x51, 0xf7, 0x9c, 0x76, 0x5c, 0xb6, 0xeb, 0x12, 0x69, 0x0d, 0xfa, 0x47, 0x4b, 0x27,
    0x95, 0x0b, 0x07, 0x29, 0x10, 0x8d, 0x69, 0x32, 0x72, 0x26, 0xec, 0x71, 0x72, 0xcd, 0x38, 0x3d,
    0xe1, 0xb6, 0xe5, 0x36, 0x67, 0x86, 0xa2, 0x15, 0xf3, 0xf3, 0x9e, 0xf8, 0x27, 0x11, 0xa9, 0x0b,
];

fn fingerprint(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DEDUP_DOMAIN);
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    #[test]
    fn http1_hit_extracts_embark_bearer() {
        let token = fake_jwt();
        let request = format!(
            "POST /v1/shared/manifest HTTP/1.1\r\n\
             Host: api-gateway.europe.es-pio.net\r\n\
             Authorization: Bearer {token}\r\n\
             User-Agent: PioneerGame/test\r\n\
             x-embark-request-id: request-123\r\n\
             Content-Length: 2\r\n\
             \r\n{{}}"
        );

        let (hit, consumed) = http1_hit(request.as_bytes()).expect("token hit");
        assert_eq!(hit.token, token);
        assert_eq!(hit.host, EMBARK_HOST);
        assert_eq!(hit.method.as_deref(), Some("POST"));
        assert_eq!(hit.path.as_deref(), Some("/v1/shared/manifest"));
        assert_eq!(hit.user_agent.as_deref(), Some("PioneerGame/test"));
        assert_eq!(hit.request_id.as_deref(), Some("request-123"));
        assert_eq!(consumed, request.find("\r\n\r\n").unwrap() + 4);
    }

    #[test]
    fn http1_hit_extracts_bearer_from_client2pubsub_host() {
        let token = fake_jwt();
        let request = format!(
            "POST /client2pubsub.Client2PubSub/TransferBatched HTTP/1.1\r\n\
             Host: client2pubsub-ipv4.europe.es-pio.net\r\n\
             Authorization: Bearer {token}\r\n\
             \r\n"
        );

        let (hit, _) = http1_hit(request.as_bytes()).expect("token hit");
        assert_eq!(hit.token, token);
        assert_eq!(hit.host, "client2pubsub-ipv4.europe.es-pio.net");
        assert_eq!(
            hit.path.as_deref(),
            Some("/client2pubsub.Client2PubSub/TransferBatched")
        );
    }

    #[test]
    fn http1_hit_rejects_other_hosts() {
        for host in [
            "example.com",
            "auth.embark.net",
            "client2pubsub-ipv4.europe.es-pio.net.evil.test",
        ] {
            let request = format!(
                "POST /v1/shared/manifest HTTP/1.1\r\n\
                 Host: {host}\r\n\
                 Authorization: Bearer {}\r\n\
                 \r\n",
                fake_jwt()
            );

            assert!(
                http1_hit(request.as_bytes()).is_none(),
                "host should not produce a hit: {host}"
            );
        }
    }

    #[test]
    fn http1_hit_accepts_host_port_trailing_dot_and_bearer_case() {
        let token = fake_jwt();
        let request = format!(
            "GET /profile HTTP/1.1\r\n\
             Host: API-GATEWAY.EUROPE.ES-PIO.NET:443.\r\n\
             Authorization: bEaReR {token}\r\n\
             \r\n"
        );

        let (hit, _) = http1_hit(request.as_bytes()).expect("token hit");

        assert_eq!(hit.token, token);
        assert_eq!(hit.host, "API-GATEWAY.EUROPE.ES-PIO.NET:443.");
        assert_eq!(hit.method.as_deref(), Some("GET"));
        assert_eq!(hit.path.as_deref(), Some("/profile"));
    }

    #[test]
    fn http1_debug_reports_embark_host_without_bearer() {
        let request = format!(
            "POST /v1/shared/manifest HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: PioneerGame/test\r\n\
             \r\n",
            EMBARK_HOST
        );

        let (debug, consumed) = http1_debug(request.as_bytes()).expect("debug observation");

        assert_eq!(debug.host.as_deref(), Some(EMBARK_HOST));
        assert_eq!(debug.method.as_deref(), Some("POST"));
        assert_eq!(debug.path.as_deref(), Some("/v1/shared/manifest"));
        assert!(debug.has_embark_host);
        assert!(!debug.has_bearer);
        assert_eq!(consumed, request.find("\r\n\r\n").unwrap() + 4);
    }

    #[test]
    fn http1_hit_rejects_malformed_or_non_bearer_authorization() {
        for authorization in [
            "Bearer not-a-jwt",
            "Bearer one.two",
            "Basic abc.def.ghi",
            "Bearer",
        ] {
            let request = format!(
                "POST /v1/shared/manifest HTTP/1.1\r\n\
                 Host: {EMBARK_HOST}\r\n\
                 Authorization: {authorization}\r\n\
                 \r\n"
            );

            assert!(
                http1_hit(request.as_bytes()).is_none(),
                "authorization should not produce a hit: {authorization}"
            );
        }
    }

    #[test]
    fn find_http1_method_offset_returns_earliest_supported_method() {
        let data = b"xxDELETE /old HTTP/1.1\r\n\r\nPOST /new HTTP/1.1\r\n\r\n";

        assert_eq!(find_http1_method_offset(data), Some(2));
    }

    #[test]
    fn token_observation_expires_at_decodes_jwt_exp_claim() {
        let exp = 1_780_003_600i64;
        let observation = TokenObservation::from_hit(RawTokenHit {
            token: fake_jwt_with_exp(exp),
            host: EMBARK_HOST.to_string(),
            ..Default::default()
        });

        assert_eq!(observation.expires_at().map(|dt| dt.timestamp()), Some(exp));
    }

    fn fake_jwt() -> String {
        fake_jwt_with_exp(1_780_003_600)
    }

    fn fake_jwt_with_exp(exp: i64) -> String {
        let header = serde_json::json!({ "alg": "none", "typ": "JWT" }).to_string();
        let payload = serde_json::json!({
            "sub": "subject-1",
            "iss": "https://auth.embark.net/",
            "aud": ["https://pioneer.embark.net"],
            "iat": 1_780_000_000i64,
            "exp": exp,
            "ext": {
                "embark_user_id": "user-1",
                "tenancy_name": "pioneer-live",
                "client_id": "embark-pioneer"
            }
        })
        .to_string();

        format!(
            "{}.{}.signature",
            BASE64_URL_SAFE_NO_PAD.encode(header),
            BASE64_URL_SAFE_NO_PAD.encode(payload)
        )
    }
}
