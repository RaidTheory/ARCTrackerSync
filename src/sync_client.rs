use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::token::TokenObservation;

pub const BASE_URL: &str = "https://arctracker.io";

/// Timeouts so a stalled connection can't wedge the worker thread.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
}

/// Failure from a backend submit call. Carries the HTTP status (when the server
/// responded) so callers can branch on it instead of sniffing the message.
#[derive(Debug)]
pub struct SubmitError {
    pub status: Option<u16>,
    pub message: String,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SubmitError {}

impl From<serde_json::Error> for SubmitError {
    fn from(error: serde_json::Error) -> Self {
        SubmitError {
            status: None,
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitResponse {
    pub success: bool,
    #[serde(default, rename = "syncEnabled")]
    pub sync_enabled: bool,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default, rename = "displayNameDiscriminator")]
    pub display_name_discriminator: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmitRequest<'a> {
    #[serde(rename = "accessToken")]
    access_token: &'a str,
    #[serde(rename = "observedAt")]
    observed_at: String,
    host: &'a str,
    path: Option<&'a str>,
    #[serde(rename = "requestId")]
    request_id: Option<&'a str>,
    source: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
struct RefreshResponse {
    token: String,
}

/// Exchange the current bridge JWT for a fresh 30-day token. A 401 here means
/// the token is expired or revoked; the caller decides whether to sign out.
pub fn submit_refresh(auth_token: &str) -> Result<String, SubmitError> {
    let url = format!("{BASE_URL}/api/auth/bridge/refresh");
    let response = match agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {auth_token}"))
        .set("Content-Type", "application/json")
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let message = response.into_string().unwrap_or_default();
            return Err(SubmitError {
                status: Some(status),
                message: format!(
                    "ARCTracker rejected sign-in refresh with HTTP {status}: {message}"
                ),
            });
        }
        Err(error) => {
            return Err(SubmitError {
                status: None,
                message: format!("refreshing sign-in at {url}: {error}"),
            });
        }
    };

    if !(200..300).contains(&response.status()) {
        let status = response.status();
        return Err(SubmitError {
            status: Some(status),
            message: format!("ARCTracker rejected sign-in refresh with HTTP {status}"),
        });
    }

    let refreshed = response
        .into_json::<RefreshResponse>()
        .map_err(|error| SubmitError {
            status: None,
            message: format!("parsing sign-in refresh response: {error}"),
        })?;

    if refreshed.token.trim().is_empty() {
        return Err(SubmitError {
            status: None,
            message: "ARCTracker sign-in refresh returned an empty token".to_string(),
        });
    }

    Ok(refreshed.token)
}

pub fn submit_embark_token(
    auth_token: &str,
    observation: &TokenObservation,
) -> Result<SubmitResponse, SubmitError> {
    let body = SubmitRequest {
        access_token: &observation.token,
        observed_at: observation.observed_at.to_rfc3339(),
        host: &observation.host,
        path: observation.path.as_deref(),
        request_id: observation.request_id.as_deref(),
        source: "arctracker-sync",
    };

    let url = format!("{BASE_URL}/api/desktop/embark-token");
    let response = match agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {auth_token}"))
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(&body)?)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let message = response.into_string().unwrap_or_default();
            return Err(SubmitError {
                status: Some(status),
                message: format!(
                    "ARCTracker rejected token submission with HTTP {status}: {message}"
                ),
            });
        }
        Err(error) => {
            return Err(SubmitError {
                status: None,
                message: format!("posting token observation to {url}: {error}"),
            });
        }
    };

    if !(200..300).contains(&response.status()) {
        let status = response.status();
        return Err(SubmitError {
            status: Some(status),
            message: format!("ARCTracker rejected token submission with HTTP {status}"),
        });
    }

    response
        .into_json::<SubmitResponse>()
        .map_err(|error| SubmitError {
            status: None,
            message: format!("parsing token submission response: {error}"),
        })
}
