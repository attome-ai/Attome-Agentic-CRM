//! ETA's invoicing API (roadmap AG3-T1): sign in, submit, poll.
//!
//! - `POST {identity}/connect/token` (form: `grant_type=client_credentials`,
//!   the ERP's client id and secret, `scope=InvoicingAPI`) gives a bearer
//!   token for an hour.
//! - `POST {api}/api/v1/documentsubmissions` with `{"documents": [..]}`
//!   answers 202 with the submission id, the accepted documents (their ETA
//!   `uuid`) and the rejected ones with ETA's error.
//! - `GET {api}/api/v1/documents/{uuid}/details` gives a document's status:
//!   `Valid`, `Invalid` (with the validation results), `Submitted` (still
//!   being validated: poll again), `Cancelled` or `Rejected`.
//!
//! A 5xx, 429 or no answer is retryable; another 4xx is the request's
//! fault. The sandbox is ETA's pre-production environment.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::zatca::api::{HttpAnswer, Transport};

/// ETA's two environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtaEnvironment {
    PreProduction,
    Production,
}

impl EtaEnvironment {
    pub fn identity_url(self) -> &'static str {
        match self {
            Self::PreProduction => "https://id.preprod.eta.gov.eg",
            Self::Production => "https://id.eta.gov.eg",
        }
    }

    pub fn api_url(self) -> &'static str {
        match self {
            Self::PreProduction => "https://api.preprod.invoicing.eta.gov.eg",
            Self::Production => "https://api.invoicing.eta.gov.eg",
        }
    }
}

/// The ERP system's credentials (from the secret store).
#[derive(Clone)]
pub struct EtaCredentials {
    pub environment: EtaEnvironment,
    pub client_id: String,
    pub client_secret: String,
}

impl std::fmt::Debug for EtaCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtaCredentials")
            .field("environment", &self.environment)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EtaApiError {
    #[error("ETA could not be reached: {0}")]
    Retryable(String),
    #[error("ETA refused the request: {0}")]
    Refused(String),
    #[error("ETA refused the credentials")]
    Unauthorised,
}

/// A document ETA took into a submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub uuid: String,
    pub internal_id: String,
}

/// A document ETA refused at submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub internal_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub id: String,
    pub accepted: Vec<Accepted>,
    pub refused: Vec<Refused>,
}

/// Where a document stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtaStatus {
    /// Still being validated.
    Submitted,
    Valid,
    Invalid {
        results: Value,
    },
    Cancelled,
    Rejected,
}

impl EtaStatus {
    /// The status ETA names. Pure.
    pub fn parse(status: &str, results: Option<Value>) -> Self {
        match status.to_ascii_lowercase().as_str() {
            "valid" => Self::Valid,
            "invalid" => Self::Invalid {
                results: results.unwrap_or(Value::Null),
            },
            "cancelled" => Self::Cancelled,
            "rejected" => Self::Rejected,
            _ => Self::Submitted,
        }
    }
}

fn classify(answer: &HttpAnswer) -> Result<(), EtaApiError> {
    match answer.status {
        200..=299 => Ok(()),
        401 => Err(EtaApiError::Unauthorised),
        429 | 500..=599 => Err(EtaApiError::Retryable(format!("status {}", answer.status))),
        status => Err(EtaApiError::Refused(format!(
            "status {status}: {}",
            answer.body.chars().take(500).collect::<String>()
        ))),
    }
}

/// `application/x-www-form-urlencoded` value encoding. Pure.
fn form(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: Option<String>,
}

/// Signs in; the token lasts an hour.
pub async fn token(
    transport: &dyn Transport,
    credentials: &EtaCredentials,
) -> Result<String, EtaApiError> {
    let body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=InvoicingAPI",
        form(&credentials.client_id),
        form(&credentials.client_secret)
    );
    let headers = vec![(
        "Content-Type",
        "application/x-www-form-urlencoded".to_owned(),
    )];
    let url = format!("{}/connect/token", credentials.environment.identity_url());
    let answer = transport
        .post(&url, &headers, body)
        .await
        .map_err(|e| EtaApiError::Retryable(e.0))?;
    if answer.status == 400 {
        // The identity server answers a wrong client with 400 invalid_client.
        return Err(EtaApiError::Unauthorised);
    }
    classify(&answer)?;
    serde_json::from_str::<TokenAnswer>(&answer.body)
        .ok()
        .and_then(|t| t.access_token)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| EtaApiError::Retryable("the token answer carries no token".into()))
}

/// Submits signed documents (at most 100 per submission).
pub async fn submit(
    transport: &dyn Transport,
    environment: EtaEnvironment,
    token: &str,
    documents: &[Value],
) -> Result<Submission, EtaApiError> {
    if documents.is_empty() || documents.len() > 100 {
        return Err(EtaApiError::Refused(
            "a submission carries one to 100 documents".into(),
        ));
    }
    let headers = vec![("Authorization", format!("Bearer {token}"))];
    let url = format!("{}/api/v1/documentsubmissions", environment.api_url());
    let body = json!({ "documents": documents }).to_string();
    let answer = transport
        .post(&url, &headers, body)
        .await
        .map_err(|e| EtaApiError::Retryable(e.0))?;
    classify(&answer)?;
    let v: Value = serde_json::from_str(&answer.body)
        .map_err(|e| EtaApiError::Retryable(format!("an answer that is not ETA's: {e}")))?;
    let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    Ok(Submission {
        id: text(&v["submissionId"]),
        accepted: v["acceptedDocuments"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|d| Accepted {
                uuid: text(&d["uuid"]),
                internal_id: text(&d["internalId"]),
            })
            .collect(),
        refused: v["rejectedDocuments"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|d| Refused {
                internal_id: text(&d["internalId"]),
                message: d["error"]["message"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| d["error"].to_string()),
            })
            .collect(),
    })
}

/// Asks where a document stands.
pub async fn status(
    transport: &dyn Transport,
    environment: EtaEnvironment,
    token: &str,
    uuid: &str,
) -> Result<EtaStatus, EtaApiError> {
    if uuid.is_empty() || !uuid.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(EtaApiError::Refused(
            "an ETA document UUID is alphanumeric".into(),
        ));
    }
    let headers = vec![("Authorization", format!("Bearer {token}"))];
    let url = format!("{}/api/v1/documents/{uuid}/details", environment.api_url());
    let answer = transport
        .get(&url, &headers)
        .await
        .map_err(|e| EtaApiError::Retryable(e.0))?;
    classify(&answer)?;
    let v: Value = serde_json::from_str(&answer.body)
        .map_err(|e| EtaApiError::Retryable(format!("an answer that is not ETA's: {e}")))?;
    Ok(EtaStatus::parse(
        v["status"].as_str().unwrap_or("Submitted"),
        v.get("validationResults").cloned(),
    ))
}
