//! Outbound HTTP to one customer server (design §5): the anonymous
//! `GET /version` and `GET /health/ready`, and the rollout routes signed
//! with the customer's rollout S2S credential.
//!
//! **Signing.** The customer's `attome_s2s::middleware::s2s_authn` verifies
//! `HMAC-SHA256(hex_decode(secret), METHOD\nPATH?QUERY\nSHA256(body)hex\nTIMESTAMP\nNONCE)`
//! over the request's own path-and-query and the exact body bytes it
//! received. [`sign`] builds that message with the verifier's own
//! `attome_s2s::crypto::{canonical_message, sha256_hex, sign_hmac}`, and the
//! request sends exactly the bytes and the path it signed — the base URL is
//! an origin with no path (see [`normalize_base_url`]), so the path the
//! customer sees is the path signed here.
//!
//! **Failures** are named ([`RemoteError::code`]): `timeout`, `tls`,
//! `connect_failed`, `auth_refused`, `not_found`, `remote_error`, … never a
//! raw response body (design §6.1). A customer's JSON error envelope
//! (`{error, message}`) is kept as code + message for the developer.
//!
//! **Correlation.** Every call may carry the console's action id as
//! `x-correlation-id` (an S2S-supported header), so the customer's audit rows
//! and the console's action log join on one id (design §5.2).

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::core::VersionProbe;
use crate::crypto::RolloutSecret;
use attome_types::AppError;

const H_CLIENT_ID: &str = "x-s2s-client-id";
const H_KEY_ID: &str = "x-s2s-key-id";
const H_TIMESTAMP: &str = "x-s2s-timestamp";
const H_NONCE: &str = "x-s2s-nonce";
const H_SIGNATURE: &str = "x-s2s-signature";
const H_CORRELATION: &str = "x-correlation-id";

/// The largest response body the console reads from a customer.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The customer-side rollout routes (design §5.2; lane FC-A).
pub mod paths {
    pub const VERSION: &str = "/version";
    pub const READY: &str = "/health/ready";
    pub const ROLLOUT_STATUS: &str = "/api/v1/admin/metadata/rollout/status";
    pub const PLAN: &str = "/api/v1/admin/metadata/changesets/plan";
    pub const APPLY: &str = "/api/v1/admin/metadata/changesets/apply";
    pub const LEDGER: &str = "/api/v1/admin/metadata/changesets/ledger";
    pub const REPORTS: &str = "/api/v1/admin/metadata/release-reports";
    pub const REPORT_SUMMARY: &str = "/api/v1/admin/metadata/release-reports/summary";
    pub const REPORT_ITEMS: &str = "/api/v1/admin/metadata/release-report-items";
    pub const APPROVALS: &str = "/api/v1/admin/approvals";
}

/// One customer's rollout S2S credential. `Debug` redacts the secret.
#[derive(Debug, Clone)]
pub struct S2sCredential {
    pub client_id: String,
    pub key_id: String,
    pub secret: RolloutSecret,
}

/// The five `x-s2s-*` header values of one signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub client_id: String,
    pub key_id: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

/// Signs one request exactly as the customer's S2S middleware verifies it.
pub fn sign(
    credential: &S2sCredential,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    timestamp_ms: i64,
    nonce: &str,
) -> Result<SignedHeaders, AppError> {
    let timestamp = timestamp_ms.to_string();
    let body_hash = attome_s2s::crypto::sha256_hex(body);
    let message = attome_s2s::crypto::canonical_message(
        method,
        path_and_query,
        &body_hash,
        &timestamp,
        nonce,
    );
    let signature = attome_s2s::crypto::sign_hmac(credential.secret.expose(), &message)
        .ok_or_else(|| AppError::internal("a fleet rollout secret is not hex"))?;
    Ok(SignedHeaders {
        client_id: credential.client_id.clone(),
        key_id: credential.key_id.clone(),
        timestamp,
        nonce: nonce.to_owned(),
        signature,
    })
}

/// A named failure of one customer call (never a raw body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    Timeout,
    Tls,
    Connect,
    /// 401 or 403 from the customer: the credential is wrong, revoked, from
    /// a disallowed address, or lacks `metadata.rollout`.
    AuthRefused {
        status: u16,
    },
    NotFound,
    /// No rollout credential is stored for this deployment.
    NoCredential,
    /// Any other non-2xx: the customer's error code and message, if it sent
    /// its JSON envelope.
    Status {
        status: u16,
        code: Option<String>,
        message: Option<String>,
    },
    BodyTooLarge,
    InvalidBody,
    Other,
}

impl RemoteError {
    /// The stable name stored as `error_code` and shown in the console.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Connect => "connect_failed",
            Self::AuthRefused { .. } => "auth_refused",
            Self::NotFound => "not_found",
            Self::NoCredential => "no_credential",
            Self::Status { .. } => "remote_error",
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidBody => "invalid_body",
            Self::Other => "request_failed",
        }
    }

    /// The customer's HTTP status, when it answered.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::AuthRefused { status } | Self::Status { status, .. } => Some(*status),
            Self::NotFound => Some(404),
            _ => None,
        }
    }

    fn from_transport(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            return Self::Timeout;
        }
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
        while let Some(current) = source {
            let text = current.to_string().to_ascii_lowercase();
            if text.contains("certificate") || text.contains("tls") || text.contains("handshake") {
                return Self::Tls;
            }
            source = current.source();
        }
        if error.is_connect() {
            Self::Connect
        } else {
            Self::Other
        }
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status {
                status,
                code: Some(code),
                ..
            } => write!(f, "remote_error ({status} {code})"),
            Self::Status { status, .. } => write!(f, "remote_error ({status})"),
            other => f.write_str(other.code()),
        }
    }
}

/// A 2xx answer.
#[derive(Debug, Clone)]
pub struct RemoteResponse {
    pub status: u16,
    pub body: Value,
}

/// `GET /api/v1/admin/metadata/rollout/status` (design §5.2). Read loosely:
/// every field defaults, so a customer on an older or newer shape still
/// answers what it has.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RemoteRolloutStatus {
    pub application_version: Option<String>,
    pub schema_version: Option<i64>,
    pub configuration_version: Option<String>,
    pub ready: Option<bool>,
    pub release_report: RemoteReportSummary,
    /// `[{layer, scope, changeset_id, seq, status}]`: ids and numbers only.
    pub ledger_head: Value,
    pub pending_approvals: Option<i64>,
}

/// The release-report part of the status, or the summary route's answer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RemoteReportSummary {
    pub open_items: Option<i64>,
    pub last_report_id: Option<Uuid>,
    pub last_release_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Checks and normalizes a deployment's base URL: an origin only
/// (`scheme://host[:port]`), `https://`, or plain `http://` for a loopback
/// host (local test deployments). No path, query, fragment or userinfo: the
/// signed path must be the path the customer's server sees.
pub fn normalize_base_url(raw: &str) -> Result<String, AppError> {
    let value = raw.trim().trim_end_matches('/');
    let invalid = |why: &str| {
        Err(AppError::Validation(format!(
            "base_url: {why} (expected https://host[:port], or http:// for a loopback host)"
        )))
    };
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return invalid("missing scheme"),
    };
    if rest.is_empty() {
        return invalid("missing host");
    }
    if rest
        .chars()
        .any(|c| matches!(c, '/' | '?' | '#' | '@' | '\\') || c.is_whitespace())
    {
        return invalid("must be an origin with no path, query, fragment or user info");
    }
    let host = if let Some(bracketed) = rest.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((host, _)) => host,
            None => return invalid("unterminated IPv6 host"),
        }
    } else {
        rest.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return invalid("missing host");
    }
    match scheme.as_str() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        "http" => return invalid("plain http is allowed only for a loopback host"),
        _ => return invalid("scheme must be https"),
    }
    Ok(format!("{scheme}://{rest}"))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Builds the console's HTTP client: bounded by `fleet.request_timeout_secs`,
/// no redirects (a redirect would re-send a signed request somewhere else).
///
/// Q21-T1: a customer server is reached at a public address, or on loopback
/// for local development, the one case [`normalize_base_url`] accepts plain
/// `http://` for; no other private address is reachable.
pub fn build_http(request_timeout_secs: u64) -> Result<attome_outbound::http::Outbound, AppError> {
    let purpose = attome_outbound::http::Purpose::public("fleet-console")
        .with_private_hosts(["localhost", "127.0.0.1", "::1"])
        .no_redirects();
    attome_outbound::http::client(purpose, |b| {
        b.timeout(Duration::from_secs(request_timeout_secs))
            .connect_timeout(Duration::from_secs(request_timeout_secs.min(5)))
            .user_agent(concat!("attome-fleet-console/", env!("CARGO_PKG_VERSION")))
    })
    .map_err(AppError::internal)
}

/// Checks a query value the console builds into a signed path: plain
/// `[A-Za-z0-9_-]`, so no encoding step can make the sent path differ from
/// the signed one.
pub fn is_safe_query_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One customer server.
#[derive(Clone)]
pub struct CustomerClient {
    http: attome_outbound::http::Outbound,
    base_url: String,
    credential: Option<S2sCredential>,
}

impl std::fmt::Debug for CustomerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomerClient")
            .field("base_url", &self.base_url)
            .field("has_credential", &self.credential.is_some())
            .finish()
    }
}

impl CustomerClient {
    /// `base_url` must already be normalized ([`normalize_base_url`]).
    pub fn new(
        http: attome_outbound::http::Outbound,
        base_url: impl Into<String>,
        credential: Option<S2sCredential>,
    ) -> Self {
        Self {
            http,
            base_url: base_url.into(),
            credential,
        }
    }

    pub fn has_credential(&self) -> bool {
        self.credential.is_some()
    }

    /// `GET /version` (anonymous, D-345).
    pub async fn version(&self) -> Result<VersionProbe, RemoteError> {
        let response = self
            .send(Method::GET, paths::VERSION, None, false, None, None)
            .await?;
        serde_json::from_value(response.body).map_err(|_| RemoteError::InvalidBody)
    }

    /// `GET /health/ready` (anonymous): `true` on 200, `false` on 503.
    pub async fn ready(&self) -> Result<bool, RemoteError> {
        match self
            .send(Method::GET, paths::READY, None, false, None, None)
            .await
        {
            Ok(_) => Ok(true),
            Err(RemoteError::Status { status: 503, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `GET …/rollout/status` (signed).
    pub async fn rollout_status(
        &self,
        correlation: Option<Uuid>,
    ) -> Result<RemoteRolloutStatus, RemoteError> {
        let body = self.get(paths::ROLLOUT_STATUS, correlation).await?;
        serde_json::from_value(body).map_err(|_| RemoteError::InvalidBody)
    }

    /// `GET …/release-reports/summary` (signed): the fallback when a customer
    /// does not have `/rollout/status` yet.
    pub async fn report_summary(
        &self,
        correlation: Option<Uuid>,
    ) -> Result<RemoteReportSummary, RemoteError> {
        let body = self.get(paths::REPORT_SUMMARY, correlation).await?;
        serde_json::from_value(body).map_err(|_| RemoteError::InvalidBody)
    }

    /// A signed `GET`; `path_and_query` must be built from safe values only.
    pub async fn get(
        &self,
        path_and_query: &str,
        correlation: Option<Uuid>,
    ) -> Result<Value, RemoteError> {
        Ok(self
            .send(Method::GET, path_and_query, None, true, None, correlation)
            .await?
            .body)
    }

    /// A signed `POST` with a JSON body and an optional `If-Match`.
    pub async fn post(
        &self,
        path: &str,
        body: &Value,
        if_match: Option<i64>,
        correlation: Option<Uuid>,
    ) -> Result<RemoteResponse, RemoteError> {
        self.send(Method::POST, path, Some(body), true, if_match, correlation)
            .await
    }

    async fn send(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&Value>,
        signed: bool,
        if_match: Option<i64>,
        correlation: Option<Uuid>,
    ) -> Result<RemoteResponse, RemoteError> {
        let bytes: Vec<u8> = match body {
            Some(value) => serde_json::to_vec(value).map_err(|_| RemoteError::InvalidBody)?,
            None => Vec::new(),
        };
        let url = format!("{}{}", self.base_url, path_and_query);
        let mut request = self.http.request(method.clone(), url);
        if body.is_some() {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        request = request.header(reqwest::header::ACCEPT, "application/json");
        if let Some(version) = if_match {
            request = request.header(reqwest::header::IF_MATCH, format!("\"{version}\""));
        }
        if let Some(id) = correlation {
            request = request.header(H_CORRELATION, id.to_string());
        }
        if signed {
            let credential = self.credential.as_ref().ok_or(RemoteError::NoCredential)?;
            let nonce = Uuid::new_v4().to_string();
            let headers = sign(
                credential,
                method.as_str(),
                path_and_query,
                &bytes,
                chrono::Utc::now().timestamp_millis(),
                &nonce,
            )
            .map_err(|_| RemoteError::NoCredential)?;
            request = request
                .header(H_CLIENT_ID, headers.client_id)
                .header(H_KEY_ID, headers.key_id)
                .header(H_TIMESTAMP, headers.timestamp)
                .header(H_NONCE, headers.nonce)
                .header(H_SIGNATURE, headers.signature);
        }
        let mut response = request
            .body(bytes)
            .send()
            .await
            .map_err(|e| RemoteError::from_transport(&e))?;
        let status = response.status();
        let mut collected: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| RemoteError::from_transport(&e))?
        {
            if collected.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(RemoteError::BodyTooLarge);
            }
            collected.extend_from_slice(&chunk);
        }
        let parsed: Option<Value> = if collected.is_empty() {
            None
        } else {
            serde_json::from_slice(&collected).ok()
        };
        classify(status, parsed)
    }
}

/// Maps a customer answer onto success or a named failure.
fn classify(status: StatusCode, body: Option<Value>) -> Result<RemoteResponse, RemoteError> {
    let code = status.as_u16();
    if status.is_success() {
        return Ok(RemoteResponse {
            status: code,
            body: body.unwrap_or(Value::Null),
        });
    }
    match code {
        401 | 403 => Err(RemoteError::AuthRefused { status: code }),
        404 => Err(RemoteError::NotFound),
        _ => {
            let field = |name: &str| {
                body.as_ref()
                    .and_then(|b| b.get(name))
                    .and_then(Value::as_str)
                    .map(|s| s.chars().take(500).collect::<String>())
            };
            Err(RemoteError::Status {
                status: code,
                code: field("error"),
                message: field("message"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Bytes, http::HeaderMap};

    fn credential() -> S2sCredential {
        S2sCredential {
            client_id: "rollout-bmd".into(),
            key_id: "key-1".into(),
            secret: RolloutSecret::parse(&attome_s2s::crypto::generate_secret()).expect("hex"),
        }
    }

    #[test]
    fn the_signature_is_what_the_customer_verifier_accepts() {
        let credential = credential();
        let body = br#"{"changesets":[]}"#;
        let headers = sign(
            &credential,
            "POST",
            paths::PLAN,
            body,
            1_720_000_000_000,
            "nonce-1",
        )
        .expect("signs");
        let message = attome_s2s::crypto::canonical_message(
            "POST",
            paths::PLAN,
            &attome_s2s::crypto::sha256_hex(body),
            &headers.timestamp,
            &headers.nonce,
        );
        assert!(attome_s2s::crypto::verify_hmac(
            credential.secret.expose(),
            &message,
            &headers.signature
        ));
        // A different body, path or nonce does not verify.
        let tampered = attome_s2s::crypto::canonical_message(
            "POST",
            paths::APPLY,
            &attome_s2s::crypto::sha256_hex(body),
            &headers.timestamp,
            &headers.nonce,
        );
        assert!(!attome_s2s::crypto::verify_hmac(
            credential.secret.expose(),
            &tampered,
            &headers.signature
        ));
    }

    /// A local mock customer that verifies the five headers with
    /// `attome_s2s::crypto` over the path-and-query and body bytes it actually
    /// received — proves the request on the wire matches what was signed.
    #[tokio::test]
    async fn a_signed_request_verifies_on_the_wire() {
        let credential = credential();
        let secret = credential.secret.expose().to_owned();
        let app = Router::new().fallback(
            move |method: axum::http::Method,
                  uri: axum::http::Uri,
                  headers: HeaderMap,
                  body: Bytes| {
                let secret = secret.clone();
                async move {
                    let header = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_owned()
                    };
                    let path_and_query = uri
                        .path_and_query()
                        .map(|pq| pq.as_str().to_owned())
                        .unwrap_or_default();
                    let message = attome_s2s::crypto::canonical_message(
                        method.as_str(),
                        &path_and_query,
                        &attome_s2s::crypto::sha256_hex(&body),
                        &header(H_TIMESTAMP),
                        &header(H_NONCE),
                    );
                    let ok =
                        attome_s2s::crypto::verify_hmac(&secret, &message, &header(H_SIGNATURE))
                            && header(H_CLIENT_ID) == "rollout-bmd"
                            && header(H_KEY_ID) == "key-1"
                            && header(H_CORRELATION).len() == 36;
                    if ok {
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({"verified": true})),
                        )
                    } else {
                        (
                            axum::http::StatusCode::UNAUTHORIZED,
                            axum::Json(serde_json::json!({"error": "unauthorized"})),
                        )
                    }
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CustomerClient::new(
            build_http(5).expect("client"),
            format!("http://{address}"),
            Some(credential),
        );
        let posted = client
            .post(
                paths::PLAN,
                &serde_json::json!({"changesets": [{"id": "x"}]}),
                Some(3),
                Some(Uuid::now_v7()),
            )
            .await
            .expect("the mock verifies a signed POST");
        assert_eq!(posted.body["verified"], true);
        let got = client
            .get(
                &format!("{}?page=1&page_size=20", paths::REPORTS),
                Some(Uuid::now_v7()),
            )
            .await
            .expect("the mock verifies a signed GET with a query");
        assert_eq!(got["verified"], true);
        server.abort();
    }

    #[tokio::test]
    async fn a_signed_call_without_a_credential_never_leaves_the_console() {
        let client = CustomerClient::new(build_http(1).expect("client"), "https://x.invalid", None);
        assert_eq!(
            client.get(paths::ROLLOUT_STATUS, None).await.unwrap_err(),
            RemoteError::NoCredential
        );
    }

    #[test]
    fn answers_map_to_named_failures() {
        assert!(classify(StatusCode::OK, None).is_ok());
        assert_eq!(
            classify(StatusCode::FORBIDDEN, None).unwrap_err(),
            RemoteError::AuthRefused { status: 403 }
        );
        assert_eq!(
            classify(StatusCode::NOT_FOUND, None).unwrap_err().code(),
            "not_found"
        );
        let conflict = classify(
            StatusCode::CONFLICT,
            Some(serde_json::json!({"error": "conflict", "message": "decided"})),
        )
        .unwrap_err();
        assert_eq!(
            conflict,
            RemoteError::Status {
                status: 409,
                code: Some("conflict".into()),
                message: Some("decided".into()),
            }
        );
        assert_eq!(conflict.code(), "remote_error");
    }

    #[test]
    fn base_urls_are_origins_with_https_or_loopback_http() {
        assert_eq!(
            normalize_base_url(" https://bmd.example.com/ ").unwrap(),
            "https://bmd.example.com"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:7865").unwrap(),
            "http://127.0.0.1:7865"
        );
        assert_eq!(
            normalize_base_url("http://[::1]:8201").unwrap(),
            "http://[::1]:8201"
        );
        assert!(normalize_base_url("http://localhost:8201").is_ok());
        assert!(normalize_base_url("http://bmd.example.com").is_err());
        assert!(normalize_base_url("https://bmd.example.com/api").is_err());
        assert!(normalize_base_url("https://user@bmd.example.com").is_err());
        assert!(normalize_base_url("ftp://bmd.example.com").is_err());
        assert!(normalize_base_url("bmd.example.com").is_err());
    }

    #[test]
    fn only_plain_tokens_go_into_a_signed_query() {
        assert!(is_safe_query_value("open"));
        assert!(is_safe_query_value("0190f6f2-0000-7000-8000-000000000000"));
        assert!(!is_safe_query_value("a b"));
        assert!(!is_safe_query_value("a&b=c"));
        assert!(!is_safe_query_value(""));
    }
}
