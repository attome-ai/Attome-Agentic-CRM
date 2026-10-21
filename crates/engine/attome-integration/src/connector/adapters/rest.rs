//! The generic, config-driven REST adapter — Phase 1's only real connector
//! implementation. "Config-driven" means the admin-authored knobs are
//! `integration_system.base_url`/`auth_type`/`config` (endpoint path,
//! pagination style), never a script: every request this adapter issues is
//! built by the fixed logic below, not by evaluating anything an admin typed.
//!
//! SSRF posture (M59 checklist "SSRF at save + send"): `admin.rs` runs
//! `attome_server::ssrf_guard::validate_url` at save time; every method here
//! re-validates AND dials through `attome_server::ssrf_guard::GuardedClient` —
//! the dial-time guard (literal check per request, resolver check per dial),
//! which is the one that cannot be bypassed regardless of how `base_url` got
//! written (see `admin.rs`'s module doc for why save-time alone isn't
//! sufficient).
//!
//! Request/response shaping (`build_request`/`parse_records`) is factored out
//! as plain functions so `tests` below can exercise the actual wire behavior
//! against a local mock HTTP server with a plain, unguarded `reqwest::Client`
//! — `attome_server::ssrf_guard` deliberately has no test-only bypass (see its
//! module doc), so a loopback mock server can never be dialed through the
//! guarded client, and this crate does not weaken that guard to make a test
//! convenient (guidelines §13).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_types::AppError;
use serde_json::Value;

use crate::connection::Connection;
use crate::connector::{Connector, HealthResult, PullResult, PushResult, WebhookEvent};
use crate::credential::Credential;
use crate::system::IntegrationSystem;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// Bound on every outbound call this adapter makes — pull/push/health are
/// all interactive (a human is waiting on "test connection", or a bounded
/// job in Phase 2), never a long-running stream.
const REQUEST_TIMEOUT_SECS: u64 = 15;

#[derive(Debug)]
pub struct RestAdapter;

/// Adds the credential to a request per `system.auth_type`, through the
/// system's [`Connection`] (Z1-T10), which sets it without handing the
/// value out.
fn apply_auth(
    builder: reqwest::RequestBuilder,
    system: &IntegrationSystem,
    credential: Option<&Credential>,
    body_for_hmac: &[u8],
) -> Result<reqwest::RequestBuilder, AppError> {
    Connection::of(system).authorize(builder, credential, body_for_hmac)
}

/// Parses a pull response body into records + an optional cursor. Accepts
/// either a bare JSON array, or `{"items": [...], "next_cursor": "..."}` —
/// the two shapes admin-configured REST APIs commonly use; a genuinely
/// bespoke pagination style is exactly what Phase 2's "connector templates"
/// (per-system endpoint/pagination config) will parameterize.
fn parse_pull_response(body: &[u8]) -> Result<PullResult, AppError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| AppError::Validation(format!("pull response was not valid JSON: {e}")))?;
    match value {
        Value::Array(items) => Ok(PullResult {
            records: items,
            next_cursor: None,
        }),
        Value::Object(mut obj) => {
            let next_cursor = obj
                .remove("next_cursor")
                .and_then(|v| v.as_str().map(str::to_string));
            let records = match obj.remove("items") {
                Some(Value::Array(items)) => items,
                _ => {
                    return Err(AppError::Validation(
                        "pull response object must carry an \"items\" array".into(),
                    ));
                }
            };
            Ok(PullResult {
                records,
                next_cursor,
            })
        }
        _ => Err(AppError::Validation(
            "pull response must be a JSON array or an object with an \"items\" array".into(),
        )),
    }
}

/// The client a call goes through: the shared guarded client, or, for a
/// `client_certificate` connection, one presenting its TLS identity behind
/// the same address guard.
enum Client {
    Guarded(attome_server::ssrf_guard::GuardedClient),
    Identity(attome_outbound::http::Outbound),
}

async fn guarded_client(
    system: &IntegrationSystem,
    credential: Option<&Credential>,
) -> Result<Client, AppError> {
    if let Some(identity) =
        Connection::of(system).client(credential, Duration::from_secs(REQUEST_TIMEOUT_SECS))?
    {
        return Ok(Client::Identity(identity));
    }
    attome_server::ssrf_guard::GuardedClient::new(REQUEST_TIMEOUT_SECS)
        .map(Client::Guarded)
        .map_err(AppError::internal)
}

fn guarded_request(
    client: &Client,
    method: reqwest::Method,
    url: reqwest::Url,
) -> Result<reqwest::RequestBuilder, AppError> {
    match client {
        Client::Guarded(client) => client
            .request(method, url)
            .map_err(|e| AppError::Validation(format!("base_url rejected: {e}"))),
        Client::Identity(client) => Ok(client.request(method, url)),
    }
}

async fn validate_target(url: &str) -> Result<reqwest::Url, AppError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| AppError::Validation("base_url is not a valid URL".into()))?;
    attome_server::ssrf_guard::validate_url(&parsed)
        .await
        .map_err(|e| AppError::Validation(format!("base_url rejected: {e}")))?;
    Ok(parsed)
}

impl Connector for RestAdapter {
    fn pull<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a Credential>,
        cursor: Option<&'a str>,
    ) -> BoxFuture<'a, PullResult> {
        Box::pin(async move {
            let mut url = validate_target(&system.base_url).await?;
            if let Some(cursor) = cursor {
                url.query_pairs_mut().append_pair("cursor", cursor);
            }
            let client = guarded_client(system, credential).await?;
            let request = apply_auth(
                guarded_request(&client, reqwest::Method::GET, url)?,
                system,
                credential,
                b"",
            )?;
            let response = request.send().await.map_err(|e| {
                AppError::Validation(format!("pull request to {} failed: {e}", system.base_url))
            })?;
            if !response.status().is_success() {
                return Err(AppError::Validation(format!(
                    "pull request to {} returned HTTP {}",
                    system.base_url,
                    response.status()
                )));
            }
            let body = response.bytes().await.map_err(AppError::internal)?;
            parse_pull_response(&body)
        })
    }

    fn push<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a Credential>,
        event: &'a Value,
    ) -> BoxFuture<'a, PushResult> {
        Box::pin(async move {
            let url = validate_target(&system.base_url).await?;
            let client = guarded_client(system, credential).await?;
            let body = serde_json::to_vec(event).map_err(AppError::internal)?;
            let mut request = apply_auth(
                guarded_request(&client, reqwest::Method::POST, url)?,
                system,
                credential,
                &body,
            )?;
            // S9-T5: the same key on every retry of this effect.
            if let Some(key) = system.idempotency_header() {
                request = request.header("Idempotency-Key", key);
            }
            let response = request
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| {
                    AppError::Validation(format!("push request to {} failed: {e}", system.base_url))
                })?;
            let ok = response.status().is_success();
            let detail = if ok {
                None
            } else {
                Some(format!("HTTP {}", response.status()))
            };
            Ok(PushResult { ok, detail })
        })
    }

    fn webhook<'a>(
        &'a self,
        _system: &'a IntegrationSystem,
        _credential: Option<&'a Credential>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Vec<WebhookEvent>> {
        Box::pin(async move {
            // Phase 1: one generic event per inbound call — the payload
            // decoded as-is. Mapping a payload's shape onto a specific
            // `event_type`/target entity via M12's data-mapping model is
            // Phase 2 (sync runs); this is the durable-inbox half only
            // (D-425), not the transform.
            let payload: Value = serde_json::from_slice(body).map_err(|e| {
                AppError::Validation(format!("webhook body was not valid JSON: {e}"))
            })?;
            Ok(vec![WebhookEvent {
                event_type: "webhook.received".to_string(),
                payload,
            }])
        })
    }

    fn health<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a Credential>,
    ) -> BoxFuture<'a, HealthResult> {
        Box::pin(async move {
            let url = match validate_target(&system.base_url).await {
                Ok(url) => url,
                Err(e) => {
                    return Ok(HealthResult {
                        ok: false,
                        detail: Some(e.to_string()),
                    });
                }
            };
            let client = guarded_client(system, credential).await?;
            let request = match guarded_request(&client, reqwest::Method::GET, url)
                .and_then(|builder| apply_auth(builder, system, credential, b""))
            {
                Ok(r) => r,
                Err(e) => {
                    return Ok(HealthResult {
                        ok: false,
                        detail: Some(e.to_string()),
                    });
                }
            };
            match request
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => Ok(HealthResult {
                    ok: true,
                    detail: None,
                }),
                Ok(response) => Ok(HealthResult {
                    ok: false,
                    detail: Some(format!("HTTP {}", response.status())),
                }),
                Err(e) => Ok(HealthResult {
                    ok: false,
                    detail: Some(e.to_string()),
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn stub_system(base_url: String, auth_type: &str) -> IntegrationSystem {
        IntegrationSystem {
            id: uuid::Uuid::nil(),
            name: "Test System".into(),
            kind: "rest".into(),
            base_url,
            auth_type: auth_type.into(),
            credential_ref: None,
            rate_limit: None,
            status: "active".into(),
            health_last_ok_at: None,
            health_last_error: None,
            service_principal_ref: uuid::Uuid::nil().to_string(),
            config: None,
            row_version: 0,
        }
    }

    // ── Pure parsing/auth logic — no network, no ssrf_guard involved ──────

    #[test]
    fn parse_pull_response_accepts_a_bare_array() {
        let body = br#"[{"id": 1}, {"id": 2}]"#;
        let result = parse_pull_response(body).unwrap();
        assert_eq!(result.records.len(), 2);
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn parse_pull_response_accepts_an_items_object_with_a_cursor() {
        let body = br#"{"items": [{"id": 1}], "next_cursor": "abc"}"#;
        let result = parse_pull_response(body).unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.next_cursor.as_deref(), Some("abc"));
    }

    #[test]
    fn parse_pull_response_rejects_an_object_with_no_items_array() {
        let body = br#"{"foo": "bar"}"#;
        assert!(parse_pull_response(body).is_err());
    }

    #[test]
    fn apply_auth_rejects_a_missing_credential() {
        let system = stub_system("https://example.com".into(), "api_key");
        let client = reqwest::Client::new();
        let err = apply_auth(client.get("https://example.com"), &system, None, b"").unwrap_err();
        assert!(err.to_string().contains("no credential configured"));
    }

    #[test]
    fn apply_auth_rejects_oauth2_client_credentials_in_phase_1() {
        let system = stub_system("https://example.com".into(), "oauth2_client_credentials");
        let client = reqwest::Client::new();
        let err = apply_auth(
            client.get("https://example.com"),
            &system,
            Some(&Credential::new("x".into())),
            b"",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not implemented"));
    }

    #[test]
    fn hmac_sha256_hex_is_deterministic_and_key_sensitive() {
        let a = Credential::new("key-a".into()).hmac_sha256_hex(b"body");
        let b = Credential::new("key-a".into()).hmac_sha256_hex(b"body");
        let c = Credential::new("key-b".into()).hmac_sha256_hex(b"body");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64, "must be 32 bytes hex-encoded");
    }

    // ── Real HTTP exchange against a local mock server ─────────────────────
    //
    // Deliberately does NOT go through `Connector::pull`/`push`/`health`
    // (those dial through `attome_server::ssrf_guard::GuardedClient`, which
    // refuses a loopback target by design — see this module's doc). Instead
    // this drives the same `parse_pull_response` logic the trait method
    // calls, over a real socket, with a plain unguarded client — proving the
    // wire-format handling end to end without weakening the guard.

    /// Starts a one-shot mock HTTP server on an OS-assigned loopback port
    /// that replies with `body` to the first request it receives.
    async fn mock_server(status_line: &'static str, body: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await; // drain the request
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn pull_response_from_a_real_http_exchange_parses_correctly() {
        let addr = mock_server(
            "HTTP/1.1 200 OK",
            r#"{"items": [{"id": "rec-1"}], "next_cursor": "page-2"}"#,
        )
        .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{addr}/records"))
            .send()
            .await
            .expect("mock server request must succeed");
        assert!(response.status().is_success());
        let body = response.bytes().await.expect("read body");

        let result = parse_pull_response(&body).expect("parse mock response");
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.next_cursor.as_deref(), Some("page-2"));
    }

    #[tokio::test]
    async fn a_non_success_status_from_a_real_http_exchange_is_surfaced() {
        let addr = mock_server("HTTP/1.1 500 Internal Server Error", "{}").await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{addr}/records"))
            .send()
            .await
            .expect("mock server request must succeed");
        assert!(!response.status().is_success());
        assert_eq!(response.status().as_u16(), 500);
    }

    /// BSV-F08a (B5): the adapter's own client refuses a loopback literal
    /// even when `validate_target` was skipped.
    #[tokio::test]
    async fn the_adapter_client_refuses_a_loopback_literal_without_validate_target() {
        let system = stub_system("https://example.com".into(), "api_key");
        let client = guarded_client(&system, None).await.expect("client builds");
        let url = reqwest::Url::parse("http://127.0.0.1:9/").expect("url parses");
        let err = guarded_request(&client, reqwest::Method::GET, url).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }
}
