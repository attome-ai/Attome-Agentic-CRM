//! Sending through an accredited service provider (roadmap AG3-T2).
//!
//! Each UAE ASP has its own API, so Attome speaks one small contract and a
//! deployment points it at its ASP (or at the ASP's adapter):
//!
//! - `POST {base}/documents` with `{"format": "pint-ae", "document":
//!   <base64 UBL>, "reference": <invoice number>}` answers `{"id": ..,
//!   "status": ..}`;
//! - `POST {base}/documents/{id}/status` with `{}` answers the same shape,
//!   plus `"message"` when rejected.
//!
//! Every call carries the ASP key as a bearer token. Statuses map to
//! [`AspStatus`]: `accepted`/`delivered`/`reported` are accepted,
//! `rejected`/`failed` rejected, anything else pending (poll again). A 5xx
//! or no answer is retryable; a 4xx is the document's fault and is not.
//! The transport is the guarded HTTP client (Q21-T1) shared with ZATCA.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::zatca::api::{HttpAnswer, Transport};

/// Where the ASP is and how Attome signs in.
#[derive(Clone)]
pub struct AspConfig {
    /// The ASP API's base URL, without a trailing slash.
    pub base_url: String,
    /// The API key the ASP issued (from the secret store).
    pub api_key: String,
}

impl std::fmt::Debug for AspConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AspConfig")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Where a document stands at the ASP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AspStatus {
    Pending,
    Accepted,
    Rejected { message: String },
}

impl AspStatus {
    /// The status an ASP answer names. Pure.
    pub fn parse(status: &str, message: Option<String>) -> Self {
        match status.to_ascii_lowercase().as_str() {
            "accepted" | "delivered" | "reported" => Self::Accepted,
            "rejected" | "failed" => Self::Rejected {
                message: message.unwrap_or_else(|| "rejected by the service provider".into()),
            },
            _ => Self::Pending,
        }
    }
}

/// A document the ASP took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AspSubmission {
    pub id: String,
    pub status: AspStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AspError {
    /// Try again later: the ASP did not answer or failed itself.
    #[error("the service provider could not be reached: {0}")]
    Retryable(String),
    /// The ASP refused the request; sending it again will not help.
    #[error("the service provider refused the document: {0}")]
    Refused(String),
}

#[derive(Debug, Deserialize)]
struct Answer {
    id: Option<String>,
    status: Option<String>,
    message: Option<String>,
}

fn read(answer: HttpAnswer) -> Result<Answer, AspError> {
    match answer.status {
        200..=299 => serde_json::from_str(&answer.body)
            .map_err(|e| AspError::Retryable(format!("an answer that is not the contract: {e}"))),
        500..=599 => Err(AspError::Retryable(format!("status {}", answer.status))),
        status => Err(AspError::Refused(format!(
            "status {status}: {}",
            answer.body.chars().take(500).collect::<String>()
        ))),
    }
}

fn headers(config: &AspConfig) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", format!("Bearer {}", config.api_key)),
        ("Content-Type", "application/json".to_owned()),
        ("Accept", "application/json".to_owned()),
    ]
}

/// Sends one PINT AE document.
pub async fn send(
    transport: &dyn Transport,
    config: &AspConfig,
    reference: &str,
    xml: &str,
) -> Result<AspSubmission, AspError> {
    let body = serde_json::json!({
        "format": "pint-ae",
        "reference": reference,
        "document": STANDARD.encode(xml.as_bytes()),
    })
    .to_string();
    let headers = headers(config);
    let url = format!("{}/documents", config.base_url.trim_end_matches('/'));
    let answer = transport
        .post(&url, &headers, body)
        .await
        .map_err(|e| AspError::Retryable(e.0))?;
    let answer = read(answer)?;
    let id = answer
        .id
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| AspError::Retryable("the answer names no document id".into()))?;
    Ok(AspSubmission {
        id,
        status: AspStatus::parse(
            answer.status.as_deref().unwrap_or("pending"),
            answer.message,
        ),
    })
}

/// Asks where a sent document stands.
pub async fn status(
    transport: &dyn Transport,
    config: &AspConfig,
    id: &str,
) -> Result<AspStatus, AspError> {
    let headers = headers(config);
    let url = format!(
        "{}/documents/{}/status",
        config.base_url.trim_end_matches('/'),
        urlencoding_segment(id)
    );
    let answer = transport
        .post(&url, &headers, "{}".to_owned())
        .await
        .map_err(|e| AspError::Retryable(e.0))?;
    let answer = read(answer)?;
    Ok(AspStatus::parse(
        answer.status.as_deref().unwrap_or("pending"),
        answer.message,
    ))
}

/// A path segment with anything but unreserved characters percent-encoded. Pure.
fn urlencoding_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod uae_pint_asp {
    use super::*;
    use crate::zatca::api::TransportError;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// A fixture ASP: records each call and answers from a script.
    struct Fixture {
        answers: Mutex<Vec<Result<HttpAnswer, TransportError>>>,
        calls: Mutex<Vec<(String, String, String)>>,
    }

    impl Fixture {
        fn new(answers: Vec<Result<HttpAnswer, TransportError>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Fixture {
        fn post<'a>(
            &'a self,
            url: &'a str,
            headers: &'a [(&'a str, String)],
            body: String,
        ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>> {
            let auth = headers
                .iter()
                .find(|(k, _)| *k == "Authorization")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            self.calls
                .lock()
                .unwrap()
                .push((url.to_owned(), auth, body));
            let answer = self.answers.lock().unwrap().remove(0);
            Box::pin(async move { answer })
        }
    }

    /// Runs a future the fixture answers at once (no runtime needed).
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    fn ok(body: &str) -> Result<HttpAnswer, TransportError> {
        Ok(HttpAnswer {
            status: 200,
            body: body.to_owned(),
        })
    }

    fn config() -> AspConfig {
        AspConfig {
            base_url: "https://asp.example/api/".into(),
            api_key: "k-123".into(),
        }
    }

    #[test]
    fn sends_the_document_and_polls_its_status() {
        let asp = Fixture::new(vec![
            ok(r#"{"id":"doc-1","status":"received"}"#),
            ok(r#"{"id":"doc-1","status":"rejected","message":"TRN not found"}"#),
        ]);
        let sent = block_on(send(&asp, &config(), "INV-1", "<Invoice/>")).unwrap();
        assert_eq!(sent.id, "doc-1");
        assert_eq!(sent.status, AspStatus::Pending);
        let polled = block_on(status(&asp, &config(), "doc-1")).unwrap();
        assert_eq!(
            polled,
            AspStatus::Rejected {
                message: "TRN not found".into()
            }
        );
        let calls = asp.calls.lock().unwrap();
        assert_eq!(calls[0].0, "https://asp.example/api/documents");
        assert_eq!(calls[0].1, "Bearer k-123");
        let body: serde_json::Value = serde_json::from_str(&calls[0].2).unwrap();
        assert_eq!(body["format"], "pint-ae");
        assert_eq!(
            STANDARD.decode(body["document"].as_str().unwrap()).unwrap(),
            b"<Invoice/>"
        );
        assert_eq!(calls[1].0, "https://asp.example/api/documents/doc-1/status");
    }

    #[test]
    fn server_trouble_is_retried_and_a_refusal_is_not() {
        let asp = Fixture::new(vec![
            Ok(HttpAnswer {
                status: 503,
                body: String::new(),
            }),
            Ok(HttpAnswer {
                status: 422,
                body: "bad UBL".into(),
            }),
            Err(TransportError("timeout".into())),
        ]);
        assert!(matches!(
            block_on(send(&asp, &config(), "INV-1", "<Invoice/>")),
            Err(AspError::Retryable(_))
        ));
        assert!(matches!(
            block_on(send(&asp, &config(), "INV-1", "<Invoice/>")),
            Err(AspError::Refused(_))
        ));
        assert!(matches!(
            block_on(send(&asp, &config(), "INV-1", "<Invoice/>")),
            Err(AspError::Retryable(_))
        ));
    }

    #[test]
    fn statuses_and_ids_are_read_safely() {
        assert_eq!(AspStatus::parse("Delivered", None), AspStatus::Accepted);
        assert_eq!(AspStatus::parse("queued", None), AspStatus::Pending);
        assert_eq!(urlencoding_segment("a/b c"), "a%2Fb%20c");
    }
}
