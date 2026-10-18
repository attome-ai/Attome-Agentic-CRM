//! ZATCA's Fatoora API (AG2-T3): onboarding and the invoice calls.
//!
//! - `POST /compliance` with the OTP and the CSR gives the compliance CSID
//!   (certificate token, secret and request id).
//! - `POST /compliance/invoices` checks a sample document with the
//!   compliance CSID; onboarding sends one of each kind the device issues.
//! - `POST /production/csids` with the compliance request id gives the
//!   production CSID.
//! - `POST /invoices/clearance/single` clears a standard invoice before it
//!   is shared; `POST /invoices/reporting/single` reports a simplified one
//!   within 24 hours.
//!
//! Calls authenticate with HTTP basic auth (`token:secret`) and send
//! `Accept-Version: V2`. Every answer is classified ([`Outcome`]): accepted
//! (200, or 202 with warnings), rejected (400: the document is wrong and
//! retrying will not help), unauthorised (401: the CSID is wrong or
//! expired), or a failure to retry later (429, 5xx, timeouts), which the
//! caller's job retries with back-off. The transport is a trait so tests run
//! on recorded answers and never reach ZATCA.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::csr::Environment;

/// One HTTP answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAnswer {
    pub status: u16,
    pub body: String,
}

/// A failure before any answer (connect, timeout).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ZATCA could not be reached: {0}")]
pub struct TransportError(pub String);

/// Sends one JSON POST to ZATCA.
pub trait Transport: Send + Sync {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, String)],
        body: String,
    ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>>;
}

/// The real transport: reqwest, with an explicit timeout.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
}

impl HttpTransport {
    pub fn new(timeout: Duration) -> Result<Self, TransportError> {
        reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map(|client| Self { client })
            .map_err(|e| TransportError(e.to_string()))
    }
}

impl Transport for HttpTransport {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: &'a [(&'a str, String)],
        body: String,
    ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let mut request = self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .body(body);
            for (name, value) in headers {
                request = request.header(*name, value);
            }
            let response = request
                .send()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            let status = response.status().as_u16();
            let body = response
                .text()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(HttpAnswer { status, body })
        })
    }
}

/// A message in ZATCA's validation results.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidationMessage {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub code: Option<String>,
    pub category: Option<String>,
    pub message: Option<String>,
    pub status: Option<String>,
}

/// What ZATCA's validation said about a document.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ValidationResults {
    pub info_messages: Vec<ValidationMessage>,
    pub warning_messages: Vec<ValidationMessage>,
    pub error_messages: Vec<ValidationMessage>,
    pub status: Option<String>,
}

/// The answer to a document call (compliance check, clearance, reporting).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DocumentAnswer {
    pub validation_results: Option<ValidationResults>,
    pub clearance_status: Option<String>,
    pub reporting_status: Option<String>,
    /// For a cleared invoice: ZATCA's stamped copy (base64 XML), the one to share.
    pub cleared_invoice: Option<String>,
}

/// The answer to a CSID call.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CsidAnswer {
    #[serde(rename = "requestID")]
    pub request_id: Option<serde_json::Value>,
    pub disposition_message: Option<String>,
    pub binary_security_token: Option<String>,
    pub secret: Option<String>,
}

impl CsidAnswer {
    /// The request id as text (ZATCA sends a number).
    pub fn request_id_text(&self) -> Option<String> {
        match &self.request_id {
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            _ => None,
        }
    }
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    /// 200, or 202 (accepted with warnings).
    Accepted { answer: T, with_warnings: bool },
    /// 400: the request or document is wrong; do not retry.
    Rejected { answer: Option<T>, body: String },
    /// 401: the CSID is wrong or expired.
    Unauthorized,
    /// 429, 5xx or no answer: retry later.
    RetryLater { reason: String },
}

fn classify<T: for<'de> Deserialize<'de>>(
    answer: Result<HttpAnswer, TransportError>,
) -> Outcome<T> {
    match answer {
        Err(e) => Outcome::RetryLater {
            reason: e.to_string(),
        },
        Ok(HttpAnswer { status, body }) => match status {
            200 | 202 => match serde_json::from_str::<T>(&body) {
                Ok(answer) => Outcome::Accepted {
                    answer,
                    with_warnings: status == 202,
                },
                Err(e) => Outcome::RetryLater {
                    reason: format!("ZATCA's answer did not read: {e}"),
                },
            },
            400 | 406 | 409 => Outcome::Rejected {
                answer: serde_json::from_str::<T>(&body).ok(),
                body,
            },
            401 | 403 => Outcome::Unauthorized,
            _ => Outcome::RetryLater {
                reason: format!("ZATCA answered {status}"),
            },
        },
    }
}

/// Credentials for a call: the CSID's token and secret.
#[derive(Clone)]
pub struct Credentials {
    pub token: String,
    pub secret: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}

impl Credentials {
    fn header(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.token, self.secret))
        )
    }
}

/// A document sent for checking, clearance or reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentRequest {
    pub invoice_hash: String,
    pub uuid: String,
    /// The stamped XML, base64.
    pub invoice: String,
}

impl DocumentRequest {
    pub fn new(invoice_hash: &str, uuid: &str, xml: &str) -> Self {
        Self {
            invoice_hash: invoice_hash.to_owned(),
            uuid: uuid.to_owned(),
            invoice: STANDARD.encode(xml),
        }
    }
}

/// The API of one environment.
pub struct Api<'t> {
    pub environment: Environment,
    pub transport: &'t dyn Transport,
}

impl std::fmt::Debug for Api<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

impl Api<'_> {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.environment.base_url())
    }

    /// The compliance CSID for a CSR (`csr` as [`super::csr::Csr::for_api`]).
    pub async fn compliance_csid(&self, otp: &str, csr: &str) -> Outcome<CsidAnswer> {
        let headers = [
            ("OTP", otp.to_owned()),
            ("Accept-Version", "V2".to_owned()),
            ("Accept-Language", "en".to_owned()),
        ];
        let body = serde_json::json!({ "csr": csr }).to_string();
        classify(
            self.transport
                .post(&self.url("/compliance"), &headers, body)
                .await,
        )
    }

    /// Checks a sample document with the compliance CSID.
    pub async fn compliance_check(
        &self,
        credentials: &Credentials,
        document: &DocumentRequest,
    ) -> Outcome<DocumentAnswer> {
        self.document_call("/compliance/invoices", credentials, document, None)
            .await
    }

    /// The production CSID, once the compliance checks passed.
    pub async fn production_csid(
        &self,
        credentials: &Credentials,
        compliance_request_id: &str,
    ) -> Outcome<CsidAnswer> {
        let headers = [
            ("Authorization", credentials.header()),
            ("Accept-Version", "V2".to_owned()),
            ("Accept-Language", "en".to_owned()),
        ];
        let body =
            serde_json::json!({ "compliance_request_id": compliance_request_id }).to_string();
        classify(
            self.transport
                .post(&self.url("/production/csids"), &headers, body)
                .await,
        )
    }

    /// Clears a standard invoice.
    pub async fn clear(
        &self,
        credentials: &Credentials,
        document: &DocumentRequest,
    ) -> Outcome<DocumentAnswer> {
        self.document_call(
            "/invoices/clearance/single",
            credentials,
            document,
            Some(("Clearance-Status", "1".to_owned())),
        )
        .await
    }

    /// Reports a simplified invoice.
    pub async fn report(
        &self,
        credentials: &Credentials,
        document: &DocumentRequest,
    ) -> Outcome<DocumentAnswer> {
        self.document_call(
            "/invoices/reporting/single",
            credentials,
            document,
            Some(("Clearance-Status", "0".to_owned())),
        )
        .await
    }

    async fn document_call(
        &self,
        path: &str,
        credentials: &Credentials,
        document: &DocumentRequest,
        extra: Option<(&str, String)>,
    ) -> Outcome<DocumentAnswer> {
        let mut headers = vec![
            ("Authorization", credentials.header()),
            ("Accept-Version", "V2".to_owned()),
            ("Accept-Language", "en".to_owned()),
        ];
        if let Some(header) = extra {
            headers.push(header);
        }
        let body = match serde_json::to_string(document) {
            Ok(body) => body,
            Err(e) => {
                return Outcome::Rejected {
                    answer: None,
                    body: e.to_string(),
                };
            }
        };
        classify(self.transport.post(&self.url(path), &headers, body).await)
    }
}

/// When to try a document again after its `attempt`-th failure: one
/// minute, doubling, at most an hour. Reporting has 24 hours.
pub fn retry_after(attempt: u32) -> Duration {
    Duration::from_secs((60u64 << attempt.min(6)).min(3600))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers recorded in the shapes ZATCA's API documentation shows.
    pub(crate) const CSID: &str = r#"{"requestID":1234567890123,"dispositionMessage":"ISSUED","binarySecurityToken":"VEVTVA==","secret":"Xlj15LyMCgSC66ObnEO/qVPfhSbs3kDTjWnGheYhfSs=","errors":null}"#;
    pub(crate) const CLEARED: &str = r#"{"validationResults":{"infoMessages":[{"type":"INFO","code":"XSD_ZATCA_VALID","category":"XSD validation","message":"Complied with UBL 2.1 standards in line with ZATCA specifications","status":"PASS"}],"warningMessages":[],"errorMessages":[],"status":"PASS"},"clearanceStatus":"CLEARED","clearedInvoice":"PD94bWwgdmVyc2lvbj0iMS4wIj8+PEludm9pY2UvPg=="}"#;
    pub(crate) const REPORTED_WITH_WARNING: &str = r#"{"validationResults":{"infoMessages":[],"warningMessages":[{"type":"WARNING","code":"BR-KSA-08","category":"KSA","message":"The seller identification is missing","status":"WARNING"}],"errorMessages":[],"status":"WARNING"},"reportingStatus":"REPORTED"}"#;
    pub(crate) const REJECTED: &str = r#"{"validationResults":{"infoMessages":[],"warningMessages":[],"errorMessages":[{"type":"ERROR","code":"invoiceHash_QRCODE_INVALID","category":"QR_CODE_ERROR","message":"Invoice hash in QR code does not match the calculated hash","status":"ERROR"}],"status":"ERROR"},"clearanceStatus":"NOT_CLEARED"}"#;

    /// One request a recorded transport saw: URL, headers, body.
    pub(crate) type Sent = (String, Vec<(String, String)>, String);

    /// A transport that answers from a script and keeps what it was sent.
    #[derive(Default)]
    pub(crate) struct Recorded {
        pub answers: Mutex<Vec<Result<HttpAnswer, TransportError>>>,
        pub sent: Mutex<Vec<Sent>>,
    }

    impl Recorded {
        pub(crate) fn answering(answers: Vec<(u16, &str)>) -> Self {
            Self {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .rev()
                        .map(|(status, body)| {
                            Ok(HttpAnswer {
                                status,
                                body: body.to_owned(),
                            })
                        })
                        .collect(),
                ),
                sent: Mutex::default(),
            }
        }
    }

    impl Transport for Recorded {
        fn post<'a>(
            &'a self,
            url: &'a str,
            headers: &'a [(&'a str, String)],
            body: String,
        ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>> {
            self.sent.lock().unwrap().push((
                url.to_owned(),
                headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.clone()))
                    .collect(),
                body,
            ));
            let next = self
                .answers
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Err(TransportError("no recorded answer".into())));
            Box::pin(async move { next })
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        // The calls never wait on I/O here: a recorded transport answers
        // immediately, so polling once with a no-op waker finishes them.
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("a recorded call waited"),
        }
    }

    fn creds() -> Credentials {
        Credentials {
            token: "VEVTVA==".into(),
            secret: "s3cret".into(),
        }
    }

    #[test]
    fn zatca_api_onboarding_sends_the_otp_and_reads_the_csid() {
        let t = Recorded::answering(vec![(200, CSID)]);
        let api = Api {
            environment: Environment::Sandbox,
            transport: &t,
        };
        let outcome = block_on(api.compliance_csid("123345", "Q1NS"));
        let Outcome::Accepted { answer, .. } = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(answer.request_id_text().as_deref(), Some("1234567890123"));
        assert_eq!(answer.binary_security_token.as_deref(), Some("VEVTVA=="));
        let sent = t.sent.lock().unwrap();
        assert_eq!(
            sent[0].0,
            "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance"
        );
        assert!(sent[0].1.contains(&("OTP".into(), "123345".into())));
        assert!(sent[0].1.contains(&("Accept-Version".into(), "V2".into())));
        assert_eq!(sent[0].2, r#"{"csr":"Q1NS"}"#);
    }

    #[test]
    fn zatca_api_clearance_and_reporting_read_zatcas_answers() {
        let t = Recorded::answering(vec![(200, CLEARED), (202, REPORTED_WITH_WARNING)]);
        let api = Api {
            environment: Environment::Simulation,
            transport: &t,
        };
        let doc = DocumentRequest::new(
            "aGFzaA==",
            "3cf5ee18-ee25-44ea-a444-2c37ba7f28be",
            "<Invoice/>",
        );
        let Outcome::Accepted {
            answer,
            with_warnings,
        } = block_on(api.clear(&creds(), &doc))
        else {
            panic!("not cleared");
        };
        assert!(!with_warnings);
        assert_eq!(answer.clearance_status.as_deref(), Some("CLEARED"));
        assert!(answer.cleared_invoice.is_some());
        let Outcome::Accepted {
            answer,
            with_warnings,
        } = block_on(api.report(&creds(), &doc))
        else {
            panic!("not reported");
        };
        assert!(with_warnings);
        assert_eq!(answer.reporting_status.as_deref(), Some("REPORTED"));
        assert_eq!(
            answer.validation_results.unwrap().warning_messages[0]
                .code
                .as_deref(),
            Some("BR-KSA-08")
        );
        let sent = t.sent.lock().unwrap();
        assert!(sent[0].0.ends_with("/simulation/invoices/clearance/single"));
        assert!(sent[0].1.contains(&("Clearance-Status".into(), "1".into())));
        assert!(
            sent[0]
                .1
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Basic VkVWVFZBPT06czNjcmV0")
        );
        assert!(sent[1].0.ends_with("/invoices/reporting/single"));
        let body: serde_json::Value = serde_json::from_str(&sent[0].2).unwrap();
        assert_eq!(body["invoice"], STANDARD.encode("<Invoice/>"));
        assert_eq!(body["invoiceHash"], "aGFzaA==");
    }

    #[test]
    fn zatca_api_rejections_unauthorised_and_outages_are_told_apart() {
        let t = Recorded::answering(vec![(400, REJECTED), (401, ""), (503, "down"), (429, "")]);
        let api = Api {
            environment: Environment::Production,
            transport: &t,
        };
        let doc = DocumentRequest::new("h", "u", "<Invoice/>");
        let Outcome::Rejected {
            answer: Some(answer),
            ..
        } = block_on(api.clear(&creds(), &doc))
        else {
            panic!("not rejected");
        };
        assert_eq!(answer.clearance_status.as_deref(), Some("NOT_CLEARED"));
        assert_eq!(
            answer.validation_results.unwrap().error_messages[0]
                .code
                .as_deref(),
            Some("invoiceHash_QRCODE_INVALID")
        );
        assert_eq!(block_on(api.clear(&creds(), &doc)), Outcome::Unauthorized);
        assert!(matches!(
            block_on(api.clear(&creds(), &doc)),
            Outcome::RetryLater { .. }
        ));
        assert!(matches!(
            block_on(api.clear(&creds(), &doc)),
            Outcome::RetryLater { .. }
        ));
        // No recorded answer: a transport failure, retried.
        assert!(matches!(
            block_on(api.clear(&creds(), &doc)),
            Outcome::RetryLater { .. }
        ));
    }

    #[test]
    fn zatca_api_retries_back_off_to_an_hour() {
        assert_eq!(retry_after(0), Duration::from_secs(60));
        assert_eq!(retry_after(1), Duration::from_secs(120));
        assert_eq!(retry_after(10), Duration::from_secs(3600));
    }
}
