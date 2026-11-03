//! Egypt e-invoicing through the Egyptian Tax Authority (roadmap AG3-T1).
//!
//! Egypt's model is clearance by the authority: the taxpayer's ERP writes
//! the document ([`document`]), signs its canonical text ([`serialize`])
//! with the taxpayer's CAdES certificate through a signer service that
//! holds the USB token or HSM ([`signer`]), submits it and polls until ETA
//! names it valid or invalid ([`api`]). The transport is the one ZATCA and
//! the UAE use, so tests run on recorded answers and never reach ETA.

pub mod api;
pub mod document;
pub mod serialize;
pub mod signer;

#[cfg(test)]
mod eta_flow {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::{Value, json};

    use super::api::{self, EtaApiError, EtaCredentials, EtaEnvironment, EtaStatus};
    use super::serialize::{canonical, digest_hex};
    use super::signer::{self, SignerConfig, SignerError};
    use crate::zatca::api::{HttpAnswer, Transport, TransportError};

    /// One recorded call: method, URL, headers and body.
    type Call = (String, String, Vec<(String, String)>, String);

    /// A scripted ETA and signer: records each call and answers in turn.
    struct Fixture {
        answers: Mutex<Vec<Result<HttpAnswer, TransportError>>>,
        calls: Mutex<Vec<Call>>,
    }

    impl Fixture {
        fn new(answers: Vec<Result<HttpAnswer, TransportError>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, method: &str, url: &str, headers: &[(&str, String)], body: String) {
            self.calls.lock().unwrap().push((
                method.to_owned(),
                url.to_owned(),
                headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.clone()))
                    .collect(),
                body,
            ));
        }
    }

    impl Transport for Fixture {
        fn post<'a>(
            &'a self,
            url: &'a str,
            headers: &'a [(&'a str, String)],
            body: String,
        ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>> {
            self.record("POST", url, headers, body);
            let answer = self.answers.lock().unwrap().remove(0);
            Box::pin(async move { answer })
        }

        fn get<'a>(
            &'a self,
            url: &'a str,
            headers: &'a [(&'a str, String)],
        ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>> {
            self.record("GET", url, headers, String::new());
            let answer = self.answers.lock().unwrap().remove(0);
            Box::pin(async move { answer })
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                return value;
            }
        }
    }

    fn ok(status: u16, body: &str) -> Result<HttpAnswer, TransportError> {
        Ok(HttpAnswer {
            status,
            body: body.to_owned(),
        })
    }

    fn credentials() -> EtaCredentials {
        EtaCredentials {
            environment: EtaEnvironment::PreProduction,
            client_id: "erp-client".into(),
            client_secret: "s3cret/+=".into(),
        }
    }

    fn doc() -> Value {
        json!({ "documentType": "I", "internalID": "INV-2026-001", "totalAmount": 5927.9886 })
    }

    #[test]
    fn signs_submits_and_polls_on_sandbox_answers() {
        let cms = STANDARD.encode(b"cms-signature");
        let eta = Fixture::new(vec![
            ok(200, &json!({ "signature": cms }).to_string()),
            ok(
                200,
                r#"{"access_token":"tok-1","expires_in":3600,"token_type":"Bearer"}"#,
            ),
            ok(202, include_str!("testdata/submission_answer.json")),
            ok(
                200,
                r#"{"uuid":"4HB9MZXBK6A0RYPWAR2T1XKJ10","status":"Submitted"}"#,
            ),
            ok(200, include_str!("testdata/details_invalid.json")),
        ]);
        let signer_config = SignerConfig {
            base_url: "http://signer.local:8443/".into(),
            api_key: "sk".into(),
        };
        let signed = block_on(signer::sign(&eta, &signer_config, &doc())).unwrap();
        assert_eq!(
            signed["signatures"],
            json!([{ "signatureType": "I", "value": cms }])
        );
        // The signature covers the text without the signatures.
        assert_eq!(canonical(&signed), canonical(&doc()));

        let token = block_on(api::token(&eta, &credentials())).unwrap();
        assert_eq!(token, "tok-1");
        let submission = block_on(api::submit(
            &eta,
            EtaEnvironment::PreProduction,
            &token,
            &[signed],
        ))
        .unwrap();
        assert_eq!(submission.id, "B0RBH3YB1T6ZRK8P2XAH71KJ10");
        assert_eq!(submission.accepted[0].uuid, "4HB9MZXBK6A0RYPWAR2T1XKJ10");
        assert_eq!(submission.refused[0].internal_id, "INV-2026-002");
        assert_eq!(submission.refused[0].message, "Validation Error");

        let uuid = &submission.accepted[0].uuid;
        let first = block_on(api::status(
            &eta,
            EtaEnvironment::PreProduction,
            &token,
            uuid,
        ));
        assert_eq!(first.unwrap(), EtaStatus::Submitted);
        let second = block_on(api::status(
            &eta,
            EtaEnvironment::PreProduction,
            &token,
            uuid,
        ))
        .unwrap();
        let EtaStatus::Invalid { results } = second else {
            panic!("{second:?}");
        };
        assert_eq!(results["validationSteps"][0]["error"]["errorCode"], "4043");

        let calls = eta.calls.lock().unwrap();
        // The signer got the canonical text and its digest, with its key.
        assert_eq!(calls[0].1, "http://signer.local:8443/sign");
        let sent: Value = serde_json::from_str(&calls[0].3).unwrap();
        assert_eq!(
            STANDARD.decode(sent["data"].as_str().unwrap()).unwrap(),
            canonical(&doc()).as_bytes()
        );
        assert_eq!(sent["digest"], digest_hex(&doc()));
        assert!(
            calls[0]
                .2
                .contains(&("Authorization".into(), "Bearer sk".into()))
        );
        // The token request is a form, its secret encoded.
        assert_eq!(calls[1].1, "https://id.preprod.eta.gov.eg/connect/token");
        assert!(calls[1].3.contains("client_secret=s3cret%2F%2B%3D"));
        assert!(calls[1].3.contains("scope=InvoicingAPI"));
        assert!(calls[1].2.contains(&(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into()
        )));
        assert_eq!(
            calls[2].1,
            "https://api.preprod.invoicing.eta.gov.eg/api/v1/documentsubmissions"
        );
        assert!(
            calls[2]
                .2
                .contains(&("Authorization".into(), "Bearer tok-1".into()))
        );
        assert_eq!(
            (calls[3].0.as_str(), calls[3].1.as_str()),
            (
                "GET",
                "https://api.preprod.invoicing.eta.gov.eg/api/v1/documents/4HB9MZXBK6A0RYPWAR2T1XKJ10/details"
            )
        );
    }

    #[test]
    fn failures_are_classified() {
        let eta = Fixture::new(vec![
            ok(400, r#"{"error":"invalid_client"}"#),
            ok(503, ""),
            Err(TransportError("timeout".into())),
            ok(422, "bad document"),
            ok(200, r#"{"signature":"not base64!"}"#),
            ok(500, ""),
        ]);
        assert_eq!(
            block_on(api::token(&eta, &credentials())),
            Err(EtaApiError::Unauthorised)
        );
        assert!(matches!(
            block_on(api::token(&eta, &credentials())),
            Err(EtaApiError::Retryable(_))
        ));
        assert!(matches!(
            block_on(api::submit(&eta, EtaEnvironment::Production, "t", &[doc()])),
            Err(EtaApiError::Retryable(_))
        ));
        assert!(matches!(
            block_on(api::submit(&eta, EtaEnvironment::Production, "t", &[doc()])),
            Err(EtaApiError::Refused(_))
        ));
        let config = SignerConfig {
            base_url: "http://signer".into(),
            api_key: "k".into(),
        };
        assert!(matches!(
            block_on(signer::sign(&eta, &config, &doc())),
            Err(SignerError::Refused(_))
        ));
        assert!(matches!(
            block_on(signer::sign(&eta, &config, &doc())),
            Err(SignerError::Retryable(_))
        ));
        // Nothing is sent for an empty submission or a malformed UUID.
        assert!(block_on(api::submit(&eta, EtaEnvironment::Production, "t", &[])).is_err());
        assert!(block_on(api::status(&eta, EtaEnvironment::Production, "t", "../x")).is_err());
        assert_eq!(eta.calls.lock().unwrap().len(), 6);
    }
}
