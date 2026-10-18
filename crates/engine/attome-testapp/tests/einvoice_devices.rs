//! AG2-T3: an e-invoicing device is created with its key and CSR, and
//! onboarded through ZATCA's calls (recorded answers here, never the real
//! service): compliance CSID, one compliance check per document kind, then
//! the production CSID. Secrets are stored encrypted and every credential
//! write leaves a Credential audit event.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use attome_einvoice::zatca::api::{HttpAnswer, Transport, TransportError};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use uuid::Uuid;

/// A certificate ZATCA issued (the sample invoices'), as a CSID token.
fn sample_token() -> String {
    let xml = include_str!("../../attome-einvoice/src/zatca/testdata/standard_invoice_signed.xml");
    let start = xml.find("<ds:X509Certificate>").unwrap() + "<ds:X509Certificate>".len();
    let cert = &xml[start..start + xml[start..].find('<').unwrap()];
    STANDARD.encode(cert)
}

/// Answers in order and keeps the paths it was sent.
struct Recorded {
    answers: Mutex<Vec<(u16, String)>>,
    paths: Mutex<Vec<String>>,
}

impl Recorded {
    fn new(answers: Vec<(u16, String)>) -> Self {
        let mut answers = answers;
        answers.reverse();
        Self {
            answers: Mutex::new(answers),
            paths: Mutex::new(Vec::new()),
        }
    }
}

impl Transport for Recorded {
    fn post<'a>(
        &'a self,
        url: &'a str,
        _headers: &'a [(&'a str, String)],
        _body: String,
    ) -> Pin<Box<dyn Future<Output = Result<HttpAnswer, TransportError>> + Send + 'a>> {
        self.paths.lock().unwrap().push(url.to_owned());
        let next = self.answers.lock().unwrap().pop();
        Box::pin(async move {
            next.map(|(status, body)| HttpAnswer { status, body })
                .ok_or_else(|| TransportError("no recorded answer".into()))
        })
    }
}

async fn set(app: &TestApp, key: &str, value: &str) {
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/api/v1/admin/settings/{key}"),
            Some(json!({ "scope": "deployment", "value": value })),
        )
        .await;
    assert!(status.is_success(), "{key}: {status} {body}");
}

async fn seller_settings(app: &TestApp) {
    for (key, value) in [
        ("billing.seller_name", "Attome Trading"),
        ("billing.seller_vat_number", "399999999900003"),
        ("billing.seller_crn", "1010010000"),
        ("billing.seller_street", "Prince Sultan"),
        ("billing.seller_building_number", "2322"),
        ("billing.seller_district", "Al-Murabba"),
        ("billing.seller_city", "Riyadh"),
        ("billing.seller_postal_zone", "23333"),
    ] {
        set(app, key, value).await;
    }
}

async fn audit_events(app: &TestApp, record: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE record_id = $1) \
              + (SELECT COUNT(*) FROM audit_ingest WHERE payload->>'record_id' = $2)",
    )
    .bind(record)
    .bind(record.to_string())
    .fetch_one(app.db())
    .await
    .expect("count audit events")
}

// feature: AG2
#[test]
fn einvoice_device_onboards_through_zatca() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // Without the seller's details, no device.
        let new_device = json!({
            "name": format!("EGS-{}", Uuid::now_v7().simple()),
            "environment": "sandbox",
            "organization_unit": "Riyadh Branch",
            "location": "RRRD2929",
            "industry": "Software",
        });
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/einvoice/devices",
                Some(new_device.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        seller_settings(&app).await;
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/einvoice/devices",
                Some(new_device.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "new");
        let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        let (status, _) = app
            .request(Method::POST, "/api/v1/einvoice/devices", Some(new_device))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "names are unique");
        let csr: String = sqlx::query_scalar("SELECT csr FROM einvoice_device WHERE id = $1")
            .bind(id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert!(csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));

        // Onboarding: the CSID, six compliance checks (standard and
        // simplified invoice, credit and debit note), the production CSID.
        let token = sample_token();
        let csid = json!({
            "requestID": 1_234_567_890_123_u64,
            "dispositionMessage": "ISSUED",
            "binarySecurityToken": token,
            "secret": "the-compliance-secret",
        })
        .to_string();
        let checked = r#"{"validationResults":{"infoMessages":[],"warningMessages":[],"errorMessages":[],"status":"PASS"},"reportingStatus":"REPORTED"}"#;
        let production = json!({
            "requestID": 30_368,
            "binarySecurityToken": token,
            "secret": "the-production-secret",
        })
        .to_string();
        let mut answers = vec![(200, csid)];
        answers.extend(std::iter::repeat_n((200, checked.to_owned()), 6));
        answers.push((200, production));
        let zatca = Recorded::new(answers);
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let device = attome_einvoice::device::onboard(&app.state, &ctx, id, "123345", &zatca)
            .await
            .expect("onboarded");
        assert_eq!(device.status, "active");
        assert!(device.has_production_csid);
        let paths = zatca.paths.lock().unwrap().clone();
        assert_eq!(paths.len(), 8);
        assert!(paths[0].ends_with("/developer-portal/compliance"));
        assert!(
            paths[1..7]
                .iter()
                .all(|p| p.ends_with("/compliance/invoices"))
        );
        assert!(paths[7].ends_with("/production/csids"));

        // Secrets are stored encrypted; the certificate's issuer is kept.
        let (secret, issuer): (String, String) = sqlx::query_as(
            "SELECT production_secret_encrypted, cert_issuer FROM einvoice_device WHERE id = $1",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(!secret.contains("the-production-secret"));
        assert!(issuer.starts_with("CN="), "{issuer}");
        assert!(
            audit_events(&app, id).await >= 3,
            "create and two CSIDs are audited"
        );

        // Onboarded once: a second OTP is refused.
        let again = attome_einvoice::device::onboard(&app.state, &ctx, id, "123345", &zatca).await;
        assert!(
            matches!(again, Err(attome_types::AppError::Conflict(_))),
            "{again:?}"
        );

        // A refused OTP leaves the device failed with ZATCA's reason.
        let (_, body) = app
            .request(
                Method::POST,
                "/api/v1/einvoice/devices",
                Some(json!({
                    "name": format!("EGS-{}", Uuid::now_v7().simple()),
                    "environment": "sandbox",
                    "organization_unit": "Riyadh Branch",
                    "location": "RRRD2929",
                    "industry": "Software",
                    "invoice_types": "0100",
                })),
            )
            .await;
        let other: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        let refusing = Recorded::new(vec![(
            400,
            r#"{"errors":[{"code":"Invalid-OTP","message":"The provided OTP is invalid"}]}"#
                .to_owned(),
        )]);
        let refused =
            attome_einvoice::device::onboard(&app.state, &ctx, other, "111111", &refusing).await;
        assert!(
            matches!(refused, Err(attome_types::AppError::Validation(_))),
            "{refused:?}"
        );
        let (status, body) = app
            .request(Method::GET, "/api/v1/einvoice/devices", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        let failed = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"] == json!(other))
            .unwrap()
            .clone();
        assert_eq!(failed["status"], "failed");
        assert!(
            failed["last_error"]
                .as_str()
                .unwrap()
                .contains("Invalid-OTP")
        );
    });
}
