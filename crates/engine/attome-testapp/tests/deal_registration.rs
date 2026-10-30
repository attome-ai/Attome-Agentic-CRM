//! F9-T3: a deal registration that conflicts is flagged; an approved one
//! names the partner on the opportunity with protection from its tier; a
//! second partner cannot take protected ground; a rejection needs a reason;
//! and protection that has ended lapses.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

fn packs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

async fn install(app: &TestApp, pack: &str) -> Result<(), String> {
    let dir = packs_dir().join(pack).join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .map_err(|e| format!("{}: {e}", file.display()))?;
    }
    Ok(())
}

/// The packs the partner pack's lookups need, in whatever order they install.
async fn install_partner(app: &TestApp) {
    let mut left = vec!["crm", "sales", "contract-management", "partner"];
    for _ in 0..4 {
        let mut failed = Vec::new();
        for pack in left {
            if let Err(error) = install(app, pack).await {
                failed.push((pack, error));
            }
        }
        if failed.is_empty() {
            let registry = attome_core::build_registry(app.db()).await.unwrap();
            app.state.entities.swap(registry);
            return;
        }
        left = failed.iter().map(|(pack, _)| *pack).collect();
        if left.len() == 4 {
            panic!("no pack installs: {failed:?}");
        }
    }
    panic!("packs left uninstalled: {left:?}");
}

async fn create(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, out) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}: {out}");
    out["id"].as_str().unwrap().parse().unwrap()
}

async fn row(app: &TestApp, table: &str, id: Uuid) -> Value {
    sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id = $1",
        attome_core::quote_ident(table)
    ))
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn decide(app: &TestApp, id: Uuid, body: Value) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/partner/registrations/{id}/decision"),
        Some(body),
    )
    .await
}

struct World {
    partner_a: Uuid,
    partner_b: Uuid,
    customer: Uuid,
}

async fn world(app: &TestApp) -> World {
    let programme = create(app, "partner_programme", json!({ "name": "Resellers" })).await;
    let tier = create(
        app,
        "partner_tier",
        json!({ "programme_ref": programme, "name": "Gold", "protection_days": 30 }),
    )
    .await;
    let suffix = Uuid::now_v7().simple().to_string();
    World {
        partner_a: create(
            app,
            "account",
            json!({ "name": format!("Partner A {suffix}"), "is_partner": true, "partner_tier_ref": tier }),
        )
        .await,
        partner_b: create(
            app,
            "account",
            json!({ "name": format!("Partner B {suffix}"), "is_partner": true }),
        )
        .await,
        customer: create(
            app,
            "account",
            json!({ "name": format!("أحمد للتجارة {suffix}") }),
        )
        .await,
    }
}

// feature: F9
#[test]
fn conflicting_registration_goes_to_conflict() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let name = format!("أحمد للتجارة {}", Uuid::now_v7().simple());
        let first = create(
            &app,
            "deal_registration",
            json!({ "partner_account_ref": w.partner_a, "customer_account_ref": w.customer, "customer_name": name }),
        )
        .await;
        attome_partner::registration::intake_tick(&app.state)
            .await
            .unwrap();
        let checked = row(&app, "deal_registration", first).await;
        assert_eq!(checked["status"], "submitted", "{checked}");
        assert!(!checked["checked_at"].is_null());

        // Another partner, the same customer spelled without the hamza.
        let second = create(
            &app,
            "deal_registration",
            json!({ "partner_account_ref": w.partner_b, "customer_name": name.replacen('أ', "ا", 1) }),
        )
        .await;
        attome_partner::registration::intake_tick(&app.state)
            .await
            .unwrap();
        let flagged = row(&app, "deal_registration", second).await;
        assert_eq!(flagged["status"], "conflict", "{flagged}");
        assert!(
            flagged["conflict_summary"]
                .as_str()
                .unwrap()
                .contains(&first.to_string())
        );
    });
}

// feature: F9
#[test]
fn approval_names_the_partner_and_protection_lapses() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let customer = format!("Customer {}", Uuid::now_v7().simple());
        let registration = create(
            &app,
            "deal_registration",
            json!({ "partner_account_ref": w.partner_a, "customer_account_ref": w.customer,
                    "customer_name": customer, "amount": 25000 }),
        )
        .await;
        attome_partner::registration::intake_tick(&app.state)
            .await
            .unwrap();

        let (status, decided) = decide(&app, registration, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::OK, "{decided}");
        assert_eq!(decided["status"], "approved");
        let opportunity: Uuid = decided["opportunity_id"].as_str().unwrap().parse().unwrap();
        let deal = row(&app, "opportunity", opportunity).await;
        assert_eq!(deal["partner_account_ref"], json!(w.partner_a.to_string()));
        assert_eq!(deal["account_ref"], json!(w.customer.to_string()));
        // Protection from the Gold tier: 30 days.
        let ends: chrono::DateTime<chrono::Utc> = decided["protection_ends_on"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let days = (ends - chrono::Utc::now()).num_days();
        assert!((29..=30).contains(&days), "{days}");
        let (status, _) = decide(&app, registration, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::CONFLICT, "decided once");

        // A second partner on the same customer cannot take protected ground.
        let rival = create(
            &app,
            "deal_registration",
            json!({ "partner_account_ref": w.partner_b, "customer_account_ref": w.customer,
                    "customer_name": customer }),
        )
        .await;
        attome_partner::registration::intake_tick(&app.state)
            .await
            .unwrap();
        assert_eq!(
            row(&app, "deal_registration", rival).await["status"],
            "conflict"
        );
        let (status, body) = decide(&app, rival, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, _) = decide(&app, rival, json!({ "decision": "reject" })).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a rejection needs a reason"
        );
        let (status, body) = decide(
            &app,
            rival,
            json!({ "decision": "reject", "reason": "the customer is protected" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            row(&app, "deal_registration", rival).await["decision_reason"],
            "the customer is protected"
        );

        // Protection ends: the registration lapses and the open deal stops
        // naming the partner.
        sqlx::query(
            "UPDATE deal_registration SET protection_ends_on = now() - interval '1 day' WHERE id = $1",
        )
        .bind(registration)
        .execute(app.db())
        .await
        .unwrap();
        attome_partner::registration::lapse_tick(&app.state)
            .await
            .unwrap();
        assert_eq!(
            row(&app, "deal_registration", registration).await["status"],
            "lapsed"
        );
        assert!(row(&app, "opportunity", opportunity).await["partner_account_ref"].is_null());
    });
}

async fn mdf_decide(app: &TestApp, kind: &str, id: Uuid, body: Value) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/partner/mdf/{kind}/{id}/decision"),
        Some(body),
    )
    .await
}

async fn change_events(app: &TestApp, id: Uuid, name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event WHERE record_id = $1 AND event_name = $2",
    )
    .bind(id)
    .bind(name)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: F9
#[test]
fn mdf_requests_respect_the_fund_and_an_approved_claim_emits_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let fund = create(
            &app,
            "mdf_fund",
            json!({ "partner_account_ref": w.partner_a, "fiscal_year": "2027", "amount": 1000 }),
        )
        .await;
        let request = |amount: i64| {
            let app = &app;
            async move {
                create(
                    app,
                    "mdf_request",
                    json!({ "fund_ref": fund, "activity": "Webinar", "amount": amount, "status": "submitted" }),
                )
                .await
            }
        };

        // 600 fits; 500 more does not, and the check refuses it.
        let first = request(600).await;
        let over = request(500).await;
        attome_partner::mdf::check_tick(&app.state).await.unwrap();
        assert_eq!(row(&app, "mdf_request", first).await["status"], "submitted");
        let refused = row(&app, "mdf_request", over).await;
        assert_eq!(refused["status"], "rejected", "{refused}");
        let (status, body) =
            mdf_decide(&app, "requests", first, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // request_over_remaining_fund_is_422: decided before the check runs.
        let late = request(500).await;
        let (status, _) =
            mdf_decide(&app, "requests", late, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // claim_needs_approved_request: against the refused request.
        let stray = create(
            &app,
            "mdf_claim",
            json!({ "request_ref": over, "amount": 100 }),
        )
        .await;
        let (status, _) = mdf_decide(&app, "claims", stray, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // A claim on the approved request needs its proof, then emits once.
        let claim = create(
            &app,
            "mdf_claim",
            json!({ "request_ref": first, "amount": 400 }),
        )
        .await;
        let (status, _) = mdf_decide(&app, "claims", claim, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "no proof yet");
        sqlx::query("UPDATE mdf_claim SET proof_file = 'mdf/proof.pdf' WHERE id = $1")
            .bind(claim)
            .execute(app.db())
            .await
            .unwrap();
        let (status, body) =
            mdf_decide(&app, "claims", claim, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = mdf_decide(&app, "claims", claim, json!({ "decision": "approve" })).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            change_events(&app, claim, attome_partner::mdf::CLAIM_APPROVED).await,
            1
        );
    });
}

// feature: F9
#[test]
fn warns_once_30_days_before_expiry() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let soon = (chrono::Utc::now() + chrono::Duration::days(10)).to_rfc3339();
        let later = (chrono::Utc::now() + chrono::Duration::days(60)).to_rfc3339();
        let expiring = create(
            &app,
            "partner_certification",
            json!({ "partner_account_ref": w.partner_a, "name": "Cloud Expert", "expires_on": soon }),
        )
        .await;
        let fresh = create(
            &app,
            "partner_certification",
            json!({ "partner_account_ref": w.partner_a, "name": "Data Expert", "expires_on": later }),
        )
        .await;
        attome_partner::certification::expiry_tick(&app.state)
            .await
            .unwrap();
        let warned = row(&app, "partner_certification", expiring).await["warned_on"].clone();
        assert!(!warned.is_null());
        assert!(row(&app, "partner_certification", fresh).await["warned_on"].is_null());
        // Once: a second run leaves it as it was.
        attome_partner::certification::expiry_tick(&app.state)
            .await
            .unwrap();
        assert_eq!(
            row(&app, "partner_certification", expiring).await["warned_on"],
            warned
        );
    });
}
