//! D21-T13: the power dialer end to end on the throwaway database, with the
//! fake telephone: a list built from three leads, a claim that passes over
//! the one without consent and snoozes the one outside calling hours, a
//! call, an outcome whose rule changes the lead's status, and the calling
//! metric counting the call for the person who made it.
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-testapp --test dialer_flow"
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::dialer::build::{CallListRecord, SalesBuildListBody, build_list};
use attome_sales::dialer::claim::{SkipReason, claim_next};
use attome_sales::dialer::outcome::apply_rules;
use attome_sales::dialer::telephony::{DialRequest, FakeTelephony, dial};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

async fn install(app: &TestApp) {
    for pack in ["crm", "sales"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

/// A Wednesday, 10:00 UTC: 13:00 in Riyadh, 06:00 in New York.
fn now() -> DateTime<Utc> {
    "2026-10-21T10:00:00Z".parse().unwrap()
}

async fn lead(app: &TestApp, name: &str, phone: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO lead (name, phone, lead_status, is_active, row_version) \
         VALUES ($1, $2, 'new', true, 0) RETURNING id",
    )
    .bind(name)
    .bind(phone)
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// Sales calls need consent; `granted` holds it.
async fn consent(app: &TestApp, granted: &[Uuid]) {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_consent_purpose WHERE key = 'sales_calls' AND is_active IS NOT FALSE \
         LIMIT 1",
    )
    .fetch_optional(app.db())
    .await
    .unwrap();
    if existing.is_none() {
        sqlx::query(
            "INSERT INTO audit_consent_purpose (key, lawful_basis, is_active, row_version) \
             VALUES ('sales_calls', 'consent', true, 0)",
        )
        .execute(app.db())
        .await
        .unwrap();
    }
    // Every sales_calls purpose, so the one a claim reads is covered.
    for person in granted {
        sqlx::query(
            "INSERT INTO audit_consent (purpose_ref, regarding_entity, regarding_id, \
                 subject_reference, status, source, is_active, row_version) \
             SELECT id, 'lead', $1, $1, 'granted', 'manual', true, 0 \
               FROM audit_consent_purpose WHERE key = 'sales_calls' AND is_active IS NOT FALSE",
        )
        .bind(person.to_string())
        .execute(app.db())
        .await
        .unwrap();
    }
}

/// Riyadh any time; New York only in its office hours on Wednesdays.
async fn calling_hours(app: &TestApp) {
    for weekday in 1..=7_i32 {
        sqlx::query(
            "INSERT INTO calling_hours (country_code, weekday, start_local, end_local, is_active, \
                 row_version) VALUES ('SA', $1::int, '00:00', '23:59', true, 0)",
        )
        .bind(weekday)
        .execute(app.db())
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO calling_hours (country_code, weekday, start_local, end_local, is_active, \
             row_version) VALUES ('US', 3, '09:00', '17:00', true, 0)",
    )
    .execute(app.db())
    .await
    .unwrap();
}

struct Flow {
    list: Uuid,
    called: Uuid,
    no_consent: Uuid,
    out_of_hours: Uuid,
    skipped: Vec<(Uuid, SkipReason)>,
    member: Uuid,
}

/// Builds the list, sets its rule and claims the first callable member.
async fn build_and_claim(app: &TestApp) -> Flow {
    install(app).await;
    calling_hours(app).await;
    let no_consent = lead(app, "No consent", "+966500000002").await;
    let out_of_hours = lead(app, "New York", "+12125550100").await;
    let called = lead(app, "Callable", "+966500000001").await;
    consent(app, &[called, out_of_hours]).await;

    let list: Uuid = sqlx::query_scalar(
        "INSERT INTO call_list (name, source_kind, is_active, row_version) \
         VALUES ('Flow list', 'manual', true, 0) RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO call_outcome_rule (list_ref, outcome, set_lead_status, is_active, row_version) \
         VALUES ($1, 'not_interested', 'disqualified', true, 0)",
    )
    .bind(list)
    .execute(app.db())
    .await
    .unwrap();

    let ctx = app
        .state
        .base
        .security
        .resolve_strict(app.admin.id)
        .await
        .unwrap();
    let records = [no_consent, out_of_hours, called]
        .into_iter()
        .map(|record_id| CallListRecord {
            entity: "lead".into(),
            record_id,
        })
        .collect();
    let stats = build_list(&app.state, &ctx, list, &SalesBuildListBody { records })
        .await
        .unwrap();
    assert_eq!(stats.added, 3);

    let claimed = claim_next(&app.state, app.admin.id, list, now())
        .await
        .unwrap();
    let member = claimed.member.expect("a callable member");
    assert_eq!(member.record_id, called.to_string());
    Flow {
        list,
        called,
        no_consent,
        out_of_hours,
        skipped: claimed
            .skipped
            .iter()
            .map(|s| (s.member_id, s.reason))
            .collect(),
        member: member.member_id,
    }
}

async fn member_of(app: &TestApp, list: Uuid, record: Uuid) -> (Uuid, String, Option<String>) {
    sqlx::query_as(
        "SELECT id, member_status, skip_reason FROM call_list_member \
          WHERE list_ref = $1 AND record_id = $2",
    )
    .bind(list)
    .bind(record.to_string())
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: D21
#[test]
fn power_dialer_full_flow() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            eprintln!("skipped: no test database (DATABASE_URL unset)");
            return;
        };
        let flow = build_and_claim(&app).await;

        let (_, status, reason) = member_of(&app, flow.list, flow.no_consent).await;
        assert_eq!(
            (status.as_str(), reason.as_deref()),
            ("skipped", Some("no_consent"))
        );
        let (_, status, reason) = member_of(&app, flow.list, flow.out_of_hours).await;
        assert_eq!(
            (status.as_str(), reason.as_deref()),
            ("snoozed", Some("hours"))
        );

        // The call, through the fake telephone.
        let ctx = app
            .state
            .base
            .security
            .resolve_strict(app.admin.id)
            .await
            .unwrap();
        let telephone = FakeTelephony::default();
        let handle = dial(
            &app.state,
            &telephone,
            &ctx,
            flow.list,
            &DialRequest {
                to: "+966500000001".into(),
                entity_name: "lead".into(),
                record_id: flow.called,
            },
            &[],
        )
        .await
        .unwrap();
        assert_eq!(telephone.dialled.lock().unwrap().len(), 1);

        // The outcome, then its rule (the job the outcome queued).
        let (status, saved) = app
            .request(
                Method::POST,
                &format!("/api/v1/sales/call-list-members/{}/outcome", flow.member),
                Some(json!({
                    "outcome": "not_interested",
                    "duration_seconds": 42,
                    "activity_id": handle.activity_id.to_string(),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{saved}");
        assert_eq!(saved["member_status"], "done");
        let attempt = Uuid::parse_str(saved["attempt_id"].as_str().unwrap()).unwrap();
        apply_rules(&app.state, attempt).await.unwrap();
        let lead_status: String = sqlx::query_scalar("SELECT lead_status FROM lead WHERE id = $1")
            .bind(flow.called)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(lead_status, "disqualified");

        // The calling metric counts the call for the person who made it.
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs/sales/changesets/0022-sales-calling-metrics-caller.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let sql = doc["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["target"]["query"] == "Calling: Calls per Person per Day")
            .and_then(|op| op["args"]["definition"]["sql"].as_str())
            .unwrap()
            .to_owned();
        let rows: Vec<(Option<Uuid>, chrono::NaiveDate, i64)> =
            sqlx::query_as(&sql).fetch_all(app.db()).await.unwrap();
        assert!(
            rows.iter()
                .any(|(user, _, calls)| *user == Some(app.admin.id) && *calls >= 1),
            "a metrics row for the caller: {rows:?}"
        );
    });
}

// feature: D21
#[test]
fn skipped_number_is_audited() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            eprintln!("skipped: no test database (DATABASE_URL unset)");
            return;
        };
        let flow = build_and_claim(&app).await;
        assert_eq!(flow.skipped.len(), 2, "{:?}", flow.skipped);
        assert!(
            flow.skipped
                .iter()
                .any(|(_, r)| *r == SkipReason::NoConsent)
        );
        assert!(flow.skipped.iter().any(|(_, r)| *r == SkipReason::Hours));
        for (member, reason) in &flow.skipped {
            let events: i64 = sqlx::query_scalar(
                "SELECT (SELECT COUNT(*) FROM audit_header WHERE record_id = $1) \
                      + (SELECT COUNT(*) FROM audit_ingest WHERE payload->>'record_id' = $2)",
            )
            .bind(member)
            .bind(member.to_string())
            .fetch_one(app.db())
            .await
            .unwrap();
            assert_eq!(events, 1, "one audit event for the {reason:?} skip");
        }
    });
}
