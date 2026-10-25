//! AB4-T6, AB4-T7 and AB4-T10 over HTTP: signed drill evidence is stored
//! once and never within retention deleted, the history pages one-based,
//! drill schedules change only with `If-Match` and move on when evidence
//! arrives, the auditor pack is a bounded export, and a person without the
//! ops privileges reaches none of it. The app here trusts one fixed drill
//! key (`ops.drill_public_keys`).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ops::evidence::{self, Evidence, EvidenceKind, SigningKey};
use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const SEED: [u8; 32] = [11; 32];

static APP: tokio::sync::OnceCell<Option<TestApp>> = tokio::sync::OnceCell::const_new();

async fn app() -> Option<TestApp> {
    APP.get_or_init(|| async {
        TestApp::start_with(|config| {
            config.ops.drill_public_keys =
                vec![evidence::public_key_base64(&SigningKey::from_bytes(&SEED))];
            // AB2-T8: a Patroni node is named (nothing listens there; no
            // test here lets a switchover run).
            config.ops.patroni_api_urls = vec!["http://127.0.0.1:9".into()];
        })
        .await
    })
    .await
    .clone()
}

fn report(kind: EvidenceKind, key: &SigningKey) -> Value {
    let at = chrono::Utc::now();
    let mut e = Evidence {
        schema: evidence::SCHEMA.into(),
        kind,
        drill_id: Uuid::now_v7(),
        started_at: at,
        finished_at: at,
        platform_version: "2.0.0".into(),
        image_digest: None,
        deployment_id: None,
        checks: Vec::new(),
        rpo_seconds: Some(60.0),
        rto_seconds: Some(120.0),
        data_size_bytes: Some(4096),
        restore_ok: true,
        provenance_ok: true,
        overall_ok: false,
        extra: serde_json::Map::new(),
    };
    e.compute_overall();
    serde_json::to_value(evidence::sign(&e, key).unwrap()).unwrap()
}

#[test]
fn upload_valid_evidence_is_stored_once() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let signed = report(EvidenceKind::Drain, &SigningKey::from_bytes(&SEED));
        let (status, first) = app
            .request(
                Method::POST,
                "/api/v1/ops/drills/evidence",
                Some(signed.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{first}");
        assert_eq!(first["created"], json!(true));
        let (status, again) = app
            .request(
                Method::POST,
                "/api/v1/ops/drills/evidence",
                Some(signed.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["id"], first["id"]);
        assert_eq!(again["created"], json!(false));

        let id = first["id"].as_str().unwrap();
        let (status, stored) = app
            .request(Method::GET, &format!("/api/v1/ops/drills/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored, signed);
    });
}

#[test]
fn upload_with_bad_signature_is_422() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let mut signed = report(EvidenceKind::Drain, &SigningKey::from_bytes(&SEED));
        signed["evidence"]["rto_seconds"] = json!(1.0);
        let (status, _) = app
            .request(Method::POST, "/api/v1/ops/drills/evidence", Some(signed))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let stranger = report(EvidenceKind::Drain, &SigningKey::from_bytes(&[12; 32]));
        let (status, _) = app
            .request(Method::POST, "/api/v1/ops/drills/evidence", Some(stranger))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

#[test]
fn delete_within_retention_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let signed = report(EvidenceKind::Drain, &SigningKey::from_bytes(&SEED));
        let (status, body) = app
            .request(Method::POST, "/api/v1/ops/drills/evidence", Some(signed))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
        let deleted = sqlx::query("DELETE FROM ops_drill_run WHERE id = $1")
            .bind(id)
            .execute(app.db())
            .await;
        assert!(deleted.is_err(), "a fresh drill run must not be deletable");
        let updated =
            sqlx::query("UPDATE ops_drill_run SET overall_ok = NOT overall_ok WHERE id = $1")
                .bind(id)
                .execute(app.db())
                .await;
        assert!(updated.is_err(), "a drill run is append-only");
    });
}

#[test]
fn history_is_paged_one_based() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let key = SigningKey::from_bytes(&SEED);
        for _ in 0..2 {
            let (status, _) = app
                .request(
                    Method::POST,
                    "/api/v1/ops/drills/evidence",
                    Some(report(EvidenceKind::Chaos, &key)),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let (status, page) = app
            .request(
                Method::GET,
                "/api/v1/ops/drills?kind=chaos&page=1&page_size=1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["page"], json!(1));
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert!(page["total"].as_i64().unwrap() >= 2);
        assert!(
            page["items"][0].get("evidence").is_none(),
            "the list carries no raw evidence"
        );
        let (status, _) = app
            .request(Method::GET, "/api/v1/ops/drills?kind=nonsense", None)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

#[test]
fn a_person_without_ops_privileges_reaches_nothing() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let user = seed_user(app.db(), "ops-none").await;
        let signed = report(EvidenceKind::Drain, &SigningKey::from_bytes(&SEED));
        for (method, path, body) in [
            (Method::POST, "/api/v1/ops/drills/evidence", Some(signed)),
            (Method::GET, "/api/v1/ops/drills", None),
            (Method::GET, "/api/v1/ops/drills/due", None),
            (Method::GET, "/api/v1/ops/drill-schedules", None),
            (
                Method::GET,
                "/api/v1/ops/drills/auditor-pack?from=2026-01-01&to=2026-01-31",
                None,
            ),
        ] {
            let (status, _) = app.request_as(&user.cookie, method, path, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        }
    });
}

#[test]
fn default_monthly_restore_is_seeded_disabled_and_upload_advances_next_due() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let (status, list) = app
            .request(Method::GET, "/api/v1/ops/drill-schedules", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let restore = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["kind"] == json!("restore"))
            .cloned()
            .expect("migration 0267 seeds the restore schedule");
        assert_eq!(restore["cadence"], json!("monthly"));
        let id = restore["id"].as_str().unwrap().to_owned();

        // No If-Match: refused.
        let (status, _) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/ops/drill-schedules/{id}"),
                Some(json!({"enabled": true})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Enabled with no due date: due now, so on the due list.
        let if_match = format!("\"{}\"", restore["row_version"].as_i64().unwrap());
        let (status, enabled) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/ops/drill-schedules/{id}"),
                &[("if-match", if_match.as_str())],
                Some(json!({"enabled": true, "next_due_at": chrono::Utc::now() - chrono::Duration::minutes(1)})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{enabled}");
        let (status, due) = app
            .request(Method::GET, "/api/v1/ops/drills/due", None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            due["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["id"] == json!(id))
        );

        // A stale version: conflict.
        let (status, _) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/ops/drill-schedules/{id}"),
                &[("if-match", if_match.as_str())],
                Some(json!({"cadence": "weekly"})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Restore evidence moves it on by a month.
        let (status, uploaded) = app
            .request(
                Method::POST,
                "/api/v1/ops/drills/evidence",
                Some(report(
                    EvidenceKind::Restore,
                    &SigningKey::from_bytes(&SEED),
                )),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{uploaded}");
        let (next_due, last_run): (chrono::DateTime<chrono::Utc>, Option<Uuid>) = sqlx::query_as(
            "SELECT next_due_at, last_run_id FROM ops_drill_schedule WHERE kind = 'restore'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(next_due > chrono::Utc::now() + chrono::Duration::days(20));
        assert!(last_run.is_some());
    });
}

#[test]
fn the_auditor_pack_is_bounded_to_400_days() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let (status, _) = app
            .request(
                Method::GET,
                "/api/v1/ops/drills/auditor-pack?from=2025-01-01&to=2026-03-01",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let today = chrono::Utc::now().date_naive();
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/ops/drills/auditor-pack?from={today}&to={today}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    });
}

/// The Operations role a switchover waits on, with one member who is not
/// the administrator.
async fn operations_role(app: &TestApp) {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM role WHERE name = 'Operations' AND is_deleted = false LIMIT 1",
    )
    .fetch_optional(app.db())
    .await
    .unwrap();
    if existing.is_some() {
        return;
    }
    let role = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer)          VALUES ($1, 'Operations', 'ops approvers', 'project')",
    )
    .bind(role)
    .execute(app.db())
    .await
    .unwrap();
    let member = seed_user(app.db(), "operations").await;
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(member.id)
        .bind(role)
        .execute(app.db())
        .await
        .unwrap();
}

#[test]
fn request_creates_pending_approval_and_no_patroni_call() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/ops/cluster/switchover",
                Some(json!({"reason": "too short"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        operations_role(&app).await;
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/ops/cluster/switchover",
                Some(json!({"candidate": "db2", "reason": "planned kernel patching"})),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let approval = Uuid::parse_str(body["approval_id"].as_str().unwrap()).unwrap();
        let (action, state): (String, String) =
            sqlx::query_as("SELECT action_type, status::text FROM approval_request WHERE id = $1")
                .bind(approval)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(action, "ops.switchover");
        assert_eq!(state, "pending");
        let switched: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ops_failover_event WHERE kind = 'switchover'")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(switched, 0, "nothing moves before a second person approves");
    });
}

#[test]
fn self_approval_is_refused() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        operations_role(&app).await;
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/ops/cluster/switchover",
                Some(json!({"reason": "planned failover rehearsal"})),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let approval = body["approval_id"].as_str().unwrap().to_owned();
        let version: i64 =
            sqlx::query_scalar("SELECT row_version FROM approval_request WHERE id = $1")
                .bind(Uuid::parse_str(&approval).unwrap())
                .fetch_one(app.db())
                .await
                .unwrap();
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/approvals/{approval}/decide"),
                Some(json!({"decision": "approve", "row_version": version})),
            )
            .await;
        assert!(
            !status.is_success(),
            "the requester decided their own switchover: {status}"
        );
        let state: String =
            sqlx::query_scalar("SELECT status::text FROM approval_request WHERE id = $1")
                .bind(Uuid::parse_str(&approval).unwrap())
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(state, "pending");
    });
}

#[test]
fn non_ops_user_gets_403() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let user = seed_user(app.db(), "ops-cluster-none").await;
        for path in ["/api/v1/ops/cluster", "/api/v1/ops/failovers"] {
            let (status, _) = app.request_as(&user.cookie, Method::GET, path, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        }
        let (status, _) = app
            .request_as(
                &user.cookie,
                Method::POST,
                "/api/v1/ops/cluster/switchover",
                Some(json!({"reason": "planned kernel patching"})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // The administrator sees a configured cluster that does not answer
        // as `ha` with no leader, never an error.
        let (status, cluster) = app.request(Method::GET, "/api/v1/ops/cluster", None).await;
        assert_eq!(status, StatusCode::OK, "{cluster}");
        assert_eq!(cluster["mode"], json!("ha"));
    });
}

#[test]
fn failovers_are_paged_one_based() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        for n in 0..2 {
            sqlx::query(
                "INSERT INTO ops_failover_event (id, kind, old_leader, new_leader, timeline, started_at)                  VALUES ($1, 'failover', 'db1', $2, $3, now())",
            )
            .bind(Uuid::now_v7())
            .bind(format!("db-{}", Uuid::now_v7()))
            .bind(i64::from(n))
            .execute(app.db())
            .await
            .unwrap();
        }
        let (status, page) = app
            .request(
                Method::GET,
                "/api/v1/ops/failovers?page=1&page_size=1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(page["page"], json!(1));
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert!(page["total"].as_i64().unwrap() >= 2);
    });
}

#[test]
fn freshness_turns_fresh_after_a_passing_upload() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        let (status, uploaded) = app
            .request(
                Method::POST,
                "/api/v1/ops/drills/evidence",
                Some(report(
                    EvidenceKind::Secrets,
                    &SigningKey::from_bytes(&SEED),
                )),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{uploaded}");
        let (status, page) = app
            .request(Method::GET, "/api/v1/ops/drills/freshness", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let secrets = page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["kind"] == json!("secrets"))
            .cloned()
            .unwrap();
        assert_eq!(secrets["status"], json!("fresh"));
        assert_eq!(page["items"].as_array().unwrap().len(), 7);
    });
}

async fn target(app: &TestApp, profile: &str, scenario: &str) -> Value {
    let (status, page) = app
        .request(
            Method::GET,
            &format!("/api/v1/ops/recovery-targets?profile={profile}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["scenario"] == json!(scenario))
        .cloned()
        .expect("migration 0268 seeds every profile and scenario")
}

#[test]
fn seeded_targets_are_not_proven_without_evidence() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        // No test here uploads failover evidence.
        let ha = target(&app, "ha", "node_loss").await;
        assert_eq!(ha["evidence_kind"], json!("failover"));
        assert_eq!(ha["rpo_seconds"], json!(0));
        assert_eq!(ha["proven"], json!(false));
        let (status, _) = app
            .request(
                Method::GET,
                "/api/v1/ops/recovery-targets?profile=huge",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

#[test]
fn fresh_recovery_evidence_within_target_marks_proven_and_over_target_does_not() {
    attome_testkit::run_shared(async {
        let Some(app) = app().await else {
            return;
        };
        // RPO 60 s and RTO 120 s, within solo corruption's 300 s / 3600 s.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/ops/drills/evidence",
                Some(report(
                    EvidenceKind::Recovery,
                    &SigningKey::from_bytes(&SEED),
                )),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let corruption = target(&app, "solo", "corruption").await;
        assert_eq!(corruption["proven"], json!(true), "{corruption}");
        assert!(corruption["proven_on"].is_string());

        // Tighten team ransomware below the measured 60 s: no longer proven.
        let ransomware = target(&app, "team", "ransomware").await;
        let id = ransomware["id"].as_str().unwrap();
        let (status, _) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/ops/recovery-targets/{id}"),
                Some(json!({"rpo_seconds": 10})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "If-Match is required"
        );
        let if_match = format!("\"{}\"", ransomware["row_version"].as_i64().unwrap());
        let (status, changed) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/ops/recovery-targets/{id}"),
                &[("if-match", if_match.as_str())],
                Some(json!({"rpo_seconds": 10})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{changed}");
        assert_eq!(changed["rpo_seconds"], json!(10));
        assert_eq!(changed["proven"], json!(false));
    });
}
