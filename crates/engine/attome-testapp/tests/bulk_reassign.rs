//! Q14-T5: bulk reassign and bulk share run as a batch job, with a preview
//! and progress. A reassign of 2,000 records goes in four chunks of 500, each
//! with one security event naming its records.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_security::admin::{BULK_ACCESS_JOB, BulkAccessPayload, run_bulk_access};
use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// An entity with `count` live records owned by `owner`.
async fn entity_owned_by(app: &TestApp, owner: Uuid, count: i64) -> String {
    let entity = format!("q14_bulk_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    // A test database: the rows are seeded directly, as fixtures are.
    sqlx::query(&format!(
        "INSERT INTO \"{entity}\" (owner_ref, owner_type) \
         SELECT $1, 0 FROM generate_series(1, $2)"
    ))
    .bind(owner)
    .bind(count)
    .execute(app.db())
    .await
    .expect("seed records");
    entity
}

/// The payload the route queued for `batch`, as the worker would read it:
/// the object in the queued job that holds `batch_id`.
async fn queued_payload(app: &TestApp, batch: Uuid) -> BulkAccessPayload {
    fn find(value: &serde_json::Value) -> Option<&serde_json::Value> {
        match value {
            serde_json::Value::Object(map) if map.contains_key("batch_id") => Some(value),
            serde_json::Value::Object(map) => map.values().find_map(find),
            serde_json::Value::Array(items) => items.iter().find_map(find),
            _ => None,
        }
    }
    let job: serde_json::Value =
        sqlx::query_scalar("SELECT job FROM apalis.jobs WHERE job::text LIKE '%' || $1 || '%'")
            .bind(batch.to_string())
            .fetch_one(app.db())
            .await
            .expect("the start queued one job");
    let payload = find(&job).expect("the job carries the payload").clone();
    serde_json::from_value(payload).expect("payload parses")
}

// feature: Q14
#[test]
fn bulk_reassign_of_2000_records_runs_in_chunks_with_progress() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // The binary registers the job; this test runs it itself.
        let _ = attome_core::jobs::JOB_TYPES.register(
            attome_jobs::JobType::new(BULK_ACCESS_JOB, 1),
            |_state: attome_core::EngineState, _job| async { Ok(()) },
        );
        let from = seed_user(app.db(), "q14-from").await;
        let to = seed_user(app.db(), "q14-to").await;
        let to_email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(to.id)
            .fetch_one(app.db())
            .await
            .unwrap();
        let from_email: String = sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(from.id)
            .fetch_one(app.db())
            .await
            .unwrap();
        let entity = entity_owned_by(&app, from.id, 2_000).await;
        let body = |preview: bool| {
            json!({
                "operation": "reassign", "entity": entity,
                "records": { "owner_email": from_email },
                "user_email": to_email, "preview": preview
            })
        };

        // Preview: the count and the first 50, nothing changed.
        let (status, preview) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/record-shares/bulk",
                Some(body(true)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["count"], 2_000);
        assert_eq!(preview["record_ids"].as_array().unwrap().len(), 50);
        let still: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{entity}\" WHERE owner_ref = $1"
        ))
        .bind(from.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(still, 2_000, "a preview changes nothing");

        // Start: a batch with the total, queued for the worker.
        let (status, started) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/record-shares/bulk",
                Some(body(false)),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{started}");
        assert_eq!(started["total"], 2_000);
        let batch = Uuid::parse_str(started["job_id"].as_str().unwrap()).unwrap();
        let (status, progress) = app
            .request(Method::GET, &format!("/api/v1/jobs/{batch}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{progress}");
        assert_eq!(progress["done"], 0);

        // The worker's run.
        let payload = queued_payload(&app, batch).await;
        run_bulk_access(&app.state, payload.clone())
            .await
            .expect("the batch runs");

        let moved: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{entity}\" WHERE owner_ref = $1"
        ))
        .bind(to.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(moved, 2_000);
        let shares: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM record_share s JOIN entity_info e ON e.id = s.entity_ref \
              WHERE e.logicalname = $1 AND s.principal_id = $2 AND s.capability = 1",
        )
        .bind(&entity)
        .bind(to.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(shares, 2_000, "the new owner gets an action share on each");

        let (_, progress) = app
            .request(Method::GET, &format!("/api/v1/jobs/{batch}"), None)
            .await;
        assert_eq!(progress["done"], 2_000, "{progress}");
        assert_eq!(progress["status"], "finished", "{progress}");

        // Security events are written to the ingest table first; the
        // chainer moves them on into the hash chain.
        let events: Vec<(Option<i32>, Option<String>)> = sqlx::query_as(
            "SELECT (payload->'extras'->>'occurrence_count')::int, payload->>'event_comment'                FROM audit_ingest WHERE payload->>'event_comment' LIKE '%' || $1 || '%'               ORDER BY created_at",
        )
        .bind(batch.to_string())
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(events.len(), 4, "one security event per chunk of 500");
        for (count, comment) in &events {
            assert_eq!(*count, Some(500));
            assert_eq!(comment.as_deref().unwrap().matches(',').count(), 499);
        }

        // A second run of the same job (a retry) changes nothing more.
        run_bulk_access(&app.state, payload)
            .await
            .expect("a repeat is safe");
        let after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_ingest               WHERE payload->>'event_comment' LIKE '%' || $1 || '%'",
        )
        .bind(batch.to_string())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(after, 4);
    })
}

// negative: POST /api/v1/admin/security/record-shares/bulk
#[test]
fn bulk_share_and_bad_requests() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let owner = seed_user(app.db(), "q14-owner").await;
        let reader = seed_user(app.db(), "q14-reader").await;
        let reader_email: String =
            sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
                .bind(reader.id)
                .fetch_one(app.db())
                .await
                .unwrap();
        let entity = entity_owned_by(&app, owner.id, 3).await;
        let ids: Vec<Uuid> =
            sqlx::query_scalar(&format!("SELECT id FROM \"{entity}\" ORDER BY id"))
                .fetch_all(app.db())
                .await
                .unwrap();

        let path = "/api/v1/admin/security/record-shares/bulk";
        let (status, body) = app
            .request(
                Method::POST,
                path,
                Some(json!({
                    "operation": "share", "entity": entity,
                    "records": { "record_ids": ids[..2] },
                    "user_email": reader_email, "capability": "view", "preview": true
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["count"], 2);

        for bad in [
            json!({ "operation": "share", "entity": entity, "records": { "record_ids": ids },
                     "user_email": reader_email }),
            json!({ "operation": "reassign", "entity": entity, "records": {},
                     "user_email": reader_email }),
            json!({ "operation": "reassign", "entity": entity,
                     "records": { "record_ids": ids, "owner_email": reader_email },
                     "user_email": reader_email }),
            json!({ "operation": "reassign", "entity": "no_such_entity",
                     "records": { "record_ids": ids }, "user_email": reader_email }),
        ] {
            let (status, body) = app.request(Method::POST, path, Some(bad)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        }

        // A non-administrator is refused.
        let (status, _) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                path,
                Some(json!({
                    "operation": "share", "entity": entity,
                    "records": { "record_ids": ids }, "user_email": reader_email,
                    "capability": "view", "preview": true
                })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
}
