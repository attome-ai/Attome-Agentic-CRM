//! Y10-T5: an extension is uploaded as numbered versions, one is published
//! at a time (publishing an older one rolls back), and switching it off
//! stops every version at once.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine;
use serde_json::json;
use uuid::Uuid;

const MODULE: &str = r#"(module (func (export "run") (param i32) (result i32) (local.get 0)))"#;

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
}

// feature: Y10
// op: upload_extension
// op: publish_extension
// op: switch_off_extension
// op: list_extension_runs
// op: test_extension
#[test]
fn extensions_version_publish_roll_back_and_switch_off() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let name = format!("ext_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let manifest =
            json!({ "entities": { "account": { "read": true } }, "hosts": ["api.erp.example"] });

        // A module that does not compile, and bad grants, are refused.
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions",
                Some(
                    json!({ "name": name, "module_base64": b64("not wasm"), "manifest": manifest }),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions",
                Some(json!({ "name": name, "module_base64": b64(MODULE), "manifest": { "hosts": ["*.example"] } })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        for expected in [1, 2] {
            let (status, body) = app
                .request(
                    Method::POST,
                    "/api/v1/admin/extensions",
                    Some(
                        json!({ "name": name, "module_base64": b64(MODULE), "manifest": manifest }),
                    ),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(body["version"], expected);
            assert_eq!(body["status"], "draft");
        }

        let publish = |v: i32| format!("/api/v1/admin/extensions/{name}/versions/{v}/publish");
        let (status, body) = app.request(Method::POST, &publish(2), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            attome_api::extension_admin::published(app.db(), &name)
                .await
                .unwrap()
                .map(|v| v.version),
            Some(2)
        );
        // Roll back to 1: 2 is superseded.
        let (status, _) = app.request(Method::POST, &publish(1), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            attome_api::extension_admin::published(app.db(), &name)
                .await
                .unwrap()
                .map(|v| v.version),
            Some(1)
        );
        let (status, _) = app.request(Method::POST, &publish(9), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Off: nothing runs.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/off"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            attome_api::extension_admin::published(app.db(), &name)
                .await
                .unwrap()
                .is_none()
        );
        let statuses: Vec<String> =
            sqlx::query_scalar("SELECT status FROM extension WHERE name = $1 ORDER BY version")
                .bind(&name)
                .fetch_all(app.db())
                .await
                .unwrap();
        assert_eq!(statuses, vec!["off".to_owned(), "off".to_owned()]);

        // Y10-T6: a run is logged with its cost and its lines masked.
        attome_api::extension_admin::record_run(
            app.db(),
            &name,
            1,
            attome_extension::CallCost {
                fuel_used: 1234,
                elapsed: std::time::Duration::from_millis(7),
            },
            None,
            &[(
                attome_extension::Level::Info,
                "called ERP with key s3cr3t-value".to_owned(),
            )],
            &["s3cr3t-value"],
            true,
        )
        .await
        .unwrap();
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/extensions/{name}/runs"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let run = &body["items"][0];
        assert_eq!(run["fuel_used"], 1234);
        assert_eq!(run["ok"], true);
        assert_eq!(run["logs"][0]["message"], "called ERP with key ***");
    });
}

/// Answers `{"change":{"name":"Set by wasm"}}` (33 bytes at 0).
const CHANGES_NAME: &str = r#"(module
    (memory (export "memory") 1)
    (data (i32.const 0) "{\"change\":{\"name\":\"Set by wasm\"}}")
    (func (export "alloc") (param i32) (result i32) (i32.const 1024))
    (func (export "on_record") (param i32 i32) (result i64) (i64.const 33)))"#;

/// Answers `{"reject":"wasm says no"}` (25 bytes at 0).
const REJECTS: &str = r#"(module
    (memory (export "memory") 1)
    (data (i32.const 0) "{\"reject\":\"wasm says no\"}")
    (func (export "alloc") (param i32) (result i32) (i32.const 1024))
    (func (export "on_record") (param i32 i32) (result i64) (i64.const 25)))"#;

async fn create_account(
    state: &attome_core::EngineState,
    ctx: &attome_server::security::SecurityContext,
    admin: Uuid,
    label: String,
) -> Result<Uuid, attome_types::AppError> {
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        admin,
        "account",
        json!({ "name": label }),
    )
    .await
    .map(|(id, _)| id)
}

async fn account_name(db: &attome_db::DbPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT name FROM account WHERE id = $1")
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
}

// feature: Y10
#[test]
fn published_extensions_run_at_their_hook_stage() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let name = format!("hook_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let manifest = json!({
            "entities": { "account": { "read": true, "write": true, "attributes": ["name"] } },
            "hooks": [{ "entity": "account", "stage": "before_save" }]
        });
        let upload_and_publish = |module: &'static str, version: i32| {
            let app = &app;
            let name = name.clone();
            let manifest = manifest.clone();
            async move {
                let (status, body) = app
                    .request(
                        Method::POST,
                        "/api/v1/admin/extensions",
                        Some(json!({ "name": name, "module_base64": b64(module), "manifest": manifest })),
                    )
                    .await;
                assert_eq!(status, StatusCode::CREATED, "{body}");
                let (status, body) = app
                    .request(
                        Method::POST,
                        &format!("/api/v1/admin/extensions/{name}/versions/{version}/publish"),
                        None,
                    )
                    .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                assert!(
                    attome_api::extension_hooks::refresh(&app.state)
                        .await
                        .unwrap()
                        >= 1
                );
            }
        };

        let mut state = app.state.clone();
        state.record_hooks = std::sync::Arc::new(
            attome_api::extension_hooks::ExtensionHooks::all()
                .into_iter()
                .map(|h| {
                    std::sync::Arc::new(h)
                        as std::sync::Arc<dyn attome_core::record_hooks::RecordHook>
                })
                .collect(),
        );
        let ctx = state
            .base
            .security
            .resolve(app.admin.id)
            .await
            .expect("ctx");

        // Version 1 changes the name before the save.
        upload_and_publish(CHANGES_NAME, 1).await;
        let id = create_account(&state, &ctx, app.admin.id, format!("Typed {name}"))
            .await
            .expect("a changed create");
        assert_eq!(account_name(app.db(), id).await, "Set by wasm");
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/extensions/{name}/runs"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["items"][0]["ok"], true, "the run is logged");

        // Y10-T6: a sample run saves nothing and is logged as a test.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/versions/1/test"),
                Some(json!({ "samples": [
                    { "stage": "before_save", "entity": "account", "is_create": true,
                      "values": { "name": "Sample" } }
                ] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["items"][0]["answer"]["change"]["name"], "Set by wasm");
        let tests: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM extension_run WHERE extension_name = $1 AND is_test",
        )
        .bind(&name)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(tests, 1);
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/versions/1/test"),
                Some(json!({ "samples": [] })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Version 2 refuses the save with its message.
        upload_and_publish(REJECTS, 2).await;
        let refused = create_account(&state, &ctx, app.admin.id, format!("Refused {name}")).await;
        assert!(
            matches!(&refused, Err(attome_types::AppError::Validation(m)) if m == "wasm says no"),
            "{refused:?}"
        );

        // Off is immediate, before any refresh.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/off"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let id = create_account(&state, &ctx, app.admin.id, format!("Free {name}"))
            .await
            .expect("no extension runs");
        assert_eq!(account_name(app.db(), id).await, format!("Free {name}"));
    });
}

/// Answers `{"records":[{"entity":"account","values":{"name":"From a job"}}]}`
/// (65 bytes at 0) from `on_job`.
const JOB_CREATES_ACCOUNT: &str = r#"(module
    (memory (export "memory") 1)
    (data (i32.const 0) "{\"records\":[{\"entity\":\"account\",\"values\":{\"name\":\"From a job\"}}]}")
    (func (export "alloc") (param i32) (result i32) (i32.const 1024))
    (func (export "on_job") (param i32 i32) (result i64) (i64.const 65)))"#;

// feature: M17
// op: queue_extension_job
#[test]
fn a_job_extension_writes_what_it_answers_as_the_caller() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let name = format!("job_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let upload = |manifest: serde_json::Value| {
            let app = &app;
            let name = name.clone();
            async move {
                app.request(
                    Method::POST,
                    "/api/v1/admin/extensions",
                    Some(json!({ "name": name, "module_base64": b64(JOB_CREATES_ACCOUNT), "manifest": manifest })),
                )
                .await
            }
        };
        // Version 1 may only read accounts: its write is refused.
        let (status, _) = upload(json!({ "entities": { "account": { "read": true } } })).await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/versions/1/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let refused = attome_api::extension_kinds::run_kind(
            &app.state,
            &name,
            attome_api::extension_kinds::JOB_EXPORT,
            app.admin.id,
            &json!({ "kind": "job", "input": {} }),
        )
        .await;
        assert!(
            matches!(&refused, Err(attome_types::AppError::Validation(m)) if m.contains("may not write account")),
            "{refused:?}"
        );

        // Version 2 may write account names: the account is created as the caller.
        let (status, _) = upload(
            json!({ "entities": { "account": { "read": true, "write": true, "attributes": ["name"] } } }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/versions/2/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let written = attome_api::extension_kinds::run_kind(
            &app.state,
            &name,
            attome_api::extension_kinds::JOB_EXPORT,
            app.admin.id,
            &json!({ "kind": "job", "input": {} }),
        )
        .await
        .unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(account_name(app.db(), written[0]).await, "From a job");
        let runs: i64 =
            sqlx::query_scalar("SELECT count(*) FROM extension_run WHERE extension_name = $1")
                .bind(&name)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(runs, 2, "both runs are logged");

        // Queued through the route; an unknown extension is a 404.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/jobs"),
                Some(json!({ "input": { "since": "2026-11-01" } })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions/no_such_extension/jobs",
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// feature: M17
#[test]
fn a_scheduled_job_extension_is_claimed_through_the_schedule_ledger() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        app.install_packs(&["crm"]).await;
        let name = format!("sched_{}", &Uuid::now_v7().simple().to_string()[24..]);
        let manifest = |cron: &str| {
            json!({
                "entities": { "account": { "read": true, "write": true, "attributes": ["name"] } },
                "schedule": { "cron": cron, "timezone": "Asia/Riyadh", "input": { "since": "yesterday" } }
            })
        };
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions",
                Some(json!({ "name": name, "module_base64": b64(JOB_CREATES_ACCOUNT), "manifest": manifest("not a cron") })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/extensions",
                Some(json!({ "name": name, "module_base64": b64(JOB_CREATES_ACCOUNT), "manifest": manifest("0 6 * * *") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/extensions/{name}/versions/1/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);

        attome_api::extension_kinds::sweep_schedules(&app.state)
            .await
            .unwrap();
        let ledger: i64 = sqlx::query_scalar("SELECT count(*) FROM job_schedule WHERE name = $1")
            .bind(format!("extension:{name}"))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(ledger, 1, "the extension's schedule has its ledger row");
        // A second sweep in the same slot queues nothing more.
        assert_eq!(
            attome_api::extension_kinds::sweep_schedules(&app.state)
                .await
                .unwrap(),
            0
        );
    });
}
