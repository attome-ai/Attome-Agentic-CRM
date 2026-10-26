//! A23-T4: validating a staged import is a dry run: mapping, type
//! conversion, lookups by name, matching existing records, duplicates inside
//! the file, and counts, with no entity row written.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_document::import_stage::{header_names, stage_rows};
use attome_records::import_validate::{ValidateCounts, validate};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

fn uniq(prefix: &str) -> String {
    format!("{prefix}_{}", &Uuid::now_v7().simple().to_string()[..12])
}

async fn entity(app: &TestApp, fields: &[Value]) -> (String, String) {
    let name = uniq("iv");
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    for field in fields {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(field.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    (name, id)
}

async fn record(app: &TestApp, entity: &str, body: Value) {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
}

/// Accounts `Acme`, `Beta` and two named `Twin`; a contact entity with a
/// title, a level and an account lookup, holding one contact `existing`.
/// Returns the contact entity's name.
async fn fixture(app: &TestApp) -> String {
    let text = |n: &str| json!({ "logicalname": n, "name": n, "field_type": "text" });
    let (accounts, account_id) = entity(app, &[text("title"), text("code")]).await;
    for (title, code) in [
        ("Acme", "A1"),
        ("Beta", "B1"),
        ("Twin", "T1"),
        ("Twin", "T2"),
    ] {
        record(app, &accounts, json!({ "title": title, "code": code })).await;
    }
    let (contacts, _) = entity(
        app,
        &[
            text("title"),
            json!({ "logicalname": "level", "name": "level", "field_type": "number" }),
            json!({ "logicalname": "account", "name": "account", "field_type": "lookup",
                    "lookup_entity_ref": account_id }),
        ],
    )
    .await;
    record(app, &contacts, json!({ "title": "existing", "level": 1 })).await;
    contacts
}

/// Stages `rows` (Name, Level, Account, Note) as a staged upsert job over
/// `entity` matched by title.
async fn staged_job(app: &TestApp, entity: &str, rows: &[[&str; 4]]) -> Uuid {
    let id = Uuid::now_v7();
    let mapping = json!({
        "columns": [
            {"source": "Name", "target": "title"},
            {"source": "Level", "target": "level"},
            {"source": "Account", "target": "account"},
            {"source": "Note", "skip": true},
        ],
        "lookups": {"account": {"by": "name", "field": "title"}},
    });
    sqlx::query(
        "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                 mapping, match_mode, match_columns, status, created_by) \
         VALUES ($1, $2, 'imports/test.csv', 'test.csv', $3, $4, 'upsert', '{title}', \
                 'staged', $5)",
    )
    .bind(id)
    .bind(entity)
    .bind(id.to_string())
    .bind(mapping)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .expect("insert an import job");
    let names = header_names(&[
        "Name".into(),
        "Level".into(),
        "Account".into(),
        "Note".into(),
    ]);
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| (*c).to_owned()).collect())
        .collect();
    stage_rows(app.db(), id, &names, &rows, 1_000, None)
        .await
        .expect("stage the rows");
    id
}

const ROWS: [[&str; 4]; 6] = [
    ["new one", "3", "Acme", "first"],
    ["existing", "٥", "Beta", ""],
    ["twin ref", "", "Twin", ""],
    ["missing ref", "", "Nope", ""],
    ["new one", "4", "Acme", "again"],
    ["bad level", "x", "", ""],
];

async fn stage_row(
    app: &TestApp,
    job: Uuid,
    row_no: i32,
) -> (String, Option<String>, Value, Value) {
    sqlx::query_as(
        "SELECT status, action, COALESCE(mapped, 'null'::jsonb), COALESCE(error, 'null'::jsonb) \
           FROM import_stage WHERE job_id = $1 AND row_no = $2",
    )
    .bind(job)
    .bind(row_no)
    .fetch_one(app.db())
    .await
    .expect("read a staged row")
}

fn codes(error: &Value) -> Vec<String> {
    error["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .map(|e| e["code"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn count(app: &TestApp, entity: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM \"{entity}\""))
        .fetch_one(app.db())
        .await
        .expect("count the records")
}

// feature: A23
#[test]
fn dry_run_writes_no_records() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let contacts = fixture(&app).await;
        let before = count(&app, &contacts).await;
        let job = staged_job(&app, &contacts, &ROWS).await;
        let counts = validate(&app.state, job).await.expect("validate");
        assert_eq!(
            counts,
            ValidateCounts {
                create: 2,
                update: 1,
                skip: 0,
                invalid: 3,
                duplicates: 1,
            }
        );
        assert_eq!(
            count(&app, &contacts).await,
            before,
            "a dry run writes nothing"
        );
        let (status, stored): (String, Value) =
            sqlx::query_as("SELECT status, counts FROM import_job WHERE id = $1")
                .bind(job)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "validated");
        assert_eq!(stored["create"], 2, "{stored}");
        // A rerun recomputes the same answer.
        assert_eq!(validate(&app.state, job).await.expect("revalidate"), counts);
        // The second row matched the existing record, with Arabic digits read.
        let (status, action, mapped, _) = stage_row(&app, job, 2).await;
        assert_eq!(
            (status.as_str(), action.as_deref()),
            ("valid", Some("update"))
        );
        assert_eq!(mapped["level"], 5.0, "{mapped}");
        let (status, _, _, error) = stage_row(&app, job, 6).await;
        assert_eq!(status, "invalid");
        assert_eq!(codes(&error), ["invalid_number"], "{error}");
    });
}

// feature: A23
#[test]
fn lookup_by_name_resolves() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let contacts = fixture(&app).await;
        let job = staged_job(&app, &contacts, &ROWS).await;
        validate(&app.state, job).await.expect("validate");
        let (status, action, mapped, _) = stage_row(&app, job, 1).await;
        assert_eq!(
            (status.as_str(), action.as_deref()),
            ("valid", Some("create"))
        );
        let account = mapped["account"]
            .as_str()
            .expect("the lookup resolved to an id");
        assert!(Uuid::parse_str(account).is_ok(), "{mapped}");
        assert!(mapped.get("Note").is_none(), "a skipped column is dropped");
        let (_, _, missing, error) = stage_row(&app, job, 4).await;
        assert_eq!(codes(&error), ["missing_lookup"], "{error}");
        assert!(missing.get("account").is_none(), "{missing}");
    });
}

// feature: A23
#[test]
fn ambiguous_lookup_reported() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let contacts = fixture(&app).await;
        let job = staged_job(&app, &contacts, &ROWS).await;
        validate(&app.state, job).await.expect("validate");
        let (status, action, _, error) = stage_row(&app, job, 3).await;
        assert_eq!(status, "invalid");
        assert_eq!(action, None);
        assert_eq!(codes(&error), ["ambiguous_lookup"], "{error}");
        assert_eq!(error["errors"][0]["field"], "account", "{error}");
        assert_eq!(
            error["errors"][0]["message_key"], "import.error.ambiguous_lookup",
            "{error}"
        );
    });
}

// feature: A23
#[test]
fn duplicate_inside_file_reported() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let contacts = fixture(&app).await;
        let job = staged_job(&app, &contacts, &ROWS).await;
        validate(&app.state, job).await.expect("validate");
        let (status, _, _, error) = stage_row(&app, job, 5).await;
        assert_eq!(status, "valid", "a repeat is reported, not refused");
        assert_eq!(error["duplicate_of_row"], 1, "{error}");
        let (_, _, _, first) = stage_row(&app, job, 1).await;
        assert!(first.is_null(), "the first occurrence is clean: {first}");
    });
}
