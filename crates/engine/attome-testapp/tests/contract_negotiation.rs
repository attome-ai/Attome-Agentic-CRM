//! W1-T8: a counterparty review link shows one contract's current version
//! and what came through that link, takes a comment or a version, and
//! expires; a version they send is compared with the one before once its
//! scan is clean.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use base64::Engine as _;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde_json::{Value, json};
use uuid::Uuid;

const PACKS: [&str; 6] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
];

async fn install(app: &TestApp) {
    // The app registers the comparison job (W1-T7); this binary stands in.
    let _ = attome_core::jobs::JOB_TYPES.register(
        attome_jobs::JobType::new(attome_contract::compare::JOB, 1),
        |_state: attome_core::EngineState, _job: attome_jobs::RegisteredJob| async move {
            Ok::<(), attome_jobs::registry::BoxError>(())
        },
    );
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-contract")
        .await
        .expect("apply the contract platform definition");
    for pack in PACKS {
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
    let registry = attome_core::build_registry(&app.state.base.db)
        .await
        .expect("build the metadata registry");
    app.state.entities.swap(registry);
}

/// A draft contract titled `title` with a drafted version holding a file
/// (stored when `store`). Answers the contract and the version.
async fn contract(app: &TestApp, title: &str, store: bool) -> (Uuid, Uuid) {
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/contract",
            Some(json!({ "title": title, "counterparty": "Gulf Services Co", "contract_value": 50000 })),
        )
        .await;
    assert!(code.is_success(), "{code} {body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let version = Uuid::now_v7();
    let key = format!(
        "contract_version/{version}/file/{}-draft.pdf",
        Uuid::now_v7()
    );
    if store {
        app.state
            .base
            .storage
            .store()
            .put(
                &ObjectPath::parse(&key).unwrap(),
                b"%PDF-1.4 our draft".to_vec().into(),
            )
            .await
            .expect("store the drafted file");
    }
    sqlx::query(
        "INSERT INTO contract_version \
           (id, contract_id, source, version_no, file, created_by_ref, created_by, owner_ref) \
         VALUES ($1, $2, 'draft', 1, $3, $4, $4, $4)",
    )
    .bind(version)
    .bind(id.to_string())
    .bind(&key)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .unwrap();
    (id, version)
}

/// Shares `contract` for review; answers the link's id.
async fn share(app: &TestApp, contract: Uuid) -> Uuid {
    let (code, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/contract/contracts/{contract}/share-for-review"),
            Some(json!({ "email": "counsel@counterparty.example", "name": "Counsel" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    body["link_id"].as_str().unwrap().parse().unwrap()
}

fn token(app: &TestApp, link: Uuid) -> String {
    attome_contract::negotiation::token_for(
        &app.state,
        link,
        chrono::Utc::now() + chrono::Duration::days(14),
    )
    .unwrap()
}

// feature: W1
#[test]
fn expired_token_is_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (id, _) = contract(&app, "Supply agreement", false).await;
        let link = share(&app, id).await;
        let path = format!("/api/v1/contract/review/{}", token(&app, link));
        let (code, body) = app.request(Method::GET, &path, None).await;
        assert_eq!(code, StatusCode::OK, "{body}");

        // A token past its own expiry.
        let stale = attome_contract::negotiation::token_for(
            &app.state,
            link,
            chrono::Utc::now() - chrono::Duration::minutes(1),
        )
        .unwrap();
        let (code, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/contract/review/{stale}"),
                None,
            )
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND);

        // The round's own expiry.
        sqlx::query("UPDATE contract_review_link SET expires_at = now() - interval '1 minute' WHERE id = $1")
            .bind(link)
            .execute(app.db())
            .await
            .unwrap();
        let (code, _) = app.request(Method::GET, &path, None).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        let (code, _) = app
            .request(Method::POST, &path, Some(json!({ "comment": "late" })))
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    });
}

// feature: W1
#[test]
fn token_reveals_only_its_contract() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (ours, _) = contract(&app, "Facilities agreement", false).await;
        let (other, _) = contract(&app, "Undisclosed merger terms", false).await;
        let ours_link = share(&app, ours).await;
        let other_link = share(&app, other).await;
        let other_path = format!("/api/v1/contract/review/{}", token(&app, other_link));
        let (code, _) = app
            .request(
                Method::POST,
                &other_path,
                Some(json!({ "comment": "only for the other contract" })),
            )
            .await;
        assert_eq!(code, StatusCode::OK);

        let path = format!("/api/v1/contract/review/{}", token(&app, ours_link));
        let (code, view) = app.request(Method::GET, &path, None).await;
        assert_eq!(code, StatusCode::OK, "{view}");
        assert_eq!(view["contract_title"], "Facilities agreement");
        assert_eq!(view["round"], 1);
        assert!(view["entries"].as_array().unwrap().is_empty());
        let text = view.to_string();
        assert!(!text.contains("Undisclosed"), "{text}");
        assert!(!text.contains("only for the other"), "{text}");
        // Internal notes stay inside.
        assert!(!text.contains("Review round"), "{text}");

        // A new round closes the old link.
        share(&app, ours).await;
        let (code, _) = app.request(Method::GET, &path, None).await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    });
}

// feature: W1
#[test]
fn upload_creates_version_and_comparison() {
    // The tick logs why a version was not compared (a warning).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .with_test_writer()
        .try_init();
    attome_testkit::run_shared(async {
        if attome_testkit::s3_or_skip().is_none() {
            return;
        }
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (id, drafted) = contract(&app, "Services agreement", true).await;
        let link = share(&app, id).await;
        let path = format!("/api/v1/contract/review/{}", token(&app, link));
        let (code, done) = app
            .request(
                Method::POST,
                &path,
                Some(json!({
                    "comment": "Our changes to clause 7.",
                    "file_name": "services-v2.pdf",
                    "content_type": "application/pdf",
                    "content_base64": base64::engine::general_purpose::STANDARD
                        .encode(b"%PDF-1.4 their version"),
                })),
            )
            .await;
        assert_eq!(code, StatusCode::OK, "{done}");
        let version: Uuid = done["version_id"].as_str().unwrap().parse().unwrap();
        let source: String =
            sqlx::query_scalar("SELECT source::text FROM contract_version WHERE id = $1")
                .bind(version)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(source, "counterparty_upload");
        // A version ends the round.
        let (code, _) = app.request(Method::GET, &path, None).await;
        assert_eq!(code, StatusCode::NOT_FOUND);

        // Nothing is compared before the scan.
        assert_eq!(
            attome_contract::negotiation::tick(&app.state)
                .await
                .unwrap(),
            0
        );
        // The scan passes: the file is promoted to its final key.
        let (session, name): (Uuid, String) = sqlx::query_as(
            "SELECT session_id, file_name FROM contract_review_entry \
              WHERE link_id = $1 AND kind = 'upload'",
        )
        .bind(link)
        .fetch_one(app.db())
        .await
        .unwrap();
        let final_key =
            attome_document::files::final_key("contract_version", version, "file", session, &name);
        app.state
            .base
            .storage
            .store()
            .put(
                &ObjectPath::parse(&final_key).unwrap(),
                b"%PDF-1.4 their version".to_vec().into(),
            )
            .await
            .unwrap();
        sqlx::query("UPDATE upload_session SET status = 'clean', final_key = $2 WHERE id = $1")
            .bind(session)
            .bind(&final_key)
            .execute(app.db())
            .await
            .unwrap();
        assert_eq!(
            attome_contract::negotiation::tick(&app.state)
                .await
                .unwrap(),
            1
        );
        let compared: (String, String) = sqlx::query_as(
            "SELECT from_version_ref::text, to_version_ref::text FROM contract_comparison \
              WHERE contract_id = $1",
        )
        .bind(id.to_string())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(compared, (drafted.to_string(), version.to_string()));
        let file: Option<String> =
            sqlx::query_scalar("SELECT file FROM contract_version WHERE id = $1")
                .bind(version)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(file.as_deref(), Some(final_key.as_str()));
    });
}
