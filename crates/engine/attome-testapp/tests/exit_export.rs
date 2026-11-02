//! Y5-T5: the clean-exit export builds one archive with the records, the
//! metadata, the audit log and a README, whose hash the API reports; a
//! deletion is asked for only with that hash, waits on two administrators,
//! and is asked for once. The deletion itself (which empties every table) is
//! not run here: this database is shared with the other test binaries.
//! Its own binary, so no other test starts an export beside it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::io::Read;

use attome_testapp::{TestApp, seed_admin};
use axum::http::{Method, StatusCode};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// feature: Y5
#[test]
fn export_then_delete_request() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // The app registers the job types; this binary stands in for it.
        let _ = attome_core::jobs::JOB_TYPES.register(
            attome_jobs::JobType::new(attome_api::exit::EXPORT_JOB, 1),
            |_state: attome_core::EngineState, _job: attome_jobs::RegisteredJob| async move {
                Ok::<(), attome_jobs::registry::BoxError>(())
            },
        );
        sqlx::query("INSERT INTO account (name, owner_ref) VALUES ('Exit Co', $1)")
            .bind(app.admin.id)
            .execute(app.db())
            .await
            .unwrap();

        let (status, body) = app
            .request(Method::POST, "/api/v1/admin/exit/export", None)
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(body["status"], "queued");
        let (busy, _) = app
            .request(Method::POST, "/api/v1/admin/exit/export", None)
            .await;
        assert_eq!(busy, StatusCode::CONFLICT, "one export at a time");

        assert_eq!(
            attome_api::exit::run_export(&app.state, id).await.unwrap(),
            "done"
        );
        let (status, done) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/exit/export/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["status"], "done");
        assert!(done["download_url"].as_str().is_some_and(|u| !u.is_empty()));
        let sha = done["sha256"].as_str().unwrap().to_owned();

        let key = ObjectPath::parse(attome_api::exit::archive_key(id)).unwrap();
        let bytes = app
            .state
            .base
            .storage
            .store()
            .get(&key)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            sha,
            "the reported hash"
        );
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec())).unwrap();
        let names: Vec<String> = archive.file_names().map(str::to_owned).collect();
        for needed in ["README.txt", "metadata/bundle.json", "data/account.csv"] {
            assert!(names.iter().any(|n| n == needed), "{needed} in {names:?}");
        }
        let mut accounts = String::new();
        archive
            .by_name("data/account.csv")
            .unwrap()
            .read_to_string(&mut accounts)
            .unwrap();
        assert!(accounts.contains("Exit Co"), "the account row is exported");

        // A deletion needs the archive's hash, and two other administrators.
        seed_admin(app.db()).await;
        seed_admin(app.db()).await;
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/exit/delete",
                Some(json!({ "export_id": id, "export_sha256": "00" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a wrong hash");
        let (status, asked) = app
            .request(
                Method::POST,
                "/api/v1/admin/exit/delete",
                Some(json!({ "export_id": id, "export_sha256": sha })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{asked}");
        assert_eq!(asked["approvals_needed"], 2);
        let approval: Uuid = asked["approval_id"].as_str().unwrap().parse().unwrap();
        let (action, state): (String, String) =
            sqlx::query_as("SELECT action_type, status::text FROM approval_request WHERE id = $1")
                .bind(approval)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(action, attome_api::exit::ACTION_DELETE);
        assert_ne!(state, "approved", "nothing is deleted until two approve");
        let (again, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/exit/delete",
                Some(json!({ "export_id": id, "export_sha256": sha })),
            )
            .await;
        assert_eq!(again, StatusCode::CONFLICT, "asked for once");
    });
}
