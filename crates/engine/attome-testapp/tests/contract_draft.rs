//! W1-T6: drafting a contract adds version 1 and attaches the rendered
//! document to it; a field the requester cannot read renders empty.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser};
use axum::http::{Method, StatusCode};
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 6] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
];

const BODY: &str = "<h1>{{ title }}</h1><p>Value: {{ contract_value }}</p>\
    {% for c in contract_clause limit 20 %}<p>{{ c.title }}</p>{% endfor %}";

async fn install(app: &TestApp) {
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
}

async fn user_with_role(app: &TestApp, label: &str, role: &str) -> TestUser {
    let user = attome_testapp::seed_user(app.db(), label).await;
    let role: Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(role)
            .fetch_one(app.db())
            .await
            .unwrap_or_else(|e| panic!("role {role}: {e}"));
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role)
        .execute(app.db())
        .await
        .expect("grant role");
    user
}

/// A template, a type that drafts with it, and a contract of that type with
/// one chosen clause.
async fn fixture(app: &TestApp) -> Uuid {
    let template: Uuid = sqlx::query_scalar(
        "INSERT INTO docgen_template (name, entity, format, body, is_active, row_version) \
         VALUES ('Contract draft', 'contract', 'docx', $1, true, 0) RETURNING id",
    )
    .bind(BODY)
    .fetch_one(app.db())
    .await
    .unwrap();
    let kind: Uuid = sqlx::query_scalar(
        "INSERT INTO contract_type (name, draft_template_ref, is_active, row_version) \
         VALUES ('Supply', $1, true, 0) RETURNING id",
    )
    .bind(template)
    .fetch_one(app.db())
    .await
    .unwrap();
    let contract: Uuid = sqlx::query_scalar(
        "INSERT INTO contract (title, contract_type_ref, contract_value, language, \
             is_confidential, status, is_active, row_version) \
         VALUES ('Cement supply 2027', $1, 777123, 'en', false, 'draft', true, 0) RETURNING id",
    )
    .bind(kind)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO contract_clause (contract_ref, title, body_html, position, is_active, \
             row_version) \
         VALUES ($1, 'Delivery terms', '<p>Ex works</p>', 1, true, 0)",
    )
    .bind(contract)
    .execute(app.db())
    .await
    .unwrap();
    contract
}

// feature: W1
#[test]
fn draft_creates_version_one() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let contract = fixture(&app).await;
        let manager = user_with_role(&app, "drafter", "Contract Manager").await;

        let (status, body) = app
            .request_as(
                &manager.cookie,
                Method::POST,
                &format!("/api/v1/contract/contracts/{contract}/draft"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["version_no"], 1, "{body}");
        let version: Uuid = body["version_id"].as_str().unwrap().parse().unwrap();
        let render: Uuid = body["render_id"].as_str().unwrap().parse().unwrap();

        // The worker's job, run here.
        attome_docgen::render::process(&app.state, render)
            .await
            .unwrap();
        let (status, attached): (String, bool) =
            sqlx::query_as("SELECT status, attached FROM docgen_render WHERE id = $1")
                .bind(render)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "completed");
        assert!(attached, "the draft is attached to the version");
        let (contract_id, source, file): (String, String, Option<String>) = sqlx::query_as(
            "SELECT contract_id, source, file::text FROM contract_version WHERE id = $1",
        )
        .bind(version)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(contract_id, contract.to_string());
        assert_eq!(source, "draft");
        assert!(
            file.is_some_and(|f| !f.is_empty()),
            "the version has its file"
        );
    });
}

// feature: W1
#[test]
fn hidden_field_not_rendered() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let contract = fixture(&app).await;
        let viewer = user_with_role(&app, "reader", "Contract Viewer").await;
        let legal = user_with_role(&app, "counsel", "Legal").await;

        let render_as = |user: Uuid| {
            let state = app.state.clone();
            async move {
                let security = attome_security::resolve_uncached(&state.base.db, user)
                    .await
                    .unwrap();
                let input = attome_docgen::document_render::build_input(
                    &state, &security, "contract", contract, BODY,
                )
                .await
                .unwrap();
                attome_docgen::document_render::render_document(BODY, input, "en").unwrap()
            }
        };
        let seen_by_viewer = render_as(viewer.id).await;
        assert!(
            seen_by_viewer.contains("Cement supply 2027"),
            "{seen_by_viewer}"
        );
        assert!(
            seen_by_viewer.contains("Delivery terms"),
            "{seen_by_viewer}"
        );
        assert!(
            !seen_by_viewer.contains("777"),
            "the value is outside the viewer's profile: {seen_by_viewer}"
        );
        let seen_by_legal = render_as(legal.id).await;
        assert!(seen_by_legal.contains("777"), "{seen_by_legal}");
    });
}
