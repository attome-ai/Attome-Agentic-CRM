//! E7-T8: a marketing list's wide access. A user without
//! `marketing_list.grant_wide_access` is refused the change, an
//! administrator's grant is an Access security event, and a list with wide
//! access refreshes as the configured marketing user, refusing when none is
//! set. One test: `marketing.segment_user` is deployment-wide.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::record_check::{RecordCheck, RecordSave};
use attome_marketing::segment_access::{SEGMENT_USER_SETTING, WideAccessCheck, refresh_context};
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn install(app: &TestApp) {
    for pack in ["crm", "marketing"] {
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
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

/// The list's wide-access events: the chained ones, and those captured
/// past the last chained batch (a chained event stays in `audit_ingest`
/// until it is pruned, so it is counted once, from the header).
async fn events(app: &TestApp, list: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name FROM ( \
             SELECT payload::jsonb ->> 'event_name' AS name, \
                    payload::jsonb ->> 'record_id' AS rid \
             FROM audit_ingest i \
             WHERE i.id > COALESCE(( \
                 SELECT b.last_ingest_id FROM audit_chain_batch b \
                  WHERE b.organization_ref = i.organization_ref \
                  ORDER BY b.id DESC LIMIT 1 \
             ), '00000000-0000-0000-0000-000000000000'::uuid) \
             UNION ALL \
             SELECT event_name, record_id::text FROM audit_header \
         ) e WHERE rid = $1 AND name LIKE 'marketing_list.wide_access%' ORDER BY name",
    )
    .bind(list.to_string())
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: E7
#[test]
fn non_admin_cannot_grant_wide_access() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/marketing_list",
                Some(json!({ "name": format!("e7-t8 {}", Uuid::now_v7()), "owner_ref": app.admin.id })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let list: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        // A user with no grant privilege is refused, and nothing is audited.
        let user = attome_testapp::seed_user(app.db(), "e7-t8").await;
        let body = json!({ "wide_access_granted": true });
        let body = body.as_object().unwrap();
        let mut conn = app.db().acquire().await.unwrap();
        let refused = WideAccessCheck
            .check(
                &mut conn,
                &app.state,
                RecordSave {
                    entity: "marketing_list",
                    record_id: Some(list),
                    actor: Some(user.id),
                    body,
                },
            )
            .await;
        drop(conn);
        assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
        assert!(events(&app, list).await.is_empty());

        // Without the grant the list refreshes as its owner.
        let as_owner = refresh_context(&app.state, list).await.unwrap();
        assert_eq!(as_owner.user_id, app.admin.id);

        // The administrator grants it through the generic API: audited.
        let (_, current) = app
            .request(Method::GET, &format!("/api/v1/marketing_list/{list}"), None)
            .await;
        let version = current["row_version"].to_string();
        let if_match = format!("\"{}\"", version.trim_matches('"'));
        let (status, updated) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/marketing_list/{list}"),
                &[("if-match", if_match.as_str())],
                Some(json!({ "wide_access_granted": true })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        attome_testapp::drain_audit(&app).await;
        assert_eq!(
            events(&app, list).await,
            ["marketing_list.wide_access_granted"]
        );

        // Wide access with no marketing user is refused, not run as the owner.
        let refused = refresh_context(&app.state, list).await;
        assert!(
            matches!(&refused, Err(AppError::Validation(m)) if m == "segment.no_marketing_role"),
            "{:?}",
            refused.map(|c| c.user_id)
        );

        // With one set, the refresh runs as that user.
        let marketing = attome_testapp::seed_user(app.db(), "e7-t8-marketing").await;
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/api/v1/admin/settings/{SEGMENT_USER_SETTING}"),
                Some(json!({ "scope": "deployment", "value": marketing.id.to_string() })),
            )
            .await;
        assert!(status.is_success(), "{status}: {body}");
        let as_marketing = refresh_context(&app.state, list).await.unwrap();
        assert_eq!(as_marketing.user_id, marketing.id);
    });
}
