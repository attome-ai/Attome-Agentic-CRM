//! L4-T2: the catalog asset index is filled from the metadata, keeps the
//! descriptions people wrote, and drops assets that no longer exist.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;

// feature: L4
#[test]
fn rebuild_indexes_every_kind_and_removes_deleted() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // An entity the metadata has, a written description on it, and a row
        // for an asset that does not exist, before the rebuild.
        let entity: Option<String> = sqlx::query_scalar(
            "SELECT logicalname FROM entity_info WHERE is_active IS NOT FALSE               ORDER BY logicalname LIMIT 1",
        )
        .fetch_optional(app.db())
        .await
        .unwrap();
        let Some(entity) = entity else {
            return;
        };
        sqlx::query(
            "INSERT INTO catalog_asset (kind, ref, name_en) VALUES ('view', 'no-such-view', 'Gone')              ON CONFLICT (kind, ref) DO NOTHING",
        )
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO catalog_asset (kind, ref, description_en, description_status)              VALUES ('entity', $1, 'Written by a person', 'reviewed')              ON CONFLICT (kind, ref) DO UPDATE SET description_en = EXCLUDED.description_en,                     description_status = 'reviewed'",
        )
        .bind(&entity)
        .execute(app.db())
        .await
        .unwrap();

        let counts = attome_api::catalog_index::rebuild_assets(&app.state)
            .await
            .unwrap();
        assert!(counts.upserted > 0);
        assert!(counts.removed >= 1);

        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT kind FROM catalog_asset ORDER BY kind")
                .fetch_all(app.db())
                .await
                .unwrap();
        for kind in ["agent_tool", "attribute", "entity"] {
            assert!(kinds.iter().any(|k| k == kind), "{kind} in {kinds:?}");
        }
        let gone: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM catalog_asset WHERE kind = 'view' AND ref = 'no-such-view'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(gone, 0);
        let (description, status): (Option<String>, String) = sqlx::query_as(
            "SELECT description_en, description_status FROM catalog_asset \
              WHERE kind = 'entity' AND ref = $1",
        )
        .bind(&entity)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(description.as_deref(), Some("Written by a person"));
        assert_eq!(status, "reviewed");
        let searchable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM catalog_asset \
              WHERE kind = 'entity' AND ref = $1 AND search IS NOT NULL",
        )
        .bind(&entity)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(searchable, 1, "the entity has a search vector");
    });
}
