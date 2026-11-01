//! K6-T4: a recrawl that changes an imported page updates its knowledge
//! item as a new version; an item a person published from a review source
//! is flagged for review instead, and importing the page again replaces it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use uuid::Uuid;

async fn definitions(app: &TestApp) {
    for name in ["attome-webcrawl", "attome-webcrawl-item-versions"] {
        attome_api::changeset::boot::apply_platform_definition(&app.state, name)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let registry = attome_core::build_registry(&app.state.base.db)
        .await
        .expect("build the metadata registry");
    app.state.entities.swap(registry);
}

async fn source(app: &TestApp, import_mode: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO webcrawl_target (url, created_by, status, import_mode) \
         VALUES ('https://docs.example.com/', $1, 'completed', $2) RETURNING id",
    )
    .bind(app.admin.id)
    .bind(import_mode)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn page(app: &TestApp, target: Uuid, path: &str, text: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO webcrawl_page (target_ref, url_path, status, content, content_hash) \
         VALUES ($1, $2, 'crawled', $3, md5($3)) RETURNING id",
    )
    .bind(target)
    .bind(path)
    .bind(text)
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// What a recrawl does to a page: new text and a new hash.
async fn recrawl(app: &TestApp, page: Uuid, text: &str) {
    sqlx::query("UPDATE webcrawl_page SET content = $2, content_hash = md5($2) WHERE id = $1")
        .bind(page)
        .bind(text)
        .execute(app.db())
        .await
        .unwrap();
}

async fn item_of(app: &TestApp, page: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT imported_data_item_ref FROM webcrawl_page WHERE id = $1")
        .bind(page)
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn item(app: &TestApp, id: Uuid) -> (Option<String>, Option<f64>, Option<bool>) {
    sqlx::query_as(
        "SELECT text, version::float8, needs_review FROM knowledge_data_item WHERE id = $1",
    )
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: K6
#[test]
fn changed_page_bumps_version_and_reindexes_one_item() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        definitions(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let target = source(&app, "review").await;
        let changing = page(&app, target, "/pricing", "Plans start at 10").await;
        let steady = page(&app, target, "/about", "About us").await;

        let result =
            attome_webcrawl::import::import_pages(&app.state, &admin, target, &[changing, steady])
                .await
                .unwrap();
        assert_eq!(result.imported_count, 2);
        let changed_item = item_of(&app, changing).await;
        let steady_item = item_of(&app, steady).await;
        assert_eq!(item(&app, changed_item).await.1, Some(1.0));

        recrawl(&app, changing, "Plans start at 12").await;
        let stats = attome_webcrawl::import::sync_after_crawl(&app.state, target)
            .await
            .unwrap();
        assert_eq!(stats.updated, 1, "{stats:?}");
        let (text, version, needs_review) = item(&app, changed_item).await;
        assert_eq!(text.as_deref(), Some("Plans start at 12"));
        assert_eq!(version, Some(2.0));
        assert_eq!(needs_review, Some(false));
        // The unchanged page's item was not touched.
        let (text, version, _) = item(&app, steady_item).await;
        assert_eq!(text.as_deref(), Some("About us"));
        assert_eq!(version, Some(1.0));

        // Nothing changed since: a second sync does nothing.
        let stats = attome_webcrawl::import::sync_after_crawl(&app.state, target)
            .await
            .unwrap();
        assert_eq!(stats.updated + stats.flagged, 0, "{stats:?}");
    });
}

// feature: K6
#[test]
fn reviewed_item_becomes_needs_review() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        definitions(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let target = source(&app, "review").await;
        let reviewed = page(&app, target, "/terms", "Terms v1").await;
        attome_webcrawl::import::import_pages(&app.state, &admin, target, &[reviewed])
            .await
            .unwrap();
        let reviewed_item = item_of(&app, reviewed).await;
        // A person reviewed and published it.
        sqlx::query("UPDATE knowledge_data_item SET lifecycle = 'published' WHERE id = $1")
            .bind(reviewed_item)
            .execute(app.db())
            .await
            .unwrap();

        recrawl(&app, reviewed, "Terms v2").await;
        let stats = attome_webcrawl::import::sync_after_crawl(&app.state, target)
            .await
            .unwrap();
        assert_eq!(stats.flagged, 1, "{stats:?}");
        let (text, version, needs_review) = item(&app, reviewed_item).await;
        assert_eq!(
            text.as_deref(),
            Some("Terms v1"),
            "the published text stays"
        );
        assert_eq!(version, Some(1.0));
        assert_eq!(needs_review, Some(true));

        // The reviewer imports the page again: the new text replaces it.
        let result = attome_webcrawl::import::import_pages(&app.state, &admin, target, &[reviewed])
            .await
            .unwrap();
        assert_eq!(result.updated_count, 1);
        let (text, version, needs_review) = item(&app, reviewed_item).await;
        assert_eq!(text.as_deref(), Some("Terms v2"));
        assert_eq!(version, Some(2.0));
        assert_eq!(needs_review, Some(false));
    });
}

// feature: K6
#[test]
fn an_automatic_source_imports_its_new_pages_published() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        definitions(&app).await;
        let target = source(&app, "automatic").await;
        let fresh = page(&app, target, "/faq", "Questions").await;
        let stats = attome_webcrawl::import::sync_after_crawl(&app.state, target)
            .await
            .unwrap();
        assert_eq!(stats.imported, 1, "{stats:?}");
        let lifecycle: Option<String> =
            sqlx::query_scalar("SELECT lifecycle::text FROM knowledge_data_item WHERE id = $1")
                .bind(item_of(&app, fresh).await)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(lifecycle.as_deref(), Some("published"));
    });
}

// feature: K6
#[test]
fn missing_twice_unpublishes_and_duplicate_becomes_alias() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        definitions(&app).await;

        // Two pages with the same text in an automatic source: one item, one alias.
        let target = source(&app, "automatic").await;
        let first = page(&app, target, "/a", "Same words").await;
        let second = page(&app, target, "/b", "Same words").await;
        let stats = attome_webcrawl::import::sync_after_crawl(&app.state, target)
            .await
            .unwrap();
        assert_eq!((stats.imported, stats.aliased), (1, 1), "{stats:?}");
        let (aliased, original) = if item_of_opt(&app, first).await.is_some() {
            (second, first)
        } else {
            (first, second)
        };
        let alias_of: Option<Uuid> =
            sqlx::query_scalar("SELECT alias_of FROM webcrawl_page WHERE id = $1")
                .bind(aliased)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(alias_of, Some(original));

        // The imported page goes missing from two complete crawls in a row.
        let item = item_of(&app, original).await;
        for (round, retired) in [(1, 0), (2, 1)] {
            let after: chrono::DateTime<chrono::Utc> =
                sqlx::query_scalar("SELECT now() + interval '1 second'")
                    .fetch_one(app.db())
                    .await
                    .unwrap();
            let got = attome_webcrawl::import::retire_missing(&app.state, target, after)
                .await
                .unwrap();
            assert_eq!(got, retired, "round {round}");
        }
        let lifecycle: Option<String> =
            sqlx::query_scalar("SELECT lifecycle::text FROM knowledge_data_item WHERE id = $1")
                .bind(item)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(lifecycle.as_deref(), Some("expired"), "retired, and kept");
    });
}

async fn item_of_opt(app: &TestApp, page: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT imported_data_item_ref FROM webcrawl_page WHERE id = $1")
        .bind(page)
        .fetch_one(app.db())
        .await
        .unwrap()
}
