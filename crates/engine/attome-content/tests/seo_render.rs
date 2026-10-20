//! E12-T1, E13-T6: a published page's server-rendered head against a real
//! database — an English article and its Arabic translation each carry
//! their canonical link, the hreflang pair, x-default on the original and
//! one valid JSON-LD block.
//!
//! Fixture rows are direct SQL against this binary's throwaway database
//! (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-content --test seo_render"
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool"
)]

use attome_content::render_html::{Site, render_version_in_tx};
use attome_content::versions::record_version_in_tx;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use uuid::Uuid;

async fn space(db: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_space (id, name, created_by, updated_by, owner_layer) \
         VALUES ($1, $2, $3, $3, 'project')",
    )
    .bind(id)
    .bind(format!("SEO Render Space {id}"))
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("insert content_space");
    id
}

async fn page(
    db: &PgPool,
    space: Uuid,
    title: &str,
    path: &str,
    language: &str,
    translation_of: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    let blocks = serde_json::json!([
        {"id": Uuid::now_v7(), "kind": "heading", "props": {"text": title}},
        {"id": Uuid::now_v7(), "kind": "rich_text", "props": {"html": "<p>A first paragraph.</p>"}}
    ]);
    sqlx::query(
        "INSERT INTO content_page \
            (id, content_space_id, title, url_path, status, blocks_draft, blocks_published, \
             created_by, updated_by, audience, language, translation_of, page_type, published_at) \
         VALUES ($1, $2, $3, $4, 'published', $5, $5, $6, $6, 'public', $7, $8, 'article', now())",
    )
    .bind(id)
    .bind(space)
    .bind(title)
    .bind(path)
    .bind(&blocks)
    .bind(Uuid::now_v7())
    .bind(language)
    .bind(translation_of)
    .execute(db)
    .await
    .expect("insert content_page");
    id
}

/// Publishes the page's current content as a version and renders it.
async fn publish(db: &PgPool, page: Uuid, site: &Site) -> String {
    let mut tx = db.begin().await.expect("begin");
    let version = record_version_in_tx(&mut tx, page, Uuid::now_v7(), None)
        .await
        .expect("version");
    render_version_in_tx(&mut tx, page, version, site)
        .await
        .expect("render");
    tx.commit().await.expect("commit");
    sqlx::query_scalar(
        "SELECT html FROM content_page_version WHERE page_id = $1 AND version_number = $2",
    )
    .bind(page)
    .bind(version)
    .fetch_one(db)
    .await
    .expect("html")
}

#[tokio::test]
async fn published_page_head_has_seo_tags() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(3).await);
    let site = Site {
        base_url: "https://site.example".into(),
    };
    let space = space(&db).await;
    let tag = Uuid::now_v7().simple().to_string();
    let en_path = format!("/pricing-{tag}");
    let ar_path = format!("/ar/pricing-{tag}");
    let en = page(&db, space, "Pricing", &en_path, "en", None).await;
    let ar = page(&db, space, "الأسعار", &ar_path, "ar", Some(en)).await;

    let english = publish(&db, en, &site).await;
    let arabic = publish(&db, ar, &site).await;

    let en_url = format!("https://site.example{en_path}");
    let ar_url = format!("https://site.example{ar_path}");
    for html in [&english, &arabic] {
        assert!(
            html.contains(&format!(
                "<link rel=\"alternate\" hreflang=\"en\" href=\"{en_url}\">"
            )),
            "{html}"
        );
        assert!(html.contains(&format!(
            "<link rel=\"alternate\" hreflang=\"ar\" href=\"{ar_url}\">"
        )));
        assert!(html.contains(&format!(
            "<link rel=\"alternate\" hreflang=\"x-default\" href=\"{en_url}\">"
        )));
        assert_eq!(
            html.matches("<script type=\"application/ld+json\">")
                .count(),
            1
        );
        assert!(html.contains("\"@type\":\"Article\""));
    }
    assert!(english.contains(&format!("<link rel=\"canonical\" href=\"{en_url}\">")));
    assert!(arabic.contains(&format!("<link rel=\"canonical\" href=\"{ar_url}\">")));
    assert!(arabic.starts_with("<!doctype html><html lang=\"ar\" dir=\"rtl\">"));
    assert!(arabic.contains("<meta property=\"og:locale\" content=\"ar_SA\">"));
    assert!(english.contains("<meta name=\"description\" content=\"A first paragraph.\">"));
}
