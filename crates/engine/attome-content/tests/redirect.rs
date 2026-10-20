//! E13-T5: page redirects against a real database — a moved page answers
//! at every old path with its current one, a page that takes an old path
//! releases its redirect, and a redirect never names a page outside the
//! caller's audiences.
//!
//! Fixture rows are direct SQL against this binary's throwaway database
//! (guidelines §4's test exemption).
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-content --test redirect"
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

use attome_content::redirect::{record_path_change, release_path, resolve};
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
    .bind(format!("Redirect Test Space {id}"))
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("insert content_space");
    id
}

async fn page(db: &PgPool, space: Uuid, path: &str, audience: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO content_page \
            (id, content_space_id, title, url_path, status, blocks_draft, blocks_published, \
             created_by, updated_by, audience) \
         VALUES ($1, $2, $3, $4, 'published', '[]'::jsonb, '[]'::jsonb, $5, $5, $6)",
    )
    .bind(id)
    .bind(space)
    .bind(format!("Redirect Test Page {id}"))
    .bind(path)
    .bind(Uuid::now_v7())
    .bind(audience)
    .execute(db)
    .await
    .expect("insert content_page");
    id
}

/// Moves `page` to `new_path` the way the admin update does: the path
/// change and its redirect in one transaction.
async fn move_page(db: &PgPool, page: Uuid, old_path: &str, new_path: &str) {
    let mut tx = db.begin().await.expect("begin");
    sqlx::query("UPDATE content_page SET url_path = $2 WHERE id = $1")
        .bind(page)
        .bind(new_path)
        .execute(&mut *tx)
        .await
        .expect("move page");
    record_path_change(&mut tx, page, old_path, new_path)
        .await
        .expect("record redirect");
    tx.commit().await.expect("commit");
}

fn public() -> Vec<String> {
    vec!["public".to_string()]
}

#[tokio::test]
async fn a_moved_page_answers_at_every_old_path() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(3).await);
    let space = space(&db).await;
    let tag = Uuid::now_v7().simple().to_string();
    let first = format!("/first-{tag}");
    let second = format!("/second-{tag}");
    let arabic = format!("/دليل-{tag}");
    let id = page(&db, space, &first, "public").await;

    move_page(&db, id, &first, &second).await;
    assert_eq!(
        resolve(&db, &first, &public()).await.unwrap(),
        Some((space, second.clone()))
    );

    move_page(&db, id, &second, &arabic).await;
    for old in [&first, &second] {
        assert_eq!(
            resolve(&db, old, &public()).await.unwrap(),
            Some((space, arabic.clone())),
            "{old}"
        );
    }
    assert_eq!(resolve(&db, &arabic, &public()).await.unwrap(), None);

    // A new page at the first path takes it over.
    let mut tx = db.begin().await.expect("begin");
    release_path(&mut tx, &first).await.expect("release");
    tx.commit().await.expect("commit");
    page(&db, space, &first, "public").await;
    assert_eq!(resolve(&db, &first, &public()).await.unwrap(), None);
}

#[tokio::test]
async fn a_redirect_never_names_a_page_outside_the_audience() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(3).await);
    let space = space(&db).await;
    let tag = Uuid::now_v7().simple().to_string();
    let old = format!("/staff-old-{tag}");
    let new = format!("/staff-new-{tag}");
    let id = page(&db, space, &old, "internal").await;
    move_page(&db, id, &old, &new).await;

    assert_eq!(resolve(&db, &old, &public()).await.unwrap(), None);
    let both = vec!["public".to_string(), "internal".to_string()];
    assert_eq!(resolve(&db, &old, &both).await.unwrap(), Some((space, new)));
}
