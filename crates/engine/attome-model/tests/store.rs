//! The metadata object store's schema (roadmap Y1-T2), on a migrated
//! throwaway database.

#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_model::store::{self, ObjectSpec};
use attome_model::{
    Artefact, CookInput, Issue, Kind, KindName, Layer, ObjectId, Reference, ValidationCtx,
};
use attome_types::{AppError, OnePageQuery};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

/// A minimal form-like kind for the store tests.
struct NoteKind;

impl Kind for NoteKind {
    fn name(&self) -> KindName {
        KindName("test_note")
    }
    fn schema_version(&self) -> u32 {
        1
    }
    fn json_schema(&self) -> Value {
        json!({ "type": "object" })
    }
    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        if doc.get("title").is_some_and(Value::is_string) {
            Ok(())
        } else {
            Err(vec![Issue::new("/title", "required", "a note has a title")])
        }
    }
    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }
    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }
    fn cook(&self, _docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        Ok(Vec::new())
    }
    fn agent_tool_description(&self) -> &'static str {
        "a note"
    }
}

fn registry() -> attome_model::KindRegistry {
    let mut registry = attome_model::KindRegistry::default();
    registry
        .register(std::sync::Arc::new(NoteKind))
        .expect("register the note kind");
    registry
}

async fn pool() -> Option<sqlx::PgPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect to the migrated test database"),
    )
}

fn spec() -> ObjectSpec {
    let id = ObjectId::new();
    ObjectSpec {
        id,
        name: format!("note-{id}"),
        app: "customer".to_owned(),
        layer: Layer::Customer,
    }
}

async fn save(pool: &sqlx::PgPool, object: &ObjectSpec, doc: Value) -> store::DraftSaved {
    let mut tx = pool.begin().await.expect("begin");
    let saved = store::save_draft(&mut tx, &registry(), &NoteKind, object, &doc, None)
        .await
        .expect("save draft");
    tx.commit().await.expect("commit");
    saved
}

#[tokio::test]
async fn save_draft_twice_keeps_one_draft() {
    let Some(pool) = pool().await else {
        return;
    };
    let object = spec();
    let first = save(&pool, &object, json!({ "title": "one" })).await;
    let second = save(&pool, &object, json!({ "title": "two" })).await;
    assert!(first.opened && !second.opened);
    assert_eq!(
        first.version_no, second.version_no,
        "the draft is replaced, not added"
    );
    assert_ne!(first.content_hash, second.content_hash);
    let read = store::read(&pool, object.id.0, None).await.unwrap();
    assert_eq!(read.doc["title"], "two");
    assert_eq!(read.state, "draft");

    let mut tx = pool.begin().await.unwrap();
    let refused = store::save_draft(
        &mut tx,
        &registry(),
        &NoteKind,
        &object,
        &json!({ "no": "title" }),
        None,
    )
    .await;
    assert!(
        matches!(refused, Err(AppError::Validation(_))),
        "the shape is checked on save"
    );
}

#[tokio::test]
async fn history_lists_newest_first() {
    let Some(pool) = pool().await else {
        return;
    };
    let object = spec();
    save(&pool, &object, json!({ "title": "v1" })).await;
    // Publishing is a later task; the test publishes by hand in its own
    // throwaway database so a second draft can open.
    sqlx::query("UPDATE metadata_object_version SET state = 'published' WHERE object_id = $1")
        .bind(object.id.0)
        .execute(&pool)
        .await
        .unwrap();
    let second = save(&pool, &object, json!({ "title": "v2" })).await;
    assert_eq!(second.version_no, 2);
    let page = store::history(
        &pool,
        object.id.0,
        &OnePageQuery {
            page: None,
            page_size: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.total, 2);
    let versions: Vec<i64> = page.items.iter().map(|v| v.version_no).collect();
    assert_eq!(versions, [2, 1]);
    let ops = store::diff(&pool, object.id.0, 1, 2).await.unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].path, "/title");
    assert!(matches!(
        store::history(
            &pool,
            uuid::Uuid::now_v7(),
            &OnePageQuery {
                page: None,
                page_size: None
            }
        )
        .await,
        Err(AppError::NotFound)
    ));
}

#[tokio::test]
async fn concurrent_save_returns_conflict() {
    let Some(pool) = pool().await else {
        return;
    };
    let object = spec();
    save(&pool, &object, json!({ "title": "base" })).await;
    let mut holder = pool.begin().await.unwrap();
    store::save_draft(
        &mut holder,
        &registry(),
        &NoteKind,
        &object,
        &json!({ "title": "held" }),
        None,
    )
    .await
    .expect("the first writer takes the lock");
    let mut second = pool.begin().await.unwrap();
    let refused = store::save_draft(
        &mut second,
        &registry(),
        &NoteKind,
        &object,
        &json!({ "title": "late" }),
        None,
    )
    .await;
    assert!(matches!(refused, Err(AppError::Conflict(_))), "{refused:?}");
    holder.rollback().await.unwrap();
}

#[tokio::test]
async fn migration_creates_metadata_store_tables() {
    let Some(url) = attome_testkit::migrated_db_url() else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to the migrated test database");
    for table in [
        "metadata_object",
        "metadata_object_version",
        "metadata_artefact",
    ] {
        let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
        assert_eq!(found.as_deref(), Some(table), "{table} exists");
    }
    // One open draft per object: a second draft row is refused.
    let object = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_object (id, kind, name, owner_layer) VALUES ($1, 'form', $2, 'customer')",
    )
    .bind(object)
    .bind(format!("f-{object}"))
    .execute(&pool)
    .await
    .expect("insert object");
    let draft = |version: i64| {
        sqlx::query(
            "INSERT INTO metadata_object_version \
             (object_id, version_no, kind_schema_version, doc, content_hash, state) \
             VALUES ($1, $2, 1, '{}'::jsonb, 'h', 'draft')",
        )
        .bind(object)
        .bind(version)
        .execute(&pool)
    };
    draft(1).await.expect("the first draft");
    assert!(draft(2).await.is_err(), "a second open draft is refused");
}
