//! C-16 (M01 §7) proof: `attome_core::crud::append_only_insert` (renamed
//! from `insert` by C-17) must be able to write a multi-select `choice` row.
//! Before C-16, `crud.rs`'s own `sql_cast`/`json_to_str` had drifted from the
//! canonical field-type codec (missing the `choice`/`file` multi-valued
//! arms entirely), so a multi-select field inserted through this path — the
//! one `attome-audit` uses for the audit chain — failed to cast.
//!
//! C-17 (M01 §7) proof: `resolve`/`append_only_insert`/
//! `append_only_insert_many` each get a unit-shaped test below, including
//! the unknown-key rejection that used to be a silent drop.
//!
//! Requires a live Postgres (`DATABASE_URL`/`attome_testkit::test_db_url`) —
//! same convention as `tests/meta_registry.rs`. Uses throwaway
//! logicalnames/tables (random UUID suffix), never a shared table.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_core::crud;
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Shared throwaway-entity setup for every test below: one
/// `entity_info` row plus a caller-supplied set of attributes and a
/// matching physical table. Returns the entity's `logicalname`.
async fn provision_test_entity(
    db: &DbPool,
    columns_sql: &str,
    attrs: &[(&str, i32, Option<serde_json::Value>)],
) -> String {
    let logicalname = format!("crudtest_{}", Uuid::now_v7().simple());
    let entity_id = Uuid::now_v7();

    sqlx::query(
        "INSERT INTO entity_info (id, logicalname, name, is_active, is_append_only, created_at, owner_layer) \
         VALUES ($1, $2, $3, true, false, NOW(), 'project')",
    )
    .bind(entity_id)
    .bind(&logicalname)
    .bind("Crud Test")
    .execute(db)
    .await
    .expect("insert throwaway entity_info row");

    for (name, field_type_int, options) in attrs {
        sqlx::query(
            r#"INSERT INTO attribute_info
                   (id, entity_ref, logicalname, name, "type", options, is_sensitive, is_active, created_at, owner_layer)
               VALUES ($1, $2, $3, $3, $4, $5, false, true, NOW(), 'project')"#,
        )
        .bind(Uuid::now_v7())
        .bind(entity_id)
        .bind(name)
        .bind(field_type_int)
        .bind(options)
        .execute(db)
        .await
        .expect("insert throwaway attribute_info row");
    }

    sqlx::query(&format!(r#"CREATE TABLE "{logicalname}" {columns_sql}"#))
        .execute(db)
        .await
        .expect("create throwaway entity table");

    logicalname
}

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

#[tokio::test]
async fn insert_writes_a_multi_select_choice_row() {
    let db = skip_if_no_db!(test_db().await);

    // field_type_int 7 == choice; options.multi = true == C-16's drifted arm
    // (D-078: multi-select choice is TEXT[] on the physical table).
    let logicalname = provision_test_entity(
        &db,
        "(id UUID PRIMARY KEY DEFAULT uuidv7(), tags TEXT[])",
        &[(
            "tags",
            7,
            Some(json!({"choices": ["red", "blue", "green"], "multi": true})),
        )],
    )
    .await;

    let mut tx = db.begin().await.expect("begin tx");
    let record_id =
        crud::append_only_insert(&mut tx, &logicalname, &json!({"tags": ["red", "blue"]}))
            .await
            .expect("insert a multi-select row through attome_core::crud");
    tx.commit().await.expect("commit tx");

    let stored: Vec<String> = sqlx::query_scalar(&format!(
        r#"SELECT tags FROM "{logicalname}" WHERE id = $1"#
    ))
    .bind(record_id)
    .fetch_one(&db)
    .await
    .expect("read back the inserted row");

    assert_eq!(stored, vec!["red".to_owned(), "blue".to_owned()]);
}

/// C-17 (M01 §7) proof: a plain scalar insert still works after the
/// unknown-key rejection was added — a `data` object whose keys are all
/// recognised attributes must not be affected by the new check.
#[tokio::test]
async fn insert_writes_a_recognised_scalar_row() {
    let db = skip_if_no_db!(test_db().await);

    // field_type_int 3 == text (the same default `fetch_attrs` COALESCEs to).
    let logicalname = provision_test_entity(
        &db,
        "(id UUID PRIMARY KEY DEFAULT uuidv7(), name TEXT)",
        &[("name", 3, None)],
    )
    .await;

    let mut tx = db.begin().await.expect("begin tx");
    let record_id = crud::append_only_insert(&mut tx, &logicalname, &json!({"name": "Alice"}))
        .await
        .expect("insert a plain scalar row");
    tx.commit().await.expect("commit tx");

    let stored: String = sqlx::query_scalar(&format!(
        r#"SELECT name FROM "{logicalname}" WHERE id = $1"#
    ))
    .bind(record_id)
    .fetch_one(&db)
    .await
    .expect("read back the inserted row");

    assert_eq!(stored, "Alice");
}

/// C-17 (M01 §7) proof: `append_only_insert` used to silently drop a `data`
/// key with no matching attribute; it must now return an error and write
/// nothing.
#[tokio::test]
async fn insert_rejects_an_unrecognised_key_instead_of_dropping_it() {
    let db = skip_if_no_db!(test_db().await);

    let logicalname = provision_test_entity(
        &db,
        "(id UUID PRIMARY KEY DEFAULT uuidv7(), name TEXT)",
        &[("name", 3, None)],
    )
    .await;

    let mut tx = db.begin().await.expect("begin tx");
    let err = crud::append_only_insert(
        &mut tx,
        &logicalname,
        &json!({"name": "Alice", "not_a_real_field": "sneaky"}),
    )
    .await
    .expect_err("an unrecognised key must be rejected, not silently dropped");
    assert!(matches!(err, AppError::Internal(_)));

    let row_count: i64 = sqlx::query_scalar(&format!(r#"SELECT count(*) FROM "{logicalname}""#))
        .fetch_one(&mut *tx)
        .await
        .expect("count rows in the throwaway table");
    assert_eq!(
        row_count, 0,
        "a rejected insert must not have written a row"
    );
}

/// C-17 (M01 §7) proof: `append_only_insert_many` writes every row's columns
/// in one multi-row INSERT and resolves metadata exactly once.
#[tokio::test]
async fn insert_many_writes_every_row() {
    let db = skip_if_no_db!(test_db().await);

    let logicalname = provision_test_entity(
        &db,
        "(id UUID PRIMARY KEY DEFAULT uuidv7(), name TEXT)",
        &[("name", 3, None)],
    )
    .await;

    let mut tx = db.begin().await.expect("begin tx");
    crud::append_only_insert_many(
        &mut tx,
        &logicalname,
        &[json!({"name": "Alice"}), json!({"name": "Bob"})],
    )
    .await
    .expect("insert two rows through append_only_insert_many");
    tx.commit().await.expect("commit tx");

    let mut stored: Vec<String> = sqlx::query_scalar(&format!(
        r#"SELECT name FROM "{logicalname}" ORDER BY name"#
    ))
    .fetch_all(&db)
    .await
    .expect("read back the inserted rows");
    stored.sort();

    assert_eq!(stored, vec!["Alice".to_owned(), "Bob".to_owned()]);
}

/// C-17 (M01 §7) proof: `append_only_insert_many` checks every row's keys,
/// not just the first row's — a later row's unrecognised key must not slip
/// through just because the column set was already fixed from row 0.
#[tokio::test]
async fn insert_many_rejects_an_unrecognised_key_on_a_later_row() {
    let db = skip_if_no_db!(test_db().await);

    let logicalname = provision_test_entity(
        &db,
        "(id UUID PRIMARY KEY DEFAULT uuidv7(), name TEXT)",
        &[("name", 3, None)],
    )
    .await;

    let mut tx = db.begin().await.expect("begin tx");
    let err = crud::append_only_insert_many(
        &mut tx,
        &logicalname,
        &[
            json!({"name": "Alice"}),
            json!({"name": "Bob", "not_a_real_field": "sneaky"}),
        ],
    )
    .await
    .expect_err("a later row's unrecognised key must be rejected");
    assert!(matches!(err, AppError::Internal(_)));

    let row_count: i64 = sqlx::query_scalar(&format!(r#"SELECT count(*) FROM "{logicalname}""#))
        .fetch_one(&mut *tx)
        .await
        .expect("count rows in the throwaway table");
    assert_eq!(
        row_count, 0,
        "a rejected insert_many must not have written any row"
    );
}

/// C-17 (M01 §7) proof: `resolve` returns the entity id/table name/
/// append-only flag for a known logicalname, and `AppError::NotFound` for an
/// unknown one — the two paths `append_only_insert`/`append_only_insert_many`
/// themselves rely on.
#[tokio::test]
async fn resolve_finds_a_known_entity_and_rejects_an_unknown_one() {
    let db = skip_if_no_db!(test_db().await);

    let logicalname =
        provision_test_entity(&db, "(id UUID PRIMARY KEY DEFAULT uuidv7())", &[]).await;

    let mut tx = db.begin().await.expect("begin tx");
    let (_, table_name, is_append_only) = crud::resolve(&mut tx, &logicalname)
        .await
        .expect("resolve the throwaway entity");
    assert_eq!(table_name, logicalname);
    assert!(!is_append_only);

    let unknown = format!("crudtest_missing_{}", Uuid::now_v7().simple());
    let err = crud::resolve(&mut tx, &unknown)
        .await
        .expect_err("an unregistered logicalname must not resolve");
    assert!(matches!(err, AppError::NotFound));
}
