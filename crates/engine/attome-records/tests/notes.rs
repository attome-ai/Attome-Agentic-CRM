//! C1-T1: note replies move from the note's JSON list to `note_reply`
//! records, keeping their text, author, time and attachments, on the note's
//! parent record; a list that is not JSON stays on the note; a second run
//! moves nothing.
//!
//! The `note` and `note_reply` tables are provisioned here (boot provisions
//! them from the platform changeset), and fixture rows are written with
//! direct SQL against this binary's throwaway database — guidelines §4's
//! test exemption.
//!
//! ```powershell
//! .\scripts\run-integration-tests.ps1 -TestArgs "-p attome-records --test notes"
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

use attome_testkit::skip_if_no_db;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// One `note_reply` row as the move test reads it.
type ReplyRow = (
    String,
    String,
    String,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    chrono::DateTime<chrono::Utc>,
);

async fn provision(db: &PgPool, name: &str, fields: &[(&str, &str)]) {
    let id = attome_metadata::provision::ensure_entity(db, name, name, None, false)
        .await
        .unwrap_or_else(|e| panic!("ensure {name}: {e}"));
    for (field, field_type) in fields {
        attome_metadata::provision::ensure_attribute(
            db, id, field, field, field_type, false, false, false, true, None, None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure {name}.{field}: {e}"));
    }
}

async fn test_db() -> Option<PgPool> {
    let db = attome_testkit::migrated_pool(5).await?;
    provision(
        &db,
        "note",
        &[
            ("title", "text"),
            ("note_text", "text"),
            ("entity_name", "text"),
            ("record_id", "text"),
            ("attachments", "text"),
            ("replies", "text"),
        ],
    )
    .await;
    provision(
        &db,
        "note_reply",
        &[
            ("note_id", "text"),
            ("entity_name", "text"),
            ("record_id", "text"),
            ("note_text", "text"),
            ("attachments", "text"),
        ],
    )
    .await;
    Some(db)
}

async fn insert_note(db: &PgPool, author: Uuid, record: &str, replies: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO note (id, title, note_text, entity_name, record_id, replies, created_by, owner_ref, created_at) \
         VALUES ($1, 'Thread', 'Body', 'account', $2, $3, $4, $4, '2026-08-01T00:00:00Z')",
    )
    .bind(id)
    .bind(record)
    .bind(replies)
    .bind(author)
    .execute(db)
    .await
    .expect("insert note");
    id
}

#[tokio::test]
async fn replies_become_records_and_old_replies_are_kept() {
    let db = skip_if_no_db!(test_db().await);
    let author = Uuid::now_v7();
    let replier = Uuid::now_v7();
    let record = Uuid::now_v7().to_string();
    let replies = json!([
        {
            "id": "legacy-1",
            "author_id": replier.to_string(),
            "author_name": "Sara",
            "note_text": "First reply",
            "created_at": "2026-08-14T11:00:00Z",
            "attachments": [{ "name": "a.pdf", "key": "note/x/files/k1" }]
        },
        { "id": "legacy-2", "author_name": "You", "note_text": "Second reply" }
    ])
    .to_string();
    let note = insert_note(&db, author, &record, &replies).await;
    let broken = insert_note(&db, author, &record, "not json").await;

    attome_records::note_replies::move_legacy_replies(&db)
        .await
        .expect("move replies");

    let rows: Vec<ReplyRow> = sqlx::query_as(
        "SELECT note_text, entity_name, record_id, attachments, created_by, owner_ref, created_at \
               FROM note_reply WHERE note_id = $1 ORDER BY created_at, note_text",
    )
    .bind(note.to_string())
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    // The reply without its own time takes the note's (2026-08-01).
    let (text, entity, on, attachments, by, owner, _) = &rows[0];
    assert_eq!(text, "Second reply");
    assert_eq!((entity.as_str(), on.as_str()), ("account", record.as_str()));
    assert_eq!(
        *by,
        Some(author),
        "an author that is not an id falls back to the note's"
    );
    assert_eq!(*owner, Some(author));
    assert!(attachments.is_none());
    let (text, _, _, attachments, by, _, at) = &rows[1];
    assert_eq!(text, "First reply");
    assert_eq!(*by, Some(replier));
    assert_eq!(at.to_rfc3339(), "2026-08-14T11:00:00+00:00");
    assert!(attachments.as_deref().unwrap().contains("note/x/files/k1"));

    let left: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT (SELECT replies FROM note WHERE id = $1), (SELECT replies FROM note WHERE id = $2)",
    )
    .bind(note)
    .bind(broken)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(left.0, None, "the moved list is cleared");
    assert_eq!(
        left.1.as_deref(),
        Some("not json"),
        "a list that is not JSON stays"
    );

    // A second boot moves nothing again.
    attome_records::note_replies::move_legacy_replies(&db)
        .await
        .expect("move again");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM note_reply WHERE note_id = $1")
        .bind(note.to_string())
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 2);
}
