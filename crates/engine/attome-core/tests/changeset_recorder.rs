//! Solution 7 Phase 1 (D-785) — the changeset recorder against a real
//! `changeset` / `changeset_operation` (migration
//! `0521_changeset_store.sql`).
//!
//! Proves the transaction contract of `attome_core::changeset`
//! (design §4.2–§4.6):
//!
//! 1. open -> record in a transaction -> close: one operation per `record`,
//!    `seq` 1..n, `op_count` kept in step, and nothing recorded when the
//!    write's transaction rolls back;
//! 2. `record` takes the changeset row `FOR UPDATE`: a second writer queues
//!    behind the first and gets the next `seq`, so `seq` order is commit order;
//! 3. abandon only when empty, close only when not empty;
//! 4. the layer rule: a project changeset may not change a platform row, and
//!    selection refuses a missing header target, an ambiguous author and (in
//!    `required` mode) no changeset at all; `auto` mode records every write of
//!    one request into one closed automatic changeset.
//!
//! Needs a test database migrated through 0521. When the template predates it
//! the tests say so and skip (build a private template, see the `testing`
//! skill; never migrate the shared one).
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-core --test changeset_recorder -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test inspects state on a raw pool; production code uses attome_db::tx::begin"
)]

use std::time::Duration;

use attome_core::changeset::errors::code_of;
use attome_core::changeset::store::{self, NewChangeset, Seal};
use attome_core::changeset::{
    ChangesetStatus, Layer, Op, RecordedOp, Recording, RecordingMode, RequestContext,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("failed to connect to DATABASE_URL");
    let present: bool = sqlx::query_scalar("SELECT to_regclass('changeset_operation') IS NOT NULL")
        .fetch_one(&db)
        .await
        .expect("probe");
    if !present {
        eprintln!(
            "the test database predates migration 0521 (no changeset_operation); \
             skipping — build a private template migrated through 0522"
        );
        return None;
    }
    Some(db)
}

fn suffix() -> String {
    let hex = Uuid::now_v7().simple().to_string();
    hex[hex.len() - 10..].to_owned()
}

async fn open(db: &DbPool, author: Uuid, layer: Layer) -> store::ChangesetRow {
    store::open(
        db,
        &NewChangeset {
            layer,
            scope: "recorder-test".into(),
            name: format!("t-{}", suffix()),
            title: "Recorder test".into(),
            description: String::new(),
            requires: json!({}),
            author_ref: Some(author),
            author_label: format!("user:{author}"),
        },
    )
    .await
    .expect("open")
}

fn request(author: Uuid, header: Option<Uuid>, mode: RecordingMode) -> Recording {
    Recording::for_request(RequestContext {
        header,
        actor: Some(author),
        actor_label: format!("user:{author}"),
        request_id: Some("req-test".into()),
        route: "POST /api/v1/admin/views".into(),
        mode,
        auto_layer: Layer::Project,
        break_glass: false,
    })
}

fn view_op(name: &str) -> RecordedOp {
    RecordedOp {
        op: Op::UpsertView,
        object_kind: "view",
        object_ref: Some(Uuid::now_v7()),
        target: json!({ "entity": "account", "view": name }),
        snapshot: json!({ "name": name }),
        changed: vec!["name"],
    }
}

async fn record_committed(db: &DbPool, recording: &Recording, op: RecordedOp) {
    let mut tx = attome_db::tx::begin(db).await.expect("begin");
    recording.record(&mut tx, op).await.expect("record");
    attome_db::tx::commit(tx).await.expect("commit");
}

fn conflict_code(err: AppError) -> String {
    match err {
        AppError::Conflict(message) => code_of(message).to_owned(),
        other => panic!("expected a 409 conflict, got {other:?}"),
    }
}

async fn cleanup(db: &DbPool, author: Uuid) {
    // The test role owns the tables; the runtime role has no DELETE by design.
    let _ = sqlx::query(
        "DELETE FROM changeset_operation WHERE changeset_ref IN \
         (SELECT id FROM changeset WHERE author_ref = $1)",
    )
    .bind(author)
    .execute(db)
    .await;
    let _ = sqlx::query("DELETE FROM changeset WHERE author_ref = $1")
        .bind(author)
        .execute(db)
        .await;
}

fn seal() -> Seal {
    Seal {
        document: json!({ "format": "attome-changeset/v1" }),
        checksum: format!("sha256:{}", "0".repeat(64)),
        ops_hash: "0".repeat(64),
    }
}

#[tokio::test]
async fn open_record_close_appends_one_op_per_write_in_order() {
    let db = skip_if_no_db!(test_db().await);
    let author = Uuid::now_v7();
    let cs = open(&db, author, Layer::Project).await;
    assert_eq!(cs.status, ChangesetStatus::Open);
    assert_eq!(cs.op_count, 0);

    // Resolved from the author's one open changeset (no header).
    let recording = request(author, None, RecordingMode::Required);
    let resolved = recording.preflight(&db).await.expect("preflight");
    assert_eq!(resolved.changeset_id, Some(cs.id));
    assert_eq!(recording.stamp().ok(), Some(Layer::Project));

    record_committed(&db, &recording, view_op("first")).await;
    record_committed(&db, &recording, view_op("second")).await;

    // A rolled-back write records nothing.
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    recording
        .record(&mut tx, view_op("rolled_back"))
        .await
        .expect("record");
    tx.rollback().await.expect("rollback");

    let ops = store::operations(&db, cs.id).await.expect("operations");
    let seqs: Vec<i32> = ops.iter().map(|o| o.seq).collect();
    assert_eq!(seqs, vec![1, 2]);
    assert_eq!(ops[0].target["view"], "first");
    assert_eq!(ops[1].target["view"], "second");
    assert_eq!(ops[0].op, "upsert_view");
    assert_eq!(ops[0].phase, "expand");
    assert_eq!(ops[0].route, "POST /api/v1/admin/views");
    assert_eq!(ops[0].actor_ref, Some(author));
    assert_eq!(ops[0].changed, vec!["name".to_owned()]);
    assert!(ops[0].args.is_none());

    let row = store::get(&db, cs.id).await.expect("get").expect("row");
    assert_eq!(row.op_count, 2);

    // The one-time args fill, then close with a stale and a current version.
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    store::fill_args(&mut tx, cs.id, 1, &json!({ "definition": {} }))
        .await
        .expect("fill");
    assert!(
        store::fill_args(&mut tx, cs.id, 1, &json!({}))
            .await
            .is_err(),
        "args are filled once"
    );
    let stale = store::close(&mut tx, cs.id, Some(row.row_version + 7), &seal()).await;
    assert!(matches!(stale, Err(AppError::VersionConflict)));
    let closed = store::close(&mut tx, cs.id, Some(row.row_version), &seal())
        .await
        .expect("close");
    attome_db::tx::commit(tx).await.expect("commit");
    assert_eq!(closed.status, ChangesetStatus::Closed);
    assert!(closed.closed_at.is_some() && closed.checksum.is_some());

    // A closed changeset takes no further operation.
    let late = request(author, Some(cs.id), RecordingMode::Required);
    let err = late.preflight(&db).await.expect_err("closed");
    assert_eq!(conflict_code(err), "changeset_not_open");

    cleanup(&db, author).await;
}

#[tokio::test]
async fn a_second_writer_queues_on_the_changeset_row_and_gets_the_next_seq() {
    let db = skip_if_no_db!(test_db().await);
    let author = Uuid::now_v7();
    let cs = open(&db, author, Layer::Project).await;

    let first = request(author, Some(cs.id), RecordingMode::Required);
    let mut tx_a = attome_db::tx::begin(&db).await.expect("begin a");
    first
        .record(&mut tx_a, view_op("a"))
        .await
        .expect("record a");

    // B records into the same changeset while A still holds the row lock.
    let db_b = db.clone();
    let b = tokio::spawn(async move {
        let second = request(author, Some(cs.id), RecordingMode::Required);
        let mut tx_b = attome_db::tx::begin(&db_b).await.expect("begin b");
        second
            .record(&mut tx_b, view_op("b"))
            .await
            .expect("record b");
        attome_db::tx::commit(tx_b).await.expect("commit b");
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!b.is_finished(), "B must wait for A's FOR UPDATE lock");

    attome_db::tx::commit(tx_a).await.expect("commit a");
    tokio::time::timeout(Duration::from_secs(10), b)
        .await
        .expect("B finishes once A commits")
        .expect("B did not panic");

    let ops = store::operations(&db, cs.id).await.expect("operations");
    let order: Vec<(i32, String)> = ops
        .iter()
        .map(|o| {
            (
                o.seq,
                o.target["view"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(order, vec![(1, "a".to_owned()), (2, "b".to_owned())]);

    cleanup(&db, author).await;
}

#[tokio::test]
async fn abandon_only_when_empty_and_close_only_when_not() {
    let db = skip_if_no_db!(test_db().await);
    let author = Uuid::now_v7();

    let empty = open(&db, author, Layer::Project).await;
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let err = store::close(&mut tx, empty.id, None, &seal())
        .await
        .expect_err("empty close");
    assert_eq!(conflict_code(err), "changeset_empty");
    let abandoned = store::abandon(&mut tx, empty.id, None)
        .await
        .expect("abandon");
    attome_db::tx::commit(tx).await.expect("commit");
    assert_eq!(abandoned.status, ChangesetStatus::Abandoned);

    let busy = open(&db, author, Layer::Project).await;
    record_committed(
        &db,
        &request(author, Some(busy.id), RecordingMode::Required),
        view_op("kept"),
    )
    .await;
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let err = store::abandon(&mut tx, busy.id, None)
        .await
        .expect_err("non-empty abandon");
    assert_eq!(conflict_code(err), "changeset_not_empty");
    drop(tx);

    // Abandoned is final.
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    let err = store::abandon(&mut tx, empty.id, None)
        .await
        .expect_err("abandon twice");
    assert_eq!(conflict_code(err), "changeset_not_open");
    drop(tx);

    cleanup(&db, author).await;
}

#[tokio::test]
async fn selection_and_the_layer_rule() {
    let db = skip_if_no_db!(test_db().await);
    let author = Uuid::now_v7();

    // Required mode, nothing open: refused before any work.
    let none = request(author, None, RecordingMode::Required);
    assert_eq!(
        conflict_code(none.preflight(&db).await.expect_err("required")),
        "changeset_required"
    );
    // A header naming no changeset.
    let missing = request(author, Some(Uuid::now_v7()), RecordingMode::Required);
    assert_eq!(
        conflict_code(missing.preflight(&db).await.expect_err("missing")),
        "changeset_not_open"
    );

    // Layer rule on update: a project changeset may change project rows only.
    let project = open(&db, author, Layer::Project).await;
    let recording = request(author, None, RecordingMode::Required);
    recording.preflight(&db).await.expect("preflight");
    assert!(recording.check_owner(Layer::Project).is_ok());
    assert_eq!(
        conflict_code(
            recording
                .check_owner(Layer::Platform)
                .expect_err("platform row")
        ),
        "layer_mismatch"
    );

    // A platform changeset stamps platform and may change platform rows.
    let platform = open(&db, author, Layer::Platform).await;
    let by_header = request(author, Some(platform.id), RecordingMode::Required);
    by_header.preflight(&db).await.expect("preflight");
    assert_eq!(by_header.stamp().ok(), Some(Layer::Platform));
    assert!(by_header.check_owner(Layer::Platform).is_ok());
    assert!(by_header.check_owner(Layer::Project).is_err());

    // Two open changesets and no header: ambiguous.
    let ambiguous = request(author, None, RecordingMode::Required);
    assert_eq!(
        conflict_code(ambiguous.preflight(&db).await.expect_err("ambiguous")),
        "changeset_ambiguous"
    );

    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    store::abandon(&mut tx, project.id, None)
        .await
        .expect("abandon");
    store::abandon(&mut tx, platform.id, None)
        .await
        .expect("abandon");
    attome_db::tx::commit(tx).await.expect("commit");
    cleanup(&db, author).await;
}

#[tokio::test]
async fn auto_mode_records_one_request_into_one_closed_automatic_changeset() {
    let db = skip_if_no_db!(test_db().await);
    let author = Uuid::now_v7();

    let recording = request(author, None, RecordingMode::Auto);
    let resolved = recording.preflight(&db).await.expect("preflight");
    assert_eq!(resolved.changeset_id, None, "preflight writes nothing");
    assert_eq!(recording.stamp().ok(), Some(Layer::Project));

    record_committed(&db, &recording, view_op("one")).await;
    record_committed(&db, &recording, view_op("two")).await;

    let ids: Vec<(Uuid, String, String, i32)> =
        sqlx::query_as("SELECT id, status, origin, op_count FROM changeset WHERE author_ref = $1")
            .bind(author)
            .fetch_all(&db)
            .await
            .expect("changesets");
    assert_eq!(ids.len(), 1, "one automatic changeset per request");
    let (id, status, origin, op_count) = ids[0].clone();
    assert_eq!(
        (status.as_str(), origin.as_str(), op_count),
        ("closed", "auto", 2)
    );

    // Once sealed, a further write of the same request opens a fresh one.
    let mut tx = attome_db::tx::begin(&db).await.expect("begin");
    assert!(
        store::seal_automatic(&mut tx, id, &seal())
            .await
            .expect("seal")
    );
    attome_db::tx::commit(tx).await.expect("commit");
    record_committed(&db, &recording, view_op("three")).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM changeset WHERE author_ref = $1")
        .bind(author)
        .fetch_one(&db)
        .await
        .expect("count");
    assert_eq!(count, 2);

    cleanup(&db, author).await;
}
