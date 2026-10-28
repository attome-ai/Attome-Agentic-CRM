//! D-358 — the multi-consumer change feed, against a real
//! `entity_change_event` + `change_consumer_cursor`
//! (migrations `0091`, `0104`, `0105`).
//!
//! Four properties, all of which the single-consumer `processed_at` claim
//! either lacked or actively broke:
//!
//! 1. **Two consumers advance independently over the same rows.** This is the
//!    whole point: attome-workflow's destructive claim meant a second consumer
//!    silently ate its events.
//! 2. **A write transaction longer than any plausible time lag still has its
//!    event consumed.** This is the one a `created_at`-keyed cursor gets
//!    wrong, and gets wrong *silently* — the event is simply never read. The
//!    test writes an event in a transaction that stays open across a poll,
//!    polls (must see nothing — it is not yet visible), commits, and polls
//!    again (must now see it), which is exactly the sequence the naive cursor
//!    loses.
//! 3. **The cursor never rewinds**, so an overlapping second worker of the
//!    same consumer cannot re-deliver the feed.
//! 4. **Prune respects the slowest cursor**, so retention cannot delete
//!    events a lagging consumer has not read.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://...@localhost:5556/attome_test"
//! cargo test -p attome-core --test change_feed
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_core::change_feed::{self, ChangeOperation};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use std::sync::OnceLock;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// The visibility horizon these tests depend on
/// (`pg_snapshot_xmin(pg_current_snapshot())`) is a property of the whole
/// PostgreSQL cluster, not of one database or one connection: ANY open write
/// transaction anywhere holds it down, and holds every consumer's feed with
/// it. That is the design's documented cost (migration `0104`), and it is
/// exactly what `an_event_from_a_long_write_transaction_is_never_skipped`
/// deliberately provokes — so running these tests in parallel would have that
/// one test stall the other four.
///
/// Serialized rather than "fixed": the coupling is real and intended, and a
/// test that hid it would be testing something the production path does not
/// do. `drain_at_least` still polls, because a sibling test *binary* can hold
/// the horizon down too and the contract is bounded staleness, not instant
/// delivery.
/// `tokio::sync::Mutex`, not `std`'s: the guard is held across `.await`
/// points for the whole test body, which is exactly what a blocking guard must
/// never do (guidelines §10, and clippy's `await_holding_lock`).
async fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

/// How long a drain waits for the horizon to move past events it knows are
/// committed. Generous: a slow CI runner with a concurrent suite holding a
/// write transaction is the case this absorbs.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

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

/// A consumer name unique to this test run. Cursors are keyed by name and the
/// test database is shared, so a fixed name would inherit a previous run's
/// position and read nothing.
fn consumer_name(suffix: &str) -> String {
    format!("test/{}-{}", suffix, Uuid::now_v7())
}

/// An entity logicalname no other test writes to, so a batch read can assert
/// on exact contents rather than filtering a shared feed.
fn entity_name() -> String {
    format!("test_feed_{}", Uuid::now_v7().simple())
}

async fn emit_committed(db: &DbPool, entity: &str, record_id: Uuid, op: ChangeOperation) {
    let mut tx = db.begin().await.expect("begin");
    change_feed::emit(&mut tx, entity, record_id, op)
        .await
        .expect("emit must succeed");
    tx.commit().await.expect("commit");
}

/// Reads every currently-visible event for `entity`, advancing the consumer's
/// cursor over everything it reads — which is what a real consumer does. The
/// feed is shared with whatever else the test database is doing, so this
/// filters by entity while still advancing past foreign rows.
async fn drain_once(db: &DbPool, consumer: &str, entity: &str) -> Vec<(Uuid, String)> {
    let mut conn = db.acquire().await.expect("acquire");
    let mut out = Vec::new();
    loop {
        let batch = change_feed::read_batch(&mut conn, consumer, 100)
            .await
            .expect("read_batch must succeed");
        if batch.is_empty() {
            break;
        }
        for event in &batch {
            if event.entity_logicalname == entity {
                out.push((event.record_id, event.operation.clone()));
            }
            change_feed::advance(&mut conn, consumer, event)
                .await
                .expect("advance must succeed");
        }
    }
    out
}

/// Drains until `want` events for `entity` have arrived, or [`DRAIN_TIMEOUT`]
/// elapses. Accumulates across polls, because the horizon can move mid-drain
/// and a partial batch is a legitimate intermediate state, not a failure.
async fn drain_at_least(
    db: &DbPool,
    consumer: &str,
    entity: &str,
    want: usize,
) -> Vec<(Uuid, String)> {
    let deadline = std::time::Instant::now() + DRAIN_TIMEOUT;
    let mut seen = Vec::new();
    loop {
        seen.extend(drain_once(db, consumer, entity).await);
        if seen.len() >= want || std::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn two_consumers_advance_independently_over_the_same_rows() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = entity_name();
    let a = consumer_name("consumer-a");
    let b = consumer_name("consumer-b");

    let r1 = Uuid::now_v7();
    let r2 = Uuid::now_v7();
    emit_committed(&db, &entity, r1, ChangeOperation::Create).await;
    emit_committed(&db, &entity, r2, ChangeOperation::Delete).await;

    let seen_a = drain_at_least(&db, &a, &entity, 2).await;
    // B reads the same rows A already consumed — under the old destructive
    // claim this would be empty, and nothing would report the loss.
    let seen_b = drain_at_least(&db, &b, &entity, 2).await;

    assert_eq!(
        seen_a,
        vec![(r1, "create".to_string()), (r2, "delete".to_string())],
        "consumer A must see both events, in commit order"
    );
    assert_eq!(
        seen_b, seen_a,
        "consumer B must see exactly the same events — a cursor read is \
         non-destructive, unlike the processed_at claim it coexists with"
    );

    // A second drain by the same consumer sees nothing new: the cursor stuck.
    assert!(
        drain_once(&db, &a, &entity).await.is_empty(),
        "a consumer must not re-read events it already advanced past"
    );
}

#[tokio::test]
async fn an_event_from_a_long_write_transaction_is_never_skipped() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = entity_name();
    let consumer = consumer_name("long-tx");

    // A long write transaction opens and writes its event. `created_at`
    // defaults to NOW() = this transaction's START, so from here on the event
    // is stamped with a timestamp that a polling consumer is about to move
    // past.
    let mut slow_tx = db.begin().await.expect("begin slow tx");
    let slow_record = Uuid::now_v7();
    change_feed::emit(&mut slow_tx, &entity, slow_record, ChangeOperation::Update)
        .await
        .expect("emit inside the long transaction");

    // Meanwhile a short transaction commits an event and the consumer polls,
    // advancing its cursor past the slow transaction's `created_at`.
    let fast_record = Uuid::now_v7();
    emit_committed(&db, &entity, fast_record, ChangeOperation::Create).await;

    // NOT `drain_at_least`: the point of this poll is what is NOT there yet,
    // and the slow transaction is holding the horizon down, so the committed
    // fast event is not visible either. Both are correct — the cursor has not
    // advanced past anything, which is what makes the second poll sound.
    let first_poll = drain_once(&db, &consumer, &entity).await;
    assert!(
        !first_poll.iter().any(|(id, _)| *id == slow_record),
        "an event from a still-open transaction must never be read: {first_poll:?}"
    );

    slow_tx.commit().await.expect("commit slow tx");

    let second_poll = drain_at_least(&db, &consumer, &entity, 2 - first_poll.len()).await;
    let all: Vec<_> = first_poll
        .iter()
        .chain(second_poll.iter())
        .cloned()
        .collect();
    // The delivery guarantee is the point; the ORDER pins the other half of
    // the contract. The slow transaction took its xid first (it wrote first),
    // so it sorts first — the feed is ordered by transaction-id ASSIGNMENT,
    // not by commit time. That is sound for this feed precisely because an
    // event carries no payload: a consumer re-projects the record's CURRENT
    // state, so "stale event, fresh read" converges. A consumer that instead
    // applied event payloads in feed order would be wrong here, which is why
    // the feed does not carry payloads and this test asserts the order rather
    // than tolerating either.
    assert_eq!(
        all,
        vec![
            (slow_record, "update".to_string()),
            (fast_record, "create".to_string()),
        ],
        "the long transaction's event MUST be delivered once it commits, even \
         though the cursor already advanced past a LATER-started transaction. \
         A created_at-keyed cursor loses it here permanently and silently — \
         see migration 0104's header"
    );
}

#[tokio::test]
async fn advancing_over_an_older_event_never_rewinds_the_cursor() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = entity_name();
    let consumer = consumer_name("no-rewind");

    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    emit_committed(&db, &entity, first, ChangeOperation::Create).await;
    emit_committed(&db, &entity, second, ChangeOperation::Update).await;

    // Wait for the horizon to clear both, without advancing this consumer's
    // cursor — the advance ordering is what the test is about.
    let probe = consumer_name("no-rewind-probe");
    assert_eq!(
        drain_at_least(&db, &probe, &entity, 2).await.len(),
        2,
        "both events must become visible before the advance ordering is tested"
    );

    let mut conn = db.acquire().await.expect("acquire");
    let batch = change_feed::read_batch(&mut conn, &consumer, 1000)
        .await
        .expect("read_batch");
    let ours: Vec<_> = batch
        .iter()
        .filter(|e| e.entity_logicalname == entity)
        .collect();
    assert_eq!(ours.len(), 2, "both events must be in one batch");

    // Advance to the NEWER event first, then replay the older one — the shape
    // two overlapping workers of one consumer produce.
    change_feed::advance(&mut conn, &consumer, ours[1])
        .await
        .expect("advance to newer");
    let after_newer = change_feed::cursor(&mut conn, &consumer)
        .await
        .expect("cursor");
    change_feed::advance(&mut conn, &consumer, ours[0])
        .await
        .expect("advance to older");
    let after_older = change_feed::cursor(&mut conn, &consumer)
        .await
        .expect("cursor");

    assert_eq!(
        after_older.last_commit_xid, after_newer.last_commit_xid,
        "a late advance over an older event must be a no-op, not a rewind — \
         a rewind re-delivers an unbounded amount of the feed"
    );
}

#[tokio::test]
async fn prune_respects_the_slowest_cursor() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = entity_name();
    let fast = consumer_name("prune-fast");
    let slow = consumer_name("prune-slow");

    // `prune` is deliberately blocked by the slowest cursor in the WHOLE
    // table, so sibling tests' consumers would mask the property under test.
    // Clearing them is safe here and only here: the serialization guard means
    // no other test is mid-drain, and each test registers its own fresh
    // consumer at its start.
    //
    // The production reading of that same fact: an ABANDONED consumer blocks
    // pruning forever. That is the correct default (silently deleting a
    // lagging consumer's events is the failure the cursor exists to prevent),
    // and it is why the cursor row carries `updated_at` — a stalled-consumer
    // alarm, and deliberate removal of a decommissioned consumer's row, are
    // the operator's release valve, not a time-based override inside prune.
    sqlx::query("DELETE FROM change_consumer_cursor")
        .execute(&db)
        .await
        .expect("clear sibling cursors");

    let record = Uuid::now_v7();
    emit_committed(&db, &entity, record, ChangeOperation::Create).await;

    // The fast consumer reads and advances; the slow one registers a cursor
    // but never advances past zero.
    assert_eq!(
        drain_at_least(&db, &fast, &entity, 1).await.len(),
        1,
        "the fast consumer must actually consume the event"
    );
    let mut conn = db.acquire().await.expect("acquire");
    change_feed::cursor(&mut conn, &slow)
        .await
        .expect("register the slow cursor");

    // Mark the row processed and make it old enough for the age floor, so the
    // ONLY thing standing between it and deletion is the slow cursor.
    sqlx::query(
        "UPDATE entity_change_event \
            SET processed_at = NOW(), created_at = NOW() - INTERVAL '30 days' \
          WHERE entity_logicalname = $1",
    )
    .bind(&entity)
    .execute(&db)
    .await
    .expect("age the event");

    change_feed::prune(&mut conn, std::time::Duration::from_secs(60))
        .await
        .expect("prune must succeed");

    let survivors: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event WHERE entity_logicalname = $1",
    )
    .bind(&entity)
    .fetch_one(&db)
    .await
    .expect("count survivors");
    assert_eq!(
        survivors, 1,
        "prune must not delete an event the slowest registered cursor has not \
         reached, however old and however processed it is"
    );

    // Once the slow consumer catches up, the same prune removes it.
    assert_eq!(
        drain_at_least(&db, &slow, &entity, 1).await.len(),
        1,
        "the slow consumer must catch up before the second prune"
    );
    change_feed::prune(&mut conn, std::time::Duration::from_secs(60))
        .await
        .expect("prune must succeed");

    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM entity_change_event WHERE entity_logicalname = $1",
    )
    .bind(&entity)
    .fetch_one(&db)
    .await
    .expect("count remaining");
    assert_eq!(
        remaining, 0,
        "with every cursor past it, an old processed event must be prunable"
    );
}

#[tokio::test]
async fn every_operation_the_check_constraint_allows_can_actually_be_written() {
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = entity_name();
    let consumer = consumer_name("all-ops");

    // 0105 widened the CHECK from ('create','update'). If the Rust wire values
    // and the constraint ever disagree, this INSERT is a runtime 23514 on a
    // delete — i.e. deletes start failing in production, not in CI.
    let ops = [
        ChangeOperation::Create,
        ChangeOperation::Update,
        ChangeOperation::Delete,
        ChangeOperation::Restore,
        ChangeOperation::Purge,
    ];
    let mut expected = Vec::new();
    for op in ops {
        let record = Uuid::now_v7();
        emit_committed(&db, &entity, record, op).await;
        expected.push((record, op.as_str().to_string()));
    }

    assert_eq!(
        drain_at_least(&db, &consumer, &entity, expected.len()).await,
        expected,
        "every operation in ChangeOperation must satisfy 0105's CHECK and \
         round-trip through the feed"
    );
}

/// Y7-T4: a rewound consumer reads its events again, and the apply-once set
/// stops it applying any of them twice.
#[tokio::test]
async fn a_rewound_consumer_rereads_and_applies_each_event_once() {
    let _serial = serialize().await;
    let db = skip_if_no_db!(test_db().await);
    let consumer = consumer_name("rewind");
    let entity = entity_name();
    let first = Uuid::now_v7();
    emit_committed(&db, &entity, first, ChangeOperation::Create).await;
    emit_committed(&db, &entity, Uuid::now_v7(), ChangeOperation::Update).await;

    // Apply as a consumer does: claim, then work, in one transaction.
    let apply_all = |db: DbPool, consumer: String, entity: String| async move {
        let mut conn = db.acquire().await.expect("acquire");
        let mut applied = 0;
        loop {
            let batch = change_feed::read_batch(&mut conn, &consumer, 100)
                .await
                .expect("read");
            if batch.is_empty() {
                break;
            }
            for event in &batch {
                if event.entity_logicalname == entity
                    && change_feed::claim_apply(&mut conn, &consumer, event.id)
                        .await
                        .expect("claim")
                {
                    applied += 1;
                }
                change_feed::advance(&mut conn, &consumer, event)
                    .await
                    .expect("advance");
            }
        }
        applied
    };
    let deadline = std::time::Instant::now() + DRAIN_TIMEOUT;
    let mut applied = 0;
    while applied < 2 && std::time::Instant::now() < deadline {
        applied += apply_all(db.clone(), consumer.clone(), entity.clone()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(applied, 2, "both events are applied once");

    let seq: i64 = sqlx::query_scalar("SELECT seq FROM entity_change_event WHERE record_id = $1")
        .bind(first)
        .fetch_one(&db)
        .await
        .expect("read seq");
    let mut conn = db.acquire().await.expect("acquire");
    change_feed::rewind(&mut conn, &consumer, change_feed::RewindTo::Seq(seq))
        .await
        .expect("rewind");
    drop(conn);
    let reread = drain_at_least(&db, &consumer, &entity, 2).await;
    assert_eq!(reread.len(), 2, "the rewound consumer reads both again");
    let mut conn = db.acquire().await.expect("acquire");
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM change_consumer_applied WHERE consumer = $1")
            .bind(&consumer)
            .fetch_one(&mut *conn)
            .await
            .expect("count applied");
    assert_eq!(rows, 2, "nothing was applied twice");
    assert!(matches!(
        change_feed::rewind(
            &mut conn,
            "no-such-consumer",
            change_feed::RewindTo::Seq(seq)
        )
        .await,
        Err(attome_types::AppError::NotFound)
    ));
}

/// L7-T2: a write made inside a flow run's provenance scope names the run and
/// the `flow` channel on its event; one made outside leaves both NULL.
#[tokio::test]
async fn a_flow_write_names_its_run_on_the_change_event() {
    use attome_core::provenance_scope::{self, FLOW_CHANNEL, Provenance};
    let db = skip_if_no_db!(test_db().await);
    let _guard = serialize().await;
    let entity = entity_name();
    let run = Uuid::now_v7();
    let (flow_record, plain_record) = (Uuid::now_v7(), Uuid::now_v7());

    provenance_scope::scope(
        Provenance {
            channel: FLOW_CHANNEL,
            run_id: Some(run),
        },
        emit_committed(&db, &entity, flow_record, ChangeOperation::Update),
    )
    .await;
    emit_committed(&db, &entity, plain_record, ChangeOperation::Update).await;

    let rows: Vec<(Uuid, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT record_id, channel, flow_run_id FROM entity_change_event \
         WHERE entity_logicalname = $1 ORDER BY id",
    )
    .bind(&entity)
    .fetch_all(&db)
    .await
    .expect("read events");
    assert_eq!(
        rows,
        vec![
            (flow_record, Some(FLOW_CHANNEL.to_string()), Some(run)),
            (plain_record, None, None),
        ]
    );
}

/// Y7-T3: a fake clock in the year 2000, so the cutoff covers only this
/// test's partitions and never the shared database's real days. A day past
/// retention is dropped unless it holds an event no consumer has processed;
/// a row of a day that had no partition yet moves out of the default
/// partition when the day gets one.
#[tokio::test]
async fn change_feed_retention_drops_expired_days_with_a_fake_clock() {
    use attome_core::change_feed::partitions;
    let db = skip_if_no_db!(test_db().await);
    let _serial = serialize().await;
    let day = |s: &str| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
    let start = day("2000-01-20");
    let later = day("2000-02-20");

    // What an interrupted earlier run may have left in the year 2000.
    sqlx::query("DELETE FROM entity_change_event WHERE created_at < '2001-01-01'")
        .execute(&db)
        .await
        .unwrap();
    partitions::drop_expired(&db, later, 14).await.unwrap();

    // An unprocessed event of 2000-01-21, before that day has a partition.
    let held: Uuid = sqlx::query_scalar(
        "INSERT INTO entity_change_event (entity_logicalname, record_id, operation, created_at) \
         VALUES ($1, $2, 'update', '2000-01-21 10:00:00+00') RETURNING id",
    )
    .bind(entity_name())
    .bind(Uuid::now_v7())
    .fetch_one(&db)
    .await
    .unwrap();

    assert_eq!(partitions::ensure_ahead(&db, start).await.unwrap(), 4);
    assert_eq!(partitions::ensure_ahead(&db, start).await.unwrap(), 0);
    let home: String = sqlx::query_scalar(
        "SELECT tableoid::regclass::text FROM entity_change_event WHERE id = $1",
    )
    .bind(held)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(home, partitions::partition_name(day("2000-01-21")));

    // A month later, with 14 days' retention: every 2000-01 day is past it,
    // but the 21st still holds the unprocessed event.
    let mut dropped = partitions::drop_expired(&db, later, 14).await.unwrap();
    dropped.sort();
    assert_eq!(
        dropped,
        ["2000-01-20", "2000-01-22", "2000-01-23"]
            .map(|d| partitions::partition_name(day(d)))
            .to_vec()
    );

    // Once the event is gone the day goes too, and so do applied rows that
    // named it.
    sqlx::query("INSERT INTO change_consumer_applied (consumer, event_id) VALUES ($1, $2)")
        .bind(consumer_name("y7t3"))
        .bind(held)
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM entity_change_event WHERE id = $1")
        .bind(held)
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        partitions::drop_expired(&db, later, 14).await.unwrap(),
        vec![partitions::partition_name(day("2000-01-21"))]
    );
    assert!(partitions::prune_applied(&db).await.unwrap() >= 1);
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM change_consumer_applied WHERE event_id = $1")
            .bind(held)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(left, 0);
}
