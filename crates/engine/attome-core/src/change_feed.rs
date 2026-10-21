//! The entity change feed — `entity_change_event` (migration `0091`)
//! plus the per-consumer cursor migration `0104` added and the
//! delete/restore/purge operations migration `0105` added — both D-358.
//!
//! **Why this lives in `attome-core` and not in `attome-server`.** `0091`'s own
//! header calls the outbox "a platform-level fact, not a workflow-owned one",
//! but its only writer was `attome_server::entity_mutation`, which is the top of
//! the engine layer. `attome-metadata`'s purge path (`purge::scrub_record`) sits
//! *below* `attome-server` and must emit too, and a search/notification consumer
//! would sit beside it. A shared writer therefore has to live in the crate
//! both can see. `attome-core` is that crate, and the outbox is exactly the
//! kind of concept guidelines §1 says belongs here: more than one engine
//! genuinely owns it.
//!
//! **Two consumption models, deliberately.**
//!
//! * `processed_at` — attome-workflow's original destructive claim
//!   (`UPDATE ... WHERE processed_at IS NULL ... FOR UPDATE SKIP LOCKED`).
//!   Unchanged, still workflow's, still correct *for exactly one consumer*.
//! * [`read_batch`]/[`advance`] — a non-destructive per-consumer cursor. Every
//!   consumer added from D-358 onward uses this. Nothing about it touches
//!   `processed_at`, so the two coexist over the same rows.
//!
//! A consumer must NOT use both, and a second consumer must never use the
//! first: see `0104`'s header for what the race silently does.
//!
//! **Ordering, stated exactly.** The feed is ordered by transaction-id
//! *assignment* (when a transaction first wrote), not by commit time. A long
//! transaction that started before a short one is delivered before it, even
//! though it committed after. That is sound here for one specific reason: a
//! feed row carries no payload — only `(entity, record_id, operation)` — so a
//! consumer re-projects the record's CURRENT state and converges regardless of
//! the order it learns about it. A consumer that applied event payloads in
//! feed order would be wrong, which is why there are no payloads to apply.
//! `change_feed.rs`'s
//! `an_event_from_a_long_write_transaction_is_never_skipped` pins this.

use attome_types::AppError;
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use uuid::Uuid;

/// Operations the feed carries. Kept as a typed enum rather than bare strings
/// so a new operation is a compile error at every match site instead of a
/// silently-ignored row, and so the wire values can never drift from
/// `0105`'s `CHECK` constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeOperation {
    Create,
    Update,
    /// Soft delete (`is_active = false`) — of the target, or of a dependent
    /// record a `CascadeDeactivate` policy touched in another entity.
    Delete,
    /// A soft-deleted record was made live again. A consumer holding a derived
    /// copy must re-add it; without this the record is unfindable forever.
    Restore,
    /// The record's business columns were scrubbed to NULL. A consumer holding
    /// a derived copy of that text must ERASE it, not merely hide it — the
    /// copy inherits the original's erasure obligation
    /// (P-data-protection-governance).
    Purge,
}

impl ChangeOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeOperation::Create => "create",
            ChangeOperation::Update => "update",
            ChangeOperation::Delete => "delete",
            ChangeOperation::Restore => "restore",
            ChangeOperation::Purge => "purge",
        }
    }

    /// `None` for an unrecognised value rather than an error: a consumer
    /// running older code than the writer must skip an operation it does not
    /// understand, not crash the drain. The reconciliation scan is what
    /// eventually repairs anything a skip left behind.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "create" => Some(ChangeOperation::Create),
            "update" => Some(ChangeOperation::Update),
            "delete" => Some(ChangeOperation::Delete),
            "restore" => Some(ChangeOperation::Restore),
            "purge" => Some(ChangeOperation::Purge),
            _ => None,
        }
    }
}

/// One feed row as a cursor consumer sees it.
#[derive(Clone, Debug)]
pub struct ChangeEvent {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub record_id: Uuid,
    /// The raw column value. Use [`ChangeEvent::operation`] to get the typed
    /// form; a row whose operation this build does not recognise still
    /// advances the cursor.
    pub operation: String,
    /// Set only for a row [`emit_named`] wrote (e.g. `"sla.breached"`);
    /// `None` for an ordinary entity-change row [`emit`]/[`emit_many`]
    /// wrote. REVIEW-2026-09-02 finding #3 — added so a consumer (M62's
    /// `attome_events::filter::SubscriptionFilter`) can match on it.
    pub event_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Y7-T1: the attributes the write changed (empty for a row written
    /// before the outbox carried them, or by a path that does not know).
    pub changed_attributes: Vec<String>,
}

/// M1-T1: the event name on a merge survivor's change event, which a
/// workflow `merge` trigger matches.
pub const MERGED_EVENT: &str = "record.merged";

/// Y7-T2: what a write changed, for its outbox row.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChangePayload {
    pub changed_attributes: Vec<String>,
    /// The changed attributes' values before and after, by name; a sensitive
    /// attribute's value is `{"ref": true}`.
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    /// A16-T2: the record's row version after this write, set by the
    /// generic update path, so a stale update can tell exactly what each
    /// version it missed changed. `None` for any other write.
    pub row_version: Option<i64>,
}

/// Y7-T2: [`emit`] with what changed, and optionally an event name (a merge
/// survivor's `record.merged`), in the caller's transaction.
pub async fn emit_with(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    record_id: Uuid,
    operation: ChangeOperation,
    event_name: Option<&str>,
    payload: &ChangePayload,
) -> Result<(), AppError> {
    let (initiator, agent_session) = crate::agent_scope::columns();
    sqlx::query(
        "INSERT INTO entity_change_event \
             (entity_logicalname, record_id, operation, event_name, changed_attributes, before, after, \
              row_version, initiator, agent_session_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(operation.as_str())
    .bind(event_name)
    .bind(&payload.changed_attributes)
    .bind(&payload.before)
    .bind(&payload.after)
    .bind(payload.row_version)
    .bind(initiator)
    .bind(agent_session)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

impl ChangeEvent {
    pub fn operation(&self) -> Option<ChangeOperation> {
        ChangeOperation::parse(&self.operation)
    }
}

/// Where a consumer's cursor currently sits.
#[derive(Clone, Copy, Debug)]
pub struct CursorPosition {
    /// Exclusive lower bound, as a 64-bit transaction id. `0` for a consumer
    /// that has never run, which reads the whole retained feed.
    pub last_commit_xid: i64,
    pub last_id: Option<Uuid>,
}

/// Writes one feed row in the CALLER'S transaction (AK3-T1: every writer here
/// also records who drove the change, a person or an agent with its session,
/// from [`crate::agent_scope`]). This is the whole point of
/// an outbox: an event can never exist for a write that rolled back, or be
/// lost for one that committed. Passing a pooled connection instead of the
/// mutating transaction's own would reintroduce exactly the dual-write bug
/// `0091` exists to prevent.
pub async fn emit(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    record_id: Uuid,
    operation: ChangeOperation,
) -> Result<(), AppError> {
    let (initiator, agent_session) = crate::agent_scope::columns();
    sqlx::query(
        "INSERT INTO entity_change_event \
             (entity_logicalname, record_id, operation, initiator, agent_session_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(operation.as_str())
    .bind(initiator)
    .bind(agent_session)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// M62 §3 "Domain events": writes one feed row carrying a non-NULL
/// `event_name` — the additive column migration `0145` added, and the shape
/// M62 Phase 2 describes ("engines publish named events... through the same
/// outbox with `event_name`") but that no writer had used yet as of this
/// crate's own `event_name` column comment. `event_name` is a caller-chosen
/// dotted name (e.g. `sla.breached`, `sla.warning`) — this function does not
/// validate its shape, same posture `operation` already has for a caller
/// passing a typed [`ChangeOperation`].
///
/// Full M62 Phase 2 subscription routing (`attome-events`' filter/dispatch
/// reading `event_name`) is not wired to this yet — that remains real,
/// separate follow-up work (M62's own plan already tracks it as Phase 2).
/// This function only makes the event durable and visible in the outbox for
/// whenever that lands; the caller (M73's `sla.rs`/`clock.rs`) additionally
/// acts on it directly and synchronously, the same "add the publish call,
/// call the consumer directly" shape `sla.rs`'s own module doc already uses
/// for `sweep_breaches` not yet being a `EngineJob`.
pub async fn emit_named(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    record_id: Uuid,
    operation: ChangeOperation,
    event_name: &str,
) -> Result<(), AppError> {
    let (initiator, agent_session) = crate::agent_scope::columns();
    sqlx::query(
        "INSERT INTO entity_change_event \
             (entity_logicalname, record_id, operation, event_name, initiator, agent_session_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(operation.as_str())
    .bind(event_name)
    .bind(initiator)
    .bind(agent_session)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Batch form of [`emit`] for a cascade, which touches an unbounded number of
/// records in one statement. One multi-row INSERT via `UNNEST`, not a loop of
/// round trips — a cascade over ten thousand dependents would otherwise turn
/// one `UPDATE` into ten thousand INSERTs inside an open transaction
/// (guidelines §14's N+1 rule, and §4's "keep transactions short").
///
/// All rows share the emitting transaction's `commit_xid`; `id` orders them
/// within it.
pub async fn emit_many(
    conn: &mut PgConnection,
    entity_logicalname: &str,
    record_ids: &[Uuid],
    operation: ChangeOperation,
) -> Result<(), AppError> {
    if record_ids.is_empty() {
        return Ok(());
    }
    let (initiator, agent_session) = crate::agent_scope::columns();
    sqlx::query(
        "INSERT INTO entity_change_event \
             (entity_logicalname, record_id, operation, initiator, agent_session_id) \
         SELECT $1, r, $3, $4, $5 FROM UNNEST($2::uuid[]) AS r",
    )
    .bind(entity_logicalname)
    .bind(record_ids)
    .bind(operation.as_str())
    .bind(initiator)
    .bind(agent_session)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Transaction-typed convenience wrapper over [`emit`], for the many call
/// sites that hold a `Transaction` rather than a bare `PgConnection`.
pub async fn emit_tx(
    tx: &mut Transaction<'_, Postgres>,
    entity_logicalname: &str,
    record_id: Uuid,
    operation: ChangeOperation,
) -> Result<(), AppError> {
    emit(tx, entity_logicalname, record_id, operation).await
}

/// Reads this consumer's current position, creating a zero cursor on first
/// call. `ON CONFLICT DO NOTHING` then `SELECT` rather than an upsert with
/// `RETURNING`: two consumers racing their very first read must both end up
/// reading the same existing row, not have one of them reset the other's
/// position to zero.
pub async fn cursor(conn: &mut PgConnection, consumer: &str) -> Result<CursorPosition, AppError> {
    sqlx::query(
        "INSERT INTO change_consumer_cursor (consumer, max_lag_hours) VALUES ($1, $2) \
         ON CONFLICT (consumer) DO NOTHING",
    )
    .bind(consumer)
    .bind(max_lag_hours_for(consumer))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    let row: (i64, Option<Uuid>) = sqlx::query_as(
        "SELECT last_commit_xid::text::bigint, last_id \
         FROM change_consumer_cursor WHERE consumer = $1",
    )
    .bind(consumer)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)?;

    Ok(CursorPosition {
        last_commit_xid: row.0,
        last_id: row.1,
    })
}

/// Reads up to `limit` events after `consumer`'s cursor, oldest first.
///
/// The `commit_xid < pg_snapshot_xmin(pg_current_snapshot())` gate is the
/// correctness condition, not an optimisation: it restricts the read to
/// transactions that have finished, which is what makes advancing the cursor
/// safe. Dropping it — or replacing it with a time lag — reintroduces the
/// silent event loss `0104`'s header describes.
///
/// Reading does not mark anything. A consumer that crashes mid-batch re-reads
/// the same events on restart, so item processing must be idempotent.
pub async fn read_batch(
    conn: &mut PgConnection,
    consumer: &str,
    limit: i64,
) -> Result<Vec<ChangeEvent>, AppError> {
    let position = cursor(&mut *conn, consumer).await?;

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        Uuid,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Vec<String>,
    )> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, operation, event_name, created_at, \
                changed_attributes \
         FROM entity_change_event \
         WHERE commit_xid > $1::text::xid8 \
           AND commit_xid < pg_snapshot_xmin(pg_current_snapshot()) \
         ORDER BY commit_xid, id \
         LIMIT $2",
    )
    .bind(position.last_commit_xid.to_string())
    .bind(limit)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                entity_logicalname,
                record_id,
                operation,
                event_name,
                created_at,
                changed_attributes,
            )| ChangeEvent {
                id,
                entity_logicalname,
                record_id,
                operation,
                event_name,
                created_at,
                changed_attributes,
            },
        )
        .collect())
}

/// Z3-T5: a position before every event a transaction still open could
/// commit, and after every event already finished. A reader that starts here
/// misses nothing written from now on and reads nothing older.
pub async fn horizon(conn: &mut PgConnection) -> Result<CursorPosition, AppError> {
    let xmin: i64 =
        sqlx::query_scalar("SELECT pg_snapshot_xmin(pg_current_snapshot())::text::bigint")
            .fetch_one(conn)
            .await
            .map_err(AppError::internal)?;
    Ok(CursorPosition {
        last_commit_xid: xmin - 1,
        last_id: None,
    })
}

/// Z3-T5: up to `limit` finished events after `position`, oldest first, and
/// the position after the last of them (`position` itself when none).
///
/// The same visibility gate as [`read_batch`]
/// (`commit_xid < pg_snapshot_xmin(pg_current_snapshot())`), but the
/// position is the caller's, held in memory, not a stored consumer cursor;
/// and it is exact within one transaction's events (`(commit_xid, id)`), so
/// a batch that ends inside one transaction resumes at the next event.
pub async fn read_after(
    conn: &mut PgConnection,
    position: CursorPosition,
    limit: i64,
) -> Result<(Vec<ChangeEvent>, CursorPosition), AppError> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        Uuid,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Vec<String>,
        i64,
    )> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, operation, event_name, created_at, \
                changed_attributes, commit_xid::text::bigint \
         FROM entity_change_event \
         WHERE (commit_xid > $1::text::xid8 \
                OR (commit_xid = $1::text::xid8 AND id > $2)) \
           AND commit_xid < pg_snapshot_xmin(pg_current_snapshot()) \
         ORDER BY commit_xid, id \
         LIMIT $3",
    )
    .bind(position.last_commit_xid.to_string())
    .bind(position.last_id.unwrap_or(Uuid::nil()))
    .bind(limit)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;

    let next = rows.last().map_or(position, |row| CursorPosition {
        last_commit_xid: row.7,
        last_id: Some(row.0),
    });
    let events = rows
        .into_iter()
        .map(
            |(
                id,
                entity_logicalname,
                record_id,
                operation,
                event_name,
                created_at,
                changed_attributes,
                _,
            )| ChangeEvent {
                id,
                entity_logicalname,
                record_id,
                operation,
                event_name,
                created_at,
                changed_attributes,
            },
        )
        .collect();
    Ok((events, next))
}

/// Advances `consumer`'s cursor past `event`.
///
/// Call this AFTER the batch's work is durable, and never in the same
/// transaction as work that might roll back independently — the cursor is the
/// only record that the work happened.
///
/// The `GREATEST` guard makes a late or duplicated advance a no-op instead of
/// a rewind: two workers of the same consumer that overlap must not be able to
/// move the cursor backwards and re-deliver an arbitrary amount of the feed.
pub async fn advance(
    conn: &mut PgConnection,
    consumer: &str,
    event: &ChangeEvent,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE change_consumer_cursor \
            SET last_commit_xid = GREATEST( \
                    last_commit_xid, \
                    (SELECT commit_xid FROM entity_change_event WHERE id = $2) \
                ), \
                last_id = $2, \
                last_created_at = $3, \
                updated_at = NOW() \
          WHERE consumer = $1",
    )
    .bind(consumer)
    .bind(event.id)
    .bind(event.created_at)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Y7-T4: where to move a consumer's cursor back to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RewindTo {
    /// The first event at or after this global sequence number.
    Seq(i64),
    /// The first event written at or after this time.
    Time(chrono::DateTime<chrono::Utc>),
}

/// Y7-T4: moves `consumer`'s cursor back so it reads again from `to`, within
/// what the feed still holds. `NotFound` for an unknown consumer;
/// `Validation` when the feed no longer holds events from that point (they
/// were pruned) or holds none after it. An expired consumer becomes active
/// again. Consumers apply idempotently ([`claim_apply`]), so reading an
/// event again never applies it twice.
pub async fn rewind(conn: &mut PgConnection, consumer: &str, to: RewindTo) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM change_consumer_cursor WHERE consumer = $1)",
    )
    .bind(consumer)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let (oldest_seq, oldest_at): (Option<i64>, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT min(seq), min(created_at) FROM entity_change_event")
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    let retained = match to {
        RewindTo::Seq(seq) => oldest_seq.is_some_and(|o| o <= seq),
        RewindTo::Time(at) => oldest_at.is_some_and(|o| o <= at),
    };
    if !retained {
        return Err(AppError::Validation(
            "the change feed no longer holds events from that point".into(),
        ));
    }
    let first: Option<i64> = match to {
        RewindTo::Seq(seq) => sqlx::query_scalar(
            "SELECT min(commit_xid::text::bigint) FROM entity_change_event WHERE seq >= $1",
        )
        .bind(seq),
        RewindTo::Time(at) => sqlx::query_scalar(
            "SELECT min(commit_xid::text::bigint) FROM entity_change_event WHERE created_at >= $1",
        )
        .bind(at),
    }
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(first) = first else {
        return Err(AppError::Validation(
            "the change feed holds no events after that point".into(),
        ));
    };
    sqlx::query(
        "UPDATE change_consumer_cursor \
            SET last_commit_xid = ($2 - 1)::text::xid8, last_id = NULL, \
                status = 'active', expired_at = NULL, updated_at = NOW() \
          WHERE consumer = $1",
    )
    .bind(consumer)
    .bind(first)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Y7-T4: records that `consumer` applies `event_id`, in the consumer's own
/// transaction. `false` when it already did: skip the event. A crash after
/// the work commits but before the cursor advances re-reads the event and
/// finds it claimed.
pub async fn claim_apply(
    conn: &mut PgConnection,
    consumer: &str,
    event_id: Uuid,
) -> Result<bool, AppError> {
    let inserted = sqlx::query(
        "INSERT INTO change_consumer_applied (consumer, event_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(consumer)
    .bind(event_id)
    .execute(conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(inserted == 1)
}

/// M01 §7 C-04 — rows deleted per `DELETE` inside one batch of [`prune`]'s
/// loop. A first-ever run against years of unpruned history (D-358 shipped
/// with no caller — see that item) can be an arbitrarily large backlog;
/// `LIMIT` bounds every single statement/transaction to a modest size
/// regardless, instead of one unbounded `DELETE` holding a lock over the
/// whole backlog at once (guidelines §4 "keep transactions short", §9
/// "bounded batch sizes").
const PRUNE_BATCH_LIMIT: i64 = 10_000;

/// M01 §7 C-04 — the advisory-lock key [`prune`] takes for every batch.
/// `attome-core`'s own namespace (guidelines §2's
/// `"{crate}/{operation}:{resource}"` convention); no per-resource suffix,
/// since there is exactly one feed table to prune.
const PRUNE_LOCK_KEY: &str = "attome-core/change-feed-prune";

/// L7-T1: how far behind an outside consumer (a webhook subscription) may
/// fall before it is expired: a week.
pub const DEFAULT_MAX_LAG_HOURS: i32 = 168;
/// L7-T1: the platform's own consumers get a month.
pub const INTERNAL_MAX_LAG_HOURS: i32 = 720;
/// The name prefixes of the platform's own consumers.
const INTERNAL_PREFIXES: &[&str] = &[
    "attome-workflow/",
    "attome-search/",
    "mdm/",
    "catalog/",
    "attome-service/",
    "attome-sales/",
    "attome-commission/",
    "attome-notification/",
];

/// L7-T1: the lag a new cursor for `consumer` allows.
pub fn max_lag_hours_for(consumer: &str) -> i32 {
    if INTERNAL_PREFIXES.iter().any(|p| consumer.starts_with(p)) {
        INTERNAL_MAX_LAG_HOURS
    } else {
        DEFAULT_MAX_LAG_HOURS
    }
}

/// L7-T7: the most unread events counted per consumer; past it the count
/// reads as this value (the lag in seconds still tells how far behind).
pub const LAG_COUNT_CAP: i64 = 100_000;

/// L7-T7: how one change-feed consumer is keeping up.
#[derive(Clone, Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ConsumerHealth {
    pub consumer: String,
    /// `internal` (the platform's own) or `external` (a subscription).
    pub kind: String,
    /// `active`, or `expired` once it fell past its allowed lag.
    pub status: String,
    /// Events written after its cursor, up to [`LAG_COUNT_CAP`].
    pub lag_events: i64,
    /// Age of its oldest unread event; 0 when it has read everything.
    pub lag_seconds: f64,
    /// When it last advanced its cursor.
    pub last_read_at: chrono::DateTime<chrono::Utc>,
    /// The time of the last event it read, if any.
    pub last_event_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_lag_hours: i32,
}

/// `internal` for the platform's own consumers, `external` otherwise.
pub fn consumer_kind(consumer: &str) -> &'static str {
    if INTERNAL_PREFIXES.iter().any(|p| consumer.starts_with(p)) {
        "internal"
    } else {
        "external"
    }
}

/// One [`consumer_health`] row as read: consumer, status, unread events, lag
/// seconds, last read, last event time, allowed lag.
type HealthRow = (
    String,
    String,
    i64,
    f64,
    chrono::DateTime<chrono::Utc>,
    Option<chrono::DateTime<chrono::Utc>>,
    i32,
);

/// L7-T7: every registered consumer's lag, by name.
pub async fn consumer_health<'e, E>(db: E) -> Result<Vec<ConsumerHealth>, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<HealthRow> = sqlx::query_as(
        "SELECT c.consumer, c.status, \
                (SELECT count(*) FROM (SELECT 1 FROM entity_change_event e \
                   WHERE e.commit_xid > c.last_commit_xid LIMIT $1) unread)::bigint, \
                COALESCE((SELECT EXTRACT(EPOCH FROM now() - min(e.created_at))::float8 \
                            FROM entity_change_event e \
                           WHERE e.commit_xid > c.last_commit_xid), 0)::float8, \
                c.updated_at, c.last_created_at, c.max_lag_hours \
           FROM change_consumer_cursor c ORDER BY c.consumer",
    )
    .bind(LAG_COUNT_CAP)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(
                consumer,
                status,
                lag_events,
                lag_seconds,
                last_read_at,
                last_event_at,
                max_lag_hours,
            )| {
                ConsumerHealth {
                    kind: consumer_kind(&consumer).to_owned(),
                    consumer,
                    status,
                    lag_events,
                    lag_seconds: lag_seconds.max(0.0),
                    last_read_at,
                    last_event_at,
                    max_lag_hours,
                }
            },
        )
        .collect())
}

/// L7-T1: marks expired every active consumer whose oldest unread event is
/// older than its `max_lag_hours`, and returns their names. [`prune`] then
/// ignores them, so one stuck consumer cannot keep the whole feed forever.
/// An expired consumer keeps reading from where it is; the events pruned
/// past it are gone, which is why expiry is logged and counted for an
/// operator: each one logs a warning and counts in
/// `change_feed_consumer_expired_total`.
pub async fn expire_lagging(conn: &mut PgConnection) -> Result<Vec<String>, AppError> {
    let expired: Vec<String> = sqlx::query_scalar(
        "UPDATE change_consumer_cursor c \
            SET status = 'expired', expired_at = NOW() \
          WHERE c.status = 'active' \
            AND EXISTS ( \
                SELECT 1 FROM entity_change_event e \
                 WHERE e.commit_xid > c.last_commit_xid \
                   AND e.created_at < NOW() - make_interval(hours => c.max_lag_hours) \
            ) \
      RETURNING c.consumer",
    )
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    for consumer in &expired {
        tracing::warn!(
            consumer = %consumer,
            "change feed: consumer fell too far behind and is expired; events older than \
             retention are pruned past it, so it must resynchronise"
        );
        metrics::counter!("change_feed_consumer_expired_total", "consumer" => consumer.clone())
            .increment(1);
    }
    Ok(expired)
}

/// Deletes feed rows every consumer is finished with.
///
/// "Every consumer" is the load-bearing word, and it means both models:
///
/// * the slowest registered cursor (`MIN(last_commit_xid)`), and
/// * attome-workflow's `processed_at` claim.
///
/// A prune that respected only one of them would delete events the other had
/// not seen — the same silent loss the cursor exists to prevent, arriving from
/// the retention side instead. `min_age` is a second, independent floor so a
/// consumer that is merely *starting up* (its cursor row exists but has not
/// advanced) cannot have the feed deleted out from under it.
///
/// Runs in bounded batches (`PRUNE_BATCH_LIMIT`), each its own short
/// transaction guarded by `pg_try_advisory_xact_lock($1, hashtext($2))` on
/// [`PRUNE_LOCK_KEY`] (guidelines §2's two-argument form, bound under
/// [`crate::ADVISORY_LOCK_NAMESPACE`]) — re-acquired per batch rather than
/// held for the whole run, so a concurrent run (a second scheduler tick on
/// another node, or a slow previous run still going) only ever contends for
/// one batch at a time instead of blocking behind the entire backlog. A run
/// that loses the race for a batch stops immediately rather than spinning:
/// deleting the same, idempotent, predicate-matched rows twice is harmless,
/// but there is no reason to contend for it — the run already holding the
/// lock (or the next scheduled tick) makes further progress.
///
/// Returns the total number of rows deleted across every batch.
pub async fn prune(conn: &mut PgConnection, min_age: std::time::Duration) -> Result<u64, AppError> {
    let age_seconds = min_age.as_secs_f64();
    let mut total_deleted = 0u64;
    loop {
        let mut tx = conn.begin().await.map_err(AppError::internal)?;

        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(PRUNE_LOCK_KEY)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            break;
        }

        let deleted = sqlx::query(
            "DELETE FROM entity_change_event \
              WHERE id IN ( \
                  SELECT e.id FROM entity_change_event e \
                   WHERE e.processed_at IS NOT NULL \
                     AND e.created_at < NOW() - make_interval(secs => $1) \
                     AND e.commit_xid <= COALESCE( \
                             (SELECT MIN(last_commit_xid) FROM change_consumer_cursor \
                               WHERE status = 'active'), \
                             e.commit_xid \
                         ) \
                   LIMIT $2 \
              )",
        )
        .bind(age_seconds)
        .bind(PRUNE_BATCH_LIMIT)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();

        tx.commit().await.map_err(AppError::internal)?;

        total_deleted += deleted;
        if deleted < PRUNE_BATCH_LIMIT as u64 {
            break;
        }
    }
    Ok(total_deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L7-T1: the platform's own consumers may fall further behind.
    #[test]
    fn internal_consumers_get_the_longer_lag() {
        assert_eq!(
            max_lag_hours_for("attome-search/index-drain"),
            INTERNAL_MAX_LAG_HOURS
        );
        assert_eq!(
            max_lag_hours_for("attome-workflow/entry"),
            INTERNAL_MAX_LAG_HOURS
        );
        assert_eq!(
            max_lag_hours_for("events/subscription-1"),
            DEFAULT_MAX_LAG_HOURS
        );
    }

    #[test]
    fn operation_wire_values_round_trip() {
        for op in [
            ChangeOperation::Create,
            ChangeOperation::Update,
            ChangeOperation::Delete,
            ChangeOperation::Restore,
            ChangeOperation::Purge,
        ] {
            assert_eq!(
                ChangeOperation::parse(op.as_str()),
                Some(op),
                "every operation must survive a round trip through its wire value"
            );
        }
    }

    /// The five values here must be exactly the five in the baseline's CHECK
    /// constraint. A value added on one side only is either a write that
    /// violates the constraint at runtime, or a constraint that admits
    /// something no consumer can interpret.
    #[test]
    fn wire_values_match_the_check_constraint() {
        let migration = include_str!("../../../apps/attome/migrations/0006_engine.sql");
        for op in [
            ChangeOperation::Create,
            ChangeOperation::Update,
            ChangeOperation::Delete,
            ChangeOperation::Restore,
            ChangeOperation::Purge,
        ] {
            assert!(
                migration.contains(&format!("'{}'", op.as_str())),
                "{} is missing from the change-event CHECK constraint",
                op.as_str()
            );
        }
    }

    /// L7-T7: the platform's own consumers read as internal.
    #[test]
    fn consumer_kind_tells_internal_from_external() {
        assert_eq!(consumer_kind("attome-search/index"), "internal");
        assert_eq!(consumer_kind("attome-workflow/triggers"), "internal");
        assert_eq!(consumer_kind("webhook:erp"), "external");
    }

    #[test]
    fn unknown_operations_are_skipped_not_errors() {
        assert_eq!(ChangeOperation::parse("merge"), None);
    }
}
