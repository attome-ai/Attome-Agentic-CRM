//! A3-T8: every record write a business rule refuses, logged with its rule,
//! attribute, channel and user, off the request path.
//!
//! The write path hands each refusal to [`RejectionLog::record`], which never
//! waits: a bounded queue feeds one process-lifetime worker that inserts the
//! rows into `validation_rejection` (migration 0183) in batches of at most
//! [`BATCH`], or every [`FLUSH_EVERY`]. The log is observational (guidelines
//! §5, §10): a full queue drops the row and counts it, and a failed insert is
//! logged and dropped, so a slow database never slows or fails a write.
//! Overrides are not logged here: each is a security event in the write's
//! own transaction (A3-T4).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use attome_db::DbPool;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

/// Rows held before a batch is written.
pub const BATCH: usize = 500;
/// The longest a row waits for its batch.
pub const FLUSH_EVERY: Duration = Duration::from_secs(2);
/// Rows queued before new ones are dropped.
const QUEUE_CAP: usize = 10_000;

/// Rows dropped because the queue was full or the worker had stopped.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// One refusal.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub rule_id: Uuid,
    pub entity: String,
    /// The attribute the refusing policy is attached to, when it names one.
    pub attribute: Option<String>,
    /// `staff`, `service` (API key or S2S), `portal` or `system`.
    pub channel: &'static str,
    /// The staff user, when one wrote.
    pub user_ref: Option<Uuid>,
    pub rejected_at: DateTime<Utc>,
}

enum Msg {
    Row(Rejection),
    Flush(oneshot::Sender<()>),
}

/// The handle the write path logs through.
#[derive(Clone)]
pub struct RejectionLog {
    tx: mpsc::Sender<Msg>,
}

impl std::fmt::Debug for RejectionLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectionLog").finish_non_exhaustive()
    }
}

impl RejectionLog {
    /// Starts the worker over `db`.
    pub fn new(db: DbPool) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_CAP);
        tokio::spawn(worker(db, rx));
        Self { tx }
    }

    /// The process-wide log, started over `db` on first call (later calls
    /// ignore their argument). Must first be called inside a Tokio runtime
    /// that outlives the process's writes.
    pub fn shared(db: &DbPool) -> &'static RejectionLog {
        static SHARED: OnceLock<RejectionLog> = OnceLock::new();
        SHARED.get_or_init(|| RejectionLog::new(db.clone()))
    }

    /// Queues one refusal without waiting; a full queue drops it.
    pub fn record(&self, rejection: Rejection) -> bool {
        if self.tx.try_send(Msg::Row(rejection)).is_ok() {
            return true;
        }
        let dropped = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(1_000) {
            tracing::warn!(
                dropped,
                "validation rejection log: queue full, rows dropped (the log is observational)"
            );
        }
        false
    }

    /// Writes everything queued so far and returns once it is written (or
    /// its write failed). Shutdown and tests use it.
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }
}

/// Rows dropped so far in this process.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

async fn worker(db: DbPool, mut rx: mpsc::Receiver<Msg>) {
    let mut buf: Vec<Rejection> = Vec::with_capacity(BATCH);
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(Msg::Row(row)) => {
                    buf.push(row);
                    if buf.len() >= BATCH {
                        write(&db, &mut buf).await;
                    }
                }
                Some(Msg::Flush(ack)) => {
                    write(&db, &mut buf).await;
                    let _ = ack.send(());
                }
                None => {
                    write(&db, &mut buf).await;
                    return;
                }
            },
            _ = tick.tick() => {
                if !buf.is_empty() {
                    write(&db, &mut buf).await;
                }
            }
        }
    }
}

/// Inserts and empties `buf`; a failure is logged and the rows dropped.
async fn write(db: &DbPool, buf: &mut Vec<Rejection>) {
    if buf.is_empty() {
        return;
    }
    let rows = std::mem::take(buf);
    let rules: Vec<Uuid> = rows.iter().map(|r| r.rule_id).collect();
    let entities: Vec<&str> = rows.iter().map(|r| r.entity.as_str()).collect();
    let attributes: Vec<Option<&str>> = rows.iter().map(|r| r.attribute.as_deref()).collect();
    let channels: Vec<&str> = rows.iter().map(|r| r.channel).collect();
    let users: Vec<Option<Uuid>> = rows.iter().map(|r| r.user_ref).collect();
    let at: Vec<DateTime<Utc>> = rows.iter().map(|r| r.rejected_at).collect();
    let result = sqlx::query(
        "INSERT INTO validation_rejection \
         (rule_ref, entity, attribute, channel, user_ref, rejected_at) \
         SELECT * FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::text[], \
                              $5::uuid[], $6::timestamptz[])",
    )
    .bind(&rules)
    .bind(&entities)
    .bind(&attributes)
    .bind(&channels)
    .bind(&users)
    .bind(&at)
    .execute(db)
    .await;
    if let Err(e) = result {
        tracing::warn!(
            rows = rows.len(),
            error = %e,
            "validation rejection log: batch insert failed, rows dropped"
        );
    }
}
