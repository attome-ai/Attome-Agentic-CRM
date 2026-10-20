//! Timers (roadmap M10-T1): one table (`timer`) for every point in time the
//! platform waits for — a flow resuming at a date, a reminder, an
//! escalation. [`schedule`] adds one in the caller's transaction;
//! [`claim_due`] moves due timers from `pending` to `fired` with
//! `FOR UPDATE SKIP LOCKED`, so each is claimed once however many nodes
//! sweep; the sweep queues one `EngineJob::TimerFire` per claimed timer,
//! whose handler runs the kind's action and settles the timer `done` or
//! `failed`. [`cancel_for_target`] drops a record's pending timers (the
//! record left its condition or went away).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use attome_types::AppError;

/// Most timers one sweep claims.
pub const CLAIM_BATCH: i64 = 500;

/// A timer to add.
#[derive(Debug, Clone, PartialEq)]
pub struct NewTimer {
    pub kind: String,
    pub target_entity: Option<String>,
    pub target_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    pub due_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

/// A claimed timer.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Timer {
    pub id: Uuid,
    pub kind: String,
    pub target_entity: Option<String>,
    pub target_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    pub due_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

/// M10-T4: a timer still waiting, as people see it: what (its kind), for
/// which record, when, and from which flow run. Never its payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct PendingTimer {
    pub id: Uuid,
    pub kind: String,
    pub target_entity: Option<String>,
    pub target_id: Option<Uuid>,
    pub run_id: Option<Uuid>,
    pub due_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// The most pending timers one record lists.
pub const MAX_RECORD_TIMERS: i64 = 200;

/// M10-T4: a record's pending timers, soonest first.
pub async fn pending_for_target(
    db: &attome_db::DbPool,
    entity: &str,
    id: Uuid,
) -> Result<Vec<PendingTimer>, AppError> {
    sqlx::query_as(
        "SELECT id, kind, target_entity, target_id, run_id, due_at, created_at FROM timer \
         WHERE status = 'pending' AND target_entity = $1 AND target_id = $2 \
         ORDER BY due_at, id LIMIT $3",
    )
    .bind(entity)
    .bind(id)
    .bind(MAX_RECORD_TIMERS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// M10-T4: every pending timer, soonest first, a page at a time, with how
/// many there are in all.
pub async fn pending_page(
    db: &attome_db::DbPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<PendingTimer>, i64), AppError> {
    let items: Vec<PendingTimer> = sqlx::query_as(
        "SELECT id, kind, target_entity, target_id, run_id, due_at, created_at FROM timer \
         WHERE status = 'pending' ORDER BY due_at, id LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM timer WHERE status = 'pending'")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok((items, total))
}

/// Adds a timer in the caller's transaction.
pub async fn schedule(conn: &mut sqlx::PgConnection, timer: &NewTimer) -> Result<Uuid, AppError> {
    if timer.kind.trim().is_empty() {
        return Err(AppError::Validation("a timer needs a kind".into()));
    }
    sqlx::query_scalar(
        "INSERT INTO timer (kind, target_entity, target_id, run_id, due_at, payload) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(timer.kind.trim())
    .bind(&timer.target_entity)
    .bind(timer.target_id)
    .bind(timer.run_id)
    .bind(timer.due_at)
    .bind(&timer.payload)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

/// Moves pending timers of a kind on a record to a new time (a date they
/// follow changed); the number moved.
pub async fn reschedule_for_target(
    conn: &mut sqlx::PgConnection,
    kind: &str,
    target_entity: &str,
    target_id: Uuid,
    due_at: DateTime<Utc>,
) -> Result<u64, AppError> {
    Ok(sqlx::query(
        "UPDATE timer SET due_at = $4 \
         WHERE kind = $1 AND target_entity = $2 AND target_id = $3 AND status = 'pending'",
    )
    .bind(kind)
    .bind(target_entity)
    .bind(target_id)
    .bind(due_at)
    .execute(conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// Cancels a record's pending timers, of one kind or all; the number
/// cancelled.
pub async fn cancel_for_target(
    conn: &mut sqlx::PgConnection,
    target_entity: &str,
    target_id: Uuid,
    kind: Option<&str>,
) -> Result<u64, AppError> {
    Ok(sqlx::query(
        "UPDATE timer SET status = 'cancelled' \
         WHERE target_entity = $1 AND target_id = $2 AND status = 'pending' \
           AND ($3::text IS NULL OR kind = $3)",
    )
    .bind(target_entity)
    .bind(target_id)
    .bind(kind)
    .execute(conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// Claims the timers due at `now` (oldest first), marking them `fired`.
pub async fn claim_due(
    conn: &mut sqlx::PgConnection,
    now: DateTime<Utc>,
) -> Result<Vec<Timer>, AppError> {
    sqlx::query_as(
        "UPDATE timer t SET status = 'fired', fired_at = $1 \
         FROM (SELECT id FROM timer WHERE status = 'pending' AND due_at <= $1 \
               ORDER BY due_at LIMIT $2 FOR UPDATE SKIP LOCKED) due \
         WHERE t.id = due.id \
         RETURNING t.id, t.kind, t.target_entity, t.target_id, t.run_id, t.due_at, t.payload",
    )
    .bind(now)
    .bind(CLAIM_BATCH)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)
}

/// Settles a fired timer: `done`, or `failed` with the reason.
pub async fn settle(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE timer SET status = CASE WHEN $2::text IS NULL THEN 'done' ELSE 'failed' END, \
             last_error = $2 \
         WHERE id = $1 AND status = 'fired'",
    )
    .bind(id)
    .bind(error)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Reads a fired timer for its job.
pub async fn load(conn: &mut sqlx::PgConnection, id: Uuid) -> Result<Option<Timer>, AppError> {
    sqlx::query_as(
        "SELECT id, kind, target_entity, target_id, run_id, due_at, payload FROM timer \
         WHERE id = $1 AND status = 'fired'",
    )
    .bind(id)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)
}

// ── Timers that follow a date (M10-T2) ──────────────────────────────────────

/// The payload key of a timer that follows a date attribute of its record.
pub const FOLLOW_KEY: &str = "follow";

/// M10-T2: a timer due `offset_minutes` after (negative: before) the date in
/// its record's `attribute`, while the record meets `condition` (rule text,
/// as a workflow condition node reads it; none means always). Stored in the
/// timer's payload under [`FOLLOW_KEY`]; a change to the record moves the
/// timer with the date, and a record that leaves the condition, clears the
/// date or goes away cancels it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Follow {
    pub attribute: String,
    #[serde(default)]
    pub offset_minutes: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

impl Follow {
    /// When the timer is due for `record`, or `None` when the record has no
    /// usable date in the attribute.
    pub fn due_for(&self, record: &serde_json::Value) -> Option<DateTime<Utc>> {
        let date = date_value(record.get(&self.attribute)?)?;
        date.checked_add_signed(chrono::Duration::minutes(self.offset_minutes))
    }
}

/// The [`Follow`] a timer's payload carries, if any.
pub fn follow_of(payload: &serde_json::Value) -> Option<Follow> {
    serde_json::from_value(payload.get(FOLLOW_KEY)?.clone()).ok()
}

/// A date attribute's stored value as a time: an RFC 3339 timestamp, or a
/// `YYYY-MM-DD` date at midnight UTC.
pub fn date_value(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    let text = value.as_str()?;
    if let Ok(at) = DateTime::parse_from_rfc3339(text) {
        return Some(at.with_timezone(&Utc));
    }
    chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .ok()?
        .and_hms_opt(0, 0, 0)
        .map(|at| at.and_utc())
}

/// What a change to a followed record does to one of its timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowDecision {
    /// Still due when it was.
    Keep,
    /// The date moved; the timer is now due here.
    Move(DateTime<Utc>),
    /// The record went away, cleared the date or left the condition.
    Cancel,
}

/// M10-T2: the decision for a pending timer due at `due_at` that follows
/// `follow`, given the record as it now is (`None`: deleted or deactivated)
/// and whether it meets the follow's condition.
pub fn follow_decision(
    follow: &Follow,
    record: Option<&serde_json::Value>,
    condition_holds: bool,
    due_at: DateTime<Utc>,
) -> FollowDecision {
    let Some(record) = record else {
        return FollowDecision::Cancel;
    };
    if !condition_holds {
        return FollowDecision::Cancel;
    }
    match follow.due_for(record) {
        None => FollowDecision::Cancel,
        Some(due) if due == due_at => FollowDecision::Keep,
        Some(due) => FollowDecision::Move(due),
    }
}

/// A pending timer that follows a date: its id, when it is due and what it
/// follows.
#[derive(Debug, Clone, PartialEq)]
pub struct FollowingTimer {
    pub id: Uuid,
    pub due_at: DateTime<Utc>,
    pub follow: Follow,
}

/// M10-T2: a record's pending timers that follow one of its dates.
pub async fn following_for_target(
    conn: &mut sqlx::PgConnection,
    target_entity: &str,
    target_id: Uuid,
) -> Result<Vec<FollowingTimer>, AppError> {
    let rows: Vec<(Uuid, DateTime<Utc>, serde_json::Value)> = sqlx::query_as(
        "SELECT id, due_at, payload FROM timer \
         WHERE status = 'pending' AND target_entity = $1 AND target_id = $2 \
           AND payload ? 'follow' \
         ORDER BY due_at, id LIMIT $3",
    )
    .bind(target_entity)
    .bind(target_id)
    .bind(MAX_RECORD_TIMERS)
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, due_at, payload)| {
            follow_of(&payload).map(|follow| FollowingTimer { id, due_at, follow })
        })
        .collect())
}

/// Applies a [`FollowDecision`] to one pending timer; whether it changed (a
/// timer fired or cancelled meanwhile is left as it is).
pub async fn apply_follow(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    decision: FollowDecision,
) -> Result<bool, AppError> {
    let result = match decision {
        FollowDecision::Keep => return Ok(false),
        FollowDecision::Move(due_at) => {
            sqlx::query("UPDATE timer SET due_at = $2 WHERE id = $1 AND status = 'pending'")
                .bind(id)
                .bind(due_at)
                .execute(conn)
                .await
        }
        FollowDecision::Cancel => {
            sqlx::query(
                "UPDATE timer SET status = 'cancelled' WHERE id = $1 AND status = 'pending'",
            )
            .bind(id)
            .execute(conn)
            .await
        }
    };
    Ok(result.map_err(AppError::internal)?.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;
    use serde_json::json;

    fn renewal() -> Follow {
        Follow {
            attribute: "renewal_date".into(),
            offset_minutes: -7 * 24 * 60,
            condition: Some("status == \"active\"".into()),
        }
    }

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn timer_follow_date_reads_dates_and_timestamps() {
        assert_eq!(
            date_value(&json!("2027-03-15")),
            Some(at("2027-03-15T00:00:00Z"))
        );
        assert_eq!(
            date_value(&json!("2027-03-15T09:30:00+03:00")),
            Some(at("2027-03-15T06:30:00Z"))
        );
        assert_eq!(date_value(&json!("next week")), None);
        assert_eq!(date_value(&json!(20270315)), None);
    }

    #[test]
    fn timer_follow_date_moves_with_the_date() {
        let follow = renewal();
        let record = json!({"renewal_date": "2027-03-15", "status": "active"});
        let due = at("2027-03-08T00:00:00Z");
        assert_eq!(follow.due_for(&record), Some(due));
        assert_eq!(
            follow_decision(&follow, Some(&record), true, due),
            FollowDecision::Keep
        );
        let moved = json!({"renewal_date": "2027-04-01", "status": "active"});
        assert_eq!(
            follow_decision(&follow, Some(&moved), true, due),
            FollowDecision::Move(at("2027-03-25T00:00:00Z"))
        );
    }

    #[test]
    fn timer_follow_date_disappears_when_the_condition_stops() {
        let follow = renewal();
        let due = at("2027-03-08T00:00:00Z");
        let record = json!({"renewal_date": "2027-03-15", "status": "cancelled"});
        assert_eq!(
            follow_decision(&follow, Some(&record), false, due),
            FollowDecision::Cancel
        );
        let cleared = json!({"renewal_date": null, "status": "active"});
        assert_eq!(
            follow_decision(&follow, Some(&cleared), true, due),
            FollowDecision::Cancel
        );
        assert_eq!(
            follow_decision(&follow, None, true, due),
            FollowDecision::Cancel,
            "a deleted record takes its timers with it"
        );
    }

    #[test]
    fn timer_follow_date_payload_round_trips() {
        let payload = json!({ "flow": "renewal", "follow": renewal() });
        assert_eq!(follow_of(&payload), Some(renewal()));
        assert_eq!(follow_of(&json!({"rule_id": "x"})), None);
        let bare = json!({ "follow": {"attribute": "due_on"} });
        assert_eq!(
            follow_of(&bare),
            Some(Follow {
                attribute: "due_on".into(),
                offset_minutes: 0,
                condition: None
            })
        );
    }
}
