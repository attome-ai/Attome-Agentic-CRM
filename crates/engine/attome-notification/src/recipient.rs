//! Per-user in-app notification materialization.
//!
//! `notification_dispatch` is the durable delivery intent.  This module
//! turns that intent into explicit recipient rows so the inbox never has to
//! infer authorization from organization/global flags.  Inserts are
//! idempotent on `(dispatch_ref, user_ref, created_at)`; `created_at` is copied
//! from the dispatch so retries remain a no-op on the partitioned table.

use attome_db::{DbPool, Tx};
use attome_jobs::{EngineJob, enqueue_in_tx};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

const FANOUT_BATCH_SIZE: i64 = 1_000;

/// The advisory-lock key `prune_old_partitions` takes, under
/// [`crate::ADVISORY_LOCK_NAMESPACE`]. Public so `tests/recipient_retention.rs`
/// can hold the identical lock instead of re-typing the string — a test that
/// drifted from this value would silently stop testing contention at all.
pub const RETENTION_LOCK_KEY: &str = "attome-notification/recipient-retention";

#[derive(FromRow)]
struct DispatchAudience {
    created_at: DateTime<Utc>,
    organization_ref: Option<Uuid>,
    is_global: bool,
    recipient_user_ref: Option<Uuid>,
    subject: Option<String>,
    body_text: String,
    route: Option<String>,
    /// U5 (D-602): the category the recipients' mutes are read under, or
    /// `None` when preferences do not apply (mandatory template, no category).
    preference_category: Option<String>,
}

/// Shared per-notification payload for both the single-row and batch insert paths.
pub(crate) struct RecipientMessage<'a> {
    pub dispatch_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub title: Option<&'a str>,
    pub message: &'a str,
    pub route: Option<&'a str>,
    pub audience_kind: &'a str,
}

/// Returns whether this call actually inserted a new recipient row (`true`)
/// versus hitting the idempotency conflict on `(dispatch_ref, user_ref,
/// created_at)` (`false`) — the caller treats both as a successful send (a
/// conflict means "already delivered"), but distinguishing them keeps that
/// assumption observable instead of silently indistinguishable from a real
/// first-time delivery.
pub(crate) async fn insert_recipient(
    tx: &mut Tx<'_>,
    msg: &RecipientMessage<'_>,
    user_id: Uuid,
) -> Result<bool, AppError> {
    let inserted_id: Option<Uuid> = sqlx::query_scalar(
        r#"INSERT INTO notification_recipient
               (created_at, dispatch_ref, user_ref, title, message, notif_type,
                route, audience_kind)
           VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
           ON CONFLICT (dispatch_ref, user_ref, created_at) DO NOTHING
           RETURNING id"#,
    )
    .bind(msg.created_at)
    .bind(msg.dispatch_id)
    .bind(user_id)
    .bind(msg.title)
    .bind(msg.message)
    .bind(msg.route)
    .bind(msg.audience_kind)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(inserted_id.is_some())
}

pub(crate) async fn enqueue_fanout_in_tx(
    tx: &mut Tx<'_>,
    dispatch_id: Uuid,
) -> Result<(), AppError> {
    enqueue_in_tx(tx, EngineJob::FanOutNotification { dispatch_id })
        .await
        .map_err(AppError::internal)
}

/// Inserts one in-app row per user, skipping every user who muted `in_app`
/// for `preference_category` (U5, B-R5). With `None` the `NOT EXISTS` can
/// never match (`category = NULL` is never true), so nobody is skipped.
async fn insert_batch(
    db: &DbPool,
    msg: &RecipientMessage<'_>,
    user_ids: &[Uuid],
    preference_category: Option<&str>,
) -> Result<(), AppError> {
    if user_ids.is_empty() {
        return Ok(());
    }

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("SET LOCAL statement_timeout = '60s'")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        r#"INSERT INTO notification_recipient
               (created_at, dispatch_ref, user_ref, title, message, notif_type,
                route, audience_kind)
           SELECT $1, $2, recipients.user_ref, $3, $4, 0, $5, $6
           FROM UNNEST($7::uuid[]) AS recipients(user_ref)
           WHERE NOT EXISTS (
               SELECT 1 FROM notification_preference p
                WHERE p.user_ref = recipients.user_ref
                  AND p.category = $8
                  AND p.channel = 'in_app'
                  AND p.enabled = FALSE
                  AND p.is_deleted = FALSE
           )
           ON CONFLICT (dispatch_ref, user_ref, created_at) DO NOTHING"#,
    )
    .bind(msg.created_at)
    .bind(msg.dispatch_id)
    .bind(msg.title)
    .bind(msg.message)
    .bind(msg.route)
    .bind(msg.audience_kind)
    .bind(user_ids)
    .bind(preference_category)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)
}

async fn user_batch(
    db: &DbPool,
    organization_ref: Option<Uuid>,
    last_user_id: Option<Uuid>,
) -> Result<Vec<Uuid>, AppError> {
    let rows = match (organization_ref, last_user_id) {
        (Some(org), Some(last)) => {
            sqlx::query_scalar(
                r#"SELECT id FROM user_account
                   WHERE is_active = TRUE AND organization_ref = $1 AND id > $2
                   ORDER BY id LIMIT $3"#,
            )
            .bind(org)
            .bind(last)
            .bind(FANOUT_BATCH_SIZE)
            .fetch_all(db)
            .await
        }
        (Some(org), None) => {
            sqlx::query_scalar(
                r#"SELECT id FROM user_account
                   WHERE is_active = TRUE AND organization_ref = $1
                   ORDER BY id LIMIT $2"#,
            )
            .bind(org)
            .bind(FANOUT_BATCH_SIZE)
            .fetch_all(db)
            .await
        }
        (None, Some(last)) => {
            sqlx::query_scalar(
                r#"SELECT id FROM user_account
                   WHERE is_active = TRUE AND id > $1
                   ORDER BY id LIMIT $2"#,
            )
            .bind(last)
            .bind(FANOUT_BATCH_SIZE)
            .fetch_all(db)
            .await
        }
        (None, None) => {
            sqlx::query_scalar(
                r#"SELECT id FROM user_account
                   WHERE is_active = TRUE
                   ORDER BY id LIMIT $1"#,
            )
            .bind(FANOUT_BATCH_SIZE)
            .fetch_all(db)
            .await
        }
    };
    rows.map_err(AppError::internal)
}

/// Expands one organization/global dispatch into explicit recipient rows.
/// The operation is safe to retry and runs in 1,000-user keyset batches.
pub async fn fan_out_notification(db: &DbPool, dispatch_id: Uuid) -> Result<(), AppError> {
    let dispatch: Option<DispatchAudience> = sqlx::query_as(
        r#"SELECT created_at, organization_ref, is_global, recipient_user_ref,
                  subject, body_text, route, preference_category
           FROM notification_dispatch
           WHERE id = $1 AND is_deleted = FALSE"#,
    )
    .bind(dispatch_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(dispatch) = dispatch else {
        return Ok(());
    };

    if let Some(user_id) = dispatch.recipient_user_ref {
        let msg = RecipientMessage {
            dispatch_id,
            created_at: dispatch.created_at,
            title: dispatch.subject.as_deref(),
            message: &dispatch.body_text,
            route: dispatch.route.as_deref(),
            audience_kind: "direct",
        };
        insert_batch(
            db,
            &msg,
            &[user_id],
            dispatch.preference_category.as_deref(),
        )
        .await?;
        return Ok(());
    }

    let (organization_ref, audience_kind) = if dispatch.is_global {
        (None, "global")
    } else if dispatch.organization_ref.is_some() {
        (dispatch.organization_ref, "organization")
    } else {
        return Err(AppError::Validation(
            "notification dispatch has no valid audience".into(),
        ));
    };

    let msg = RecipientMessage {
        dispatch_id,
        created_at: dispatch.created_at,
        title: dispatch.subject.as_deref(),
        message: &dispatch.body_text,
        route: dispatch.route.as_deref(),
        audience_kind,
    };

    let mut last_user_id = None;
    loop {
        let user_ids = user_batch(db, organization_ref, last_user_id).await?;
        if user_ids.is_empty() {
            break;
        }
        insert_batch(db, &msg, &user_ids, dispatch.preference_category.as_deref()).await?;
        last_user_id = user_ids.last().copied();
        if user_ids.len() < FANOUT_BATCH_SIZE as usize {
            break;
        }
    }
    Ok(())
}

/// Adds recent organization/global in-app notifications for a newly-created
/// active user.  This closes the race where the user is created while a
/// broadcast fan-out job is already scanning users.
pub async fn backfill_for_new_user(
    db: &DbPool,
    user_id: Uuid,
    backfill_days: u32,
) -> Result<(), AppError> {
    let org_ref: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT organization_ref FROM user_account WHERE id = $1 AND is_active = TRUE",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(org_ref) = org_ref else {
        return Ok(());
    };

    let query = if org_ref.is_some() {
        r#"INSERT INTO notification_recipient
               (created_at, dispatch_ref, user_ref, title, message, notif_type,
                route, audience_kind)
           SELECT d.created_at, d.id, $1, d.subject, d.body_text, 0, d.route,
                  CASE WHEN d.is_global THEN 'global' ELSE 'organization' END
           FROM notification_dispatch d
           WHERE d.is_deleted = FALSE
             AND d.recipient_user_ref IS NULL
             AND d.channels @> '["in_app"]'::jsonb
             AND d.created_at >= NOW() - ($3::double precision * INTERVAL '1 day')
             AND (d.is_global = TRUE OR d.organization_ref = $2)
           ON CONFLICT (dispatch_ref, user_ref, created_at) DO NOTHING"#
    } else {
        r#"INSERT INTO notification_recipient
               (created_at, dispatch_ref, user_ref, title, message, notif_type,
                route, audience_kind)
           SELECT d.created_at, d.id, $1, d.subject, d.body_text, 0, d.route, 'global'
           FROM notification_dispatch d
           WHERE d.is_deleted = FALSE
             AND d.recipient_user_ref IS NULL
             AND d.is_global = TRUE
             AND d.channels @> '["in_app"]'::jsonb
             AND d.created_at >= NOW() - ($2::double precision * INTERVAL '1 day')
           ON CONFLICT (dispatch_ref, user_ref, created_at) DO NOTHING"#
    };

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("SET LOCAL statement_timeout = '60s'")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if let Some(org_ref) = org_ref {
        sqlx::query(query)
            .bind(user_id)
            .bind(org_ref)
            .bind(backfill_days as i64)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    } else {
        sqlx::query(query)
            .bind(user_id)
            .bind(backfill_days as i64)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    tx.commit().await.map_err(AppError::internal)
}

/// Reclaims expired inbox storage by dropping complete monthly partitions.
/// The pre-cutover partition is the one exception: it spans MINVALUE, so its
/// expired rows are deleted in place until all post-cutover data has aged out
/// of it. A non-blocking, transaction-scoped advisory lock (guidelines §2 —
/// `pg_try_advisory_xact_lock`, never the blocking variant) keeps concurrent
/// workers from racing on the same partition DDL: a loser skips this run
/// outright rather than queuing behind the winner.
pub async fn prune_old_partitions(db: &DbPool, retention_days: u32) -> Result<(), AppError> {
    if retention_days == 0 {
        return Ok(());
    }

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("SET LOCAL statement_timeout = '60s'")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    // Non-blocking, same primitive/pattern as attome-audit/chainer.rs's per-org
    // chain-append lock (guidelines §2) — if another worker is already
    // mid-prune (apalis retry after a crash, or an overlapping tick), skip
    // this run rather than waiting on it. The lock is transaction-scoped, so
    // the next scheduled `PruneNotificationRecipientPartitions` job (or
    // apalis's own retry of this one) tries again cleanly.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(RETENTION_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(());
    }

    let cutoff: DateTime<Utc> =
        sqlx::query_scalar("SELECT NOW() - ($1::double precision * INTERVAL '1 day')")
            .bind(retention_days as f64)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    sqlx::query("DELETE FROM notification_recipient_pre_partition WHERE created_at < $1")
        .bind(cutoff)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    let expired_partitions: Vec<String> = sqlx::query_scalar(
        r#"SELECT child.relname
             FROM pg_inherits inheritance
             JOIN pg_class parent ON parent.oid = inheritance.inhparent
             JOIN pg_class child ON child.oid = inheritance.inhrelid
            WHERE parent.oid = 'notification_recipient'::regclass
              AND child.relname ~ '^notification_recipient_p[0-9]{4}_[0-9]{2}$'
              AND (to_date(substring(child.relname FROM 'p([0-9]{4}_[0-9]{2})'), 'YYYY_MM')
                   + INTERVAL '1 month') <= ($1 AT TIME ZONE 'UTC')"#,
    )
    .bind(cutoff)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    for partition in expired_partitions {
        // Names come from the catalog and are restricted by the regex above;
        // quote again so the identifier can never become executable SQL.
        let quoted = format!("\"{}\"", partition.replace('"', "\"\""));
        sqlx::query(&format!("DROP TABLE IF EXISTS {quoted}"))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }

    tx.commit().await.map_err(AppError::internal)
}
