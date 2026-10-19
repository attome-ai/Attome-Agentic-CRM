//! Chat retention (C9-T1 with R3/R4): a channel with `retention_days` loses
//! messages older than that, in bounded batches, from the hourly
//! recovery-archive job. Legal holds win: the deployment-wide
//! `retention.legal_hold` flag stops the purge entirely, a hold on the whole
//! `chat_message` entity stops it entirely, and a hold on one `chat_channel`
//! record keeps that channel's messages.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Most messages one channel loses per run; the next run continues.
const PURGE_BATCH: i64 = 5000;

/// Whether a legal hold covers this channel's messages.
pub async fn channel_held(state: &EngineState, channel: Uuid) -> Result<bool, AppError> {
    if state.base.config.retention.legal_hold {
        return Ok(true);
    }
    let db = &state.base.db;
    Ok(
        attome_core::legal_hold::record_is_held(db, "chat_message", Uuid::nil())
            .await?
            .is_some()
            || attome_core::legal_hold::record_is_held(db, "chat_channel", channel)
                .await?
                .is_some(),
    )
}

/// Deletes messages past their channel's retention; the number deleted.
pub async fn purge_expired(db: &DbPool, deployment_hold: bool) -> Result<u64, AppError> {
    if deployment_hold
        || attome_core::legal_hold::record_is_held(db, "chat_message", Uuid::nil())
            .await?
            .is_some()
    {
        return Ok(0);
    }
    let channels: Vec<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, retention_days FROM chat_channel WHERE retention_days IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut purged = 0;
    for (channel, days) in channels {
        if attome_core::legal_hold::record_is_held(db, "chat_channel", channel)
            .await?
            .is_some()
        {
            continue;
        }
        purged += sqlx::query(
            "DELETE FROM chat_message WHERE id IN ( \
                 SELECT id FROM chat_message \
                  WHERE channel_id = $1 AND created_at < now() - make_interval(days => $2) \
                  LIMIT $3)",
        )
        .bind(channel)
        .bind(days)
        .bind(PURGE_BATCH)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    Ok(purged)
}
