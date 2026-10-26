//! Q10-T9: proposing the removal of privileges nobody uses.
//!
//! Uses are counted per person, privilege and day (`attome_server::
//! privilege_usage`, `privilege_usage_daily`). [`propose_unused`] runs daily:
//! for every live role privilege, it looks at the role's holders (direct or
//! through a team) and drafts a removal proposal when none of them used it
//! in [`UNUSED_DAYS`] days. Proposals are drafts only, one live draft per
//! role and privilege; one dismissed within the window is not proposed
//! again. Usage rows older than [`KEEP_DAYS`] are pruned. `system.admin` is
//! never proposed: an administrator's checks are not counted.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// A privilege none of a role's holders used for this long is proposed.
pub const UNUSED_DAYS: i32 = 90;
/// How long daily usage rows are kept.
pub const KEEP_DAYS: i32 = 120;

/// One removal proposal.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RemovalProposal {
    pub id: Uuid,
    pub role_id: Uuid,
    pub privilege_key: String,
    /// The role's holders when the proposal was made.
    pub holders: i32,
    /// The last day any of them used it, if ever recorded.
    pub last_used: Option<NaiveDate>,
    /// `draft`, `accepted` or `dismissed`.
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Drafts proposals for unused role privileges and prunes old usage. The
/// number of proposals drafted.
pub async fn propose_unused(db: &DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    let today = now.date_naive();
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM privilege_usage_daily WHERE day < $1 - $2::int")
        .bind(today)
        .bind(KEEP_DAYS)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let drafted = sqlx::query(
        "WITH holders AS ( \
             SELECT rp.role_ref, p.key, h.user_ref \
             FROM role_mm_privilege rp \
             JOIN role r ON r.id = rp.role_ref AND r.is_deleted = false \
             JOIN privilege p ON p.id = rp.privilege_ref AND p.is_active = true \
             JOIN ( \
                 SELECT role_ref, user_ref FROM user_account_mm_role WHERE is_deleted = false \
                 UNION \
                 SELECT rt.role_ref, ut.user_ref FROM role_mm_team rt \
                 JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref AND ut.is_deleted = false \
                 WHERE rt.is_deleted = false \
             ) h ON h.role_ref = rp.role_ref \
             WHERE rp.is_deleted = false AND p.key <> 'system.admin' \
         ), per AS ( \
             SELECT h.role_ref, h.key, COUNT(DISTINCT h.user_ref)::int AS holders, \
                    MAX(u.day) AS last_used \
             FROM holders h \
             LEFT JOIN privilege_usage_daily u \
                 ON u.user_ref = h.user_ref AND u.privilege_key = h.key \
             GROUP BY h.role_ref, h.key \
         ) \
         INSERT INTO privilege_removal_proposal (role_ref, privilege_key, holders, last_used) \
         SELECT per.role_ref, per.key, per.holders, per.last_used FROM per \
         WHERE (per.last_used IS NULL OR per.last_used < $1 - $2::int) \
           AND NOT EXISTS ( \
               SELECT 1 FROM privilege_removal_proposal d \
               WHERE d.role_ref = per.role_ref AND d.privilege_key = per.key \
                 AND d.status = 'dismissed' AND d.decided_at > $3 - make_interval(days => $2::int)) \
         ON CONFLICT (role_ref, privilege_key) WHERE status = 'draft' DO NOTHING",
    )
    .bind(today)
    .bind(UNUSED_DAYS)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    tx.commit().await.map_err(AppError::internal)?;
    Ok(drafted)
}

type ProposalRow = (
    Uuid,
    Uuid,
    String,
    i32,
    Option<NaiveDate>,
    String,
    DateTime<Utc>,
);

/// A page of proposals, newest first, optionally of one status, and the total.
pub async fn list_proposals(
    db: &DbPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<RemovalProposal>, i64), AppError> {
    let rows: Vec<ProposalRow> = sqlx::query_as(
        "SELECT id, role_ref, privilege_key, holders, last_used, status, created_at \
         FROM privilege_removal_proposal WHERE ($1::text IS NULL OR status = $1) \
         ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(status)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM privilege_removal_proposal WHERE ($1::text IS NULL OR status = $1)",
    )
    .bind(status)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok((
        rows.into_iter()
            .map(
                |(id, role_id, privilege_key, holders, last_used, status, created_at)| {
                    RemovalProposal {
                        id,
                        role_id,
                        privilege_key,
                        holders,
                        last_used,
                        status,
                        created_at,
                    }
                },
            )
            .collect(),
        total,
    ))
}
