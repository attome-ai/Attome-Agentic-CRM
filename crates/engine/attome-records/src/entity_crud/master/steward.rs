//! L1-T5: what a data steward does to a master entity's golden records.
//!
//! - **Pins.** A pinned attribute keeps the value a person chose: the
//!   rebuild skips it (`<entity>__provenance.pinned_by`). Unpinning queues a
//!   rebuild, so the survivorship rules choose again.
//! - **Held contributions.** A contribution that failed validation waits as
//!   `held`. Releasing it (with a corrected payload, or as it is once the
//!   rules changed) validates it again and attaches it; rejecting it detaches
//!   it with the steward's reason.
//! - **Detaching** an attached contribution leaves it out of its golden
//!   record and queues a rebuild without it.
//! - **Certification.** A golden record is `draft` until a steward certifies
//!   it; `retired` takes it out of use (`master_certification`).
//!
//! Pins and certification run in the caller's transaction, so a route can
//! write its security event in the same one. A contribution's status moves
//! by one conditional update each (held to attached, held to detached,
//! attached to detached), so two stewards acting at once cannot both win.

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_metadata::provision::master::{contribution_table, provenance_table};
use attome_types::AppError;
use serde_json::{Map, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

/// A golden record's certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certification {
    Draft,
    Certified,
    Retired,
}

impl Certification {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "draft" => Some(Self::Draft),
            "certified" => Some(Self::Certified),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Certified => "certified",
            Self::Retired => "retired",
        }
    }
}

/// One contribution, as a steward sees it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContributionRow {
    pub id: Uuid,
    pub golden_id: Option<Uuid>,
    pub source_system: String,
    pub external_id: String,
    pub status: String,
    pub held_reason: Option<String>,
    pub payload: Value,
}

impl ContributionRow {
    pub fn payload_object(&self) -> Map<String, Value> {
        self.payload.as_object().cloned().unwrap_or_default()
    }
}

/// The contribution `id` of `entity`.
pub async fn contribution(
    db: &DbPool,
    entity: &str,
    id: Uuid,
) -> Result<Option<ContributionRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT id, golden_id, source_system, external_id, status, held_reason, payload \
           FROM {} WHERE id = $1",
        quote_ident(&contribution_table(entity))
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Whether `golden` is a live record of `entity`.
pub async fn golden_exists(
    conn: &mut PgConnection,
    entity: &str,
    golden: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {} WHERE id = $1 AND is_active)",
        quote_ident(entity)
    ))
    .bind(golden)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

/// Pins `attribute` of `golden` for `user`: the rebuild leaves it alone.
pub async fn pin(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    golden: Uuid,
    attribute: &str,
    user: Uuid,
) -> Result<(), AppError> {
    sqlx::query(&format!(
        "INSERT INTO {t} (golden_id, attribute, contribution_id, rule, chosen_at, pinned_by) \
         VALUES ($1, $2, NULL, 'pinned', now(), $3) \
         ON CONFLICT (golden_id, attribute) DO UPDATE \
            SET pinned_by = EXCLUDED.pinned_by, chosen_at = now()",
        t = quote_ident(&provenance_table(entity))
    ))
    .bind(golden)
    .bind(attribute)
    .bind(user)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Unpins `attribute` of `golden`; false when it was not pinned.
pub async fn unpin(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    golden: Uuid,
    attribute: &str,
) -> Result<bool, AppError> {
    let done = sqlx::query(&format!(
        "UPDATE {t} SET pinned_by = NULL \
          WHERE golden_id = $1 AND attribute = $2 AND pinned_by IS NOT NULL",
        t = quote_ident(&provenance_table(entity))
    ))
    .bind(golden)
    .bind(attribute)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(done == 1)
}

/// Claims a held contribution for release, with `payload` as its corrected
/// version: it becomes `attached` only if it is still `held`, so of two
/// stewards releasing it at once one wins. False when it was not held.
pub async fn claim_release(
    db: &DbPool,
    entity: &str,
    id: Uuid,
    payload: &Map<String, Value>,
) -> Result<bool, AppError> {
    let done = sqlx::query(&format!(
        "UPDATE {} SET status = 'attached', payload = $2, held_reason = NULL \
          WHERE id = $1 AND status = 'held'",
        quote_ident(&contribution_table(entity))
    ))
    .bind(id)
    .bind(Value::Object(payload.clone()))
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(done == 1)
}

/// Puts a contribution back on hold with `reason` (a release whose attach
/// failed).
pub async fn hold(db: &DbPool, entity: &str, id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query(&format!(
        "UPDATE {} SET status = 'held', held_reason = $2 WHERE id = $1",
        quote_ident(&contribution_table(entity))
    ))
    .bind(id)
    .bind(reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Rejects a held contribution: `detached`, with the steward's reason.
/// False when it was not held.
pub async fn reject(db: &DbPool, entity: &str, id: Uuid, reason: &str) -> Result<bool, AppError> {
    let done = sqlx::query(&format!(
        "UPDATE {} SET status = 'detached', held_reason = $2 WHERE id = $1 AND status = 'held'",
        quote_ident(&contribution_table(entity))
    ))
    .bind(id)
    .bind(format!("rejected: {reason}"))
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(done == 1)
}

/// Detaches an attached contribution; the golden record it leaves, or
/// `None` when it was not attached. The row keeps `golden_id` for its
/// history; the rebuild reads attached contributions only.
pub async fn detach(db: &DbPool, entity: &str, id: Uuid) -> Result<Option<Uuid>, AppError> {
    let golden: Option<Option<Uuid>> = sqlx::query_scalar(&format!(
        "UPDATE {} SET status = 'detached' WHERE id = $1 AND status = 'attached' \
         RETURNING golden_id",
        quote_ident(&contribution_table(entity))
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(golden.flatten())
}

/// Sets `golden`'s certification; the status it had before (`draft` when
/// none was set).
pub async fn certify(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    golden: Uuid,
    status: Certification,
    user: Uuid,
) -> Result<Certification, AppError> {
    let before: Option<String> = sqlx::query_scalar(
        "SELECT status FROM master_certification \
          WHERE entity = $1 AND golden_id = $2 FOR UPDATE",
    )
    .bind(entity)
    .bind(golden)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO master_certification (entity, golden_id, status, set_by, set_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (entity, golden_id) DO UPDATE \
            SET status = EXCLUDED.status, set_by = EXCLUDED.set_by, set_at = now()",
    )
    .bind(entity)
    .bind(golden)
    .bind(status.as_str())
    .bind(user)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(before
        .as_deref()
        .and_then(Certification::parse)
        .unwrap_or(Certification::Draft))
}

/// `golden`'s certification (`draft` when none was set).
pub async fn certification(
    conn: &mut PgConnection,
    entity: &str,
    golden: Uuid,
) -> Result<Certification, AppError> {
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM master_certification WHERE entity = $1 AND golden_id = $2",
    )
    .bind(entity)
    .bind(golden)
    .fetch_optional(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(status
        .as_deref()
        .and_then(Certification::parse)
        .unwrap_or(Certification::Draft))
}

/// Whether `ctx` stewards `entity`'s golden records: an administrator, or an
/// owner or steward of the entity's data domain (L3).
pub async fn may_steward(
    state: &attome_core::EngineState,
    ctx: &attome_server::security::SecurityContext,
    entity: &str,
) -> Result<bool, AppError> {
    if ctx.is_admin {
        return Ok(true);
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::lineage::manual::may_document(&mut conn, entity, ctx.user_id).await
}

/// Releases the held contribution `id` of `entity`: its payload (`payload`
/// when given, else the stored one) is validated again and a valid one is
/// attached to its golden record, whose rebuild is queued. Of two releases at
/// once, one wins; an attach that fails holds it again. The golden record and
/// whether a rebuild was queued. The steward route (L1-T5) and an agent's
/// approved proposal (L1-T10) both release through here; the caller has
/// checked [`may_steward`].
pub async fn release_held(
    state: &attome_core::EngineState,
    ctx: &attome_server::security::SecurityContext,
    entity: &str,
    id: Uuid,
    payload: Option<Map<String, Value>>,
) -> Result<(Uuid, bool), AppError> {
    let db = &state.base.db;
    let row = contribution(db, entity, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.status != "held" {
        return Err(AppError::Conflict("the contribution is not held"));
    }
    let payload = payload.unwrap_or_else(|| row.payload_object());
    if let Some(reason) = super::validation_failure(state, entity, &payload)? {
        return Err(AppError::Validation(reason));
    }
    if !claim_release(db, entity, id, &payload).await? {
        return Err(AppError::Conflict("the contribution is not held"));
    }
    let attached = super::attach(
        state,
        ctx,
        entity,
        super::Pending {
            contribution: id,
            golden: row.golden_id,
            source_system: &row.source_system,
            external_id: &row.external_id,
            payload: &payload,
        },
    )
    .await;
    match attached {
        Ok(done) => Ok(done),
        Err(e) => {
            hold(db, entity, id, "the release could not attach it").await?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_certification_round_trips() {
        for c in [
            Certification::Draft,
            Certification::Certified,
            Certification::Retired,
        ] {
            assert_eq!(Certification::parse(c.as_str()), Some(c));
        }
        assert_eq!(Certification::parse("approved"), None);
    }
}
