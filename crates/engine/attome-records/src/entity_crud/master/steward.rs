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
    let t = quote_ident(&provenance_table(entity));
    sqlx::query(&format!(
        "INSERT INTO {t} (golden_id, attribute, contribution_id, rule, chosen_at, pinned_by) \
         VALUES ($1, $2, NULL, 'pinned', now(), $3) \
         ON CONFLICT (golden_id, attribute) DO UPDATE \
            SET pinned_by = EXCLUDED.pinned_by, chosen_at = now()"
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
    let t = quote_ident(&provenance_table(entity));
    let done = sqlx::query(&format!(
        "UPDATE {t} SET pinned_by = NULL \
          WHERE golden_id = $1 AND attribute = $2 AND pinned_by IS NOT NULL"
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
