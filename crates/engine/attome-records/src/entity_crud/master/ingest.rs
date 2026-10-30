//! L1-T4: storing a source system's contribution to a master entity.

use attome_core::{EngineState, quote_ident};
use attome_metadata::provision::master::contribution_table;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

/// What became of a contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    /// Attached to its golden record; `queued` when a rebuild was queued
    /// (an identical one may already be waiting).
    Attached {
        contribution: Uuid,
        golden: Uuid,
        queued: bool,
    },
    /// It failed the entity's field validation; nothing else changed.
    Held { contribution: Uuid, reason: String },
}

/// Whether `entity` is master data: its contribution table exists.
pub async fn is_master(state: &EngineState, entity: &str) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(quote_ident(&contribution_table(entity)))
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// `payload` against `entity`'s own field validation (A3): the reason it
/// fails, if it does.
pub fn validation_failure(
    state: &EngineState,
    entity: &str,
    payload: &Map<String, Value>,
) -> Result<Option<String>, AppError> {
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .ok_or(AppError::NotFound)?;
    Ok(
        match crate::entity_mutation::validate_body(&attrs, payload, false) {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        },
    )
}

/// Stores `payload` as `source_system`'s version of the record it calls
/// `external_id`, and attaches it to its golden record.
pub async fn ingest(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    source_system: &str,
    external_id: &str,
    payload: &Map<String, Value>,
) -> Result<Ingested, AppError> {
    let source_system = source_system.trim();
    let external_id = external_id.trim();
    if source_system.is_empty() || external_id.is_empty() {
        return Err(AppError::Validation(
            "a contribution names its source system and external id".into(),
        ));
    }
    if !is_master(state, entity).await? {
        if state.entities.load().get(entity).is_none() {
            return Err(AppError::NotFound);
        }
        return Err(AppError::Validation(format!("{entity} is not master data")));
    }

    // A3: the entity's own field validation; a failing version is held.
    let held_reason = validation_failure(state, entity, payload)?;
    let (contribution, golden): (Uuid, Option<Uuid>) = sqlx::query_as(&format!(
        "INSERT INTO {t} (source_system, external_id, payload, status, held_reason, received_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         ON CONFLICT (source_system, external_id) DO UPDATE \
            SET payload = EXCLUDED.payload, status = EXCLUDED.status, \
                held_reason = EXCLUDED.held_reason, received_at = now() \
         RETURNING id, golden_id",
        t = quote_ident(&contribution_table(entity))
    ))
    .bind(source_system)
    .bind(external_id)
    .bind(Value::Object(payload.clone()))
    .bind(if held_reason.is_some() {
        "held"
    } else {
        "attached"
    })
    .bind(&held_reason)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(reason) = held_reason {
        return Ok(Ingested::Held {
            contribution,
            reason,
        });
    }
    let (golden, queued) = attach(
        state,
        ctx,
        entity,
        Pending {
            contribution,
            golden,
            source_system,
            external_id,
            payload,
        },
    )
    .await?;
    Ok(Ingested::Attached {
        contribution,
        golden,
        queued,
    })
}

/// A valid contribution about to be attached.
#[derive(Debug)]
pub struct Pending<'a> {
    pub contribution: Uuid,
    /// The golden record it was attached to before, if any.
    pub golden: Option<Uuid>,
    pub source_system: &'a str,
    pub external_id: &'a str,
    pub payload: &'a Map<String, Value>,
}

/// Attaches a valid contribution to its golden record and queues a rebuild
/// of it; the golden record and whether a rebuild was queued. The golden
/// record is the one it was attached to before, else the record the A29
/// external-id links name, else a new one made from the contribution.
pub async fn attach(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    pending: Pending<'_>,
) -> Result<(Uuid, bool), AppError> {
    let golden = match pending.golden {
        Some(g) => g,
        None => {
            let linked: Option<Uuid> = sqlx::query_scalar(
                "SELECT record_id FROM external_id_link \
                  WHERE entity = $1 AND system = $2 AND external_id = $3",
            )
            .bind(entity)
            .bind(pending.source_system)
            .bind(pending.external_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            match linked {
                Some(g) => g,
                None => {
                    let (created, _) = super::super::create_record_for(
                        state,
                        ctx,
                        ctx.user_id,
                        entity,
                        Value::Object(pending.payload.clone()),
                    )
                    .await?;
                    sqlx::query(
                        "INSERT INTO external_id_link (entity, record_id, system, external_id) \
                         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    )
                    .bind(entity)
                    .bind(created)
                    .bind(pending.source_system)
                    .bind(pending.external_id)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    created
                }
            }
        }
    };
    sqlx::query(&format!(
        "UPDATE {t} SET golden_id = $2, status = 'attached', held_reason = NULL WHERE id = $1",
        t = quote_ident(&contribution_table(entity))
    ))
    .bind(pending.contribution)
    .bind(golden)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let queued = queue_rebuild(state, entity, golden, ctx.user_id).await?;
    Ok((golden, queued))
}

/// Queues a rebuild of `golden` unless an identical one is waiting.
pub async fn queue_rebuild(
    state: &EngineState,
    entity: &str,
    golden: Uuid,
    actor: Uuid,
) -> Result<bool, AppError> {
    attome_jobs::enqueue_dedup(
        &state.base.db,
        attome_core::jobs::EngineJob::MasterRebuild {
            entity: entity.to_owned(),
            golden_id: golden,
            actor,
        },
        &format!("master-rebuild:{entity}:{golden}"),
    )
    .await
    .map_err(AppError::internal)
}
