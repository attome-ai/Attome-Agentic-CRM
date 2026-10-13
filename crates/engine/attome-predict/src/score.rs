//! The scoring sweep (new open tickets get a prediction from every active
//! model) and the outcome-fill sweep (predictions whose horizon has passed
//! get their actual outcome recorded into M97's `outcome` ledger).
//! Both are periodic, bounded, dedup-keyed `EngineJob`s
//! (`crates/server/src/jobs.rs`'s `spawn_dedup_scheduler` pattern) rather
//! than an event-driven "ticket updated -> rescore" trigger — see this
//! crate's D-473 entry for why: every feature this crate extracts is fixed
//! at ticket-creation time (`features.rs`'s own doc comment), so a given
//! ticket's score under a given model version never changes, and there is
//! therefore nothing for a per-update rescore to *learn* — the periodic
//! sweep already reaches every never-yet-scored ticket within one interval.

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

use crate::model::PredictionModelRow;

#[derive(Debug, Default)]
pub struct ScoringSweepStats {
    pub models_considered: u32,
    pub scored: u32,
}

/// For every `status = 'active'` model, scores every open ticket that has
/// never been scored by that model's current row (`features::open_tickets`)
/// and inserts one `prediction` row per ticket.
///
/// Only `target = 'sla_breach'` / `entity = 'service_ticket'` is implemented —
/// an active model for any other (Phase 2/3-reserved) target/entity pair is
/// skipped with a `warn` log, not an error, since a future phase's model
/// definitions may exist in this table before this crate's code catches up
/// to score them.
pub async fn run_scoring_sweep(db: &DbPool) -> Result<ScoringSweepStats, AppError> {
    let mut stats = ScoringSweepStats::default();
    let models: Vec<PredictionModelRow> = sqlx::query_as(
        "SELECT id, name, target, entity, features, algorithm, trained_version, metrics, \
                model_artifact, status, created_by, organization_ref, created_at, updated_at, \
                row_version, is_deleted \
         FROM prediction_model \
         WHERE is_deleted = false AND status = 'active'",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for model in models {
        stats.models_considered += 1;
        if model.target != crate::TARGET_SLA_BREACH || model.entity != crate::ENTITY_TICKET {
            tracing::warn!(model_id = %model.id, target = %model.target, entity = %model.entity, "predict: active model targets a pair this crate build cannot score yet — skipping");
            continue;
        }
        let Some(artifact) = model.artifact() else {
            tracing::warn!(model_id = %model.id, "predict: active model has no usable model_artifact — skipping (should not happen)");
            continue;
        };
        // Defensive version-skew guard: `predict_proba` asserts its input
        // length matches the trained coefficient count (`model.rs`'s own doc
        // comment names exactly this scenario — a rolling deploy where an
        // older worker still holds a model trained under a newer
        // `FEATURE_KEYS`, or vice versa). Checking here turns that into a
        // graceful per-model skip rather than a panic mid-sweep, the same
        // fail-closed-but-not-crash posture the target/entity and
        // missing-artifact checks above already take.
        if artifact.feature_order != crate::features::fixed_feature_order() {
            tracing::warn!(
                model_id = %model.id,
                "predict: active model's feature_order does not match this build's \
                 current FEATURE_KEYS — skipping until retrained (version skew)"
            );
            continue;
        }

        let candidates = crate::features::open_tickets(db, model.id).await?;
        for candidate in candidates {
            let score = artifact.predict_proba(&candidate.features);
            let label = if score > 0.5 { "breach" } else { "no_breach" };
            let explanation = explain(&artifact, &candidate.features);

            if write_prediction(
                db,
                model.id,
                candidate.ticket_id,
                score,
                label,
                &explanation,
                candidate.horizon_at,
            )
            .await?
            {
                stats.scored += 1;
            }
        }
    }

    Ok(stats)
}

/// Top feature contributions (`weight * value` per feature, sorted by
/// absolute magnitude) — the module plan's "explanation ... top feature
/// contributions" requirement, in a structured shape a banner/widget can
/// render without re-deriving the math client-side.
fn explain(artifact: &crate::model::ModelArtifact, features: &[f64]) -> serde_json::Value {
    let mut contributions: Vec<serde_json::Value> = artifact
        .feature_order
        .iter()
        .zip(&artifact.coefficients)
        .zip(features)
        .map(|((key, weight), value)| {
            let contribution = weight * value;
            (key, value, contribution)
        })
        .map(|(key, value, contribution)| (key.clone(), *value, contribution))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|(key, value, contribution)| json!({ "key": key, "value": value, "contribution": contribution }))
        .collect();
    contributions.sort_by(|a, b| {
        let ca = a["contribution"].as_f64().unwrap_or(0.0).abs();
        let cb = b["contribution"].as_f64().unwrap_or(0.0).abs();
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });
    serde_json::Value::Array(contributions)
}

/// Inserts one `prediction` row, guarded by a per-ticket advisory lock so
/// two overlapping sweep runs (a slow tick still finishing when the next
/// tick's dedup-keyed job is claimed by a second worker) can't both insert a
/// duplicate row for the same `(model_ref, ticket)` pair — the `NOT EXISTS`
/// check in `features::open_tickets` only rules out a race that has already
/// committed, not one racing concurrently. Returns `false` (not an error)
/// when the lock is held by a concurrent writer — the other writer's insert
/// is the one that counts.
async fn write_prediction(
    db: &DbPool,
    model_ref: Uuid,
    ticket_id: Uuid,
    score: f64,
    label: &str,
    explanation: &serde_json::Value,
    horizon_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-predict/score:{ticket_id}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Ok(false);
    }

    sqlx::query(
        "INSERT INTO prediction \
            (id, model_ref, regarding_entity, regarding_id, score, label, explanation, horizon_at) \
         VALUES ($1, $2, 'service_ticket', $3, $4, $5, $6, $7) \
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(model_ref)
    .bind(ticket_id)
    .bind(score)
    .bind(label)
    .bind(explanation)
    .bind(horizon_at)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(true)
}

#[derive(Debug, Default)]
pub struct OutcomeFillStats {
    pub filled: u32,
}

/// Bounded per tick, same convention as every other sweep in this crate.
const OUTCOME_FILL_BATCH_SIZE: i64 = 500;

/// For every `prediction` row whose `horizon_at` has passed and whose
/// `outcome_ref` is still `NULL`, looks up the ticket's actual
/// `sla_breached` value and writes ONE complete `outcome` row
/// (`kind = 'prediction'`, already reserved in migration `0291`'s CHECK) —
/// see `0421`'s own `outcome_ref` doc comment for why this is a single write
/// rather than a two-phase propose/measure dual-write.
///
/// Writes `outcome` directly by bound SQL rather than through
/// `attome_ai::outcome::record_proposed`/`record_measured`: those helpers
/// gate on `ActionDescriptor::outcome_kind`, an `attome-ai`-registry concept
/// this crate has no reason to depend on (a prediction is not a
/// `attome-ai`-typed capability invocation) — `attome_ai::outcome`'s own
/// module doc names this exact "write the shared table directly, no new
/// dependency edge" pattern as the intended path for a producer outside
/// `attome-ai`.
///
/// A ticket that no longer exists (hard-deleted — this platform normally
/// soft-deletes, so this is defensive) is skipped, not an error: its
/// `outcome_ref` stays `NULL` forever, which simply excludes it from
/// accuracy reporting.
pub async fn fill_outcomes(db: &DbPool) -> Result<OutcomeFillStats, AppError> {
    let mut stats = OutcomeFillStats::default();
    let due: Vec<(Uuid, Uuid, Uuid, f64, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, model_ref, regarding_id, score, label, predicted_at FROM prediction \
          WHERE is_deleted = false AND outcome_ref IS NULL AND horizon_at < NOW() \
            AND regarding_entity = 'service_ticket' \
          ORDER BY horizon_at ASC LIMIT $1",
    )
    .bind(OUTCOME_FILL_BATCH_SIZE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for (prediction_id, model_ref, ticket_id, score, label, predicted_at) in due {
        let actual: Option<(Option<bool>, Option<String>)> = sqlx::query_as(
            "SELECT sla_breached, sla_calculation_status FROM service_ticket WHERE id = $1",
        )
        .bind(ticket_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        // D-517: a ticket whose SLA deadline was never calculated has no
        // outcome — "not breached" would be a fabricated label. Left
        // unfilled, like a missing ticket, so it stays out of accuracy.
        let Some(actual_breached) = actual.and_then(|(breached, status)| {
            (status.as_deref() != Some("unresolved")).then(|| breached.unwrap_or(false))
        }) else {
            continue;
        };

        if fill_one(
            db,
            prediction_id,
            model_ref,
            score,
            &label,
            actual_breached,
            predicted_at,
        )
        .await?
        {
            stats.filled += 1;
        }
    }
    Ok(stats)
}

/// Guarded by the same per-prediction advisory-lock pattern
/// `write_prediction` uses, for the identical "two overlapping sweeps must
/// not both write" reason.
async fn fill_one(
    db: &DbPool,
    prediction_id: Uuid,
    model_ref: Uuid,
    score: f64,
    label: &str,
    actual_breached: bool,
    predicted_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-predict/fill:{prediction_id}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        return Ok(false);
    }

    // Still guard against a concurrent writer that raced this one to commit
    // between the SELECT in `fill_outcomes` and this lock acquisition.
    let already_filled: bool =
        sqlx::query_scalar("SELECT outcome_ref IS NOT NULL FROM prediction WHERE id = $1")
            .bind(prediction_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if already_filled {
        return Ok(false);
    }

    let predicted_breach = label == "breach";
    let effectiveness = if predicted_breach == actual_breached {
        1.0
    } else {
        0.0
    };

    // Shares its id with the `prediction` row it accompanies — the same
    // "producing record's own id" convention `ai_suggestion_outcome`/
    // `outcome` already use (0291's header, `outcome.rs`'s module
    // doc).
    sqlx::query(
        "INSERT INTO outcome \
            (id, kind, source_module, entity_logicalname, regarding_entity, regarding_id, \
             model_id, proposed_at, expected_value, actual_value, measured_at, effectiveness) \
         VALUES ($1, 'prediction', 'attome-predict', 'service_ticket', 'prediction', $1, \
                 $2, $3, $4, $5, NOW(), $6)",
    )
    .bind(prediction_id)
    .bind(model_ref.to_string())
    .bind(predicted_at)
    .bind(json!({ "score": score, "label": label }))
    .bind(json!({ "actual_breached": actual_breached }))
    .bind(effectiveness)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query("UPDATE prediction SET outcome_ref = $1 WHERE id = $1")
        .bind(prediction_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(true)
}
