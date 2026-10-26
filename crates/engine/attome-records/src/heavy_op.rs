//! AA10-T2: the size check every heavy operation asks first.
//!
//! Before an update or delete over a filtered set runs, [`size_check`] counts
//! the rows the caller could change: the filter is compiled by the query
//! engine (`query_spec::compile::compile_scope`, the compiler `query/run`
//! uses), with the caller's record scope for the change (not for reading) on
//! the entity itself, and the count stops one row past the inline threshold,
//! so it never scans the whole table. Up to the threshold the count is
//! exact and the work runs inline; past it the planner's row estimate stands
//! in for the total and the work goes to the background.
//!
//! The threshold is the setting `limits.heavy_op.inline_max_rows` (500 by
//! default). The duration is the estimated rows over [`ROWS_PER_SECOND`], a
//! constant until AA10-T9 records the measured speed per kind.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::query_spec::compile::{Access, Env, compile_scope};
use crate::query_spec::{Clock, Condition, QuerySpec};

/// The setting's key under `limits.` (`SettingsSnapshot::runtime_limit`).
pub const INLINE_MAX_ROWS_LIMIT: &str = "heavy_op.inline_max_rows";
/// The inline threshold when the deployment sets none.
pub const DEFAULT_INLINE_MAX_ROWS: i64 = 500;
/// Rows a background chunk changes per second, until AA10-T9 measures it.
pub const ROWS_PER_SECOND: i64 = 2000;

/// Where a heavy operation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Path {
    /// In the request: small enough to finish now.
    Inline,
    /// As a background job with progress.
    Background,
}

/// What the size check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SizeEstimate {
    /// The rows counted, exact up to the threshold plus one.
    pub exact_upto: i64,
    /// Whether the count passed the threshold.
    pub exceeds: bool,
    /// The exact count, or the planner's estimate when it passed.
    pub estimated_rows: i64,
    pub estimated_seconds: i64,
    pub path: Path,
}

/// The estimate from a bounded `counted` (at most `threshold + 1`) and, when
/// that passed the threshold, the planner's `plan_rows`. Pure.
pub fn estimate(counted: i64, threshold: i64, plan_rows: Option<i64>) -> SizeEstimate {
    let exceeds = counted > threshold;
    let estimated_rows = if exceeds {
        plan_rows.unwrap_or(counted).max(counted)
    } else {
        counted
    };
    SizeEstimate {
        exact_upto: counted,
        exceeds,
        estimated_rows,
        estimated_seconds: (estimated_rows + ROWS_PER_SECOND - 1) / ROWS_PER_SECOND,
        path: if exceeds {
            Path::Background
        } else {
            Path::Inline
        },
    }
}

/// How many rows of `entity` matching `filter` the caller may `action`
/// (update or delete), and whether that work runs inline or in the
/// background. Refused when the caller may not `action` the entity at all.
pub async fn size_check(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    filter: Option<&Condition>,
    action: RecordAction,
) -> Result<SizeEstimate, AppError> {
    let threshold = state
        .runtime_limit(INLINE_MAX_ROWS_LIMIT)
        .unwrap_or(DEFAULT_INLINE_MAX_ROWS)
        .max(1);
    size_check_with(state, security, entity, filter, action, threshold).await
}

/// [`size_check`] against `threshold` instead of the setting.
pub async fn size_check_with(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    filter: Option<&Condition>,
    action: RecordAction,
    threshold: i64,
) -> Result<SizeEstimate, AppError> {
    if matches!(action, RecordAction::Read) {
        return Err(AppError::internal(
            "size_check: a heavy operation updates or deletes",
        ));
    }
    security.require(entity, action.as_str())?;
    let threshold = threshold.max(1);

    // Related records named in the filter are read with the caller's read
    // scope; the entity itself with the scope of the change.
    let (read, change): (HashMap<Uuid, AccessLevel>, HashMap<Uuid, AccessLevel>) =
        if security.is_admin {
            (HashMap::new(), HashMap::new())
        } else {
            let db = &state.base.db;
            (
                attome_security::resolve_all_entity_access_levels(
                    db,
                    security.user_id,
                    RecordAction::Read,
                )
                .await?
                .into_values()
                .collect(),
                attome_security::resolve_all_entity_access_levels(db, security.user_id, action)
                    .await?
                    .into_values()
                    .collect(),
            )
        };
    let mut spec: QuerySpec = serde_json::from_value(serde_json::json!({ "entity": entity }))
        .map_err(AppError::internal)?;
    spec.r#where = filter.cloned();
    let tz = state
        .base
        .config
        .app
        .time_zone
        .as_deref()
        .and_then(|z| z.parse().ok())
        .unwrap_or(chrono_tz::UTC);
    let (sql, binds) = {
        let registry = state.entities.load();
        let relationships = state.relationships.load();
        let root = registry.get(entity).ok_or(AppError::NotFound)?;
        let mut access = Access::new(read);
        if !security.is_admin {
            let level = change.get(&root.id).copied().unwrap_or(AccessLevel::None);
            access = access.with(root.id, level);
        }
        let env = Env {
            registry: &registry,
            relationships: &relationships,
            ctx: security,
            access: &access,
            clock: Clock {
                now: chrono::Utc::now(),
                tz,
                fiscal_start_month: 1,
            },
        };
        compile_scope(&spec, &env)?
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let timeout_ms = state
        .runtime_limit("query.timeout_ms.interactive")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(state.base.config.query.timeouts_ms.interactive)
        .max(1);
    sqlx::query(&attome_db::tag_dynamic(
        "heavy_op.size_check",
        &format!("SET LOCAL statement_timeout = {timeout_ms}"),
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let count_sql = attome_db::tag_dynamic(
        "heavy_op.size_check",
        &format!(
            "SELECT count(*) FROM ({sql} LIMIT {}) AS s",
            threshold.saturating_add(1)
        ),
    );
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for bind in &binds {
        count = count.bind(bind.as_str());
    }
    let counted = count
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let plan_rows = if counted > threshold {
        // Never EXPLAIN ANALYZE: that would run the scan this avoids.
        let explain_sql = attome_db::tag_dynamic(
            "heavy_op.size_check",
            &format!("EXPLAIN (FORMAT JSON) {sql}"),
        );
        let mut explain = sqlx::query_scalar::<_, Value>(&explain_sql);
        for bind in &binds {
            explain = explain.bind(bind.as_str());
        }
        let plan = explain
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        plan.pointer("/0/Plan/Plan Rows")
            .and_then(Value::as_f64)
            .map(|rows| rows.round() as i64)
    } else {
        None
    };
    drop(tx);
    Ok(estimate(counted, threshold, plan_rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_the_threshold_is_inline_and_exact() {
        let e = estimate(500, 500, None);
        assert_eq!(e.path, Path::Inline);
        assert!(!e.exceeds);
        assert_eq!(
            (e.exact_upto, e.estimated_rows, e.estimated_seconds),
            (500, 500, 1)
        );
        assert_eq!(estimate(0, 500, None).estimated_seconds, 0);
    }

    #[test]
    fn past_the_threshold_uses_the_planner_estimate() {
        let e = estimate(501, 500, Some(90_000));
        assert_eq!(e.path, Path::Background);
        assert!(e.exceeds);
        assert_eq!((e.estimated_rows, e.estimated_seconds), (90_000, 45));
        // A planner that guesses low never estimates below what was counted.
        assert_eq!(estimate(501, 500, Some(10)).estimated_rows, 501);
        assert_eq!(estimate(501, 500, None).estimated_rows, 501);
    }
}
