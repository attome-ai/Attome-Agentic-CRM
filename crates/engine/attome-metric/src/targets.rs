//! P9-T7: cascading targets — a period's total target spread to the members
//! of one of the metric's dimensions.
//!
//! `POST /api/v1/metrics/{id}/targets/spread` takes the period, the total,
//! the dimension and a method:
//!
//! - `share`: the caller's shares per member, each at least 0, summing to 1
//!   within 0.001;
//! - `last_year`: each member's actual in the snapshot for the same period a
//!   year earlier, as a share of their sum.
//!
//! Children are rounded to cents and the last one takes the rounding
//! remainder, so they always add up to the parent ([`spread`]).
//!
//! The parent is the period's total target (`dimension_value` empty) and the
//! children are member targets with `parent_target_ref` set to it, all
//! written through the generic record path (`create_record_for` /
//! `update_record_for`), so validation and audit run. A spread runs under
//! `pg_try_advisory_xact_lock(namespace, hashtext('attome-metric/spread:{metric}:{period}'))`
//! (a second spread of the same metric and period gets 409) and is
//! retry-safe: an existing parent or child is updated, not duplicated, so a
//! spread that failed half way converges when repeated. The record writes
//! are separate transactions (the generic path owns its own), so the spread
//! is not one atomic transaction; the lock transaction carries the
//! Configuration audit event and commits last.

use std::collections::BTreeMap;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{DateTime, Months, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// `attome_metric.set_target`.
#[derive(Debug)]
pub struct SetTarget;

impl PrivilegeKey for SetTarget {
    const KEY: &'static str = "attome_metric.set_target";
}

/// Most members one spread writes.
pub const MAX_CHILDREN: usize = 500;
/// How far the shares may be from 1.
pub const SHARE_TOLERANCE: f64 = 0.001;

/// How a total is divided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpreadMethod {
    /// The caller's shares.
    Share,
    /// Last year's actuals per member.
    LastYear,
}

impl SpreadMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Share => "share",
            Self::LastYear => "last_year",
        }
    }
}

/// A spread to make.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SpreadBody {
    /// The period the targets are for (its start).
    pub period_start: DateTime<Utc>,
    /// The parent target.
    pub total: f64,
    pub method: SpreadMethod,
    /// One of the metric's dimension attributes.
    pub dimension_attribute: String,
    /// With `share`: each member's share, summing to 1.
    #[serde(default)]
    pub shares: Option<BTreeMap<String, f64>>,
}

/// One member's target.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ChildTarget {
    pub dimension_value: String,
    pub target_value: f64,
}

/// What a spread wrote.
#[derive(Debug, Serialize, ToSchema)]
pub struct SpreadResult {
    pub parent_target_id: Uuid,
    pub children: Vec<ChildTarget>,
    pub sum_of_children: f64,
}

fn cents(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Checks a caller's shares. Pure.
pub fn check_shares(shares: &BTreeMap<String, f64>) -> Result<(), AppError> {
    if shares.is_empty() || shares.len() > MAX_CHILDREN {
        return Err(AppError::Validation(format!(
            "shares name 1 to {MAX_CHILDREN} members"
        )));
    }
    if shares
        .iter()
        .any(|(k, v)| k.trim().is_empty() || !v.is_finite() || *v < 0.0)
    {
        return Err(AppError::Validation(
            "each share names a member and is a number from 0".into(),
        ));
    }
    let sum: f64 = shares.values().sum();
    if (sum - 1.0).abs() > SHARE_TOLERANCE {
        return Err(AppError::Validation(format!(
            "shares add up to {sum}, not 1"
        )));
    }
    Ok(())
}

/// Shares from last year's actuals: each member's part of their sum.
/// Members with a negative actual count as 0. Pure.
pub fn shares_from_actuals(
    actuals: &BTreeMap<String, f64>,
) -> Result<BTreeMap<String, f64>, AppError> {
    let sum: f64 = actuals.values().map(|v| v.max(0.0)).sum();
    if actuals.is_empty() || sum <= 0.0 {
        return Err(AppError::Validation(
            "the metric has no positive actuals per member a year earlier".into(),
        ));
    }
    Ok(actuals
        .iter()
        .map(|(k, v)| (k.clone(), v.max(0.0) / sum))
        .collect())
}

/// Divides `total` by `shares`, in member order, to cents; the last member
/// takes the remainder so the children add up to the total. Pure.
pub fn spread(total: f64, shares: &BTreeMap<String, f64>) -> Vec<ChildTarget> {
    let sum: f64 = shares.values().sum();
    let mut out: Vec<ChildTarget> = Vec::with_capacity(shares.len());
    let mut given = 0.0;
    let last = shares.len().saturating_sub(1);
    for (i, (member, share)) in shares.iter().enumerate() {
        let value = if i == last {
            cents(total - given)
        } else {
            cents(total * share / sum)
        };
        given += value;
        out.push(ChildTarget {
            dimension_value: member.clone(),
            target_value: value,
        });
    }
    out
}

/// The latest actual per member of `attribute` for `period` a year back.
async fn last_year_actuals(
    state: &EngineState,
    metric: Uuid,
    period_start: DateTime<Utc>,
    attribute: &str,
) -> Result<BTreeMap<String, f64>, AppError> {
    let year_before = period_start
        .checked_sub_months(Months::new(12))
        .ok_or_else(|| AppError::Validation("period_start is out of range".into()))?
        .date_naive();
    let rows: Vec<(String, f64)> = sqlx::query_as(
        "SELECT DISTINCT ON (dimension_value) dimension_value, actual \
           FROM metric_snapshot \
          WHERE metric_ref = $1 AND period_start = $2 AND dimension_attribute = $3 \
            AND dimension_value IS NOT NULL AND actual IS NOT NULL \
          ORDER BY dimension_value, computed_at DESC, id DESC \
          LIMIT 1000",
    )
    .bind(metric)
    .bind(year_before)
    .bind(attribute)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// The metric's dimension attributes, `NotFound` without the metric.
async fn dimensions(state: &EngineState, metric: Uuid) -> Result<Vec<String>, AppError> {
    let row: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(d) FROM dashboard_metric_definition d \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(metric)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    Ok(crate::metric::parse_dimensions(
        row.get("dimension_attributes").and_then(Value::as_str),
    ))
}

/// The existing target for (metric, period, parent, member), with its row
/// version; the parent itself when `parent` and `member` are `None`.
async fn existing_target(
    state: &EngineState,
    metric: Uuid,
    period_start: DateTime<Utc>,
    parent: Option<Uuid>,
    member: Option<&str>,
) -> Result<Option<(Uuid, i64)>, AppError> {
    sqlx::query_as(
        "SELECT id, row_version FROM dashboard_metric_target \
          WHERE metric_ref = $1 AND period_start = $2 \
            AND (is_active IS NULL OR is_active = true) \
            AND parent_target_ref IS NOT DISTINCT FROM $3 \
            AND (CASE WHEN $4::text IS NULL THEN COALESCE(dimension_value, '') = '' \
                      ELSE dimension_value = $4 END) \
          ORDER BY id LIMIT 1",
    )
    .bind(metric)
    .bind(period_start)
    .bind(parent)
    .bind(member)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Writes one target through the generic record path: updates the
/// existing one, or creates it.
async fn put_target(
    state: &EngineState,
    ctx: &SecurityContext,
    existing: Option<(Uuid, i64)>,
    fields: Value,
) -> Result<Uuid, AppError> {
    match existing {
        Some((id, version)) => {
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                "dashboard_metric_target",
                id,
                version,
                fields,
            )
            .await?;
            Ok(id)
        }
        None => attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "dashboard_metric_target",
            fields,
        )
        .await
        .map(|(id, _)| id),
    }
}

/// Spreads a period's total target to a dimension's members.
pub async fn spread_target(
    state: &EngineState,
    ctx: &SecurityContext,
    metric: Uuid,
    body: &SpreadBody,
) -> Result<SpreadResult, AppError> {
    ctx.require("dashboard_metric_target", "create")?;
    ctx.require("dashboard_metric_target", "update")?;
    if !body.total.is_finite() || body.total < 0.0 {
        return Err(AppError::Validation("total is a number from 0".into()));
    }
    let attribute = body.dimension_attribute.trim();
    if !dimensions(state, metric)
        .await?
        .iter()
        .any(|d| d == attribute)
    {
        return Err(AppError::Validation(format!(
            "{attribute} is not one of the metric's dimensions"
        )));
    }
    let shares = match body.method {
        SpreadMethod::Share => {
            let shares = body
                .shares
                .as_ref()
                .ok_or_else(|| AppError::Validation("share needs shares".into()))?;
            check_shares(shares)?;
            shares.clone()
        }
        SpreadMethod::LastYear => {
            let actuals = last_year_actuals(state, metric, body.period_start, attribute).await?;
            let shares = shares_from_actuals(&actuals)?;
            if shares.len() > MAX_CHILDREN {
                return Err(AppError::Validation(format!(
                    "more than {MAX_CHILDREN} members"
                )));
            }
            shares
        }
    };
    let children = spread(body.total, &shares);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let key = format!(
        "attome-metric/spread:{metric}:{}",
        body.period_start.to_rfc3339()
    );
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&key)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a spread for this metric and period is running",
        ));
    }

    let parent_existing = existing_target(state, metric, body.period_start, None, None).await?;
    let parent = put_target(
        state,
        ctx,
        parent_existing,
        json!({
            "metric_ref": metric,
            "period_start": body.period_start,
            "target_value": body.total,
            "spread_method": body.method.as_str(),
        }),
    )
    .await?;
    for child in &children {
        let existing = existing_target(
            state,
            metric,
            body.period_start,
            Some(parent),
            Some(&child.dimension_value),
        )
        .await?;
        put_target(
            state,
            ctx,
            existing,
            json!({
                "metric_ref": metric,
                "period_start": body.period_start,
                "target_value": child.target_value,
                "dimension_attribute": attribute,
                "dimension_value": child.dimension_value,
                "parent_target_ref": parent,
                "spread_method": body.method.as_str(),
            }),
        )
        .await?;
    }

    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "dashboard_metric_target",
            Some(parent),
        )
        .named("metric_target.spread"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    let sum_of_children = cents(children.iter().map(|c| c.target_value).sum());
    Ok(SpreadResult {
        parent_target_id: parent,
        children,
        sum_of_children,
    })
}

/// Spread a target to a dimension's members
///
/// P9-T7: writes the period's total target and one child target per member
/// of the dimension, by the caller's shares or by last year's actuals. The
/// children add up to the total. Needs `attome_metric.set_target`.
#[utoipa::path(
    post,
    path = "/api/v1/metrics/{id}/targets/spread",
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The metric")),
    request_body = SpreadBody,
    responses(
        (status = 200, description = "The parent and its children", body = SpreadResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks attome_metric.set_target", body = ErrorResponse),
        (status = 404, description = "No such metric", body = ErrorResponse),
        (status = 409, description = "A spread for this metric and period is running", body = ErrorResponse),
        (status = 422, description = "Not one of the metric's dimensions, shares that do not add up to 1, or no actuals a year earlier", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_spread(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SetTarget>>,
    Path(metric): Path<Uuid>,
    Json(body): Json<SpreadBody>,
) -> Result<Json<SpreadResult>, AppError> {
    spread_target(&state, &ctx, metric, &body).await.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(items: &[(&str, f64)]) -> BTreeMap<String, f64> {
        items.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    #[test]
    fn spread_children_add_up_to_the_parent() {
        let children = spread(
            1000.0,
            &map(&[
                ("east", 1.0 / 3.0),
                ("north", 1.0 / 3.0),
                ("west", 1.0 / 3.0),
            ]),
        );
        let sum: f64 = children.iter().map(|c| c.target_value).sum();
        assert_eq!(cents(sum), 1000.0);
        assert_eq!(children[0].target_value, 333.33);
        assert_eq!(children[2].target_value, 333.34);
    }

    #[test]
    fn spread_shares_must_add_up_to_one() {
        assert!(check_shares(&map(&[("a", 0.5), ("b", 0.5)])).is_ok());
        assert!(check_shares(&map(&[("a", 0.5), ("b", 0.4995)])).is_ok());
        assert!(check_shares(&map(&[("a", 0.5), ("b", 0.4)])).is_err());
        assert!(check_shares(&map(&[("a", -0.5), ("b", 1.5)])).is_err());
        assert!(check_shares(&BTreeMap::new()).is_err());
    }

    #[test]
    fn spread_last_year_uses_actual_shares() {
        let shares = shares_from_actuals(&map(&[("a", 30.0), ("b", 10.0), ("c", -5.0)])).unwrap();
        assert_eq!(shares["a"], 0.75);
        assert_eq!(shares["b"], 0.25);
        assert_eq!(shares["c"], 0.0);
        assert!(shares_from_actuals(&map(&[("a", 0.0)])).is_err());
    }
}
