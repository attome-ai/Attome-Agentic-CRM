//! Plan publishing (roadmap F10-T4, the publish step): a plan's draft
//! version (the latest without `published_at`) is compiled, every component
//! through [`crate::rules::compile`], and published with the hash of what
//! was compiled. A version whose rate tables overlap or do not parse is
//! refused with the component and reason, so a broken plan never reaches a
//! calculation run.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// `comp_plan.update`: may publish a plan.
#[derive(Debug)]
pub struct PlanUpdate;

impl PrivilegeKey for PlanUpdate {
    const KEY: &'static str = "comp_plan.update";
}

/// The hash of a version's compiled components: their ids, modes, caps,
/// gates and bands in a fixed order.
pub fn compiled_hash(components: &[crate::rules::Component]) -> String {
    let mut text = String::new();
    for c in components {
        text.push_str(&format!(
            "{}|{:?}|{:?}|{:?}|{:?}|{:?}|{};",
            c.id,
            c.mode,
            c.gate_pct,
            c.margin_floor_pct,
            c.cap_per_deal,
            c.cap_per_period,
            c.minor_units
        ));
        for b in &c.bands {
            text.push_str(&format!("{}-{:?}@{},", b.from_pct, b.to_pct, b.rate_pct));
        }
    }
    format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommissionPlanPublished {
    pub plan_id: Uuid,
    pub version_id: Uuid,
    pub compiled_hash: String,
    pub components: usize,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/plans/{id}/publish",
    tag = "commission",
    params(("id" = Uuid, Path, description = "The compensation plan")),
    responses(
        (status = 200, description = "The draft version compiled and is published", body = CommissionPlanPublished),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_plan.update", body = ErrorResponse),
        (status = 404, description = "No such plan", body = ErrorResponse),
        (status = 409, description = "The plan has no draft version", body = ErrorResponse),
        (status = 422, description = "A component does not compile (overlapping bands, an unreadable rate table); the message names it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn commission_post_publish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<PlanUpdate>>,
    Path(plan): Path<Uuid>,
) -> Result<Json<CommissionPlanPublished>, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM comp_plan WHERE id = $1 \
             AND (is_active IS NULL OR is_active = true))",
    )
    .bind(plan)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let draft: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM comp_plan_version \
         WHERE plan_ref = $1 AND published_at IS NULL AND (is_active IS NULL OR is_active = true) \
         ORDER BY version DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .bind(plan)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(version) = draft else {
        return Err(AppError::Conflict(
            "the plan has no draft version to publish",
        ));
    };
    let components = crate::run::components(&state, version)
        .await
        .map_err(AppError::Validation)?;
    if components.is_empty() {
        return Err(AppError::Validation(
            "the draft version has no components".into(),
        ));
    }
    let hash = compiled_hash(&components);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let published = sqlx::query(
        "UPDATE comp_plan_version SET published_at = now()::date, compiled_hash = $2, \
             modified_at = now(), row_version = row_version + 1 \
         WHERE id = $1 AND published_at IS NULL",
    )
    .bind(version)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if published.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "the version was published by another request",
        ));
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "comp_plan_version",
            Some(version),
        )
        .comment(format!("published plan {plan}: {hash}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    // F10-T9: open periods get a preview of what the new version pays.
    if let Err(e) = crate::recalc::enqueue_open_periods(&state).await {
        tracing::warn!(%plan, error = %e, "plan published; queueing the recalculation previews failed");
    }
    Ok(Json(CommissionPlanPublished {
        plan_id: plan,
        version_id: version,
        compiled_hash: hash,
        components: components.len(),
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(commission_post_publish),
    components(schemas(CommissionPlanPublished))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Band, Component, TierMode};
    use rust_decimal::Decimal;

    fn component(rate: i64) -> Component {
        Component {
            id: Uuid::from_u128(1),
            bands: vec![Band {
                from_pct: Decimal::ZERO,
                to_pct: None,
                rate_pct: Decimal::from(rate),
            }],
            mode: TierMode::Retroactive,
            gate_pct: None,
            margin_floor_pct: None,
            cap_per_deal: None,
            cap_per_period: None,
            minor_units: 2,
        }
    }

    #[test]
    fn the_hash_follows_what_was_compiled() {
        assert_eq!(
            compiled_hash(&[component(5)]),
            compiled_hash(&[component(5)])
        );
        assert_ne!(
            compiled_hash(&[component(5)]),
            compiled_hash(&[component(6)])
        );
        assert!(compiled_hash(&[]).starts_with("sha256:"));
    }
}
