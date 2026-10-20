//! The plays for a deal (roadmap D26-T2): the enabled playbooks for
//! opportunities whose `trigger_condition` holds for this deal, each with
//! its steps in order, for the plays panel on the deal.
//!
//! The condition is an `attome-rules` expression over the deal's fields, as
//! the caller reads them (record- and field-level security apply), for
//! example `stage == "proposal"` or `amount > 100000 and stage == "negotiation"`.
//! An empty condition always holds. A condition that does not compile, or
//! names a field the caller cannot read, or does not come out true, hides
//! that playbook: the panel shows only plays that clearly apply.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::opportunity_lines::OpportunityRead;

/// The most playbooks one deal is checked against.
pub const MAX_PLAYBOOKS: i64 = 200;

/// One step of a play.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SalesPlayStep {
    pub id: Uuid,
    pub title: Option<String>,
    pub guidance: Option<String>,
    pub step_order: Option<f64>,
    pub due_after_days: Option<f64>,
    pub activity_kind: Option<String>,
}

/// A playbook that applies to the deal.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SalesPlay {
    pub playbook_id: Uuid,
    pub name: Option<String>,
    pub name_ar: Option<String>,
    pub steps: Vec<SalesPlayStep>,
}

/// Whether `condition` holds for the deal's `data`. Pure.
pub fn applies(condition: Option<&str>, data: &Value) -> bool {
    let Some(condition) = condition.map(str::trim).filter(|c| !c.is_empty()) else {
        return true;
    };
    let (schema, ctx) = attome_audit::approval::schema_and_context_for_payload(data);
    match attome_rules::compile(condition, &schema) {
        Ok(compiled) => matches!(compiled.eval(&ctx), Ok(attome_rules::Value::Bool(true))),
        Err(_) => false,
    }
}

type PlaybookRow = (Uuid, Option<String>, Option<String>, Option<String>);
type StepRow = (
    Uuid,
    Uuid,
    Option<String>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<String>,
);

/// The plays for `deal`, read as `ctx`.
pub async fn plays_for(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    deal: Uuid,
) -> Result<Vec<SalesPlay>, AppError> {
    let registry = state.entities.load();
    if registry.get("sales_playbook").is_none() || registry.get("playbook_step").is_none() {
        return Err(AppError::NotFound);
    }
    drop(registry);
    ctx.require("sales_playbook", "read")?;
    let record = attome_records::entity_crud::read_record(state, ctx, "opportunity", deal).await?;
    let db = &state.base.db;
    let books: Vec<PlaybookRow> = sqlx::query_as(
        "SELECT id, name, name_ar, trigger_condition FROM sales_playbook \
          WHERE applies_to = 'opportunity' AND is_enabled IS TRUE \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY name, id LIMIT $1",
    )
    .bind(MAX_PLAYBOOKS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let books: Vec<PlaybookRow> = books
        .into_iter()
        .filter(|(_, _, _, condition)| applies(condition.as_deref(), record.data()))
        .collect();
    if books.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = books.iter().map(|b| b.0).collect();
    let steps: Vec<StepRow> = if ctx.require("playbook_step", "read").is_ok() {
        sqlx::query_as(
            "SELECT id, playbook_ref, title, guidance, step_order::float8, \
                    due_after_days::float8, activity_kind \
               FROM playbook_step \
              WHERE playbook_ref = ANY($1) AND (is_active IS NULL OR is_active = true) \
              ORDER BY playbook_ref, step_order NULLS LAST, id",
        )
        .bind(&ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
    } else {
        Vec::new()
    };
    Ok(books
        .into_iter()
        .map(|(playbook_id, name, name_ar, _)| SalesPlay {
            playbook_id,
            name,
            name_ar,
            steps: steps
                .iter()
                .filter(|s| s.1 == playbook_id)
                .map(|s| SalesPlayStep {
                    id: s.0,
                    title: s.2.clone(),
                    guidance: s.3.clone(),
                    step_order: s.4,
                    due_after_days: s.5,
                    activity_kind: s.6.clone(),
                })
                .collect(),
        })
        .collect())
}

/// The plays for a deal.
///
/// The enabled opportunity playbooks whose condition holds for this deal
/// (as the caller reads it), each with its steps in order. A deal sees a
/// handful of plays, so the whole list is one page.
#[utoipa::path(
    get,
    path = "/api/v1/sales/opportunities/{id}/plays",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    responses(
        (status = 200, description = "The plays that apply, all on one page", body = PaginatedResponse<SalesPlay>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read this opportunity or playbooks", body = ErrorResponse),
        (status = 404, description = "No such opportunity, or playbooks are not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_sales_plays(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityRead>>,
    Path(deal): Path<Uuid>,
) -> Result<Json<PaginatedResponse<SalesPlay>>, AppError> {
    let items = plays_for(&state, &ctx, deal).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_sales_plays))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_play_applies_when_its_condition_holds_for_the_deal() {
        let deal = json!({ "stage": "proposal", "amount": 250000 });
        assert!(applies(None, &deal));
        assert!(applies(Some("  "), &deal));
        assert!(applies(Some("stage == \"proposal\""), &deal));
        assert!(applies(
            Some("amount > 100000 and stage == \"proposal\""),
            &deal
        ));
        assert!(!applies(Some("stage == \"negotiation\""), &deal));
    }

    #[test]
    fn a_broken_or_unreadable_condition_hides_the_play() {
        let deal = json!({ "stage": "proposal" });
        assert!(!applies(Some("stage =="), &deal));
        assert!(
            !applies(Some("amount > 5"), &deal),
            "amount is not readable"
        );
        assert!(!applies(Some("stage"), &deal), "not a bool");
    }
}
