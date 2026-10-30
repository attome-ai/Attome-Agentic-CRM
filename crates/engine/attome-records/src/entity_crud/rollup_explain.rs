//! A10-T5: why a rollup has its value. `GET
//! /api/v1/{entity}/{id}/rollups/{attribute}/explain` answers the
//! definition (function, path, field, filter, window), the stored value,
//! how many related records it counts, and the first
//! [`MAX_LISTED`] of them the caller may read with their amounts.
//! Related records the caller may not read are counted (the stored value
//! already includes them) but never listed.

use attome_core::EngineState;
use attome_core::rollup::{RollupOptions, contributors_sql};
use attome_security::RecordAction;
use attome_security::field_gate::{Surface, readable};
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::resolve::resolve_entity;

/// The most contributing records one answer lists.
pub const MAX_LISTED: i64 = 100;

/// One related record a rollup counts.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RollupContributor {
    pub id: Uuid,
    /// The aggregated field's value; null for a count, or when the caller
    /// may not read the field.
    #[schema(value_type = Object)]
    pub value: Value,
}

/// Why a rollup has its value.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RollupExplanation {
    pub entity: String,
    pub record_id: Uuid,
    pub attribute: String,
    /// `count`, `distinct_count`, `sum`, `min`, `max`, `avg`, `first` or `last`.
    pub function: String,
    /// `fast` or `exact`.
    pub mode: String,
    /// Each step as `entity.lookup`, from this record outwards.
    pub path: Vec<String>,
    /// The related records' field aggregated; absent for a count.
    pub field: Option<String>,
    pub filter: Option<String>,
    pub window_days: Option<u32>,
    /// The stored value.
    #[schema(value_type = Object)]
    pub value: Value,
    /// Related records counted now, readable or not.
    pub counted: i64,
    /// Of those, the ones the caller may not read.
    pub hidden: i64,
    /// The first readable ones, by id.
    pub records: Vec<RollupContributor>,
    /// More readable records than listed.
    pub truncated: bool,
}

fn explanation_head(
    entity: &str,
    record_id: Uuid,
    attribute: &str,
    opts: &RollupOptions,
    value: Value,
) -> RollupExplanation {
    RollupExplanation {
        entity: entity.to_owned(),
        record_id,
        attribute: attribute.to_owned(),
        function: opts.function.as_str().to_owned(),
        mode: match opts.mode {
            attome_core::rollup::RollupMode::Fast => "fast",
            attome_core::rollup::RollupMode::Exact => "exact",
        }
        .to_owned(),
        path: opts
            .path
            .iter()
            .map(|s| format!("{}.{}", s.entity, s.via))
            .collect(),
        field: opts.attribute.clone(),
        filter: opts.filter.clone(),
        window_days: opts.window.as_ref().map(|w| w.days),
        value,
        counted: 0,
        hidden: 0,
        records: Vec::new(),
        truncated: false,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/rollups/{attribute}/explain",
    tag = "entity",
    operation_id = "explain_rollup",
    summary = "Explain a rollup field's value",
    description ="Why a rollup field has its value (A10-T5): its definition, the stored value, how many related records it counts, and the first 100 of them the caller may read, with their amounts. Related records the caller may not read are counted but not listed. Needs read access to the record and the field.",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("attribute" = String, Path, description = "The rollup field"),
    ),
    responses(
        (status = 200, description = "The explanation", body = RollupExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such record or rollup field, or the caller cannot read it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn explain_rollup(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity_input, record_id, attribute)): Path<(String, Uuid, String)>,
) -> Result<Json<RollupExplanation>, AppError> {
    let (_, entity_name, _, _) = resolve_entity(&state, &entity_input).await?;
    let record = super::read_record(&state, &ctx, &entity_name, record_id).await?;
    let registry = std::sync::Arc::clone(&state.entities.load());
    let meta = registry.get(&entity_name).ok_or(AppError::NotFound)?;
    let attr = meta
        .attrs
        .iter()
        .find(|a| a.logicalname == attribute && a.is_rollup())
        .ok_or(AppError::NotFound)?;
    if !readable(
        &ctx,
        &entity_name,
        attr,
        meta.primary_name_attribute.as_deref(),
        Surface::Interactive,
    ) {
        return Err(AppError::NotFound);
    }
    let opts = attome_core::rollup::parse_options(attr.options.as_ref())?;
    let value = record
        .data()
        .get(&attribute)
        .cloned()
        .unwrap_or(Value::Null);
    let mut out = explanation_head(&entity_name, record_id, &attribute, &opts, value);

    let last = opts
        .path
        .last()
        .and_then(|step| registry.get(&step.entity))
        .ok_or(AppError::NotFound)?;
    let (from, alias, binds) = contributors_sql(&opts, &last.attrs)?;
    let db = &state.base.db;

    let count_sql =
        attome_db::tag_dynamic("rollup.explain_count", &format!("SELECT COUNT(*) {from}"));
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql).bind(record_id);
    for bind in &binds {
        count = count.bind(bind);
    }
    out.counted = count.fetch_one(db).await.map_err(AppError::internal)?;

    let level = attome_security::resolve_entity_access_level(
        db,
        ctx.user_id,
        last.entity_id,
        &last.logicalname,
        RecordAction::Read,
    )
    .await?;
    let pred = attome_security::rls_predicate(
        &ctx,
        last.entity_id,
        &alias,
        level,
        RecordAction::Read.share_capability(),
        2 + binds.len(),
    );
    let predicate = pred.as_ref().map_or("", |p| p.sql.as_str());
    // The amount is shown only when the caller may read the field itself.
    let amount = match opts.attribute.as_deref() {
        Some(field)
            if last.attrs.iter().any(|a| {
                a.logicalname == field
                    && readable(
                        &ctx,
                        &last.logicalname,
                        a,
                        last.primary_name_attribute.as_deref(),
                        Surface::Interactive,
                    )
            }) =>
        {
            format!("to_jsonb({alias}.{})", attome_core::quote_ident(field))
        }
        _ => "NULL::jsonb".to_owned(),
    };
    let visible_sql = attome_db::tag_dynamic(
        "rollup.explain_visible",
        &format!("SELECT COUNT(*) {from} {predicate}"),
    );
    let list_sql = attome_db::tag_dynamic(
        "rollup.explain_list",
        &format!(
            "SELECT {alias}.id, {amount} {from} {predicate} ORDER BY {alias}.id LIMIT {MAX_LISTED}"
        ),
    );
    let mut visible = sqlx::query_scalar::<_, i64>(&visible_sql).bind(record_id);
    let mut list = sqlx::query_as::<_, (Uuid, Option<Value>)>(&list_sql).bind(record_id);
    for bind in &binds {
        visible = visible.bind(bind);
        list = list.bind(bind);
    }
    if let Some(p) = &pred {
        visible = visible
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
        list = list
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let visible = visible.fetch_one(db).await.map_err(AppError::internal)?;
    out.hidden = (out.counted - visible).max(0);
    out.records = list
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(id, value)| RollupContributor {
            id,
            value: value.unwrap_or(Value::Null),
        })
        .collect();
    out.truncated = visible > MAX_LISTED;
    Ok(Json(out))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(explain_rollup))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
