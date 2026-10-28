//! Phase 5's context/variable resolution. No query engine exists yet
//! (Phase 4 built only the SQL power-user reference, not the visual query
//! builder/compiler), so nothing consumes a resolved variable in a live
//! query today. This module still gives a real, useful capability: a
//! client can ask "what would `@current_user`/`@current_date`/... resolve
//! to for this dashboard, this viewer, this embed context, these URL
//! overrides" and get back the values it would substitute into a widget's
//! `query_params` before calling `/api/v1/query/execute` itself — the same
//! response also serves the spec's "variable preview in builder" bullet
//! (call it with different `embed`/`url_overrides` values, look at the
//! result) without a second endpoint.
//!
//! **Built-in variables this module resolves, and why two are missing.**
//! Checked against `SecurityContext`'s actual fields, not assumed:
//! `@current_user` (`ctx.user_id`), `@current_date` (server UTC — no
//! per-tenant timezone config exists to resolve against), `@current_user_bu`
//! (`ctx.accessible_org_ids`), `@current_user_team` (`ctx.team_ids`).
//! `@current_user_bu`/`@current_user_team` are genuinely **arrays**, not
//! singular values — this platform's user↔organization and user↔team
//! relationships (`user_account_mm_organization`/`_mm_team`) are
//! many-to-many with no "primary" column, and `accessible_org_ids` is the
//! RLS-scoping reachable set (direct membership plus every descendant), not
//! a "home org" — collapsing either to a fake single value would fabricate
//! a semantic the data model doesn't have. `@current_record_id`/
//! `@current_entity` come from the caller-supplied embed context, when
//! present (Phase 5's "record-context injection" bullet — the record page
//! that embeds a dashboard is what supplies this, which is a Phase 14
//! embedding concern; this module only resolves the value once given).
//!
//! **Not resolved**: `@current_user_role` (`SecurityContext` carries a
//! resolved flat privilege set, not role names, and there is no "primary
//! role" concept to query for either — implementing this would need a new,
//! unverified DB join this session didn't build) and `@current_tenant`
//! (this platform is single-tenant/on-premise per D-002 — there is no
//! tenant id to resolve).
//!
//! **Expressions (Z11-T16).** A `dashboard_variable` that declares an
//! `expression` is evaluated by base-rules over every variable resolved
//! before it (declared defaults and the built-ins, each by its name without
//! the `@`), after the built-ins and before URL overrides, so a URL value
//! still wins. A variable without one keeps the resolution below unchanged.
//!
//! **Resolution order** (spec: "URL -> user session -> system defaults"):
//! applied lowest-precedence-first so each layer's `insert` naturally
//! overwrites the one before it — declared `dashboard_variable`/
//! `dashboard_parameter` default values, then the built-ins above, then
//! caller-supplied URL overrides win over everything.
use std::collections::HashMap;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_dashboard_access;
use crate::auth::DashboardRead;

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct EmbedContext {
    /// Populated by whatever record page embeds this dashboard (Phase 14).
    pub record_id: Option<Uuid>,
    pub entity_logical_name: Option<String>,
}

/// Pure — no DB, unit-tested directly (`tests` module below).
pub fn resolve_builtin_variables(
    ctx: &SecurityContext,
    embed: &EmbedContext,
) -> serde_json::Map<String, serde_json::Value> {
    let mut vars = serde_json::Map::new();
    vars.insert(
        "@current_user".to_string(),
        serde_json::Value::String(ctx.user_id.to_string()),
    );
    vars.insert(
        "@current_date".to_string(),
        serde_json::Value::String(chrono::Utc::now().date_naive().to_string()),
    );
    vars.insert(
        "@current_user_bu".to_string(),
        serde_json::json!(ctx.accessible_org_ids),
    );
    vars.insert(
        "@current_user_team".to_string(),
        serde_json::json!(ctx.team_ids),
    );
    if let Some(record_id) = embed.record_id {
        vars.insert(
            "@current_record_id".to_string(),
            serde_json::Value::String(record_id.to_string()),
        );
    }
    if let Some(entity) = &embed.entity_logical_name {
        vars.insert(
            "@current_entity".to_string(),
            serde_json::Value::String(entity.clone()),
        );
    }
    vars
}

/// Z11-T16: `expression` evaluated by base-rules with every variable in
/// `resolved` as a field named without its `@` (text, number, true/false, or
/// a list of those). Pure.
pub fn evaluate_variable_expression(
    expression: &str,
    resolved: &serde_json::Map<String, serde_json::Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value, String> {
    use attome_rules::{Context, Schema, Type, Value};
    fn rule_value(value: &serde_json::Value) -> Option<(Value, Type)> {
        Some(match value {
            serde_json::Value::String(s) => (Value::Text(s.clone()), Type::Text),
            serde_json::Value::Number(n) => (Value::Number(n.as_f64()?), Type::Number),
            serde_json::Value::Bool(b) => (Value::Bool(*b), Type::Bool),
            serde_json::Value::Array(items) => {
                let values: Vec<Value> = items
                    .iter()
                    .map(|i| rule_value(i).map(|(v, _)| v))
                    .collect::<Option<_>>()?;
                let item = items
                    .first()
                    .and_then(rule_value)
                    .map_or(Type::Text, |(_, t)| t);
                (Value::List(values), Type::List(Box::new(item)))
            }
            _ => return None,
        })
    }
    let mut schema = Schema::new();
    let mut context = Context::new(now);
    for (name, value) in resolved {
        let Some((value, ty)) = rule_value(value) else {
            continue;
        };
        let field = name.trim_start_matches('@');
        schema = schema.with_field(field, ty);
        context = context.with_field(field, value);
    }
    let compiled = attome_rules::compile(expression, &schema).map_err(|e| e.to_string())?;
    match compiled.eval(&context).map_err(|e| e.to_string())? {
        Value::Null => Ok(serde_json::Value::Null),
        Value::Bool(b) => Ok(serde_json::Value::Bool(b)),
        Value::Number(n) => Ok(serde_json::json!(n)),
        Value::Text(t) | Value::Choice(t) => Ok(serde_json::Value::String(t)),
        Value::Date(d) => Ok(serde_json::Value::String(d.to_rfc3339())),
        Value::Lookup(id) => Ok(serde_json::Value::String(id.to_string())),
        other => Err(format!("a variable is one value, not {other:?}")),
    }
}

#[derive(sqlx::FromRow)]
struct DeclaredNameDefaultRow {
    name: String,
    default_value: Option<String>,
    /// Z11-T16: a rule expression over the variables resolved before it.
    expression: Option<String>,
}

// R-13 item 3: two explicit `const` SQL strings, one per table, instead of a
// `format!("... FROM {table} ...")` — no behaviour change, just removes the
// one string-built identifier (`table` was never request-controlled, but a
// plain constant is simpler to see is safe than a `format!` call is).
const VARIABLE_DEFAULTS_SQL: &str = "SELECT name, default_value, expression FROM dashboard_variable \
     WHERE dashboard_id = $1 AND (page_id IS NULL OR page_id = $2) \
       AND (is_active IS NULL OR is_active = true)";
const PARAMETER_DEFAULTS_SQL: &str = "SELECT name, default_value, NULL::text AS expression      FROM dashboard_parameter \
     WHERE dashboard_id = $1 AND (page_id IS NULL OR page_id = $2) \
       AND (is_active IS NULL OR is_active = true)";

async fn declared_defaults(
    db: &DbPool,
    sql: &str,
    dashboard_id: Uuid,
    page_id: Option<Uuid>,
) -> Result<Vec<DeclaredNameDefaultRow>, AppError> {
    sqlx::query_as(sql)
        .bind(dashboard_id)
        .bind(page_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)
}

pub async fn do_resolve_variables(
    db: &DbPool,
    dashboard_id: Uuid,
    page_id: Option<Uuid>,
    ctx: &SecurityContext,
    embed: &EmbedContext,
    url_overrides: &HashMap<String, String>,
) -> Result<serde_json::Map<String, serde_json::Value>, AppError> {
    let mut resolved = serde_json::Map::new();

    let mut expressions = Vec::new();
    for row in declared_defaults(db, VARIABLE_DEFAULTS_SQL, dashboard_id, page_id).await? {
        if let Some(expression) = row.expression.filter(|e| !e.trim().is_empty()) {
            expressions.push((row.name.clone(), expression));
        }
        if let Some(default_value) = row.default_value {
            resolved.insert(row.name, serde_json::Value::String(default_value));
        }
    }
    for row in declared_defaults(db, PARAMETER_DEFAULTS_SQL, dashboard_id, page_id).await? {
        if let Some(default_value) = row.default_value {
            resolved.insert(row.name, serde_json::Value::String(default_value));
        }
    }

    for (key, value) in resolve_builtin_variables(ctx, embed) {
        resolved.insert(key, value);
    }

    for (name, expression) in expressions {
        let value = evaluate_variable_expression(&expression, &resolved, chrono::Utc::now())
            .map_err(|reason| {
                AppError::Validation(format!("variable {name}: expression: {reason}"))
            })?;
        resolved.insert(name, value);
    }

    for (key, value) in url_overrides {
        resolved.insert(key.clone(), serde_json::Value::String(value.clone()));
    }

    Ok(resolved)
}

// ── HTTP surface ─────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema, Default)]
struct ResolveVariablesBody {
    /// Scopes which declared `dashboard_variable`/`dashboard_parameter`
    /// rows apply — omit for dashboard-level only.
    page_id: Option<Uuid>,
    #[serde(default)]
    embed: EmbedContext,
    #[serde(default)]
    url_overrides: HashMap<String, String>,
}

#[derive(Serialize, ToSchema)]
struct ResolveVariablesResponse {
    variables: serde_json::Map<String, serde_json::Value>,
}

/// Resolve a dashboard's variables
///
/// What `@current_user`, `@current_date` and the dashboard's other variables come to for this
/// viewer, embed context and URL overrides. Writes nothing. Anyone who may read the dashboard.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/resolve-variables",
    tag = "dashboard",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "resolves declared variable/parameter defaults and embed/URL overrides for display; persists nothing",
    )))),
    params(("id" = Uuid, Path, description = "The dashboard")),
    request_body = ResolveVariablesBody,
    responses(
        (status = 200, description = "Success", body = ResolveVariablesResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn resolve_variables(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardRead>>,
    axum::extract::Path(dashboard_id): axum::extract::Path<Uuid>,
    Json(body): Json<ResolveVariablesBody>,
) -> Result<Json<ResolveVariablesResponse>, AppError> {
    require_dashboard_access(&state, &ctx, dashboard_id, RecordAction::Read).await?;
    let variables = do_resolve_variables(
        &state.base.db,
        dashboard_id,
        body.page_id,
        &ctx,
        &body.embed,
        &body.url_overrides,
    )
    .await?;
    Ok(Json(ResolveVariablesResponse { variables }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/attome-dashboard/{id}/resolve-variables",
        post(resolve_variables),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(resolve_variables))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ctx(user_id: Uuid, org_ids: &[Uuid], team_ids: &[Uuid]) -> SecurityContext {
        SecurityContext {
            user_id,
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: org_ids.to_vec(),
            team_ids: team_ids.to_vec(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    /// Z11-T16: a variable's expression reads the variables resolved before
    /// it by their names without `@`; a list variable reads as a list, and
    /// an expression that does not compile is an error, not a silent value.
    #[test]
    fn variable_expression_evaluates() {
        let mut resolved = serde_json::Map::new();
        resolved.insert("@current_user".into(), serde_json::json!("u-1"));
        resolved.insert("target".into(), serde_json::json!(120));
        resolved.insert("region".into(), serde_json::json!("riyadh"));
        resolved.insert("@current_user_team".into(), serde_json::json!(["t1", "t2"]));
        let now = chrono::Utc::now();
        assert_eq!(
            evaluate_variable_expression("target * 2", &resolved, now),
            Ok(serde_json::json!(240.0))
        );
        assert_eq!(
            evaluate_variable_expression("upper(region) + \"-\" + current_user", &resolved, now),
            Ok(serde_json::json!("RIYADH-u-1"))
        );
        assert_eq!(
            evaluate_variable_expression("in(\"t2\", current_user_team)", &resolved, now),
            Ok(serde_json::json!(true))
        );
        assert!(evaluate_variable_expression("target +", &resolved, now).is_err());
        assert!(evaluate_variable_expression("missing_variable", &resolved, now).is_err());
    }

    #[test]
    fn current_user_and_date_are_always_present() {
        let user_id = Uuid::now_v7();
        let vars = resolve_builtin_variables(&ctx(user_id, &[], &[]), &EmbedContext::default());
        assert_eq!(vars["@current_user"], user_id.to_string());
        assert!(vars.contains_key("@current_date"));
    }

    #[test]
    fn bu_and_team_resolve_as_arrays_not_a_fake_singular() {
        let org_a = Uuid::now_v7();
        let org_b = Uuid::now_v7();
        let team_a = Uuid::now_v7();
        let vars = resolve_builtin_variables(
            &ctx(Uuid::now_v7(), &[org_a, org_b], &[team_a]),
            &EmbedContext::default(),
        );
        assert_eq!(
            vars["@current_user_bu"],
            serde_json::json!([org_a, org_b]),
            "must be the whole RLS-scoping set, not one arbitrarily chosen org"
        );
        assert_eq!(vars["@current_user_team"], serde_json::json!([team_a]));
    }

    #[test]
    fn record_context_is_absent_without_an_embed_and_present_with_one() {
        let no_embed =
            resolve_builtin_variables(&ctx(Uuid::now_v7(), &[], &[]), &EmbedContext::default());
        assert!(!no_embed.contains_key("@current_record_id"));
        assert!(!no_embed.contains_key("@current_entity"));

        let record_id = Uuid::now_v7();
        let embed = EmbedContext {
            record_id: Some(record_id),
            entity_logical_name: Some("attome_project".to_string()),
        };
        let with_embed = resolve_builtin_variables(&ctx(Uuid::now_v7(), &[], &[]), &embed);
        assert_eq!(with_embed["@current_record_id"], record_id.to_string());
        assert_eq!(with_embed["@current_entity"], "attome_project");
    }

    #[test]
    fn no_role_or_tenant_variable_is_fabricated() {
        let vars =
            resolve_builtin_variables(&ctx(Uuid::now_v7(), &[], &[]), &EmbedContext::default());
        assert!(
            !vars.contains_key("@current_user_role"),
            "see this module's doc comment for why"
        );
        assert!(!vars.contains_key("@current_tenant"));
    }
}
