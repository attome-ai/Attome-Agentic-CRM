//! R3-T1: retention rules per entity and category.
//!
//! A rule names the records it covers (an entity and an optional filter
//! condition, compiled by the shared `attome_core::filter::compile`), the
//! date their retention period starts from (`created_at`, or a date attribute
//! such as a closed date or a contract end), the period in days, and what
//! happens once it has passed: `purge`, `archive` or `review`.
//!
//! The daily proposal sweep (`retention::propose_retention_actions`) turns
//! every live record past its rule's period into one `audit_retention_action`
//! row (`rule_purge`, `rule_archive` or `rule_review`, with `rule_ref`), in
//! keyset batches. A record under an active legal hold is never proposed.
//! Nothing happens until a person approves the proposal through the existing
//! approve route (four-eyes and `retention.dry_run` included):
//!
//! - `rule_review` records that the record was reviewed and kept;
//! - `rule_purge` and `rule_archive` delete the record through the records
//!   engine as the approver (audited, into the recycle bin, the same delete a
//!   person would make), then run the existing `entity_purge` or `archive`
//!   disposition on it.
//!
//! The rules are managed at `/api/v1/admin/retention/rules` (administrators);
//! every change is a Configuration security event.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::filter::{FieldCastError, FilterSchema, cast_for_attr, is_multi_choice_attr};
use attome_core::{AttrInfo, EngineState, Filter, quote_ident};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The dispositions a rule may ask for.
pub const ACTIONS: [&str; 3] = ["purge", "archive", "review"];
/// The longest retention period, in days (100 years).
pub const MAX_PERIOD_DAYS: i32 = 36_500;
/// Records one proposal batch scans.
const PROPOSAL_BATCH: i64 = 500;
/// The system date columns every provisioned entity table has.
const SYSTEM_DATE_COLUMNS: [&str; 2] = ["created_at", "modified_at"];

/// The `audit_retention_action.action_type` a rule's action proposes.
pub fn proposal_type(action: &str) -> Option<&'static str> {
    match action {
        "purge" => Some("rule_purge"),
        "archive" => Some("rule_archive"),
        "review" => Some("rule_review"),
        _ => None,
    }
}

/// One stored rule.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct RetentionRule {
    pub id: Uuid,
    pub name: String,
    pub entity_logicalname: String,
    pub category: Option<String>,
    /// Filters the covered records must match, as the list views use.
    #[schema(value_type = Vec<Filter>)]
    pub condition: sqlx::types::Json<Vec<Filter>>,
    /// The date the period starts from: `created_at`, `modified_at` or a
    /// date attribute of the entity.
    pub start_attribute: String,
    pub period_days: i32,
    /// `purge`, `archive` or `review`.
    pub action: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
}

const RULE_COLUMNS: &str = "id, name, entity_logicalname, category, condition, start_attribute, \
                            period_days, action, is_active, created_at, updated_at, row_version";

/// A rule as an administrator writes it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionRuleBody {
    pub name: String,
    /// The entity's logical name.
    pub entity: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub condition: Vec<Filter>,
    /// Defaults to `created_at`.
    #[serde(default)]
    pub start_attribute: Option<String>,
    pub period_days: i32,
    pub action: String,
    #[serde(default = "yes")]
    pub is_active: bool,
    /// On an update, the version read; a newer stored version answers 409.
    #[serde(default)]
    pub row_version: Option<i64>,
}

fn yes() -> bool {
    true
}

/// The entity facts a rule is checked against.
#[derive(Debug)]
pub struct RuleTarget<'a> {
    pub is_append_only: bool,
    pub attrs: &'a [AttrInfo],
}

struct RuleFilterSchema<'a> {
    attrs: &'a [AttrInfo],
}

impl FilterSchema for RuleFilterSchema<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        let attr = self
            .attrs
            .iter()
            .find(|a| a.logicalname == field)
            .ok_or(FieldCastError::Unknown)?;
        cast_for_attr(attr)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.attrs
            .iter()
            .find(|a| a.logicalname == field)
            .is_some_and(is_multi_choice_attr)
    }
}

/// Whether `name` is a date the period can start from on this entity.
fn is_start_attribute(name: &str, attrs: &[AttrInfo]) -> bool {
    SYSTEM_DATE_COLUMNS.contains(&name)
        || attrs
            .iter()
            .find(|a| a.logicalname == name)
            .is_some_and(|a| cast_for_attr(a) == Ok("timestamptz"))
}

/// The rule's `WHERE` fragment over `t` (the entity table) and its bound
/// values, numbered from `$1`: live records matching the condition.
pub fn condition_sql(
    condition: &[Filter],
    attrs: &[AttrInfo],
) -> Result<(String, Vec<String>), AppError> {
    let schema = RuleFilterSchema { attrs };
    let mut parts = vec!["t.is_active = true".to_owned()];
    let mut binds = Vec::new();
    for filter in condition {
        let (sql, values) = attome_core::filter::compile(filter, &schema, binds.len() + 1)?;
        parts.push(sql);
        binds.extend(values);
    }
    Ok((parts.join(" AND "), binds))
}

/// Checks a rule against its entity. Pure, so it is tested without a
/// database.
pub fn validate_rule(body: &RetentionRuleBody, target: &RuleTarget<'_>) -> Result<(), AppError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation("name is 1 to 200 characters".into()));
    }
    if body
        .category
        .as_deref()
        .is_some_and(|c| c.chars().count() > 100)
    {
        return Err(AppError::Validation(
            "category is at most 100 characters".into(),
        ));
    }
    if !(1..=MAX_PERIOD_DAYS).contains(&body.period_days) {
        return Err(AppError::Validation(format!(
            "period_days is 1 to {MAX_PERIOD_DAYS}"
        )));
    }
    if proposal_type(&body.action).is_none() {
        return Err(AppError::Validation(
            "action is purge, archive or review".into(),
        ));
    }
    if target.is_append_only {
        return Err(AppError::Validation(
            "an append-only entity keeps its records by design; it takes no retention rule".into(),
        ));
    }
    let start = body.start_attribute.as_deref().unwrap_or("created_at");
    if !is_start_attribute(start, target.attrs) {
        return Err(AppError::Validation(format!(
            "start_attribute {start} is not a date of this entity"
        )));
    }
    condition_sql(&body.condition, target.attrs)?;
    Ok(())
}

/// The rule target of `entity` from the live metadata.
fn rule_target(state: &EngineState, entity: &str) -> Result<(bool, Vec<AttrInfo>), AppError> {
    let registry = state.entities.load();
    let meta = registry
        .get(entity)
        .ok_or_else(|| AppError::Validation(format!("unknown entity {entity}")))?;
    Ok((meta.is_append_only, meta.attrs.clone()))
}

// ── Proposals ────────────────────────────────────────────────────────────

/// One proposal batch's counts.
#[derive(sqlx::FromRow)]
struct BatchCounts {
    batch_count: i64,
    max_id: Option<Uuid>,
    inserted_count: i64,
}

/// The proposal statement for one rule: `binds` filter values first, then
/// the cut-off, the cursor, the entity, the proposal type and the rule id.
/// Built from quoted identifiers, the compiled condition and numbered
/// placeholders only; every value is bound.
fn proposal_sql(table: &str, start: &str, where_sql: &str, binds: usize) -> String {
    let n = |offset: usize| format!("${}", binds + offset);
    let mut sql = String::from("WITH batch AS (SELECT t.id FROM ");
    sql.push_str(&quote_ident(table));
    sql.push_str(" t WHERE ");
    sql.push_str(where_sql);
    sql.push_str(" AND t.");
    sql.push_str(&quote_ident(start));
    sql.push_str(" < ");
    sql.push_str(&n(1));
    sql.push_str("::timestamptz AND t.id > ");
    sql.push_str(&n(2));
    sql.push_str("::uuid AND NOT EXISTS (SELECT 1 FROM legal_hold h WHERE h.entity_logicalname = ");
    sql.push_str(&n(3));
    sql.push_str(
        " AND (h.record_id = t.id OR h.record_id IS NULL) AND h.released_at IS NULL \
         AND h.is_deleted = false) ORDER BY t.id LIMIT ",
    );
    sql.push_str(&PROPOSAL_BATCH.to_string());
    sql.push_str(
        "), ins AS (INSERT INTO audit_retention_action (action_type, target, status, rule_ref) \
         SELECT ",
    );
    sql.push_str(&n(4));
    sql.push_str(", ");
    sql.push_str(&n(3));
    sql.push_str(" || ':' || b.id::text, 'proposed', ");
    sql.push_str(&n(5));
    sql.push_str(
        "::uuid FROM batch b ON CONFLICT (action_type, target) WHERE status <> 'rejected' \
         DO NOTHING RETURNING 1) \
         SELECT (SELECT count(*) FROM batch)::bigint AS batch_count, \
                (SELECT id FROM batch ORDER BY id DESC LIMIT 1) AS max_id, \
                (SELECT count(*) FROM ins)::bigint AS inserted_count",
    );
    sql
}

/// Proposes every live, unheld record past one rule's period. Returns how
/// many proposals were new.
async fn propose_for_rule(
    state: &EngineState,
    rule: &RetentionRule,
    now: DateTime<Utc>,
) -> Result<u32, AppError> {
    let Some(kind) = proposal_type(&rule.action) else {
        return Ok(0);
    };
    let (is_append_only, attrs) = match rule_target(state, &rule.entity_logicalname) {
        Ok(target) => target,
        Err(_) => {
            tracing::warn!(rule = %rule.id, entity = %rule.entity_logicalname,
                "retention rule: its entity is no longer registered; skipped");
            return Ok(0);
        }
    };
    if is_append_only || !is_start_attribute(&rule.start_attribute, &attrs) {
        tracing::warn!(rule = %rule.id, "retention rule: no longer valid for its entity; skipped");
        return Ok(0);
    }
    let (where_sql, binds) = condition_sql(&rule.condition.0, &attrs)?;
    let sql = proposal_sql(
        &rule.entity_logicalname,
        &rule.start_attribute,
        &where_sql,
        binds.len(),
    );
    let cutoff = now - chrono::Duration::days(i64::from(rule.period_days));
    let mut cursor = Uuid::nil();
    let mut proposed = 0u32;
    loop {
        let mut query = sqlx::query_as::<_, BatchCounts>(&sql);
        for value in &binds {
            query = query.bind(value);
        }
        let counts = query
            .bind(cutoff)
            .bind(cursor)
            .bind(&rule.entity_logicalname)
            .bind(kind)
            .bind(rule.id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        proposed += u32::try_from(counts.inserted_count).unwrap_or(u32::MAX);
        match counts.max_id {
            Some(last) if counts.batch_count >= PROPOSAL_BATCH => cursor = last,
            _ => break,
        }
    }
    Ok(proposed)
}

/// Every active rule's proposals; one rule's failure is logged and does not
/// stop the others. Returns how many proposals were new.
pub async fn propose_rule_actions(state: &EngineState) -> Result<u32, AppError> {
    let rules: Vec<RetentionRule> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM retention_rule WHERE is_active ORDER BY created_at"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let mut proposed = 0u32;
    for rule in &rules {
        match propose_for_rule(state, rule, now).await {
            Ok(n) => proposed += n,
            Err(error) => tracing::error!(rule = %rule.id, %error,
                "retention rule: proposing failed for this rule; the others went on"),
        }
    }
    Ok(proposed)
}

// ── Execution of an approved rule proposal ───────────────────────────────

/// Deletes a rule proposal's record through the records engine as its
/// approver, so the delete is checked, audited and lands in the recycle bin
/// like any other; the purge or archive that follows works on that deleted
/// record. A record already deleted is left as it is.
pub(crate) async fn delete_for_disposition(
    state: &EngineState,
    target: &str,
    action_id: Uuid,
    approved_by: Option<Uuid>,
) -> Result<(), AppError> {
    let (entity, record_id) = crate::retention::parse_entity_target(target)?;
    let approver = approved_by.ok_or_else(|| {
        AppError::internal("retention execute: a rule disposition without an approver")
    })?;
    let live: Option<bool> = sqlx::query_scalar(&format!(
        "SELECT is_active FROM {} WHERE id = $1",
        quote_ident(entity)
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match live {
        None => Err(AppError::internal(format!(
            "retention execute: {target} no longer exists"
        ))),
        Some(false) => Ok(()),
        Some(true) => {
            let ctx = attome_security::resolve_uncached(&state.base.db, approver).await?;
            attome_security::SecurityContextExt::require(&ctx, entity, "delete")?;
            let origin = attome_records::entity_mutation::DeleteOrigin::with_id(
                attome_records::entity_mutation::DeleteKind::Request,
                action_id.to_string(),
            )
            .reason(Some("retention rule disposition"));
            attome_records::entity_crud::delete_record_for(
                state, &ctx, approver, entity, record_id, None, &origin,
            )
            .await
        }
    }
}

// ── Admin routes ─────────────────────────────────────────────────────────

/// Every retention rule (R3-T1).
///
/// All rules, active or not, oldest first, in one page: a deployment keeps a
/// few dozen at most.
#[utoipa::path(
    get,
    path = "/api/v1/admin/retention/rules",
    tag = "admin",
    responses(
        (status = 200, description = "Every retention rule", body = PaginatedResponse<RetentionRule>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_rules(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<RetentionRule>>, AppError> {
    let rules: Vec<RetentionRule> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM retention_rule ORDER BY created_at"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(rules.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(rules, total, 1, total.max(1))))
}

fn checked_body(state: &EngineState, body: &RetentionRuleBody) -> Result<String, AppError> {
    let (is_append_only, attrs) = rule_target(state, &body.entity)?;
    validate_rule(
        body,
        &RuleTarget {
            is_append_only,
            attrs: &attrs,
        },
    )?;
    Ok(body
        .start_attribute
        .clone()
        .unwrap_or_else(|| "created_at".to_owned()))
}

/// Adds a retention rule (R3-T1).
///
/// The rule is checked against the entity's live metadata: its condition
/// must compile, its start attribute must be a date, and an append-only
/// entity takes no rule. The next proposal sweep applies it.
#[utoipa::path(
    post,
    path = "/api/v1/admin/retention/rules",
    tag = "admin",
    request_body = RetentionRuleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The rule", body = RetentionRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "The rule does not fit its entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<RetentionRuleBody>,
) -> Result<(StatusCode, Json<RetentionRule>), AppError> {
    let start = checked_body(&state, &body)?;
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Create,
        ctx.user_id,
        "retention_rule",
        None,
    )
    .named("retention_rule.created")
    .comment(format!(
        "retention rule {:?} on {}: {} after {} days",
        body.name.trim(),
        body.entity,
        body.action,
        body.period_days
    ));
    let mut stx = SecurityTx::begin(&state, event).await?;
    let rule: RetentionRule = sqlx::query_as(&format!(
        "INSERT INTO retention_rule (name, entity_logicalname, category, condition, \
             start_attribute, period_days, action, is_active, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING {RULE_COLUMNS}"
    ))
    .bind(body.name.trim())
    .bind(&body.entity)
    .bind(&body.category)
    .bind(sqlx::types::Json(&body.condition))
    .bind(&start)
    .bind(body.period_days)
    .bind(&body.action)
    .bind(body.is_active)
    .bind(ctx.user_id)
    .fetch_one(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    stx.commit().await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

/// Changes a retention rule (R3-T1).
///
/// The whole rule is replaced and checked again. With `row_version`, a rule
/// changed since it was read answers 409. Proposals already made stay until
/// they are approved or rejected.
#[utoipa::path(
    put,
    path = "/api/v1/admin/retention/rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The rule's id")),
    request_body = RetentionRuleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The rule", body = RetentionRule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 409, description = "The rule changed since it was read", body = ErrorResponse),
        (status = 422, description = "The rule does not fit its entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<RetentionRuleBody>,
) -> Result<Json<RetentionRule>, AppError> {
    let start = checked_body(&state, &body)?;
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        "retention_rule",
        Some(id),
    )
    .named("retention_rule.updated")
    .comment(format!(
        "retention rule {:?} on {}: {} after {} days",
        body.name.trim(),
        body.entity,
        body.action,
        body.period_days
    ));
    let mut stx = SecurityTx::begin(&state, event).await?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT row_version FROM retention_rule WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *stx)
            .await
            .map_err(AppError::internal)?;
    let current = current.ok_or(AppError::NotFound)?;
    if body.row_version.is_some_and(|read| read != current) {
        return Err(AppError::Conflict(
            "the retention rule changed since it was read",
        ));
    }
    let rule: RetentionRule = sqlx::query_as(&format!(
        "UPDATE retention_rule SET name = $2, entity_logicalname = $3, category = $4, \
             condition = $5, start_attribute = $6, period_days = $7, action = $8, \
             is_active = $9, updated_at = now(), row_version = row_version + 1 \
         WHERE id = $1 RETURNING {RULE_COLUMNS}"
    ))
    .bind(id)
    .bind(body.name.trim())
    .bind(&body.entity)
    .bind(&body.category)
    .bind(sqlx::types::Json(&body.condition))
    .bind(&start)
    .bind(body.period_days)
    .bind(&body.action)
    .bind(body.is_active)
    .fetch_one(&mut *stx)
    .await
    .map_err(AppError::internal)?;
    stx.commit().await?;
    Ok(Json(rule))
}

/// Removes a retention rule (R3-T1).
///
/// The rule stops proposing at once; proposals it already made stay in the
/// review list until they are approved or rejected.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/retention/rules/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The rule's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Delete)])))),
    responses(
        (status = 204, description = "The rule is removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Delete,
        ctx.user_id,
        "retention_rule",
        Some(id),
    )
    .named("retention_rule.deleted");
    let mut stx = SecurityTx::begin(&state, event).await?;
    let removed = sqlx::query("DELETE FROM retention_rule WHERE id = $1")
        .bind(id)
        .execute(&mut *stx)
        .await
        .map_err(AppError::internal)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    stx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/retention/rules",
            get(list_rules).post(create_rule),
        )
        .route(
            "/api/v1/admin/retention/rules/{id}",
            put(update_rule).delete(delete_rule),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_rules, create_rule, update_rule, delete_rule))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod retention_rules_tests {
    use super::*;

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        serde_json::from_value(serde_json::json!({
            "logicalname": name,
            "field_type_int": field_type_int,
            "is_sensitive": false,
            "is_sortable": false,
            "is_filterable": true,
        }))
        .unwrap_or_else(|_| panic!("AttrInfo from JSON"))
    }

    fn body(action: &str, start: Option<&str>, condition: Vec<Filter>) -> RetentionRuleBody {
        RetentionRuleBody {
            name: "Closed tickets".into(),
            entity: "service_ticket".into(),
            category: Some("support".into()),
            condition,
            start_attribute: start.map(str::to_owned),
            period_days: 365,
            action: action.into(),
            is_active: true,
            row_version: None,
        }
    }

    #[test]
    fn retention_rules_map_actions_to_proposal_types() {
        assert_eq!(proposal_type("purge"), Some("rule_purge"));
        assert_eq!(proposal_type("archive"), Some("rule_archive"));
        assert_eq!(proposal_type("review"), Some("rule_review"));
        assert_eq!(proposal_type("delete"), None);
    }

    #[test]
    fn retention_rules_validate_period_action_start_and_entity() {
        let attrs = vec![attr("status", 0), attr("closed_on", 5)];
        let target = RuleTarget {
            is_append_only: false,
            attrs: &attrs,
        };
        assert!(validate_rule(&body("purge", None, vec![]), &target).is_ok());
        assert!(validate_rule(&body("review", Some("modified_at"), vec![]), &target).is_ok());
        assert!(validate_rule(&body("delete", None, vec![]), &target).is_err());
        assert!(validate_rule(&body("purge", Some("status"), vec![]), &target).is_err());
        assert!(validate_rule(&body("purge", Some("nope"), vec![]), &target).is_err());
        let mut long = body("purge", None, vec![]);
        long.period_days = 0;
        assert!(validate_rule(&long, &target).is_err());
        long.period_days = MAX_PERIOD_DAYS + 1;
        assert!(validate_rule(&long, &target).is_err());
        let append_only = RuleTarget {
            is_append_only: true,
            attrs: &attrs,
        };
        assert!(validate_rule(&body("purge", None, vec![]), &append_only).is_err());
    }

    /// K1-T3: a document type maps to a retention policy as a rule on
    /// documents whose condition names the type.
    #[test]
    fn retention_rules_target_a_document_type() {
        let attrs = vec![attr("name", 0), attr("document_type", 7)];
        let target = RuleTarget {
            is_append_only: false,
            attrs: &attrs,
        };
        let condition: Filter = serde_json::from_value(
            serde_json::json!({"field": "document_type", "op": "eq", "value": "contract"}),
        )
        .unwrap_or_else(|_| panic!("a filter"));
        let mut rule = body("archive", None, vec![condition.clone()]);
        rule.entity = "attome_document".into();
        assert!(validate_rule(&rule, &target).is_ok());
        let (sql, binds) = condition_sql(&[condition], &attrs).unwrap_or_else(|e| panic!("{e}"));
        assert!(sql.contains("document_type"), "{sql}");
        assert_eq!(binds, ["contract"]);
    }

    #[test]
    fn retention_rules_condition_compiles_with_bound_values() {
        let attrs = vec![attr("status", 0)];
        let filter: Filter = serde_json::from_value(
            serde_json::json!({"field": "status", "op": "eq", "value": "closed"}),
        )
        .unwrap_or_else(|_| panic!("a filter"));
        let (sql, binds) = condition_sql(&[filter], &attrs).unwrap_or_else(|e| panic!("{e}"));
        assert!(sql.starts_with("t.is_active = true AND "), "{sql}");
        assert!(sql.contains("$1"), "{sql}");
        assert!(!sql.contains("closed"), "values are bound: {sql}");
        assert_eq!(binds, ["closed"]);
        let unknown: Filter = serde_json::from_value(
            serde_json::json!({"field": "secret", "op": "eq", "value": "x"}),
        )
        .unwrap_or_else(|_| panic!("a filter"));
        assert!(condition_sql(&[unknown], &attrs).is_err());
    }

    #[test]
    fn retention_rules_proposal_sql_numbers_after_the_condition_and_skips_held_records() {
        let sql = proposal_sql(
            "service_ticket",
            "closed_on",
            "t.is_active = true AND x = $1",
            1,
        );
        assert!(sql.contains("\"service_ticket\" t"), "{sql}");
        assert!(sql.contains("t.\"closed_on\" < $2::timestamptz"), "{sql}");
        assert!(sql.contains("t.id > $3::uuid"), "{sql}");
        assert!(sql.contains("legal_hold"), "{sql}");
        assert!(
            sql.contains("SELECT $5, $4 || ':' || b.id::text, 'proposed', $6::uuid"),
            "{sql}"
        );
        assert!(sql.contains("LIMIT 500"), "{sql}");
    }
}
