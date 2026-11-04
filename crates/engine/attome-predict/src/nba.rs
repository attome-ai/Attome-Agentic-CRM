//! O5-T1: next-best actions. An administrator defines candidate actions per
//! entity (`nba_action`, migration 0380): a name (English and Arabic), an
//! eligibility condition in the rule language, an optional propensity model
//! (O1) and a weight, and what to do (`action`, free JSON the screen acts
//! on: a task to create, a call to make).
//!
//! `GET /api/v1/predict/next-actions?regarding_entity=&regarding_id=` reads
//! the record as the caller (record-level access applies; an unreadable
//! record is 404), keeps the active actions of its entity whose condition
//! holds on it (a condition that does not compile is skipped and logged),
//! and ranks them by weight times the record's latest score from the
//! action's model (0.5 when the model has not scored it; 1 without a model),
//! at most [`MAX_SHOWN`]. Each shown action is logged once per caller and
//! record as an O11 `outcome` of kind `recommendation` (the open one is
//! reused). `POST /api/v1/predict/recommendations/{id}/accept` and
//! `.../reject` measure it (effectiveness 1 or 0), once, by the person it
//! was shown to.
//!
//! `GET`/`POST /api/v1/admin/predict/next-actions` and
//! `DELETE .../{id}` (retire) are for AI administrators.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, RecordScoped, SelfService, area};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Actions shown on a record at most.
pub const MAX_SHOWN: usize = 5;
/// The propensity assumed when a model has not scored the record.
pub const UNSCORED: f64 = 0.5;

/// A candidate action.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NbaAction {
    pub id: Uuid,
    pub entity: String,
    pub name: String,
    pub name_ar: Option<String>,
    pub condition: Option<String>,
    pub model_ref: Option<Uuid>,
    pub weight: f64,
    #[schema(value_type = Object)]
    pub action: Value,
}

/// `POST /api/v1/admin/predict/next-actions`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NbaActionBody {
    pub entity: String,
    pub name: String,
    #[serde(default)]
    pub name_ar: Option<String>,
    /// A rule-language condition over the entity's fields; none: always.
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub model_ref: Option<Uuid>,
    #[serde(default = "one")]
    pub weight: f64,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub action: Value,
}

fn one() -> f64 {
    1.0
}

/// One ranked action on a record.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(as = NbaRecommendation)]
pub struct Recommendation {
    /// The logged recommendation, to accept or reject.
    pub recommendation_id: Uuid,
    pub action_id: Uuid,
    pub name: String,
    pub name_ar: Option<String>,
    pub score: f64,
    #[schema(value_type = Object)]
    pub action: Value,
}

/// The record a request asks about.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecordQuery {
    pub regarding_entity: String,
    pub regarding_id: Uuid,
}

/// Ranks `(action, propensity)` pairs: weight times propensity, highest
/// first, at most [`MAX_SHOWN`]. Pure.
pub fn rank(candidates: Vec<(NbaAction, Option<f64>)>) -> Vec<(NbaAction, f64)> {
    let mut scored: Vec<(NbaAction, f64)> = candidates
        .into_iter()
        .map(|(action, propensity)| {
            let p = match (action.model_ref, propensity) {
                (None, _) => 1.0,
                (Some(_), Some(p)) => p,
                (Some(_), None) => UNSCORED,
            };
            let score = action.weight * p;
            (action, score)
        })
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.name.cmp(&b.0.name)));
    scored.truncate(MAX_SHOWN);
    scored
}

/// Whether `condition` holds on `record` of an entity with `attrs`; a
/// condition that does not compile does not hold. Pure apart from the clock.
pub fn eligible(
    condition: Option<&str>,
    attrs: &[attome_core::AttrInfo],
    record: &Map<String, Value>,
) -> bool {
    let Some(source) = condition.map(str::trim).filter(|c| !c.is_empty()) else {
        return true;
    };
    let schema = attome_records::rule_engine::schema_for_entity(attrs);
    match attome_rules::compile(source, &schema) {
        Ok(compiled) => {
            let ctx =
                attome_records::rule_engine::context_for_record(chrono::Utc::now(), attrs, record);
            matches!(compiled.eval(&ctx), Ok(attome_rules::Value::Bool(true)))
        }
        Err(error) => {
            tracing::warn!(%error, "next-best action: the condition does not compile");
            false
        }
    }
}

type ActionRow = (
    Uuid,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    f64,
    Value,
);

fn action_of(row: ActionRow) -> NbaAction {
    let (id, entity, name, name_ar, condition, model_ref, weight, action) = row;
    NbaAction {
        id,
        entity,
        name,
        name_ar,
        condition,
        model_ref,
        weight,
        action,
    }
}

const ACTION_COLUMNS: &str = "id, entity, name, name_ar, condition, model_ref, weight, action";

/// The ranked actions on one record, logged as shown to `ctx`.
pub async fn recommend(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record_id: Uuid,
) -> Result<Vec<Recommendation>, AppError> {
    ctx.require(entity, "read")?;
    let record = attome_records::entity_crud::read_record(state, ctx, entity, record_id).await?;
    let data: Map<String, Value> = serde_json::to_value(&record)
        .map_err(AppError::internal)?
        .get("data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|meta| meta.attrs.clone())
        .ok_or(AppError::NotFound)?;
    let rows: Vec<ActionRow> = sqlx::query_as(&format!(
        "SELECT {ACTION_COLUMNS} FROM nba_action WHERE entity = $1 AND is_active ORDER BY name"
    ))
    .bind(entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut candidates = Vec::new();
    for action in rows.into_iter().map(action_of) {
        if !eligible(action.condition.as_deref(), &attrs, &data) {
            continue;
        }
        let propensity = match action.model_ref {
            Some(model) => sqlx::query_scalar::<_, f64>(
                "SELECT score FROM prediction WHERE model_ref = $1 AND regarding_id = $2 \
                    AND is_deleted = false ORDER BY predicted_at DESC LIMIT 1",
            )
            .bind(model)
            .bind(record_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?,
            None => None,
        };
        candidates.push((action, propensity));
    }
    let mut out = Vec::new();
    for (rank_index, (action, score)) in rank(candidates).into_iter().enumerate() {
        let recommendation_id = log_shown(
            state,
            ctx.user_id,
            entity,
            record_id,
            &action,
            score,
            rank_index,
        )
        .await?;
        out.push(Recommendation {
            recommendation_id,
            action_id: action.id,
            name: action.name,
            name_ar: action.name_ar,
            score,
            action: action.action,
        });
    }
    Ok(out)
}

/// The open recommendation of `action` on the record for `user`, or a new
/// one.
async fn log_shown(
    state: &EngineState,
    user: Uuid,
    entity: &str,
    record_id: Uuid,
    action: &NbaAction,
    score: f64,
    rank_index: usize,
) -> Result<Uuid, AppError> {
    let rule = action.id.to_string();
    let open: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM outcome WHERE kind = 'recommendation' AND source_module = 'attome-predict' \
            AND regarding_id = $1 AND rule_ref = $2 AND proposed_by = $3 AND measured_at IS NULL \
          ORDER BY proposed_at DESC LIMIT 1",
    )
    .bind(record_id)
    .bind(&rule)
    .bind(user)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = open {
        return Ok(id);
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO outcome (id, kind, source_module, entity_logicalname, regarding_entity, \
             regarding_id, model_id, rule_ref, proposed_by, expected_value) \
         VALUES ($1, 'recommendation', 'attome-predict', $2, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(entity)
    .bind(record_id)
    .bind(action.model_ref.map(|m| m.to_string()))
    .bind(&rule)
    .bind(user)
    .bind(json!({ "action": action.name, "score": score, "rank": rank_index + 1 }))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

/// Read a record's next-best actions
///
/// The actions whose condition holds on the record, ranked by weight times
/// its propensity score, each logged as a recommendation to accept or reject.
#[utoipa::path(
    get,
    path = "/api/v1/predict/next-actions",
    tag = "predict",
    params(RecordQuery),
    responses(
        (status = 200, description = "The ranked actions", body = [Recommendation]),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks {regarding_entity}.read", body = ErrorResponse),
        (status = 404, description = "No such record, or not one the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn next_actions(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Query(q): Query<RecordQuery>,
) -> Result<Json<Vec<Recommendation>>, AppError> {
    Ok(Json(
        recommend(&state, &ctx, &q.regarding_entity, q.regarding_id).await?,
    ))
}

/// Records the decision on a recommendation shown to `user`; not found for
/// anyone else, and a conflict once decided.
pub async fn decide(
    state: &EngineState,
    user: Uuid,
    recommendation: Uuid,
    accepted: bool,
) -> Result<(), AppError> {
    let decided = sqlx::query(
        "UPDATE outcome SET actual_value = $3, effectiveness = $4, measured_at = now() \
          WHERE id = $1 AND kind = 'recommendation' AND source_module = 'attome-predict' \
            AND proposed_by = $2 AND measured_at IS NULL",
    )
    .bind(recommendation)
    .bind(user)
    .bind(json!({ "decision": if accepted { "accepted" } else { "rejected" } }))
    .bind(if accepted { 1.0_f64 } else { 0.0 })
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if decided.rows_affected() == 1 {
        return Ok(());
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM outcome WHERE id = $1 AND proposed_by = $2 \
            AND kind = 'recommendation')",
    )
    .bind(recommendation)
    .bind(user)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Err(AppError::Conflict("this recommendation is already decided"))
    } else {
        Err(AppError::NotFound)
    }
}

/// Accept a recommendation
///
/// Records that the person it was shown to took the action.
#[utoipa::path(
    post,
    path = "/api/v1/predict/recommendations/{id}/accept",
    tag = "predict",
    operation_id = "accept_next_action",
    params(("id" = Uuid, Path, description = "The recommendation")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Approved)])))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not a recommendation shown to the caller", body = ErrorResponse),
        (status = 409, description = "Already decided", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn accept(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    decide(&state, ctx.user_id, id, true).await?;
    write_decision_event(&state, ctx.user_id, id, true).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reject a recommendation
///
/// Records that the person it was shown to set the action aside.
#[utoipa::path(
    post,
    path = "/api/v1/predict/recommendations/{id}/reject",
    tag = "predict",
    operation_id = "reject_next_action",
    params(("id" = Uuid, Path, description = "The recommendation")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Rejected)])))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not a recommendation shown to the caller", body = ErrorResponse),
        (status = 409, description = "Already decided", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn reject(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    decide(&state, ctx.user_id, id, false).await?;
    write_decision_event(&state, ctx.user_id, id, false).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn write_decision_event(
    state: &EngineState,
    user: Uuid,
    recommendation: Uuid,
    accepted: bool,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "outcome",
            recommendation,
            if accepted {
                attome_audit::AuditOperation::Approved
            } else {
                attome_audit::AuditOperation::Rejected
            },
            if accepted {
                "predict.next_action_accepted"
            } else {
                "predict.next_action_rejected"
            },
            user,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

/// List next-best actions
#[utoipa::path(
    get,
    path = "/api/v1/admin/predict/next-actions",
    operation_id = "list_nba_actions",
    tag = "predict",
    responses(
        (status = 200, description = "Every active action", body = PaginatedResponse<NbaAction>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_actions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<PaginatedResponse<NbaAction>>, AppError> {
    let rows: Vec<ActionRow> = sqlx::query_as(&format!(
        "SELECT {ACTION_COLUMNS} FROM nba_action WHERE is_active ORDER BY entity, name LIMIT 1000"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<NbaAction> = rows.into_iter().map(action_of).collect();
    let total = i64::try_from(items.len()).unwrap_or(0);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// Create a next-best action
///
/// Checks the condition against the entity's fields and the model against the
/// entity. AI administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/predict/next-actions",
    tag = "predict",
    request_body = NbaActionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = NbaAction),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The entity already has an action of that name", body = ErrorResponse),
        (status = 422, description = "An unknown entity or model, a condition that does not compile, or a weight not above 0", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_action(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Json(body): Json<NbaActionBody>,
) -> Result<(StatusCode, Json<NbaAction>), AppError> {
    let attrs = state
        .entities
        .load()
        .get(&body.entity)
        .map(|meta| meta.attrs.clone())
        .ok_or_else(|| AppError::Validation(format!("{} is not an entity", body.entity)))?;
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation("a name is 1 to 200 characters".into()));
    }
    if !(body.weight > 0.0 && body.weight.is_finite()) {
        return Err(AppError::Validation("weight is above 0".into()));
    }
    if let Some(source) = body
        .condition
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let schema = attome_records::rule_engine::schema_for_entity(&attrs);
        attome_rules::compile(source, &schema)
            .map_err(|e| AppError::Validation(format!("the condition does not compile: {e}")))?;
    }
    if let Some(model) = body.model_ref {
        let entity: Option<String> = sqlx::query_scalar(
            "SELECT entity FROM prediction_model WHERE id = $1 AND is_deleted = false",
        )
        .bind(model)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if entity.as_deref() != Some(body.entity.as_str()) {
            return Err(AppError::Validation(
                "model_ref is a model of the same entity".into(),
            ));
        }
    }
    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let inserted = sqlx::query(
        "INSERT INTO nba_action (id, entity, name, name_ar, condition, model_ref, weight, action, \
             created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(&body.entity)
    .bind(name)
    .bind(&body.name_ar)
    .bind(&body.condition)
    .bind(body.model_ref)
    .bind(body.weight)
    .bind(&body.action)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await;
    if let Err(e) = &inserted
        && attome_db::is_unique_violation(e)
    {
        return Err(AppError::Conflict(
            "the entity already has an action of that name",
        ));
    }
    inserted.map_err(AppError::internal)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "nba_action",
            Some(id),
        )
        .named("predict.next_action_created"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(NbaAction {
            id,
            entity: body.entity,
            name: name.to_owned(),
            name_ar: body.name_ar,
            condition: body.condition,
            model_ref: body.model_ref,
            weight: body.weight,
            action: body.action,
        }),
    ))
}

/// Retire a next-best action
///
/// It is no longer offered; its past recommendations stay. AI administrators
/// only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/predict/next-actions/{id}",
    tag = "predict",
    params(("id" = Uuid, Path, description = "The action")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Retired"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active action", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn retire_action(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let retired = sqlx::query(
        "UPDATE nba_action SET is_active = false, row_version = row_version + 1 \
          WHERE id = $1 AND is_active",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if retired.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "nba_action",
            Some(id),
        )
        .named("predict.next_action_retired"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/predict/next-actions", get(next_actions))
        .route("/api/v1/predict/recommendations/{id}/accept", post(accept))
        .route("/api/v1/predict/recommendations/{id}/reject", post(reject))
        .route(
            "/api/v1/admin/predict/next-actions",
            get(list_actions).post(create_action),
        )
        .route(
            "/api/v1/admin/predict/next-actions/{id}",
            delete(retire_action),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    next_actions,
    accept,
    reject,
    list_actions,
    create_action,
    retire_action
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(name: &str, model: bool, weight: f64) -> NbaAction {
        NbaAction {
            id: Uuid::now_v7(),
            entity: "opportunity".into(),
            name: name.into(),
            name_ar: None,
            condition: None,
            model_ref: model.then(Uuid::now_v7),
            weight,
            action: json!({}),
        }
    }

    #[test]
    fn ranking_is_weight_times_propensity() {
        let ranked = rank(vec![
            (action("call", true, 1.0), Some(0.9)),
            (action("email", false, 0.5), None),
            (action("demo", true, 2.0), None),
            (action("visit", true, 1.0), Some(0.2)),
        ]);
        let names: Vec<&str> = ranked.iter().map(|(a, _)| a.name.as_str()).collect();
        assert_eq!(names, ["demo", "call", "email", "visit"]);
        assert!(
            (ranked[0].1 - 1.0).abs() < 1e-9,
            "an unscored record counts 0.5"
        );
        let many: Vec<_> = (0..9)
            .map(|i| (action(&format!("a{i}"), false, 1.0), None))
            .collect();
        assert_eq!(rank(many).len(), MAX_SHOWN);
    }

    #[test]
    fn no_condition_is_always_eligible() {
        assert!(eligible(None, &[], &Map::new()));
        assert!(eligible(Some("  "), &[], &Map::new()));
        assert!(
            !eligible(Some("no_such_field > 3"), &[], &Map::new()),
            "does not compile"
        );
    }
}
