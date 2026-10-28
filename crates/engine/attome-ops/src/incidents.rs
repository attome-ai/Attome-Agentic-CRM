//! AB11-T3: incidents on the status page.
//!
//! - `POST /api/v1/ops/incidents` (`ops.read`) opens a draft;
//!   `PATCH /api/v1/ops/incidents/{id}` (`If-Match`) changes its title,
//!   components, impact or audience while it is still a draft.
//! - `POST /api/v1/ops/incidents/{id}/updates` (`ops.incident.publish`)
//!   publishes an update in both languages: the incident moves to the
//!   update's stage (`note` keeps it), its first update publishes it, and
//!   `resolved` resolves it. A correction names an earlier update of the same
//!   incident and is a new row: no route edits or deletes an update, and the
//!   table refuses it (migration 0314). Agents reach none of these routes; no
//!   AI action publishes.
//! - `GET /api/v1/ops/incidents` (one-based pages, open first) and
//!   `GET /api/v1/ops/incidents/{id}` (with its updates), for `ops.read`.
//!
//! Every write commits with its Configuration event, and clears the cached
//! status snapshot ([`crate::public_status`]) so the next read sees it.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::upgrades::OpsRead;

/// `ops.incident.publish`: who publishes incident updates.
#[derive(Debug)]
pub struct OpsIncidentPublish;

impl PrivilegeKey for OpsIncidentPublish {
    const KEY: &'static str = "ops.incident.publish";
}

/// The stages an update may name; `note` adds text without moving the
/// incident.
pub const STAGES: [&str; 5] = [
    "investigating",
    "identified",
    "monitoring",
    "resolved",
    "note",
];
pub const IMPACTS: [&str; 3] = ["degraded", "partial", "major"];
pub const AUDIENCES: [&str; 2] = ["internal", "public"];

const MAX_TITLE: usize = 200;
const MAX_BODY: usize = 8000;

const COLUMNS: &str = "id, title_en, title_ar, audience, state, components, impact, started_at, \
     resolved_at, published_at, created_by, auto_created, row_version";
const UPDATE_COLUMNS: &str =
    "id, incident_id, stage, body_en, body_ar, corrects_update_id, published_by, published_at";

/// An incident.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct Incident {
    pub id: Uuid,
    pub title_en: String,
    pub title_ar: Option<String>,
    /// `internal` or `public`.
    pub audience: String,
    /// `draft`, `investigating`, `identified`, `monitoring` or `resolved`.
    pub state: String,
    pub components: Vec<String>,
    /// `degraded`, `partial` or `major`.
    pub impact: String,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub published_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub auto_created: bool,
    pub row_version: i64,
}

/// One published update.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct IncidentUpdate {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub stage: String,
    pub body_en: String,
    pub body_ar: Option<String>,
    /// The update this one corrects; shown after it, labelled a correction.
    pub corrects_update_id: Option<Uuid>,
    pub published_by: Option<Uuid>,
    pub published_at: DateTime<Utc>,
}

/// An incident with its updates, oldest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct IncidentDetail {
    #[serde(flatten)]
    pub incident: Incident,
    pub updates: Vec<IncidentUpdate>,
}

/// A new draft.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewIncident {
    pub title_en: String,
    #[serde(default)]
    pub title_ar: Option<String>,
    /// `internal` (the default) or `public`.
    #[serde(default)]
    pub audience: Option<String>,
    /// Component keys (`ops_status_component.key`).
    #[serde(default)]
    pub components: Vec<String>,
    /// `degraded` (the default), `partial` or `major`.
    #[serde(default)]
    pub impact: Option<String>,
}

/// A draft's changes; an absent field is kept.
#[derive(Debug, Deserialize, ToSchema)]
pub struct IncidentChange {
    pub title_en: Option<String>,
    pub title_ar: Option<String>,
    pub audience: Option<String>,
    pub components: Option<Vec<String>>,
    pub impact: Option<String>,
}

/// An update to publish.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewIncidentUpdate {
    /// One of [`STAGES`].
    pub stage: String,
    pub body_en: String,
    pub body_ar: String,
    /// The earlier update of this incident that this one corrects.
    #[serde(default)]
    pub corrects_update_id: Option<Uuid>,
}

fn one_of(field: &str, value: &str, allowed: &[&str]) -> Result<(), AppError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "{field} must be one of {}",
            allowed.join(", ")
        )))
    }
}

fn check_text(field: &str, value: &str, max: usize) -> Result<(), AppError> {
    let len = value.trim().chars().count();
    if len == 0 || len > max {
        return Err(AppError::Validation(format!(
            "{field} must be 1 to {max} characters"
        )));
    }
    Ok(())
}

/// The checks on a new update: a known stage and text in both languages.
/// Pure.
pub fn check_update(body: &NewIncidentUpdate) -> Result<(), AppError> {
    one_of("stage", &body.stage, &STAGES)?;
    check_text("body_en", &body.body_en, MAX_BODY)?;
    check_text("body_ar", &body.body_ar, MAX_BODY)
}

/// The state an incident in `current` moves to on an update of `stage`
/// (a correction never moves it). Pure.
pub fn next_state(current: &str, stage: &str, correction: bool) -> String {
    if correction || stage == "note" {
        if current == "draft" {
            // A first update publishes; a note on a draft starts it.
            "investigating".to_owned()
        } else {
            current.to_owned()
        }
    } else {
        stage.to_owned()
    }
}

async fn check_components(
    tx: &mut sqlx::PgConnection,
    components: &[String],
) -> Result<(), AppError> {
    if components.is_empty() {
        return Ok(());
    }
    let known: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ops_status_component WHERE key = ANY($1)")
            .bind(components)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let distinct = components
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if usize::try_from(known).unwrap_or(0) != distinct {
        return Err(AppError::Validation(
            "components must name status components".into(),
        ));
    }
    Ok(())
}

fn event(
    operation: AuditOperation,
    actor: Uuid,
    id: Uuid,
    name: &str,
    comment: String,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "ops_incident",
        Some(id),
    )
    .named(name.to_owned())
    .comment(comment)
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Validation("If-Match is required".into()))?;
    raw.trim().trim_matches('"').parse::<i64>().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {raw}"
        ))
    })
}

/// Open an incident draft
///
/// AB11-T3: a draft nobody but `ops.read` holders sees until its first
/// update is published. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/incidents",
    tag = "ops",
    operation_id = "create_ops_incident",
    request_body = NewIncident,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The draft", body = Incident),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 422, description = "An empty title, or an unknown audience, impact or component", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_incident(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsRead>>,
    Json(body): Json<NewIncident>,
) -> Result<(StatusCode, Json<Incident>), AppError> {
    check_text("title_en", &body.title_en, MAX_TITLE)?;
    let audience = body.audience.as_deref().unwrap_or("internal");
    let impact = body.impact.as_deref().unwrap_or("degraded");
    one_of("audience", audience, &AUDIENCES)?;
    one_of("impact", impact, &IMPACTS)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    check_components(&mut tx, &body.components).await?;
    let incident: Incident = sqlx::query_as(&format!(
        "INSERT INTO ops_incident (id, title_en, title_ar, audience, state, components, impact, created_by) \
         VALUES (uuidv7(), $1, $2, $3, 'draft', $4, $5, $6) RETURNING {COLUMNS}"
    ))
    .bind(body.title_en.trim())
    .bind(body.title_ar.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(audience)
    .bind(&body.components)
    .bind(impact)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            incident.id,
            "ops.incident_created",
            format!("incident draft opened: {}", incident.title_en),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::public_status::invalidate();
    Ok((StatusCode::CREATED, Json(incident)))
}

/// Change an incident draft
///
/// AB11-T3: title, components, impact and audience, while the incident is a
/// draft. `If-Match` names the row version. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/ops/incidents/{id}",
    tag = "ops",
    operation_id = "update_ops_incident",
    params(
        ("id" = Uuid, Path, description = "The incident"),
        ("If-Match" = String, Header, description = "The incident's row_version, quoted"),
    ),
    request_body = IncidentChange,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The changed draft", body = Incident),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 404, description = "No such incident", body = ErrorResponse),
        (status = 409, description = "No longer a draft, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match missing, or an invalid field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_incident(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsRead>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<IncidentChange>,
) -> Result<Json<Incident>, AppError> {
    let expected = if_match(&headers)?;
    if let Some(title) = &body.title_en {
        check_text("title_en", title, MAX_TITLE)?;
    }
    if let Some(audience) = &body.audience {
        one_of("audience", audience, &AUDIENCES)?;
    }
    if let Some(impact) = &body.impact {
        one_of("impact", impact, &IMPACTS)?;
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT state, row_version FROM ops_incident WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let (incident_state, version) = current.ok_or(AppError::NotFound)?;
    if incident_state != "draft" {
        return Err(AppError::Conflict(
            "a published incident changes only through its updates",
        ));
    }
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if let Some(components) = &body.components {
        check_components(&mut tx, components).await?;
    }
    let incident: Incident = sqlx::query_as(&format!(
        "UPDATE ops_incident SET \
            title_en = COALESCE($2, title_en), \
            title_ar = CASE WHEN $3::boolean THEN NULLIF(btrim($4), '') ELSE title_ar END, \
            audience = COALESCE($5, audience), \
            components = COALESCE($6, components), \
            impact = COALESCE($7, impact), \
            row_version = row_version + 1 \
          WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(body.title_en.as_deref().map(str::trim))
    .bind(body.title_ar.is_some())
    .bind(body.title_ar.as_deref())
    .bind(body.audience.as_deref())
    .bind(body.components.clone())
    .bind(body.impact.as_deref())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Update,
            ctx.user_id,
            id,
            "ops.incident_changed",
            format!("incident draft changed: {}", incident.title_en),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::public_status::invalidate();
    Ok(Json(incident))
}

/// Publish an incident update
///
/// AB11-T3: text in English and Arabic (both required). The incident moves
/// to the stage (`note` keeps it; a correction never moves it), the first
/// update publishes it, `resolved` resolves it. A correction names an
/// earlier update of the same incident. Needs `ops.incident.publish`.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/incidents/{id}/updates",
    tag = "ops",
    operation_id = "publish_ops_incident_update",
    params(("id" = Uuid, Path, description = "The incident")),
    request_body = NewIncidentUpdate,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The published update", body = IncidentUpdate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
        (status = 404, description = "No such incident", body = ErrorResponse),
        (status = 409, description = "The incident is resolved", body = ErrorResponse),
        (status = 422, description = "An unknown stage, a missing language, or a correction of another incident's update", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish_update(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Path(id): Path<Uuid>,
    Json(body): Json<NewIncidentUpdate>,
) -> Result<(StatusCode, Json<IncidentUpdate>), AppError> {
    check_update(&body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT state, resolved_at FROM ops_incident WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let (incident_state, resolved_at) = current.ok_or(AppError::NotFound)?;
    let correction = body.corrects_update_id.is_some();
    if resolved_at.is_some() && !correction {
        return Err(AppError::Conflict("this incident is resolved"));
    }
    if let Some(corrects) = body.corrects_update_id {
        let same: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM ops_incident_update WHERE id = $1 AND incident_id = $2)",
        )
        .bind(corrects)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if !same {
            return Err(AppError::Validation(
                "corrects_update_id must name an update of this incident".into(),
            ));
        }
    }
    let update: IncidentUpdate = sqlx::query_as(&format!(
        "INSERT INTO ops_incident_update \
            (id, incident_id, stage, body_en, body_ar, corrects_update_id, published_by, published_at) \
         VALUES (uuidv7(), $1, $2, $3, $4, $5, $6, now()) RETURNING {UPDATE_COLUMNS}"
    ))
    .bind(id)
    .bind(&body.stage)
    .bind(body.body_en.trim())
    .bind(body.body_ar.trim())
    .bind(body.corrects_update_id)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let moved = next_state(&incident_state, &body.stage, correction);
    sqlx::query(
        "UPDATE ops_incident SET state = $2, \
            published_at = COALESCE(published_at, now()), \
            resolved_at = CASE WHEN $2 = 'resolved' THEN COALESCE(resolved_at, now()) ELSE resolved_at END, \
            row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(&moved)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            id,
            "ops.incident_update_published",
            format!("incident update published ({}): {moved}", body.stage),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::public_status::invalidate();
    Ok((StatusCode::CREATED, Json(update)))
}

/// List incidents
///
/// AB11-T3: open incidents first, newest first. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/incidents",
    tag = "ops",
    operation_id = "list_ops_incidents",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of incidents", body = PaginatedResponse<Incident>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_incidents(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<Incident>>, AppError> {
    let w = page.window();
    let items: Vec<Incident> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_incident \
          ORDER BY (resolved_at IS NULL) DESC, started_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ops_incident")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

/// Read an incident
///
/// AB11-T3: the incident and its updates, oldest first; a correction
/// follows the update it corrects. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/incidents/{id}",
    tag = "ops",
    operation_id = "get_ops_incident",
    params(("id" = Uuid, Path, description = "The incident")),
    responses(
        (status = 200, description = "The incident and its updates", body = IncidentDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 404, description = "No such incident", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_incident(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<IncidentDetail>, AppError> {
    let incident: Incident =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM ops_incident WHERE id = $1"))
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    let updates: Vec<IncidentUpdate> = sqlx::query_as(&format!(
        "SELECT {UPDATE_COLUMNS} FROM ops_incident_update WHERE incident_id = $1 \
          ORDER BY published_at, id"
    ))
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(IncidentDetail {
        incident,
        updates: order_with_corrections(updates),
    }))
}

/// Updates in publish order, each correction moved to just after the update
/// it corrects (or the correction it corrects). Pure.
pub fn order_with_corrections(updates: Vec<IncidentUpdate>) -> Vec<IncidentUpdate> {
    let (mut base, corrections): (Vec<_>, Vec<_>) = updates
        .into_iter()
        .partition(|u| u.corrects_update_id.is_none());
    for correction in corrections {
        let at = correction
            .corrects_update_id
            .and_then(|target| {
                base.iter()
                    .rposition(|u| u.id == target || u.corrects_update_id == Some(target))
            })
            .map_or(base.len(), |i| i + 1);
        base.insert(at, correction);
    }
    base
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ops/incidents",
            get(list_incidents).post(create_incident),
        )
        .route(
            "/api/v1/ops/incidents/{id}",
            get(get_incident).patch(update_incident),
        )
        .route("/api/v1/ops/incidents/{id}/updates", post(publish_update))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_incident,
        update_incident,
        publish_update,
        list_incidents,
        get_incident
    ),
    components(schemas(
        Incident,
        IncidentUpdate,
        IncidentDetail,
        NewIncident,
        IncidentChange,
        NewIncidentUpdate
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(stage: &str, en: &str, ar: &str) -> NewIncidentUpdate {
        NewIncidentUpdate {
            stage: stage.into(),
            body_en: en.into(),
            body_ar: ar.into(),
            corrects_update_id: None,
        }
    }

    #[test]
    fn update_needs_both_languages() {
        assert!(check_update(&update("investigating", "Looking into it", "نتحقق من ذلك")).is_ok());
        assert!(check_update(&update("investigating", "Looking into it", " ")).is_err());
        assert!(check_update(&update("investigating", "", "نتحقق")).is_err());
        assert!(check_update(&update("fixed", "x", "س")).is_err());
    }

    #[test]
    fn resolve_sets_the_state_and_corrections_keep_it() {
        assert_eq!(next_state("draft", "investigating", false), "investigating");
        assert_eq!(next_state("identified", "resolved", false), "resolved");
        assert_eq!(next_state("monitoring", "note", false), "monitoring");
        assert_eq!(next_state("draft", "note", false), "investigating");
        assert_eq!(next_state("resolved", "investigating", true), "resolved");
    }

    #[test]
    fn correction_is_shown_after_what_it_corrects() {
        let at = Utc::now();
        let row = |id: u128, corrects: Option<u128>| IncidentUpdate {
            id: Uuid::from_u128(id),
            incident_id: Uuid::nil(),
            stage: "note".into(),
            body_en: String::new(),
            body_ar: None,
            corrects_update_id: corrects.map(Uuid::from_u128),
            published_by: None,
            published_at: at,
        };
        let ordered = order_with_corrections(vec![
            row(1, None),
            row(2, None),
            row(3, Some(1)),
            row(4, Some(1)),
        ]);
        let ids: Vec<u128> = ordered.iter().map(|u| u.id.as_u128()).collect();
        assert_eq!(ids, [1, 3, 4, 2]);
    }
}
