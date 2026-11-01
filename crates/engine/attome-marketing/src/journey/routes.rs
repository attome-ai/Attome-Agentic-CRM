//! Journey routes (roadmap E8-T10), the part the marketing engine owns:
//!
//! - `GET /api/v1/marketing/journeys/{id}/counts`: the node counts and goal
//!   conversion ([`super::insight::counts`]);
//! - `GET .../people/{person_id}/path`: one person's runs
//!   ([`super::insight::person_path`]);
//! - `POST .../enrolments`: enrol up to 1,000 people by hand (source
//!   `manual`), only people the caller may read, through the same admission
//!   rules as every entry ([`super::enrol::enrol`]); `is_test` enrols test
//!   runs, which a draft journey takes too;
//! - `GET .../enrolments`: the enrolments of one person entity, a page at a
//!   time, only of people the caller may read (the record predicate in the
//!   SQL, so the total counts only them);
//! - `DELETE .../enrolments/{enrolment_id}`: take a person out: the
//!   enrolment ends as `removed` and its run is cancelled.
//!
//! `{id}` is the `marketing_journey` record. Reads need
//! `marketing_journey.read`, changes `marketing_journey.update`.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::enrol::{EnrolOutcome, PersonRef};
use super::insight::{JourneyCounts, PersonRun};

/// Most people one manual enrolment takes.
pub const MAX_MANUAL: usize = 1_000;

/// `marketing_journey.read`: may look into a journey.
#[derive(Debug)]
pub struct JourneyRead;

impl PrivilegeKey for JourneyRead {
    const KEY: &'static str = "marketing_journey.read";
}

/// `marketing_journey.update`: may enrol and remove people.
#[derive(Debug)]
pub struct JourneyUpdate;

impl PrivilegeKey for JourneyUpdate {
    const KEY: &'static str = "marketing_journey.update";
}

/// The workflow definition behind journey `journey`, or 404.
async fn definition_of(state: &EngineState, journey: Uuid) -> Result<Uuid, AppError> {
    sqlx::query_scalar(
        "SELECT d.id FROM marketing_journey j \
           JOIN workflow_definition d ON d.logicalname = j.workflow_definition_logicalname \
          WHERE j.id = $1 AND j.is_active IS NOT FALSE AND d.kind = 'journey'",
    )
    .bind(journey)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Read a journey's counts
///
/// How many people entered, wait at, passed, were blocked at and left at each node, with the
/// journey's goal conversion.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/journeys/{id}/counts",
    operation_id = "get_marketing_journey_counts",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey")),
    responses(
        (status = 200, description = "The journey's node counts", body = JourneyCounts),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.read", body = ErrorResponse),
        (status = 404, description = "No such journey", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_counts(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyRead>>,
    Path(journey): Path<Uuid>,
) -> Result<Json<JourneyCounts>, AppError> {
    let definition = definition_of(&state, journey).await?;
    super::insight::counts(&state, &ctx, definition)
        .await
        .map(Json)
}

/// Read a person's path through a journey
///
/// Each of the person's runs: the nodes in the order they ran, the blocks with their reasons, and
/// how the run ended.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/journeys/{id}/people/{person_id}/path",
    operation_id = "get_marketing_journey_person_path",
    tag = "marketing",
    params(
        ("id" = Uuid, Path, description = "The journey"),
        ("person_id" = Uuid, Path, description = "The contact or lead"),
    ),
    responses(
        (status = 200, description = "The person's runs, oldest first (one page)", body = PaginatedResponse<PersonRun>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.read", body = ErrorResponse),
        (status = 404, description = "No such journey, or a person the caller may not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_person_path(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyRead>>,
    Path((journey, person)): Path<(Uuid, Uuid)>,
) -> Result<Json<PaginatedResponse<PersonRun>>, AppError> {
    let definition = definition_of(&state, journey).await?;
    let runs = super::insight::person_path(&state, &ctx, definition, person).await?;
    let total = runs.len() as i64;
    Ok(Json(PaginatedResponse::new(runs, total, 1, total.max(1))))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ManualEnrolBody {
    /// The people, at most 1,000.
    pub people: Vec<PersonRef>,
    /// Test runs: they never count toward the daily cap and a draft journey
    /// takes them.
    #[serde(default)]
    pub is_test: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct ManualEnrolResult {
    #[serde(flatten)]
    pub outcome: EnrolOutcome,
    /// People left out because the caller may not read them.
    pub skipped_unreadable: u64,
}

/// Enrol people in a journey
///
/// Enrols up to 1,000 contacts or leads the caller may read, through the journey's re-entry rule
/// and daily cap. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/journeys/{id}/enrolments",
    operation_id = "enrol_marketing_journey",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey")),
    request_body = ManualEnrolBody,
    responses(
        (status = 200, description = "Who was enrolled and who was skipped, and why", body = ManualEnrolResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.update", body = ErrorResponse),
        (status = 404, description = "No such journey", body = ErrorResponse),
        (status = 422, description = "More than 1,000 people, or a journey not live for a real enrolment", body = ErrorResponse),
        (status = 503, description = "Workflow runs cannot start on this node", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
async fn post_enrolments(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyUpdate>>,
    Path(journey): Path<Uuid>,
    Json(body): Json<ManualEnrolBody>,
) -> Result<Json<ManualEnrolResult>, AppError> {
    if body.people.len() > MAX_MANUAL {
        return Err(AppError::Validation(format!(
            "at most {MAX_MANUAL} people can be enrolled at once"
        )));
    }
    definition_of(&state, journey).await?;
    let mut by_entity: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
    for person in &body.people {
        by_entity
            .entry(person.entity.clone())
            .or_default()
            .push(person.id);
    }
    let mut people = Vec::with_capacity(body.people.len());
    for (entity, ids) in by_entity {
        let visible = crate::segment_insight::readable(&state, &ctx, &entity, &ids).await?;
        people.extend(
            ids.into_iter()
                .filter(|id| visible.contains(id))
                .map(|id| PersonRef {
                    id,
                    entity: entity.clone(),
                }),
        );
    }
    let skipped_unreadable = (body.people.len() - people.len()) as u64;
    let outcome = super::enrol::enrol(&state, journey, people, "manual", body.is_test).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "marketing_journey",
            journey,
            attome_audit::AuditOperation::Create,
            "marketing_journey.enrolled",
            ctx.user_id,
        )
        .comment(format!("{} enrolled by hand", outcome.enrolled)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(ManualEnrolResult {
        outcome,
        skipped_unreadable,
    }))
}

/// Take a person out of a journey
///
/// Ends the active enrolment as `removed` and cancels its run. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/marketing/journeys/{id}/enrolments/{enrolment_id}",
    operation_id = "remove_marketing_journey_enrolment",
    tag = "marketing",
    params(
        ("id" = Uuid, Path, description = "The journey"),
        ("enrolment_id" = Uuid, Path, description = "The enrolment"),
    ),
    responses(
        (status = 204, description = "The person is out of the journey"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.update", body = ErrorResponse),
        (status = 404, description = "No such journey, or no active enrolment with that id in it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Delete)])))),
)]
async fn delete_enrolment(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyUpdate>>,
    Path((journey, enrolment)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let definition = definition_of(&state, journey).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let instance: Option<Option<Uuid>> = sqlx::query_scalar(
        "UPDATE marketing_journey_enrolment \
            SET status = 'removed', ended_at = now(), end_reason = 'removed' \
          WHERE id = $1 AND definition_id = $2 AND status = 'active' \
          RETURNING instance_id",
    )
    .bind(enrolment)
    .bind(definition)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(instance) = instance else {
        return Err(AppError::NotFound);
    };
    if let Some(instance) = instance {
        sqlx::query(
            "UPDATE workflow_instance SET status = 'cancelled', completed_at = now(), \
                 row_version = row_version + 1 \
              WHERE id = $1 AND status IN ('queued', 'running', 'waiting', 'paused')",
        )
        .bind(instance)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "marketing_journey",
            journey,
            attome_audit::AuditOperation::Delete,
            "marketing_journey.enrolment_removed",
            ctx.user_id,
        )
        .comment(format!("enrolment {enrolment}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EnrolmentsQuery {
    /// The people's entity: `contact` (default) or `lead`.
    pub person_entity: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct JourneyEnrolment {
    pub id: Uuid,
    pub person_id: Uuid,
    pub person_entity: String,
    /// `active`, `completed`, `exited` or `removed`.
    pub status: String,
    pub entry_source: String,
    pub entered_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub end_reason: Option<String>,
    pub is_test: bool,
}

/// List a journey's enrolments
///
/// The journey's enrolments of one person entity, newest first, only of people the caller may
/// read.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/journeys/{id}/enrolments",
    operation_id = "list_marketing_journey_enrolments",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey"), EnrolmentsQuery),
    responses(
        (status = 200, description = "One page of enrolments of people the caller may read", body = PaginatedResponse<JourneyEnrolment>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.read", body = ErrorResponse),
        (status = 404, description = "No such journey", body = ErrorResponse),
        (status = 422, description = "A person entity other than contact or lead", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_enrolments(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyRead>>,
    Path(journey): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<EnrolmentsQuery>,
) -> Result<Json<PaginatedResponse<JourneyEnrolment>>, AppError> {
    let definition = definition_of(&state, journey).await?;
    let entity = q.person_entity.unwrap_or_else(|| "contact".to_owned());
    if !matches!(entity.as_str(), "contact" | "lead") {
        return Err(AppError::Validation(
            "person_entity is contact or lead".into(),
        ));
    }
    let window = attome_types::OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    let Some(entity_id) = state.entities.load().get(&entity).map(|m| m.entity_id) else {
        return Ok(Json(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        )));
    };
    let level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity,
        attome_security::RecordAction::Read,
    )
    .await?;
    // $1 the definition, $2 the entity name; the predicate's binds from $3.
    let pred = attome_security::rls_predicate(
        &ctx,
        entity_id,
        "p",
        level,
        attome_security::RecordAction::Read.share_capability(),
        3,
    );
    let from = format!(
        "FROM marketing_journey_enrolment e JOIN {} p ON p.id = e.person_id \
         WHERE e.definition_id = $1 AND e.person_entity = $2 {}",
        attome_core::quote_ident(&entity),
        pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let next = 3 + if pred.is_some() {
        attome_security::RLS_BIND_COUNT
    } else {
        0
    };
    let count_sql = format!("SELECT COUNT(*) {from}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(definition)
        .bind(&entity);
    if let Some(p) = &pred {
        count = attome_security::bind_rls_predicate(count, &p.binds);
    }
    let total = count
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let page_sql = format!(
        "SELECT e.id, e.person_id, e.person_entity, e.status, e.entry_source, e.entered_at, \
                e.ended_at, e.end_reason, e.is_test {from} \
         ORDER BY e.entered_at DESC, e.id LIMIT ${next} OFFSET ${}",
        next + 1
    );
    let mut rows = sqlx::query_as::<_, JourneyEnrolment>(&page_sql)
        .bind(definition)
        .bind(&entity);
    if let Some(p) = &pred {
        rows = attome_security::bind_rls_predicate_as(rows, &p.binds);
    }
    let items = rows
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/journeys/{id}/counts", get(get_counts))
        .route(
            "/api/v1/marketing/journeys/{id}/people/{person_id}/path",
            get(get_person_path),
        )
        .route(
            "/api/v1/marketing/journeys/{id}/enrolments",
            post(post_enrolments).get(get_enrolments),
        )
        .route(
            "/api/v1/marketing/journeys/{id}/enrolments/{enrolment_id}",
            delete(delete_enrolment),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_counts,
        get_person_path,
        post_enrolments,
        get_enrolments,
        delete_enrolment
    ),
    components(schemas(
        JourneyEnrolment,
        JourneyCounts,
        PersonRun,
        ManualEnrolBody,
        ManualEnrolResult,
        PersonRef,
        EnrolOutcome,
        super::insight::NodeCount,
        super::insight::PathStep,
        super::insight::PathBlock
    ))
)]
pub(crate) struct ApiDocFragment;
