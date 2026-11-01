//! Journey pause and resume (roadmap E8-T10), here because a journey's runs
//! are workflow runs (`attome-workflow` depends on `attome-marketing`, not
//! the other way).
//!
//! - `POST /api/v1/marketing/journeys/{id}/pause`: a live journey becomes
//!   `paused`, and each of its active people's runs that is running or
//!   waiting is paused, the same pause a single run takes
//!   ([`crate::instance_control`]), so no node of any kind runs (a message,
//!   a record update, a webhook) until it resumes. Entry sources and real
//!   enrolments already skip a journey that is not live.
//! - `POST .../resume`: the journey is `live` again and its paused runs go
//!   on where they stopped (a step still waiting keeps waiting).
//! - `POST .../publish` (`{version_id, version_mode}`): the journey's
//!   publish role when it names one, then the workflow's own publish
//!   ([`crate::admin::publish_draft`]) and the move of the people already in
//!   it (`finish_on_old` or `move_matching`); a draft journey becomes live.
//! - `POST .../simulate`: the newest published version runs in memory for
//!   up to [`MAX_SAMPLE`] sample people, each person's record as the
//!   trigger, through the workflow simulation ([`crate::simulate`]), which
//!   never writes, sends or requests anything; waits do not wait.
//!
//! Pause and resume need `marketing_journey.update` and the marketing module, hold the
//! journey's lock (`attome-workflow/journey-control:{id}`), and write a
//! Configuration security event in their transaction.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_marketing::journey::routes::JourneyUpdate;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// What a pause or resume did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct JourneyControlResult {
    pub journey_id: Uuid,
    /// `paused` or `live`.
    pub status: String,
    /// Runs paused or resumed.
    pub runs: u64,
}

/// Pauses (`true`) or resumes a journey, as `user_id`.
pub async fn set_paused(
    state: &EngineState,
    journey: Uuid,
    pause: bool,
    user_id: Uuid,
) -> Result<JourneyControlResult, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
        return Err(AppError::NotFound);
    }
    let (from, to) = if pause {
        ("live", "paused")
    } else {
        ("paused", "live")
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-workflow/journey-control:{journey}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another pause or resume of this journey is in progress",
        ));
    }
    let definition: Option<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM marketing_journey j \
           JOIN workflow_definition d ON d.logicalname = j.workflow_definition_logicalname \
          WHERE j.id = $1 AND j.is_active IS NOT FALSE AND d.kind = 'journey'",
    )
    .bind(journey)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(definition) = definition else {
        return Err(AppError::NotFound);
    };
    let moved = sqlx::query(
        "UPDATE marketing_journey SET status = $2, modified_at = now(), \
             row_version = row_version + 1 \
          WHERE id = $1 AND status = $3",
    )
    .bind(journey)
    .bind(to)
    .bind(from)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() == 0 {
        return Err(if pause {
            AppError::Conflict("the journey is not live")
        } else {
            AppError::Conflict("the journey is not paused")
        });
    }
    let runs: Vec<Uuid> = if pause {
        sqlx::query_scalar::<_, Uuid>(
            "UPDATE workflow_instance i SET status = 'paused', row_version = i.row_version + 1 \
               FROM marketing_journey_enrolment e \
              WHERE e.instance_id = i.id AND e.definition_id = $1 AND e.status = 'active' \
                AND i.status IN ('running', 'waiting') \
             RETURNING i.id",
        )
    } else {
        sqlx::query_scalar::<_, Uuid>(
            "UPDATE workflow_instance i SET status = 'running', row_version = i.row_version + 1 \
               FROM marketing_journey_enrolment e \
              WHERE e.instance_id = i.id AND e.definition_id = $1 AND e.status = 'active' \
                AND i.status = 'paused' \
             RETURNING i.id",
        )
    }
    .bind(definition)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !pause {
        // The pass settles each run back to `waiting` when a step still waits.
        for instance_id in &runs {
            attome_jobs::enqueue_in_tx(
                &mut tx,
                attome_core::jobs::EngineJob::WorkflowExecute {
                    instance_id: *instance_id,
                },
            )
            .await
            .map_err(AppError::internal)?;
        }
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            user_id,
            "marketing_journey",
            Some(journey),
        )
        .named(if pause {
            "marketing_journey.paused"
        } else {
            "marketing_journey.resumed"
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(JourneyControlResult {
        journey_id: journey,
        status: to.to_owned(),
        runs: runs.len() as u64,
    })
}

/// Pause a journey
///
/// A live journey stops: it takes no one new, and its people's runs pause where they are, every
/// kind of step included. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/journeys/{id}/pause",
    operation_id = "pause_marketing_journey",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey")),
    responses(
        (status = 200, description = "The journey and its runs are paused", body = JourneyControlResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.update", body = ErrorResponse),
        (status = 404, description = "No such journey", body = ErrorResponse),
        (status = 409, description = "The journey is not live, or another pause or resume is in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
async fn post_pause(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyUpdate>>,
    Path(journey): Path<Uuid>,
) -> Result<Json<JourneyControlResult>, AppError> {
    set_paused(&state, journey, true, ctx.user_id)
        .await
        .map(Json)
}

/// Resume a journey
///
/// A paused journey is live again, and its paused runs go on where they stopped. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/journeys/{id}/resume",
    operation_id = "resume_marketing_journey",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey")),
    responses(
        (status = 200, description = "The journey is live and its runs go on", body = JourneyControlResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.update", body = ErrorResponse),
        (status = 404, description = "No such journey", body = ErrorResponse),
        (status = 409, description = "The journey is not paused, or another pause or resume is in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
async fn post_resume(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyUpdate>>,
    Path(journey): Path<Uuid>,
) -> Result<Json<JourneyControlResult>, AppError> {
    set_paused(&state, journey, false, ctx.user_id)
        .await
        .map(Json)
}

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct JourneyPublishBody {
    /// The draft version to publish.
    pub version_id: Uuid,
    /// What happens to people already in the journey.
    #[serde(default)]
    pub version_mode: attome_marketing::journey::versions::VersionMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct JourneyPublishResult {
    pub journey_id: Uuid,
    pub version_id: Uuid,
    /// People moved to the new version.
    pub moved: u64,
    /// People who finish on the version they started.
    pub kept: u64,
}

/// Publish a journey version
///
/// Publishes a draft of the journey's workflow with the workflow's own checks, then moves the people
/// already in it as `version_mode` says; a draft journey becomes live. Needs the journey's
/// publish role when it names one. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/journeys/{id}/publish",
    operation_id = "publish_marketing_journey",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey")),
    request_body = JourneyPublishBody,
    responses(
        (status = 200, description = "The version is live and the people are placed", body = JourneyPublishResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.update or the journey's publish role", body = ErrorResponse),
        (status = 404, description = "No such journey", body = ErrorResponse),
        (status = 409, description = "Not a draft of this journey, or another publish in progress", body = ErrorResponse),
        (status = 422, description = "The graph fails the publish checks", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Activated)])))),
)]
async fn post_publish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<JourneyUpdate>>,
    recording: attome_core::changeset::RecordingCtx,
    Path(journey): Path<Uuid>,
    Json(body): Json<JourneyPublishBody>,
) -> Result<Json<JourneyPublishResult>, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_MARKETING) {
        return Err(AppError::NotFound);
    }
    let found: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT d.id, j.publish_role FROM marketing_journey j \
           JOIN workflow_definition d ON d.logicalname = j.workflow_definition_logicalname \
          WHERE j.id = $1 AND j.is_active IS NOT FALSE AND d.kind = 'journey'",
    )
    .bind(journey)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((definition, publish_role)) = found else {
        return Err(AppError::NotFound);
    };
    if let Some(role) = publish_role
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        && !ctx.is_admin
    {
        let role_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
                .bind(role)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        let holds =
            role_id.is_some_and(|id| ctx.role_ids.as_ref().is_some_and(|ids| ids.contains(&id)));
        if !holds {
            return Err(AppError::Forbidden);
        }
    }
    crate::admin::publish_draft(&state, &ctx, &recording, definition, body.version_id).await?;
    let moved = attome_marketing::journey::versions::move_to_version(
        &state,
        definition,
        body.version_id,
        body.version_mode,
        ctx.user_id,
    )
    .await?;
    sqlx::query(
        "UPDATE marketing_journey SET status = 'live', modified_at = now(), \
             row_version = row_version + 1 \
          WHERE id = $1 AND status = 'draft'",
    )
    .bind(journey)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(JourneyPublishResult {
        journey_id: journey,
        version_id: body.version_id,
        moved: moved.moved,
        kept: moved.kept,
    }))
}

/// Most sample people one simulation takes.
pub const MAX_SAMPLE: usize = 20;

#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct JourneySimulateBody {
    /// The people to run the journey for, at most 20.
    pub sample_people: Vec<crate::model::SimulateRecordRef>,
}

/// One sample person's simulated run.
#[derive(Debug, Serialize, ToSchema)]
pub struct JourneySimulatedRun {
    pub entity: String,
    pub person_id: Uuid,
    /// `completed`, `would_wait` or `failed`.
    pub status: String,
    pub trace: Vec<crate::model::SimulateNodeTrace>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JourneySimulation {
    pub journey_id: Uuid,
    pub version_id: Uuid,
    pub runs: Vec<JourneySimulatedRun>,
}

/// Simulate a journey
///
/// Runs the journey's newest published version in memory for each sample person, their record as
/// the trigger, and returns every node's trace per person. Waits do not wait; nothing is written,
/// sent or requested.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/journeys/{id}/simulate",
    operation_id = "simulate_marketing_journey",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The journey")),
    request_body = JourneySimulateBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "D-431: the journey's graph runs in memory through the workflow simulation, which \
         may never write, send or request anything under any node type.",
    )))),
    responses(
        (status = 200, description = "Each sample person's simulated run", body = JourneySimulation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_journey.read", body = ErrorResponse),
        (status = 404, description = "No such journey, no published version, or a person the caller may not read", body = ErrorResponse),
        (status = 422, description = "No sample people, more than 20, or a graph that does not parse", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_simulate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<attome_marketing::journey::routes::JourneyRead>>,
    Path(journey): Path<Uuid>,
    Json(body): Json<JourneySimulateBody>,
) -> Result<Json<JourneySimulation>, AppError> {
    if body.sample_people.is_empty() || body.sample_people.len() > MAX_SAMPLE {
        return Err(AppError::Validation(format!(
            "send 1 to {MAX_SAMPLE} sample people"
        )));
    }
    let published: Option<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT v.id, v.graph FROM marketing_journey j \
           JOIN workflow_definition d ON d.logicalname = j.workflow_definition_logicalname \
           JOIN workflow_definition_version v ON v.definition_id = d.id \
          WHERE j.id = $1 AND j.is_active IS NOT FALSE AND d.kind = 'journey' \
            AND v.status = 'published' \
          ORDER BY v.version_number DESC LIMIT 1",
    )
    .bind(journey)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((version_id, graph_json)) = published else {
        return Err(AppError::NotFound);
    };
    let graph = crate::graph::Graph::parse(&graph_json)
        .map_err(|e| AppError::Validation(format!("graph did not parse: {e}")))?;
    let decisions = std::collections::HashMap::new();
    let mut runs = Vec::with_capacity(body.sample_people.len());
    for person in &body.sample_people {
        let payload =
            crate::simulate::with_real_record(&state, &ctx, serde_json::json!({}), person).await?;
        let module_steps = crate::simulate::dry_run_module_steps(&state, &graph, &payload).await;
        let (status, trace) = crate::simulate::run_simulation_reading(
            &state,
            &ctx,
            &graph,
            payload,
            &decisions,
            &module_steps,
        )
        .await;
        runs.push(JourneySimulatedRun {
            entity: person.entity.clone(),
            person_id: person.id,
            status,
            trace,
        });
    }
    Ok(Json(JourneySimulation {
        journey_id: journey,
        version_id,
        runs,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/journeys/{id}/pause", post(post_pause))
        .route("/api/v1/marketing/journeys/{id}/resume", post(post_resume))
        .route(
            "/api/v1/marketing/journeys/{id}/simulate",
            post(post_simulate),
        )
        .route(
            "/api/v1/marketing/journeys/{id}/publish",
            post(post_publish),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_pause, post_resume, post_simulate, post_publish),
    components(schemas(
        JourneyControlResult,
        JourneyPublishBody,
        JourneyPublishResult,
        JourneySimulateBody,
        JourneySimulatedRun,
        JourneySimulation
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
