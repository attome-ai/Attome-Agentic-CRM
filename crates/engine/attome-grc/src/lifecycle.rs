//! The two thin engine routes M20-grc.md's Phase 1 checklist names —
//! `/grc/assessments/{id}/start` and `/grc/findings/{id}/remediate`.
//! Everything else on `grc_*` entities is ordinary generic entity CRUD
//! (guidelines §9: no per-entity CRUD handler for behavior the generic
//! engine already expresses); these two exist only because a status
//! transition needs a same-record advisory lock and an audit write, which
//! generic entity `PATCH` does not provide. Same shape
//! `attome-service::clock`'s pause/resume routes use for `service_ticket`.
use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AssessmentUpdate, FindingUpdate};

/// Best-effort audit write — the state transition has already committed and
/// is correct either way; a failed audit row is logged, never turned into a
/// client-visible failure that would suggest the transition didn't happen
/// when it did. Same posture `attome-service::clock::write_audit` documents.
/// Thin wrapper over the shared `attome_audit::write_business_event` (M26 R-15
/// dedup).
async fn write_audit(
    state: &EngineState,
    actor: Uuid,
    entity_name: &str,
    record_id: Uuid,
    event_name: &str,
    comment: String,
) {
    attome_audit::write_business_event(
        state,
        entity_name,
        record_id,
        AuditOperation::Update,
        event_name,
        actor,
        None,
        None,
        comment,
    )
    .await;
}

/// Advisory-locks a single record before read-modify-write, so two
/// concurrent transition requests for the same record serialize instead of
/// both reading the same pre-transition state — same "lock, then act" order
/// `attome-service::clock::lock_ticket` uses.
async fn lock_record(tx: &mut Transaction<'_, Postgres>, key: &str) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another lifecycle transition for this record is already in progress",
        ));
    }
    Ok(())
}

// ── Assessment: start ──────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct AssessmentStartResponse {
    pub id: Uuid,
    pub status: String,
    pub started_at: DateTime<Utc>,
}

/// Transitions an assessment from `planned` to `in_progress`. Idempotent on
/// an already-started (or already-completed/cancelled) assessment: the
/// current status is returned unchanged rather than erroring, the same
/// "second call is a no-op, not a conflict" posture
/// `attome-service::clock::resume_ticket` uses for an already-running clock.
pub async fn start_assessment(
    db: &DbPool,
    assessment_id: Uuid,
) -> Result<AssessmentStartResponse, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_record(&mut tx, &format!("attome-grc/assessment:{assessment_id}")).await?;

    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM grc_assessment WHERE id = $1")
            .bind(assessment_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let status = status.ok_or(AppError::NotFound)?;

    if status != "planned" {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(AssessmentStartResponse {
            id: assessment_id,
            status,
            started_at: Utc::now(),
        });
    }

    let now = Utc::now();
    let updated = sqlx::query(
        "UPDATE grc_assessment SET status = 'in_progress' \
         WHERE id = $1 AND status = 'planned'",
    )
    .bind(assessment_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::internal(
            "assessment row vanished or changed status between read and update",
        ));
    }

    tx.commit().await.map_err(AppError::internal)?;

    Ok(AssessmentStartResponse {
        id: assessment_id,
        status: "in_progress".to_string(),
        started_at: now,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/grc/assessments/{id}/start",
    tag = "grc",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Assessment started (or already past `planned`)", body = AssessmentStartResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such assessment", body = ErrorResponse),
        (status = 409, description = "Another lifecycle transition for this assessment is already in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn start_assessment_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<AssessmentUpdate>>,
    Path(assessment_id): Path<Uuid>,
) -> Result<Json<AssessmentStartResponse>, AppError> {
    let actor = ctx.user_id;
    let response = start_assessment(&state.base.db, assessment_id).await?;
    if response.status == "in_progress" {
        write_audit(
            &state,
            actor,
            "grc_assessment",
            assessment_id,
            "grc_assessment.started",
            "Assessment moved to in_progress".to_string(),
        )
        .await;
    }
    Ok(Json(response))
}

// ── Finding: remediate ─────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingRemediateResponse {
    pub id: Uuid,
    pub status: String,
    pub remediated_at: DateTime<Utc>,
}

/// Transitions a finding to `remediated`. Idempotent on an already-
/// remediated/accepted/closed finding, same posture as
/// [`start_assessment`] above.
pub async fn remediate_finding(
    db: &DbPool,
    finding_id: Uuid,
) -> Result<FindingRemediateResponse, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    lock_record(&mut tx, &format!("attome-grc/finding:{finding_id}")).await?;

    let status: Option<String> = sqlx::query_scalar("SELECT status FROM grc_finding WHERE id = $1")
        .bind(finding_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let status = status.ok_or(AppError::NotFound)?;

    if matches!(status.as_str(), "remediated" | "accepted_risk" | "closed") {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(FindingRemediateResponse {
            id: finding_id,
            status,
            remediated_at: Utc::now(),
        });
    }

    let now = Utc::now();
    let updated = sqlx::query(
        "UPDATE grc_finding SET status = 'remediated' \
         WHERE id = $1 AND status IN ('open', 'in_progress')",
    )
    .bind(finding_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::internal(
            "finding row vanished or changed status between read and update",
        ));
    }

    tx.commit().await.map_err(AppError::internal)?;

    Ok(FindingRemediateResponse {
        id: finding_id,
        status: "remediated".to_string(),
        remediated_at: now,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/grc/findings/{id}/remediate",
    tag = "grc",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Finding remediated (or already past open/in_progress)", body = FindingRemediateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such finding", body = ErrorResponse),
        (status = 409, description = "Another lifecycle transition for this finding is already in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn remediate_finding_route(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FindingUpdate>>,
    Path(finding_id): Path<Uuid>,
) -> Result<Json<FindingRemediateResponse>, AppError> {
    let actor = ctx.user_id;
    let response = remediate_finding(&state.base.db, finding_id).await?;
    if response.status == "remediated" {
        write_audit(
            &state,
            actor,
            "grc_finding",
            finding_id,
            "grc_finding.remediated",
            "Finding marked remediated".to_string(),
        )
        .await;
    }
    Ok(Json(response))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/grc/assessments/{id}/start",
            post(start_assessment_route),
        )
        .route(
            "/api/v1/grc/findings/{id}/remediate",
            post(remediate_finding_route),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(start_assessment_route, remediate_finding_route))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
