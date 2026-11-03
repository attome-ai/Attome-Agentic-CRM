//! P5-T1 step 2: personal dashboards. A dashboard whose `visibility` is
//! `private` is its owner's alone: only the owner (or an administrator) may
//! read or change it (`access::require_dashboard_access`), and the owner
//! saves it straight through, without review or the four-eyes gate, by
//! publishing the working copy (`publish-personal`). Sharing it (`share`, to
//! `team`, `organization` or `public`) clears its published version and
//! returns the working copy to draft, so a shared dashboard goes through the
//! review and publish lifecycle like any other.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::require_dashboard_access;
use crate::auth::DashboardUpdate;

/// The visibility of a personal dashboard.
pub const PERSONAL: &str = "private";

/// The visibilities a dashboard can be shared at.
pub const SHARED: [&str; 3] = ["team", "organization", "public"];

/// Whether `visibility` may be shared to. Pure.
pub fn shareable(visibility: &str) -> bool {
    SHARED.contains(&visibility)
}

/// Body of both routes: the dashboard's row version the caller holds.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PersonalBody {
    pub row_version: i64,
    /// `share` only: `team`, `organization` or `public`.
    #[serde(default)]
    pub visibility: Option<String>,
}

/// What a personal publish or a share did.
#[derive(Debug, Serialize, ToSchema)]
pub struct PersonalResponse {
    pub id: Uuid,
    pub lifecycle_status: String,
    pub visibility: String,
    pub row_version: i64,
    /// The version viewers now see; none after a share.
    pub version_id: Option<Uuid>,
}

/// The owner's personal dashboard, or why not.
async fn require_personal(state: &EngineState, id: Uuid, user: Uuid) -> Result<(), AppError> {
    let row: Option<(Option<String>, Option<Uuid>)> =
        sqlx::query_as("SELECT visibility, owner_id FROM attome_dashboard WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (visibility, owner) = row.ok_or(AppError::NotFound)?;
    if visibility.as_deref() != Some(PERSONAL) || owner != Some(user) {
        return Err(AppError::Conflict(
            "only its owner's personal (private) dashboard is saved directly; share it to publish through review",
        ));
    }
    Ok(())
}

/// Publish a personal dashboard
///
/// P5-T1: the owner of a `private` dashboard publishes its working copy at once, without review or
/// the four-eyes gate (the dashboard health gate still applies), so the owner sees it as saved. Only
/// its owner. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/publish-personal",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Activated)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The dashboard")),
    request_body = PersonalBody,
    responses(
        (status = 200, description = "Published", body = PersonalResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not the caller's personal dashboard, archived, or row_version is stale", body = ErrorResponse),
        (status = 422, description = "The dashboard health gate refuses it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish_personal(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<PersonalBody>,
) -> Result<Json<PersonalResponse>, AppError> {
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    require_personal(&state, id, ctx.user_id).await?;
    let gate = crate::publish_gate::do_publish_gate(&state, id).await?;
    if !gate.publishable() {
        return Err(gate.refusal());
    }
    // A personal dashboard skips review: its working copy is approved by
    // its owner, then published through the ordinary publish.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::lifecycle::lock_dashboard(&mut tx, id).await?;
    let approved: Option<i64> = sqlx::query_scalar(
        "UPDATE attome_dashboard SET lifecycle_status = 'approved', modified_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 AND visibility = 'private' AND owner_id = $3 \
            AND lifecycle_status IN ('draft', 'review', 'approved', 'published') \
          RETURNING row_version",
    )
    .bind(id)
    .bind(body.row_version)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(approved) = approved else {
        return Err(AppError::Conflict(
            "row_version does not match the dashboard's current state, or it is archived — reload and retry",
        ));
    };
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            id,
            AuditOperation::Approved,
            "dashboard.approve_personal",
            ctx.user_id,
        )
        .versions(Some(body.row_version), Some(approved))
        .comment("a personal dashboard approved by its owner".to_owned()),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    let (row_version, version_id, _) =
        crate::lifecycle::do_publish_dashboard(&state, id, approved, ctx.user_id).await?;
    Ok(Json(PersonalResponse {
        id,
        lifecycle_status: "published".to_owned(),
        visibility: PERSONAL.to_owned(),
        row_version,
        version_id: Some(version_id),
    }))
}

/// Share a personal dashboard
///
/// P5-T1: the owner makes a `private` dashboard `team`, `organization` or `public`. Its published
/// version is cleared and its working copy returns to draft, so what others see goes through review
/// and publish. Only its owner. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/{id}/share",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    tag = "dashboard",
    params(("id" = Uuid, Path, description = "The dashboard")),
    request_body = PersonalBody,
    responses(
        (status = 200, description = "Shared, as a draft", body = PersonalResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such dashboard", body = ErrorResponse),
        (status = 409, description = "Not the caller's personal dashboard, or row_version is stale", body = ErrorResponse),
        (status = 422, description = "visibility is not team, organization or public", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn share(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DashboardUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<PersonalBody>,
) -> Result<Json<PersonalResponse>, AppError> {
    let visibility = body.visibility.as_deref().unwrap_or("");
    if !shareable(visibility) {
        return Err(AppError::Validation(format!(
            "visibility is one of {}",
            SHARED.join(", ")
        )));
    }
    require_dashboard_access(&state, &ctx, id, RecordAction::Update).await?;
    require_personal(&state, id, ctx.user_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::lifecycle::lock_dashboard(&mut tx, id).await?;
    let row_version: Option<i64> = sqlx::query_scalar(
        "UPDATE attome_dashboard SET visibility = $4, lifecycle_status = 'draft', \
                published_version_id = NULL, modified_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 AND visibility = 'private' AND owner_id = $3 \
            AND lifecycle_status <> 'archived' \
          RETURNING row_version",
    )
    .bind(id)
    .bind(body.row_version)
    .bind(ctx.user_id)
    .bind(visibility)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row_version) = row_version else {
        return Err(AppError::Conflict(
            "row_version does not match the dashboard's current state, or it is archived — reload and retry",
        ));
    };
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "attome_dashboard",
            id,
            AuditOperation::Update,
            "dashboard.share",
            ctx.user_id,
        )
        .versions(Some(body.row_version), Some(row_version))
        .comment(format!(
            "a personal dashboard shared as {visibility}; back to draft"
        )),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(PersonalResponse {
        id,
        lifecycle_status: "draft".to_owned(),
        visibility: visibility.to_owned(),
        row_version,
        version_id: None,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/attome-dashboard/{id}/publish-personal",
            post(publish_personal),
        )
        .route("/api/v1/attome-dashboard/{id}/share", post(share))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(publish_personal, share))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_dashboards_share_only_to_the_shared_visibilities() {
        assert!(shareable("team") && shareable("organization") && shareable("public"));
        assert!(!shareable(PERSONAL));
        assert!(!shareable("everyone"));
    }
}
