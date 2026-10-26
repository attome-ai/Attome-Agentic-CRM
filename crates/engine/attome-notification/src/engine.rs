//! `EngineModel` registration for the Notification Engine (P2.11). Kept out of
//! `model.rs` because that file holds the bell-icon `Notification` types,
//! while this module owns the durable multi-channel dispatch API.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_NOTIFICATION, ModuleId};
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::Serialize;
use uuid::Uuid;

use crate::dispatch::{self, DispatchRequest};
use attome_types::ErrorResponse;
use utoipa::ToSchema;

/// Registered via `EngineSystem::builder(state).register(NotificationModel)` —
/// only mounted when `notification` is a licensed module bit (D-010). The
/// always-on bell routes use the same recipient table, so licensing the send
/// engine cannot change inbox authorization.
#[derive(Debug)]
pub struct NotificationModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for NotificationModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-notification"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_NOTIFICATION
    }

    /// D-383 — the one entity `crate::seed` provisions.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["notification_template"]
    }

    fn routes(&self) -> Router<EngineState> {
        Router::new().route("/api/v1/notification/dispatch", post(create_dispatch))
    }
}

#[derive(Serialize, ToSchema)]
struct DispatchCreated {
    id: Uuid,
}

/// Manually triggers a multi-channel notification (F163/F164/F172). This is
/// the direct-API-call path F165 leans on until Workflow Engine ships and
/// can call it automatically post-event (see `crate::dispatch`'s module
/// doc). Admin-gated for now, same reasoning as the other engine admin
/// surfaces (`s2s_admin.rs`/`license_admin.rs`) — there is no finer-grained
/// "who may send a notification" privilege model yet.
#[utoipa::path(
    post,
    path = "/api/v1/notification/dispatch",
    tag = "notification",
    request_body = DispatchRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = DispatchCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_dispatch(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<DispatchRequest>,
) -> Result<(StatusCode, Json<DispatchCreated>), AppError> {
    let id =
        dispatch::create_dispatch(&state.base.db, &state.base.config.notification, body).await?;
    // Non-mandatory BusinessEvent; `create_dispatch` manages its own writes
    // internally with no transaction to join, so this is a fire-and-forget
    // write after success (same posture as workflow instance start).
    attome_audit::write_business_event(
        &state,
        "notification_dispatch",
        id,
        attome_audit::AuditOperation::Create,
        "notification.dispatch",
        ctx.user_id,
        None,
        None,
        "manual multi-channel notification dispatch".to_string(),
    )
    .await;
    Ok((StatusCode::CREATED, Json(DispatchCreated { id })))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(create_dispatch))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
