//! M16-T3: recording RPA steps by showing. The flow editor drives a live
//! page in the browser service (`deploy/rpa-browser`, its `/record` API)
//! through these routes: it shows the page's screenshot, sends the clicks,
//! text and keys the builder makes on it, and appends the step each one
//! answers. The service's address and token come from the integration
//! system, as for the `integration.rpa` step; nothing here is stored.
//!
//! A value typed into a password field is typed into the page but recorded
//! as `{{secret:password}}`, so a recording never puts a password in a flow.

use std::time::Duration;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::rpa::{Service, call_service_at, service_for};

/// How long one recorder call may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Where a recording starts.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartRecording {
    pub url: String,
    pub allowed_hosts: Vec<String>,
}

/// One thing done on the recorded page: a click at `x`, `y` (pixels of the
/// 1280 x 800 view), `text` typed into the last clicked field, or `key`
/// pressed there.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordAction {
    pub action: String,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub text: Option<String>,
    pub key: Option<String>,
}

/// The step recorded and the page as it now looks.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordFrame {
    /// The recording, on its start.
    pub session: Option<Uuid>,
    /// The step, as the `integration.rpa` step list takes it.
    #[schema(value_type = Object)]
    pub step: Value,
    /// Whether the clicked field is a password field.
    pub password: bool,
    /// The page's screenshot, PNG.
    pub png_base64: String,
}

async fn service(state: &EngineState, system: &str) -> Result<Service, AppError> {
    service_for(state, system).await?.ok_or(AppError::NotFound)
}

fn frame(answer: Value) -> Result<RecordFrame, AppError> {
    let png_base64 = answer["png_base64"]
        .as_str()
        .ok_or_else(|| AppError::internal("the browser service sent no screenshot"))?
        .to_owned();
    Ok(RecordFrame {
        session: answer["session"].as_str().and_then(|s| s.parse().ok()),
        step: answer["step"].clone(),
        password: answer["password"].as_bool().unwrap_or(false),
        png_base64,
    })
}

/// The body the service takes for `action`, or why there is none. Pure.
pub fn action_body(action: &RecordAction) -> Result<Value, String> {
    match action.action.as_str() {
        "click" => match (action.x, action.y) {
            (Some(x), Some(y)) => Ok(json!({ "x": x, "y": y })),
            _ => Err("a click needs x and y".into()),
        },
        "type" => action
            .text
            .as_ref()
            .map(|t| json!({ "text": t }))
            .ok_or_else(|| "type needs text".into()),
        "press" => Ok(json!({ "key": action.key.as_deref().unwrap_or("Enter") })),
        _ => Err("action is click, type or press".into()),
    }
}

fn refused(reason: String) -> AppError {
    tracing::info!(%reason, "rpa recorder call refused");
    AppError::Validation(reason)
}

/// Start an RPA recording
///
/// M16-T3: opens a live page at `url` in the system's browser service,
/// held to `allowed_hosts`, and answers its first frame.
#[utoipa::path(
    post,
    path = "/api/v1/admin/integrations/rpa/{system}/record",
    operation_id = "start_rpa_recording",
    tag = "admin",
    params(("system" = String, Path, description = "The integration system of the browser service")),
    request_body = StartRecording,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "opens a page in the browser service for the editor; stores nothing"
    )))),
    responses(
        (status = 200, description = "The recording's first frame", body = RecordFrame),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No active integration system of that name", body = ErrorResponse),
        (status = 422, description = "The service refused the start", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Integrations>>,
    Path(system): Path<String>,
    Json(body): Json<StartRecording>,
) -> Result<Json<RecordFrame>, AppError> {
    let service = service(&state, &system).await?;
    let answer = call_service_at(
        &service.base_url,
        &service.token,
        "/record",
        Some(&json!({ "url": body.url, "allowed_hosts": body.allowed_hosts })),
        CALL_TIMEOUT,
    )
    .await
    .map_err(refused)?;
    frame(answer).map(Json)
}

/// Act on an RPA recording
///
/// M16-T3: a click, typed text or a key on the recorded page; answers the
/// step it recorded and the next frame.
#[utoipa::path(
    post,
    path = "/api/v1/admin/integrations/rpa/{system}/record/{session}",
    operation_id = "act_on_rpa_recording",
    tag = "admin",
    params(
        ("system" = String, Path, description = "The integration system of the browser service"),
        ("session" = Uuid, Path, description = "The recording"),
    ),
    request_body = RecordAction,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "drives the editor's page in the browser service; stores nothing"
    )))),
    responses(
        (status = 200, description = "The step and the next frame", body = RecordFrame),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No active integration system of that name", body = ErrorResponse),
        (status = 422, description = "A bad action, or the service refused it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn act(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Integrations>>,
    Path((system, session)): Path<(String, Uuid)>,
    Json(body): Json<RecordAction>,
) -> Result<Json<RecordFrame>, AppError> {
    let payload = action_body(&body).map_err(AppError::Validation)?;
    let service = service(&state, &system).await?;
    let answer = call_service_at(
        &service.base_url,
        &service.token,
        &format!("/record/{session}/{}", body.action),
        Some(&payload),
        CALL_TIMEOUT,
    )
    .await
    .map_err(refused)?;
    frame(answer).map(Json)
}

/// Stop an RPA recording
///
/// M16-T3: closes the recorded page.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/integrations/rpa/{system}/record/{session}",
    operation_id = "stop_rpa_recording",
    tag = "admin",
    params(
        ("system" = String, Path, description = "The integration system of the browser service"),
        ("session" = Uuid, Path, description = "The recording"),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "closes the editor's page in the browser service; stores nothing"
    )))),
    responses(
        (status = 204, description = "Closed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No active integration system of that name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn stop(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Integrations>>,
    Path((system, session)): Path<(String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let service = service(&state, &system).await?;
    call_service_at(
        &service.base_url,
        &service.token,
        &format!("/record/{session}"),
        None,
        CALL_TIMEOUT,
    )
    .await
    .map_err(refused)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/integrations/rpa/{system}/record",
            post(start),
        )
        .route(
            "/api/v1/admin/integrations/rpa/{system}/record/{session}",
            post(act).delete(stop),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(start, act, stop),
    components(schemas(StartRecording, RecordAction, RecordFrame))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(action: &str) -> RecordAction {
        RecordAction {
            action: action.into(),
            x: None,
            y: None,
            text: None,
            key: None,
        }
    }

    #[test]
    fn recorder_actions_become_service_bodies() {
        let click = RecordAction {
            x: Some(10.0),
            y: Some(20.5),
            ..action("click")
        };
        assert_eq!(action_body(&click), Ok(json!({ "x": 10.0, "y": 20.5 })));
        assert!(action_body(&action("click")).is_err());
        let typed = RecordAction {
            text: Some("ACME-1".into()),
            ..action("type")
        };
        assert_eq!(action_body(&typed), Ok(json!({ "text": "ACME-1" })));
        assert_eq!(action_body(&action("press")), Ok(json!({ "key": "Enter" })));
        assert!(action_body(&action("scroll")).is_err());
    }
}
