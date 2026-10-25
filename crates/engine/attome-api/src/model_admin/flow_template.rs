//! M6-T4: a flow template filled in with its arguments
//! (`POST /api/v1/admin/model/flow_template/{id}/instantiate`).
//!
//! Reads the template's newest published version, replaces its
//! placeholders (`attome_model::kinds::flow_template::instantiate`, which
//! refuses missing, unknown and ill-typed arguments) and answers the graph.
//! It writes nothing: the caller saves the graph as a new flow's draft
//! through `POST /api/v1/workflow/definitions` and `.../versions`, which
//! record into the open changeset and validate the draft like any other.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use super::IssueView;

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct InstantiateRequest {
    /// The template's arguments by parameter name.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub args: Map<String, Value>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct InstantiateResponse {
    pub template_id: Uuid,
    pub template_name: String,
    /// The filled graph; empty when `issues` is not.
    #[schema(value_type = Object)]
    pub graph: Value,
    /// Why the arguments do not fit, by argument path.
    pub issues: Vec<IssueView>,
}

/// Create a flow from a template
///
/// Create a flow from a template. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/flow_template/{id}/instantiate",
    tag = "admin",
    operation_id = "model_flow_template_instantiate",
    description = "Fills a published flow template with its arguments and answers the graph, or the arguments' issues (M6-T4). Writes nothing; save the graph as a new flow's draft.",
    params(("id" = Uuid, Path, description = "The flow template")),
    request_body = InstantiateRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "M6-T4: computes a graph from a published template; nothing is stored.",
    )))),
    responses(
        (status = 200, description = "The filled graph, or why the arguments do not fit", body = InstantiateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No published flow template with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn instantiate(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<InstantiateRequest>,
) -> Result<Json<InstantiateResponse>, AppError> {
    let published = attome_model::store::read_published(&state.base.db, id).await?;
    if published.kind != attome_model::kinds::FLOW_TEMPLATE.0 {
        return Err(AppError::NotFound);
    }
    let (graph, issues) =
        match attome_model::kinds::flow_template::instantiate(&published.doc, &body.args) {
            Ok(graph) => (graph, Vec::new()),
            Err(issues) => (Value::Null, issues.iter().map(IssueView::from).collect()),
        };
    Ok(Json(InstantiateResponse {
        template_id: id,
        template_name: published.name,
        graph,
        issues,
    }))
}
