//! Z13-T7: try a template against a real record before using it.
//! `POST /api/v1/admin/templates/preview` reads the record through the
//! ordinary read path, so the template sees only what the caller may read;
//! compiles the template against the entity's fields; renders it; and
//! warns about every field the template names that the caller cannot read
//! (it renders as empty). A field the entity does not have, or a syntax
//! error, is a 422 naming the line and column.
//!
//! A template meant for outside recipients will see only attributes marked
//! shareable once A1's data labels exist; until then the preview shows what
//! the caller can read.

use attome_core::EngineState;
use attome_html::tmpl::{Output, RenderContext, Template};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The output a preview renders.
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreviewOutput {
    #[default]
    Html,
    Text,
}

/// `POST /api/v1/admin/templates/preview`'s body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewRequest {
    /// The template source.
    pub template: String,
    /// The record's entity (logical name).
    pub entity: String,
    pub record_id: Uuid,
    /// The render's locale, e.g. `ar-SA`; the deployment's when unset.
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub output: PreviewOutput,
}

/// One field the template names that rendered empty for this caller.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewWarning {
    pub field: String,
    /// `unreadable`: the caller may not read it on this record.
    pub reason: &'static str,
}

/// The rendered preview.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewResponse {
    pub rendered: String,
    pub warnings: Vec<PreviewWarning>,
}

/// Whether `source` names `field` as a whole word.
fn mentions(source: &str, field: &str) -> bool {
    let bytes = source.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    source.match_indices(field).any(|(at, _)| {
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(at + field.len()).copied();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/templates/preview",
    tag = "docgen",
    request_body = PreviewRequest,
    responses(
        (status = 200, description = "The rendered template and the fields that rendered empty", body = PreviewResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller may not read it", body = ErrorResponse),
        (status = 422, description = "The template does not compile or render; the message names where", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::DryRun, None, "renders a preview; writes nothing")))),
)]
pub(crate) async fn preview_template(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Communication>>,
    Json(body): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, AppError> {
    let (_, entity_name, attrs, _) =
        attome_records::entity_crud::resolve_entity(&state, &body.entity).await?;
    let record =
        attome_records::entity_crud::read_record(&state, &ctx, &entity_name, body.record_id)
            .await?;
    let data = record.data().as_object().cloned().unwrap_or_default();

    let schema = attome_records::rule_engine::schema_for_entity(&attrs);
    let template = Template::compile(&body.template, &schema)
        .map_err(|e| AppError::Validation(format!("{}: {e}", e.code())))?;
    let values = attome_records::rule_engine::context_for_record(chrono::Utc::now(), &attrs, &data);
    let locale = body
        .language
        .clone()
        .unwrap_or_else(|| state.deployment_locale());
    let output = match body.output {
        PreviewOutput::Html => Output::Html,
        PreviewOutput::Text => Output::Text,
    };
    let rendered = template
        .render(&RenderContext::new(values, locale, output))
        .map_err(|e| AppError::Validation(format!("{}: {e}", e.code())))?;

    let warnings = attrs
        .iter()
        .filter(|attr| !data.contains_key(&attr.logicalname))
        .filter(|attr| mentions(&body.template, &attr.logicalname))
        .map(|attr| PreviewWarning {
            field: attr.logicalname.clone(),
            reason: "unreadable",
        })
        .collect();
    Ok(Json(PreviewResponse { rendered, warnings }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/templates/preview", post(preview_template))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(preview_template))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_is_mentioned_only_as_a_whole_word() {
        let source = "Dear {{ name }}, your {{ salary | number(0) }} is due";
        assert!(mentions(source, "name"));
        assert!(mentions(source, "salary"));
        assert!(!mentions(source, "sal"));
        assert!(!mentions("{{ full_name }}", "name"));
    }
}
