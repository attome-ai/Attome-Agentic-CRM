//! `/api/v1/admin/expressions` (roadmap Z11-T12): what an expression editor
//! and an agent need to write rule-language expressions. `validate` checks
//! one expression against an entity (`attome_records::expression_check`, the
//! function the `expression.validate` agent tool calls too) and writes
//! nothing; `spec` is the language's built-in functions and grammar notes
//! for a version. Administrators only.

use std::sync::OnceLock;

use attome_core::EngineState;
use attome_records::expression_check::{ExpressionCheck, check_expression};
use attome_rules::LanguageVersion;
use attome_rules::catalog::{FunctionSpec, GRAMMAR_NOTES, catalog};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
struct ValidateExpressionRequest {
    /// The expression text.
    expression: String,
    /// The entity's logical name; its fields are the expression's fields.
    entity: String,
    /// `v1` or `v2`; absent means the latest.
    #[serde(default)]
    language_version: Option<String>,
    /// A record of `entity` to evaluate the expression on; the response then
    /// carries its value and evaluation trace. The record is read as the
    /// caller.
    #[serde(default)]
    sample_record_id: Option<Uuid>,
}

fn language_version(raw: Option<&str>) -> Result<LanguageVersion, AppError> {
    match raw {
        None => Ok(LanguageVersion::LATEST),
        Some(v) => LanguageVersion::parse(v)
            .ok_or_else(|| AppError::Validation(format!("unknown language version '{v}'"))),
    }
}

/// Validate an expression
///
/// Checks an expression against an entity: its result type or each error
/// with its byte span, whether it runs in the database, and for a sample
/// record its value and evaluation trace. Writes nothing. Administrators
/// only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/expressions/validate",
    tag = "admin",
    request_body = ValidateExpressionRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "read-only validation: compiles and optionally evaluates an expression; writes nothing")))),
    responses(
        (status = 200, description = "What the check found", body = ExpressionCheck),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or cannot read the sample record", body = ErrorResponse),
        (status = 404, description = "No such entity or sample record", body = ErrorResponse),
        (status = 422, description = "Unknown language version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn validate_expression(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Json(body): Json<ValidateExpressionRequest>,
) -> Result<Json<ExpressionCheck>, AppError> {
    let version = language_version(body.language_version.as_deref())?;
    let check = check_expression(
        &state,
        &ctx,
        &body.expression,
        &body.entity,
        version,
        body.sample_record_id,
    )
    .await?;
    Ok(Json(check))
}

#[derive(Deserialize, IntoParams)]
struct SpecQuery {
    /// `v1` or `v2`; absent means the latest.
    version: Option<String>,
}

#[derive(Serialize, ToSchema, Clone)]
pub(crate) struct FunctionParamWire {
    name: &'static str,
    #[serde(rename = "type")]
    ty: &'static str,
}

#[derive(Serialize, ToSchema, Clone)]
pub(crate) struct FunctionSpecWire {
    name: &'static str,
    params: Vec<FunctionParamWire>,
    returns: &'static str,
    description_en: &'static str,
    description_ar: &'static str,
    example: &'static str,
    /// The language version that added it.
    since: &'static str,
}

impl From<&FunctionSpec> for FunctionSpecWire {
    fn from(spec: &FunctionSpec) -> Self {
        Self {
            name: spec.name,
            params: spec
                .params
                .iter()
                .map(|(name, ty)| FunctionParamWire { name, ty })
                .collect(),
            returns: spec.returns,
            description_en: spec.description_en,
            description_ar: spec.description_ar,
            example: spec.example,
            since: spec.since.as_str(),
        }
    }
}

#[derive(Serialize, ToSchema, Clone)]
pub(crate) struct ExpressionSpec {
    version: &'static str,
    functions: Vec<FunctionSpecWire>,
    grammar: Vec<&'static str>,
}

/// The spec for `version`, built once per version: it is static data.
pub(crate) fn spec(version: LanguageVersion) -> &'static ExpressionSpec {
    static V1: OnceLock<ExpressionSpec> = OnceLock::new();
    static V2: OnceLock<ExpressionSpec> = OnceLock::new();
    let cell = match version {
        LanguageVersion::V1 => &V1,
        LanguageVersion::V2 => &V2,
    };
    cell.get_or_init(|| ExpressionSpec {
        version: version.as_str(),
        functions: catalog(version)
            .iter()
            .map(FunctionSpecWire::from)
            .collect(),
        grammar: GRAMMAR_NOTES.to_vec(),
    })
}

/// Expression language spec
///
/// The built-in functions of a language version (parameters, result type,
/// English and Arabic descriptions, an example) and notes on the grammar.
/// Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/expressions/spec",
    tag = "admin",
    params(SpecQuery),
    responses(
        (status = 200, description = "The functions and grammar notes", body = ExpressionSpec),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Unknown language version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn expression_spec(
    _ctx: Authorized<Privilege<area::Automation>>,
    Query(q): Query<SpecQuery>,
) -> Result<Json<ExpressionSpec>, AppError> {
    let version = language_version(q.version.as_deref())?;
    Ok(Json(spec(version).clone()))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/expressions/validate",
            post(validate_expression),
        )
        .route("/api/v1/admin/expressions/spec", get(expression_spec))
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(validate_expression, expression_spec))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_is_per_version() {
        let v1 = spec(LanguageVersion::V1);
        let v2 = spec(LanguageVersion::V2);
        assert_eq!(v1.version, "v1");
        assert!(v2.functions.len() > v1.functions.len());
        assert!(v2.functions.iter().any(|f| f.name == "normalize_ar"));
        assert!(!v1.functions.iter().any(|f| f.name == "normalize_ar"));
    }

    #[test]
    fn unknown_version_is_refused() {
        assert!(language_version(Some("v9")).is_err());
        assert_eq!(language_version(None).unwrap(), LanguageVersion::LATEST);
    }
}
