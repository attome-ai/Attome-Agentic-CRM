//! `POST /api/v1/admin/ai/eval-suites/{suite}/cases/from-message` (roadmap
//! N23-T3): turn an answer that went wrong in production into a test case in
//! one step.
//!
//! Given an assistant message, the case's input is the person's message the
//! answer replied to (the latest user message before it in the same
//! conversation); the expectation is what the administrator says should have
//! happened (`expect`: tools, `text_matches`, `text_excludes`) and whether it
//! is a safety case. The case is appended to the suite's draft through the
//! same metadata edit path as every other change (`model_edit::edit`), so the
//! suite's own validation applies and a person publishes it.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// The longest case name.
const MAX_NAME_CHARS: usize = 200;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseFromMessage {
    /// The assistant message that went wrong.
    pub message_id: Uuid,
    /// The case's name; defaults to one naming the message.
    #[serde(default)]
    pub name: Option<String>,
    /// What should have happened: `tools`, `text_matches`, `text_excludes`.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub expect: Option<Value>,
    #[serde(default)]
    pub safety: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CaseAdded {
    pub suite_id: Uuid,
    /// The suite's draft after the case was added.
    pub version_no: i64,
    pub content_hash: String,
    pub case: Value,
}

/// The case a message becomes.
pub fn case_value(
    message_id: Uuid,
    input: &str,
    name: Option<&str>,
    expect: Option<&Value>,
    safety: bool,
) -> Result<Value, AppError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(AppError::Validation(
            "the message has no person's question before it".into(),
        ));
    }
    let name = name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("from message {message_id}"));
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(AppError::Validation(format!(
            "name is longer than {MAX_NAME_CHARS} characters"
        )));
    }
    let expect = match expect {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(value @ Value::Object(_)) => value.clone(),
        Some(_) => return Err(AppError::Validation("expect is an object".into())),
    };
    Ok(serde_json::json!({
        "name": name,
        "input": input,
        "expect": expect,
        "safety": safety,
    }))
}

/// Add an eval case from a message
///
/// Turns an answer that went wrong into a test case: the input is the person's message it replied to,
/// the expectation is what the administrator says should have happened (tools, text it must or must
/// not contain). AI administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/eval-suites/{suite}/cases/from-message",
    tag = "action",
    params(("suite" = Uuid, Path, description = "The eval suite object")),
    request_body = CaseFromMessage,
    responses(
        (status = 200, description = "The case was added to the suite's draft", body = CaseAdded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such suite or assistant message", body = ErrorResponse),
        (status = 409, description = "The suite changed while the case was being added", body = ErrorResponse),
        (status = 422, description = "No question before the message, or an invalid case", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn case_from_message(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(suite): Path<Uuid>,
    Json(body): Json<CaseFromMessage>,
) -> Result<Json<CaseAdded>, AppError> {
    let db = &state.base.db;
    let current = attome_model::store::read(db, suite, None).await?;
    if current.kind != attome_model::kinds::eval_suite::EVAL_SUITE.as_str() {
        return Err(AppError::NotFound);
    }
    let (conversation_id, ordinal): (Uuid, i64) = sqlx::query_as(
        "SELECT conversation_id, ordinal::bigint FROM ai_message \
         WHERE id = $1 AND role = 'assistant'",
    )
    .bind(body.message_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let input: Option<String> = sqlx::query_scalar(
        "SELECT content FROM ai_message \
         WHERE conversation_id = $1 AND role = 'user' AND ordinal < $2 \
         ORDER BY ordinal DESC LIMIT 1",
    )
    .bind(conversation_id)
    .bind(ordinal)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let case = case_value(
        body.message_id,
        input.as_deref().unwrap_or_default(),
        body.name.as_deref(),
        body.expect.as_ref(),
        body.safety,
    )?;

    let kind = attome_metadata::model_edit::registry()
        .get(attome_model::kinds::eval_suite::EVAL_SUITE.as_str())
        .ok_or(AppError::NotFound)?;
    let mut tx = attome_db::tx::begin(db).await?;
    let edited = attome_metadata::model_edit::edit(
        db,
        &mut tx,
        kind.as_ref(),
        attome_metadata::model_edit::EditRequest {
            id: suite,
            base_hash: current.content_hash.clone(),
            name: None,
            commands: vec![serde_json::json!({ "op": "add", "path": "/cases/-", "value": case })],
        },
        Some(ctx.user_id),
    )
    .await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            Some(suite),
        )
        .named("eval_suite.case_from_message")
        .comment(format!(
            "eval suite `{}` draft v{}: case from message {}",
            edited.name, edited.saved.version_no, body.message_id
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(CaseAdded {
        suite_id: suite,
        version_no: edited.saved.version_no,
        content_hash: edited.saved.content_hash.clone(),
        case,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/ai/eval-suites/{suite}/cases/from-message",
        post(case_from_message),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(case_from_message),
    components(schemas(CaseFromMessage, CaseAdded))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_message_becomes_a_case() {
        let id = Uuid::now_v7();
        let case = case_value(
            id,
            "  Refund my order  ",
            None,
            Some(&json!({ "text_excludes": "(?i)password" })),
            true,
        )
        .unwrap();
        assert_eq!(case["input"], "Refund my order");
        assert_eq!(case["name"], format!("from message {id}"));
        assert_eq!(case["expect"]["text_excludes"], "(?i)password");
        assert_eq!(case["safety"], true);
        let bare = case_value(id, "Hi", Some("greeting"), None, false).unwrap();
        assert_eq!(bare["expect"], json!({}));
        assert_eq!(bare["name"], "greeting");
    }

    #[test]
    fn a_case_needs_a_question_and_an_object_expectation() {
        let id = Uuid::now_v7();
        assert!(case_value(id, "  ", None, None, false).is_err());
        assert!(case_value(id, "Hi", None, Some(&json!("x")), false).is_err());
        assert!(case_value(id, "Hi", Some(&"n".repeat(201)), None, false).is_err());
    }
}
