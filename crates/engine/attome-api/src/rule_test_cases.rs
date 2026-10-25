//! A11-T4: a business rule's test cases, run at publish.
//!
//! A test case is an example record and what the rule must do with it:
//! `expect: pass` (the rule refuses nothing) or `expect: fail` (the rule
//! raises at least one error), and optionally the values its `set_value`
//! policies must produce. Cases are evaluated the way `.../{id}/test`
//! evaluates one record (in memory, no save), as every audience the rule
//! applies to. `POST .../{id}/publish` runs them all and refuses the publish
//! (422) naming each case that does not hold.
//!
//! - `GET /api/v1/admin/business-rules/{id}/test-cases` lists them;
//! - `POST /api/v1/admin/business-rules/{id}/test-cases` adds one (a name
//!   unique per rule);
//! - `DELETE /api/v1/admin/business-rules/{id}/test-cases/{case_id}`
//!   removes one.
//!
//! Cases live beside the rule (`rule_test_case`, migration 0260), not in its
//! definition: they do not yet travel in bundles or changesets. Conflicts
//! between rules are the other half of A11-T4 (`rule_admin::conflict_issues`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::business_rules::BUSINESS_KIND;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most test cases one rule carries.
pub const MAX_CASES: i64 = 100;

/// One test case.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow, ToSchema)]
pub struct RuleTestCase {
    pub id: Uuid,
    pub rule_ref: Uuid,
    pub name: String,
    /// The example record, attribute to value.
    #[schema(value_type = Object)]
    pub record: Value,
    /// `pass` or `fail`.
    pub expect: String,
    /// The values the rule's `set_value` policies must produce.
    #[schema(value_type = Option<Object>)]
    pub set_values: Option<Value>,
}

/// A new test case.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RuleTestCaseBody {
    pub name: String,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub record: Map<String, Value>,
    /// `pass` or `fail`.
    pub expect: String,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub set_values: Option<Map<String, Value>>,
}

/// Checks a new case's shape. Pure.
pub fn check_body(body: &RuleTestCaseBody) -> Result<(), AppError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation(
            "a test case's name is 1 to 200 characters".into(),
        ));
    }
    if !matches!(body.expect.as_str(), "pass" | "fail") {
        return Err(AppError::Validation("expect is pass or fail".into()));
    }
    if body.expect == "fail" && body.set_values.as_ref().is_some_and(|v| !v.is_empty()) {
        return Err(AppError::Validation(
            "a case that expects the rule to refuse the save checks no set values".into(),
        ));
    }
    Ok(())
}

/// What one evaluation of a case answered.
#[derive(Debug, Default)]
pub struct CaseRun {
    /// The messages of the errors the rule raised.
    pub errors: Vec<String>,
    pub set_values: Map<String, Value>,
    /// The rule could not be evaluated on the record.
    pub error: Option<String>,
}

/// Why `case` does not hold given what the rule did, or `None` when it
/// holds. Pure.
pub fn judge(case: &RuleTestCase, run: &CaseRun) -> Option<String> {
    let name = &case.name;
    if let Some(error) = &run.error {
        return Some(format!(
            "'{name}': the rule could not be evaluated: {error}"
        ));
    }
    match (case.expect.as_str(), run.errors.is_empty()) {
        ("pass", false) => {
            return Some(format!(
                "'{name}': expected the save to pass; the rule refused it ({})",
                run.errors.join("; ")
            ));
        }
        ("fail", true) => {
            return Some(format!(
                "'{name}': expected the rule to refuse the save; it passed"
            ));
        }
        _ => {}
    }
    let expected = case.set_values.as_ref().and_then(Value::as_object)?;
    for (field, want) in expected {
        let got = run.set_values.get(field);
        if got != Some(want) {
            return Some(format!(
                "'{name}': expected {field} = {want}, the rule set {}",
                got.map_or_else(|| "nothing".to_owned(), Value::to_string)
            ));
        }
    }
    None
}

/// A rule's test cases, in name order.
pub async fn cases_of(state: &EngineState, rule: Uuid) -> Result<Vec<RuleTestCase>, AppError> {
    sqlx::query_as(
        "SELECT id, rule_ref, name, record, expect, set_values FROM rule_test_case \
          WHERE rule_ref = $1 ORDER BY name, id LIMIT $2",
    )
    .bind(rule)
    .bind(MAX_CASES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn business_rule_or_404(state: &EngineState, id: Uuid) -> Result<(), AppError> {
    let kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM rule WHERE id = $1 AND is_deleted = false")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match kind {
        None => Err(AppError::NotFound),
        Some(kind) if kind != BUSINESS_KIND => Err(AppError::Validation(
            "test cases belong to business rules".into(),
        )),
        Some(_) => Ok(()),
    }
}

fn event(operation: AuditOperation, actor: Uuid, rule: Uuid, name: &'static str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "rule",
        Some(rule),
    )
    .named(name)
}

/// List a rule's test cases
///
/// A11-T4: the example records and expected outcomes the rule's publish
/// runs. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/business-rules/{id}/test-cases",
    tag = "admin",
    operation_id = "list_rule_test_cases",
    params(("id" = Uuid, Path, description = "The business rule")),
    responses(
        (status = 200, description = "The rule's test cases, at most 100", body = PaginatedResponse<RuleTestCase>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 422, description = "The rule is not a business rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_cases(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<RuleTestCase>>, AppError> {
    business_rule_or_404(&state, id).await?;
    let items = cases_of(&state, id).await?;
    let total = i64::try_from(items.len()).unwrap_or(MAX_CASES);
    Ok(Json(PaginatedResponse::new(items, total, 1, MAX_CASES)))
}

/// Add a test case to a rule
///
/// A11-T4: an example record and whether the rule must let its save pass or
/// refuse it, with the values its set_value policies must produce. Checked
/// at every publish. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/business-rules/{id}/test-cases",
    tag = "admin",
    operation_id = "create_rule_test_case",
    params(("id" = Uuid, Path, description = "The business rule")),
    request_body = RuleTestCaseBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The test case", body = RuleTestCase),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 409, description = "The rule has a test case of this name, or already 100", body = ErrorResponse),
        (status = 422, description = "A missing name, an expect other than pass or fail, or not a business rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_case(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<RuleTestCaseBody>,
) -> Result<(StatusCode, Json<RuleTestCase>), AppError> {
    check_body(&body)?;
    business_rule_or_404(&state, id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Serializes adds to one rule, so the cap holds.
    sqlx::query("SELECT id FROM rule WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_test_case WHERE rule_ref = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if count >= MAX_CASES {
        return Err(AppError::Conflict("a rule carries at most 100 test cases"));
    }
    let inserted: Result<Option<RuleTestCase>, sqlx::Error> = sqlx::query_as(
        "INSERT INTO rule_test_case (rule_ref, name, record, expect, set_values, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (rule_ref, name) DO NOTHING \
         RETURNING id, rule_ref, name, record, expect, set_values",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(Value::Object(body.record))
    .bind(&body.expect)
    .bind(body.set_values.map(Value::Object))
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await;
    let case = inserted
        .map_err(AppError::internal)?
        .ok_or(AppError::Conflict("the rule has a test case of this name"))?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            id,
            "rule.test_case_add",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(case)))
}

/// Remove a test case from a rule
///
/// A11-T4. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/business-rules/{id}/test-cases/{case_id}",
    tag = "admin",
    operation_id = "delete_rule_test_case",
    params(
        ("id" = Uuid, Path, description = "The business rule"),
        ("case_id" = Uuid, Path, description = "The test case"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule or test case", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_case(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((id, case_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let removed = sqlx::query("DELETE FROM rule_test_case WHERE id = $1 AND rule_ref = $2")
        .bind(case_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::HardDelete,
            ctx.user_id,
            id,
            "rule.test_case_remove",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/business-rules/{id}/test-cases",
            get(list_cases).post(create_case),
        )
        .route(
            "/api/v1/admin/business-rules/{id}/test-cases/{case_id}",
            delete(delete_case),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_cases, create_case, delete_case),
    components(schemas(RuleTestCase, RuleTestCaseBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn case(expect: &str, set_values: Option<Value>) -> RuleTestCase {
        RuleTestCase {
            id: Uuid::nil(),
            rule_ref: Uuid::nil(),
            name: "big discount".into(),
            record: json!({ "discount": 40 }),
            expect: expect.into(),
            set_values,
        }
    }

    #[test]
    fn rule_tests_pass_and_fail_cases_judge_the_errors() {
        let refused = CaseRun {
            errors: vec!["discount over 30 needs approval".into()],
            ..CaseRun::default()
        };
        let passed = CaseRun::default();
        assert_eq!(judge(&case("fail", None), &refused), None);
        assert!(
            judge(&case("pass", None), &refused)
                .is_some_and(|m| m.contains("refused it (discount over 30"))
        );
        assert!(judge(&case("fail", None), &passed).is_some_and(|m| m.contains("it passed")));
        let broken = CaseRun {
            error: Some("unknown field".into()),
            ..CaseRun::default()
        };
        assert!(judge(&case("pass", None), &broken).is_some());
    }

    #[test]
    fn rule_tests_check_the_values_set() {
        let mut set = Map::new();
        set.insert("approval".into(), json!("manager"));
        let run = CaseRun {
            set_values: set,
            ..CaseRun::default()
        };
        assert_eq!(
            judge(&case("pass", Some(json!({ "approval": "manager" }))), &run),
            None
        );
        assert!(
            judge(&case("pass", Some(json!({ "approval": "director" }))), &run)
                .is_some_and(|m| m.contains("expected approval = \"director\""))
        );
        assert!(
            judge(&case("pass", Some(json!({ "tier": 2 }))), &run)
                .is_some_and(|m| m.contains("the rule set nothing"))
        );
    }

    #[test]
    fn rule_tests_body_is_checked() {
        let body = |name: &str, expect: &str| RuleTestCaseBody {
            name: name.into(),
            record: Map::new(),
            expect: expect.into(),
            set_values: None,
        };
        assert!(check_body(&body("ok", "pass")).is_ok());
        assert!(check_body(&body(" ", "pass")).is_err());
        assert!(check_body(&body("ok", "maybe")).is_err());
        let mut failing = body("ok", "fail");
        failing.set_values = Some(Map::from_iter([("a".to_owned(), json!(1))]));
        assert!(check_body(&failing).is_err());
    }
}
