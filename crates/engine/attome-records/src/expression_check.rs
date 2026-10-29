//! Z11-T12: one expression checked against an entity for an editor or an
//! agent: its result type, or each error with the byte span it points at;
//! whether it runs in the database (`attome_core::rules_sql`) and, for a
//! sample record the caller can read, its value with the evaluation trace.
//! A9-T4: an expression that reads through lookups (`account_ref.region`,
//! up to [`attome_core::formula::MAX_FORMULA_HOPS`] of them, as a `read_time`
//! formula may) is checked with those paths declared, and the sample's
//! related values are read the way a formula's are when its record is read.
//! Writes nothing. `POST /api/v1/admin/expressions/validate` and the
//! `expression.validate` agent tool both call [`check_expression`].

use attome_core::EngineState;
use attome_rules::{Budgets, LanguageVersion, RulesDiagnostic};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::rule_engine::{self, context_for_record, json_from_rules_value, schema_for_entity};

/// One problem with the expression. `start`/`end` are byte offsets into the
/// expression; absent when the error has no single place (a length limit).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExpressionDiagnostic {
    pub code: String,
    pub message: String,
    pub start: Option<usize>,
    pub end: Option<usize>,
}

/// One evaluated sub-expression, in evaluation order.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExpressionTraceStep {
    pub expr: String,
    #[schema(value_type = Object)]
    pub value: Value,
}

/// What the check found.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExpressionCheck {
    pub ok: bool,
    /// The language type of the result (`number`, `text`, `bool`, ...).
    pub result_type: Option<String>,
    pub diagnostics: Vec<ExpressionDiagnostic>,
    /// Whether the expression runs in the database as a filter.
    pub sql_translatable: bool,
    /// Why it does not, when it does not.
    pub sql_reason: Option<String>,
    /// The value for the sample record, when one was given.
    #[schema(value_type = Option<Object>)]
    pub value: Option<Value>,
    pub trace: Option<Vec<ExpressionTraceStep>>,
}

fn diagnostic(d: &RulesDiagnostic) -> ExpressionDiagnostic {
    ExpressionDiagnostic {
        code: d.error.code().to_owned(),
        message: d.error.to_string(),
        start: d.span.map(|(s, _)| s),
        end: d.span.map(|(_, e)| e),
    }
}

/// Checks `expression` against `entity` as written in `version`. With
/// `sample_record_id`, the record is read as `ctx` (record access and field
/// grants apply; an unreadable record is the read's own 403/404) and the
/// expression evaluated on it. A field the caller may not read makes the
/// check fail rather than evaluate.
pub async fn check_expression(
    state: &EngineState,
    ctx: &SecurityContext,
    expression: &str,
    entity: &str,
    version: LanguageVersion,
    sample_record_id: Option<Uuid>,
) -> Result<ExpressionCheck, AppError> {
    let (_, entity_name, attrs, _) = crate::entity_crud::resolve_entity(state, entity).await?;
    let mut schema = schema_for_entity(&attrs);
    // A9-T4: the lookup paths the expression reads, as a formula resolves them.
    let mut paths = None;
    if attome_core::formula::reads_through_lookup(expression) {
        let registry = crate::formula_paths::registry_for(state, &entity_name).await?;
        let refs = attome_core::formula::formula_paths(expression, &attrs, &registry);
        if !refs.is_empty() {
            schema = attome_core::business_rules::with_related_schema(schema, &refs);
            paths = Some((registry, refs));
        }
    }
    let mut out = ExpressionCheck {
        ok: false,
        result_type: None,
        diagnostics: Vec::new(),
        sql_translatable: false,
        sql_reason: None,
        value: None,
        trace: None,
    };
    let compiled =
        match attome_rules::compile_diagnostic(expression, &schema, version, Budgets::default()) {
            Ok(compiled) => compiled,
            Err(d) => {
                out.diagnostics.push(diagnostic(&d));
                return Ok(out);
            }
        };
    let expr = attome_rules::parse(expression).map_err(AppError::internal)?;
    if let Err(e) = rule_engine::check_field_read_access(ctx, &entity_name, &attrs, &expr) {
        out.diagnostics.push(ExpressionDiagnostic {
            code: "rules.field.not_readable".to_owned(),
            message: e.to_string(),
            start: None,
            end: None,
        });
        return Ok(out);
    }
    out.ok = true;
    out.result_type = Some(compiled.result_type().to_string());
    let by_name = attrs
        .iter()
        .map(|a| (a.logicalname.clone(), a.clone()))
        .collect();
    match attome_core::rules_sql::translatable(&expr, &by_name) {
        Ok(()) => out.sql_translatable = true,
        Err(e) => out.sql_reason = Some(e.reason),
    }
    if let Some(record_id) = sample_record_id {
        let record = crate::entity_crud::read_record(state, ctx, &entity_name, record_id).await?;
        let empty = serde_json::Map::new();
        let data = record.data().as_object().unwrap_or(&empty);
        let mut rules_ctx = context_for_record(Utc::now(), &attrs, data);
        if let Some((registry, refs)) = &paths {
            rules_ctx =
                crate::formula_paths::with_paths(state, registry, data, refs, rules_ctx, 0).await?;
        }
        match compiled.eval_traced(&rules_ctx) {
            Ok((value, trace)) => {
                out.value = Some(json_from_rules_value(&value));
                out.trace = Some(
                    trace
                        .entries()
                        .iter()
                        .map(|t| ExpressionTraceStep {
                            expr: t.expr.clone(),
                            value: json_from_rules_value(&t.value),
                        })
                        .collect(),
                );
            }
            Err(e) => {
                out.ok = false;
                out.diagnostics.push(ExpressionDiagnostic {
                    code: e.code().to_owned(),
                    message: e.to_string(),
                    start: None,
                    end: None,
                });
            }
        }
    }
    Ok(out)
}
