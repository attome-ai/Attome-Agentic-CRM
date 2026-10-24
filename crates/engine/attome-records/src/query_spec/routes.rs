//! `POST /api/v1/query/run` (roadmap S4-T7): a query as a JSON spec or as
//! text (S4-T8), compiled with the caller's security inside the SQL and run
//! on the read-only pool under the interactive statement time limit; or, with
//! `explain`, planned and not run.

use std::collections::{BTreeMap, HashMap};

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::AccessLevel;
use attome_types::{AppError, CursorPage, ErrorResponse};
use axum::{Json, extract::State};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use super::aggregate::{self, AggregateResult};
use super::compile::{self, Access, Env};
use super::model::QuerySpec;
use super::operators::Clock;
use super::text;

/// The plan cost above which a query is refused: `query/execute`'s
/// interactive ceiling.
pub const GUARD_LIMIT: f64 = 100_000.0;

/// A query, as `spec` (the QuerySpec JSON form) or as `q` (its text form),
/// exactly one. `params` and `explain` apply to either; a text query takes
/// them only from here.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    /// The QuerySpec: `entity`, `select`, `where` (a condition tree of
    /// `and`/`or`/`not`/`compare`/`param`/`exists`/`not_exists` nodes, tagged
    /// by `kind`), `sort`, `page_size`, `cursor`, `group_by`, `aggregates`,
    /// `having`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub spec: Option<QuerySpec>,
    /// The text form: `SELECT … FROM … [WHERE …] [GROUP BY …] [HAVING …]
    /// [ORDER BY …] [LIMIT n]`.
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub params: BTreeMap<String, Value>,
    /// Plan the query and return the plan's summary instead of rows.
    #[serde(default)]
    pub explain: bool,
}

impl RunRequest {
    /// The query to compile: the spec as sent, or the text parsed.
    pub fn into_spec(self) -> Result<QuerySpec, AppError> {
        let mut spec = match (self.spec, self.q) {
            (Some(spec), None) => spec,
            (None, Some(q)) => text::parse(&q)?,
            _ => {
                return Err(AppError::Validation(
                    "send exactly one of spec and q".into(),
                ));
            }
        };
        spec.params.extend(self.params);
        spec.explain |= self.explain;
        Ok(spec)
    }
}

/// One result row, its columns by name (a related field by its path).
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = Object)]
pub struct RunRow(pub Map<String, Value>);

/// What the planner expects of a query; nothing is run.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExplainResponse {
    /// `scan` when the plan reads the whole root table, else `index`.
    pub plan_class: String,
    pub estimated_rows: i64,
    pub total_cost: f64,
    /// The cost above which the query would be refused.
    pub guard_limit: f64,
}

/// Rows (a keyset page), aggregate groups, or a plan.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(untagged)]
pub enum RunResponse {
    Rows(CursorPage<RunRow>),
    Aggregate(AggregateResult),
    Explain(ExplainResponse),
}

enum Plan {
    Rows(compile::Compiled),
    Aggregate(aggregate::CompiledAggregate),
}

/// Run a structured query
///
/// S4-T7: one query over one entity and what it reaches through lookups and
/// relationships, as JSON or text. Records and fields the caller may not read
/// are filtered inside the SQL; a hidden entity is a 404 like a missing one.
#[utoipa::path(
    post,
    path = "/api/v1/query/run",
    tag = "query",
    operation_id = "query_run",
    request_body = RunRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "runs one query on the read-only pool, or plans it; persists nothing",
    )))),
    responses(
        (status = 200, description = "A page of rows with its cursor, the aggregate groups, or the plan when explain is set", body = RunResponse),
        (status = 400, description = "A cursor this deployment did not issue", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such entity, or one the caller may not read", body = ErrorResponse),
        (status = 422, description = "A query outside the grammar, an unknown field or operator, or a plan over the cost limit", body = ErrorResponse),
        (status = 504, description = "The query ran past the statement time limit", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn run_query(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<RunRequest>,
) -> Result<Json<RunResponse>, AppError> {
    let spec = body.into_spec()?;
    ctx.require(&spec.entity, "read")
        .map_err(|_| AppError::NotFound)?;

    let levels: HashMap<Uuid, AccessLevel> = if ctx.is_admin {
        HashMap::new()
    } else {
        attome_security::resolve_all_entity_access_levels(
            &state.base.db,
            ctx.user_id,
            attome_security::RecordAction::Read,
        )
        .await?
        .into_values()
        .collect()
    };
    let access = Access::new(levels);
    let tz = state
        .base
        .config
        .app
        .time_zone
        .as_deref()
        .and_then(|z| z.parse().ok())
        .unwrap_or(chrono_tz::UTC);
    let plan = {
        let registry = state.entities.load();
        let relationships = state.relationships.load();
        let env = Env {
            registry: &registry,
            relationships: &relationships,
            ctx: &ctx,
            access: &access,
            clock: Clock {
                now: Utc::now(),
                tz,
                fiscal_start_month: 1,
            },
        };
        if spec.aggregates.is_empty() && spec.group_by.is_empty() && spec.having.is_none() {
            Plan::Rows(compile::compile(&spec, &env)?)
        } else {
            Plan::Aggregate(aggregate::compile(&spec, &env)?)
        }
    };
    let (sql, binds) = match &plan {
        Plan::Rows(c) => (&c.sql, &c.binds),
        Plan::Aggregate(c) => (&c.sql, &c.binds),
    };

    let db = state.base.readonly_query_pool(ctx.user_id).await;
    let mut tx = attome_db::tx::begin(db).await?;
    // AA4-T7: the deployment's interactive limit; a stored runtime setting
    // wins over the boot value (AA9-T3).
    let timeout_ms = state
        .runtime_limit("query.timeout_ms.interactive")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(state.base.config.query.timeouts_ms.interactive)
        .max(1);
    sqlx::query(&attome_db::tag_dynamic(
        "query.run",
        &format!("SET LOCAL statement_timeout = {timeout_ms}"),
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // Never EXPLAIN ANALYZE: that would run the query.
    let explain_sql = attome_db::tag_dynamic("query.run", &format!("EXPLAIN (FORMAT JSON) {sql}"));
    let mut explain = sqlx::query_scalar::<_, Value>(&explain_sql);
    for bind in binds {
        explain = explain.bind(bind.as_str());
    }
    let plan_json = explain.fetch_one(&mut *tx).await.map_err(run_error)?;
    let top = plan_json.pointer("/0/Plan").cloned().unwrap_or(Value::Null);
    let total_cost = top.get("Total Cost").and_then(Value::as_f64).unwrap_or(0.0);
    if spec.explain {
        return Ok(Json(RunResponse::Explain(ExplainResponse {
            plan_class: if scans_table(&top, &spec.entity) {
                "scan"
            } else {
                "index"
            }
            .into(),
            estimated_rows: top
                .get("Plan Rows")
                .and_then(Value::as_f64)
                .map_or(0, |rows| rows.round() as i64),
            total_cost,
            guard_limit: GUARD_LIMIT,
        })));
    }
    if total_cost > GUARD_LIMIT {
        return Err(AppError::Validation(format!(
            "query plan cost {total_cost:.2} exceeds the allowed limit {GUARD_LIMIT:.0}; narrow the query"
        )));
    }

    let wrapped = attome_db::tag_dynamic(
        "query.run",
        &format!("SELECT row_to_json(q.*) FROM ({sql}) AS q"),
    );
    let mut query = sqlx::query_scalar::<_, Value>(&wrapped);
    for bind in binds {
        query = query.bind(bind.as_str());
    }
    let rows: Vec<Map<String, Value>> = query
        .fetch_all(&mut *tx)
        .await
        .map_err(run_error)?
        .into_iter()
        .filter_map(|row| match row {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .collect();
    drop(tx);

    Ok(Json(match plan {
        Plan::Rows(compiled) => {
            let page = usize::try_from(compiled.page_size).unwrap_or(usize::MAX);
            let mut rows = rows;
            let next = if rows.len() > page {
                rows.truncate(page);
                rows.last()
                    .and_then(|row| compile::next_cursor(&compiled, row))
            } else {
                None
            };
            RunResponse::Rows(CursorPage::new(
                rows.into_iter().map(RunRow).collect(),
                next,
            ))
        }
        Plan::Aggregate(compiled) => RunResponse::Aggregate(compiled.groups(rows)?),
    }))
}

/// Whether a plan reads the whole of `table` (a sequential scan of it).
fn scans_table(node: &Value, table: &str) -> bool {
    let this = node.get("Node Type").and_then(Value::as_str) == Some("Seq Scan")
        && node.get("Relation Name").and_then(Value::as_str) == Some(table);
    this || node
        .get("Plans")
        .and_then(Value::as_array)
        .is_some_and(|plans| plans.iter().any(|p| scans_table(p, table)))
}

/// A query's database error: the time limit is a 504, a value that does not
/// fit its field's type (PostgreSQL's data exceptions, class 22, and a
/// missing operator, 42883) is the caller's to fix, anything else is masked.
fn run_error(e: sqlx::Error) -> AppError {
    let code = e
        .as_database_error()
        .and_then(|db| db.code())
        .map(|c| c.into_owned());
    match code.as_deref() {
        Some("57014") => AppError::QueryTimeout,
        Some(c) if c.starts_with("22") || c == "42883" => {
            AppError::Validation("a value in the query does not match its field's type".into())
        }
        _ => AppError::internal(e),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn exactly_one_form_is_taken() {
        let text: RunRequest = serde_json::from_value(json!({
            "q": "SELECT name FROM account WHERE city = :city",
            "params": {"city": "Riyadh"},
            "explain": true
        }))
        .unwrap();
        let spec = text.into_spec().unwrap();
        assert_eq!(spec.params.get("city"), Some(&json!("Riyadh")));
        assert!(spec.explain);

        let both: RunRequest = serde_json::from_value(json!({
            "q": "SELECT name FROM account",
            "spec": {"entity": "account"}
        }))
        .unwrap();
        assert!(both.into_spec().is_err());
        let neither: RunRequest = serde_json::from_value(json!({})).unwrap();
        assert!(neither.into_spec().is_err());
    }

    #[test]
    fn a_sequential_scan_of_the_root_is_a_scan() {
        let plan = json!({"Node Type": "Limit", "Plans": [
            {"Node Type": "Sort", "Plans": [{"Node Type": "Seq Scan", "Relation Name": "account"}]}
        ]});
        assert!(scans_table(&plan, "account"));
        assert!(!scans_table(&plan, "contact"));
        let indexed = json!({"Node Type": "Index Scan", "Relation Name": "account"});
        assert!(!scans_table(&indexed, "account"));
    }
}
