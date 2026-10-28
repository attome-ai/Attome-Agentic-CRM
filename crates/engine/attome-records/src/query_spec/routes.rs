//! `POST /api/v1/query/run` (roadmap S4-T7): a query as a JSON spec or as
//! text (S4-T8), compiled with the caller's security inside the SQL and run
//! on the read-only pool under the interactive statement time limit; or, with
//! `explain`, planned and not run.

use std::collections::{BTreeMap, HashMap};

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::{AccessLevel, SecurityContext};
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
    /// S4-T9: run the stored query with this id (its saved QuerySpec);
    /// `params` are its parameter values and `spec` and `q` are absent.
    #[serde(default)]
    pub query_id: Option<Uuid>,
    /// S4-T9: with `query_id`, the previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// S4-T10: run it as a background export instead of in the request:
    /// the answer is 202 with the export, followed at
    /// `GET /api/v1/{entity}/export/{id}`. A row query over the interactive
    /// limit needs it.
    #[serde(default)]
    pub export: bool,
    /// S4-T10: with `export`, `json` (one row per line, the default) or `csv`.
    #[serde(default)]
    pub export_format: Option<String>,
}

/// S4-T10: what refuses a query over the interactive limit; `export: true`
/// runs it as a background export instead.
pub const QUERY_TOO_LARGE: &str = "query_too_large";

/// S4-T10: `as_of` reads history, which no entity keeps yet (A1).
pub const TIME_TRAVEL_OFF: &str = "time travel is not enabled for this entity";

/// The background exports one person may have pending or running at once,
/// the same cap `POST /api/v1/{entity}/export` applies.
pub const MAX_CONCURRENT_QUERY_EXPORTS: i64 = 3;

/// The refusal of a plan costing `total_cost`, over [`GUARD_LIMIT`]. Pure.
pub fn too_large(total_cost: f64) -> AppError {
    AppError::Validation(format!(
        "{QUERY_TOO_LARGE}: the query plan costs {total_cost:.0}, over the interactive limit \
         {GUARD_LIMIT:.0}; narrow it, or send it again with export: true to run it as a \
         background export"
    ))
}

/// S4-T10: a query queued as a background export.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExportQueued {
    pub export_id: Uuid,
    /// `pending` until the worker starts it.
    pub status: String,
    /// Where to follow it and, once done, download it.
    pub status_url: String,
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
    /// S4-T10: `export: true` queued it.
    Export(ExportQueued),
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
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::DataExport"),
        "runs one query on the read-only pool, or plans it; with export it only enqueues an export, which the job audits in the export's completion transaction",
    )))),
    responses(
        (status = 200, description = "A page of rows with its cursor, the aggregate groups, or the plan when explain is set", body = RunResponse),
        (status = 202, description = "S4-T10: export is set; the export is queued", body = RunResponse),
        (status = 400, description = "A cursor this deployment did not issue", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such entity, or one the caller may not read", body = ErrorResponse),
        (status = 409, description = "Too many exports of this person already pending or running", body = ErrorResponse),
        (status = 422, description = "A query outside the grammar, an unknown field or operator, a plan over the interactive limit without export (`query_too_large`), or as_of while time travel is off", body = ErrorResponse),
        (status = 504, description = "The query ran past the statement time limit", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn run_query(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<RunRequest>,
) -> Result<(axum::http::StatusCode, Json<RunResponse>), AppError> {
    let export = body.export;
    let export_format = body.export_format.clone();
    let spec = match body.query_id {
        Some(id) => saved_spec(&state, &ctx, id, body).await?,
        None => {
            if body.cursor.is_some() {
                return Err(AppError::Validation(
                    "cursor goes inside spec; the top-level cursor is for query_id".into(),
                ));
            }
            body.into_spec()?
        }
    };
    ctx.require(&spec.entity, "read")
        .map_err(|_| AppError::NotFound)?;
    // S4-T10: no entity keeps history yet (A1), so a read as of a time
    // cannot be answered; refusing beats answering today's rows.
    if spec.as_of.is_some() {
        return Err(AppError::Validation(TIME_TRAVEL_OFF.into()));
    }
    if export {
        let queued = enqueue_export(
            &state,
            &ctx,
            spec,
            export_format.as_deref().unwrap_or("json"),
        )
        .await?;
        return Ok((
            axum::http::StatusCode::ACCEPTED,
            Json(RunResponse::Export(queued)),
        ));
    }
    Ok((
        axum::http::StatusCode::OK,
        Json(execute_spec(&state, &ctx, spec).await?),
    ))
}

/// S4-T10: queues `spec` as a background export (`data_export`, run by the
/// export worker through the query engine as `ctx`, freshly authorized). The
/// query is planned here first, so a bad one fails now and not in the job.
async fn enqueue_export(
    state: &EngineState,
    ctx: &SecurityContext,
    mut spec: QuerySpec,
    format: &str,
) -> Result<ExportQueued, AppError> {
    if !matches!(format, "json" | "csv") {
        return Err(AppError::Validation("export_format is json or csv".into()));
    }
    if !(spec.aggregates.is_empty() && spec.group_by.is_empty() && spec.having.is_none()) {
        return Err(AppError::Validation(
            "only a row query exports; an aggregate answers in the request".into(),
        ));
    }
    spec.cursor = None;
    let mut check = spec.clone();
    check.explain = true;
    execute_spec(state, ctx, check).await?;
    spec.explain = false;

    let running: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM data_export \
          WHERE created_by = $1 AND status IN ('pending', 'running') AND is_deleted = false",
    )
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if running >= MAX_CONCURRENT_QUERY_EXPORTS {
        return Err(AppError::Conflict(
            "too many exports already in progress for this account — wait for one to finish",
        ));
    }

    let export_id = Uuid::now_v7();
    let query_spec = serde_json::to_value(&spec).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO data_export \
            (id, entity_logicalname, format, columns, filters, status, created_by, labels, \
             split_rows) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, false, NULL)",
    )
    .bind(export_id)
    .bind(&spec.entity)
    .bind(format)
    .bind(serde_json::json!(spec.select))
    .bind(serde_json::json!([]))
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::DataExport(attome_core::jobs::DataExportPayload {
            export_id,
            entity_logicalname: spec.entity.clone(),
            format: format.to_owned(),
            columns: spec.select.clone(),
            filters: Vec::new(),
            user_id: ctx.user_id,
            query_spec: Some(query_spec),
        }),
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(ExportQueued {
        export_id,
        status: "pending".into(),
        status_url: format!("/api/v1/{}/export/{export_id}", spec.entity),
    })
}

/// S4-T9: the stored query `id`'s spec with the run's values: its
/// `required_privilege` (the admin default otherwise) gates it as it gates
/// `query/execute`, and each value is checked against its declaration.
/// A14-T2: a share with one of the caller's roles or teams admits a caller
/// without the privilege; the spec still compiles with the caller's own
/// record and field security, so a share never widens what it returns.
async fn saved_spec(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: RunRequest,
) -> Result<QuerySpec, AppError> {
    if body.spec.is_some() || body.q.is_some() {
        return Err(AppError::Validation(
            "a run by query_id sends values only, not spec or q".into(),
        ));
    }
    let saved = super::saved::load(&state.base.db, id).await?;
    let privileged = match &saved.required_privilege {
        Some(key) => ctx.require_key(key),
        None => ctx.require_admin(),
    };
    if let Err(refused) = privileged
        && super::share::access_for(&state.base.db, id, ctx)
            .await?
            .is_none()
    {
        return Err(refused);
    }
    let mut spec = saved.spec;
    spec.params = super::saved::coerce(&saved.params, &body.params)?;
    spec.cursor = body.cursor;
    spec.explain = body.explain;
    Ok(spec)
}

/// Compiles and runs one spec for `ctx`, who may already read its entity:
/// the body of `POST /api/v1/query/run`, shared with the OData feed (S7-T1)
/// and search's `mode=ask` (A25-T7). With `spec.explain` it compiles and
/// plans only, which checks every field and operator against the caller's
/// metadata without running anything.
pub async fn execute_spec(
    state: &EngineState,
    ctx: &SecurityContext,
    spec: QuerySpec,
) -> Result<RunResponse, AppError> {
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
            ctx,
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
        return Ok(RunResponse::Explain(ExplainResponse {
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
        }));
    }
    if total_cost > GUARD_LIMIT {
        // S4-T10: a row query this size runs as a background export.
        return Err(too_large(total_cost));
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

    Ok(match plan {
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
    })
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
    fn large_query_without_export_is_422() {
        let refused = too_large(250_000.0);
        assert!(
            matches!(&refused, AppError::Validation(m) if m.starts_with(QUERY_TOO_LARGE) && m.contains("export: true")),
            "{refused:?}"
        );
        let body: RunRequest = serde_json::from_value(json!({
            "spec": {"entity": "account"}, "export": true, "export_format": "csv"
        }))
        .unwrap();
        assert!(body.export);
        assert_eq!(body.export_format.as_deref(), Some("csv"));
        let plain: RunRequest =
            serde_json::from_value(json!({ "spec": {"entity": "account"} })).unwrap();
        assert!(!plain.export);
    }

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
