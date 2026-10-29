//! `query.run` (roadmap S4-T13): an agent runs a structured query in the
//! text form (`SELECT … FROM … [WHERE …] [GROUP BY …] [HAVING …] [ORDER BY
//! …] [LIMIT n]`), parsed by `attome_records::query_spec::text` under its
//! own limits; a JSON QuerySpec is not accepted, so nothing bypasses them.
//!
//! The query runs as the caller (`ctx.security`, the person's or the agent's
//! own context, never a service principal) through `execute_spec`, the
//! engine `POST /api/v1/query/run` uses: records and fields the caller may
//! not read are filtered inside the SQL, on the read-only pool, under the
//! interactive statement time limit. An MCP agent queries only the entities
//! admitted to it.
//!
//! It plans first. A plan estimated over [`EXPLAIN_FIRST_ROWS`] rows comes
//! back as the plan with a request to narrow the query, and nothing runs;
//! otherwise at most [`MAX_ROWS`] rows come back. AH4 sets no row or time
//! limit of its own for agents (its limits count writes, deletes and
//! messages), so the page is `query.plan`'s default and the time limit the
//! query engine's.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_records::query_spec::routes::RunResponse;
use attome_records::query_spec::{execute_spec, parse_text};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const QUERY_RUN: &str = "query.run";
/// A plan estimated above this many rows is returned instead of run.
pub const EXPLAIN_FIRST_ROWS: i64 = 5_000;
/// The most rows one answer carries.
pub const MAX_ROWS: i64 = super::nl_query::DEFAULT_LIMIT;

const QUERY_RUN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "q": {
      "type": "string",
      "description": "The query in the text form, e.g. SELECT name FROM account WHERE city = :city ORDER BY name LIMIT 5."
    },
    "params": {
      "type": "object",
      "description": "Values for the :name parameters the query names."
    }
  },
  "required": ["q"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        QUERY_RUN,
        "Run a read-only query in the text form (SELECT … FROM … WHERE … \
         GROUP BY … ORDER BY … LIMIT n) over the records the caller may read, \
         returning at most 50 rows or the groups. A query estimated over 5,000 \
         rows returns its plan instead, to be narrowed.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_CORE,
        &[],
    )
    .input_schema(QUERY_RUN_SCHEMA)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    q: String,
    #[serde(default)]
    params: BTreeMap<String, Value>,
}

pub(crate) struct QueryRun;

impl Action for QueryRun {
    fn id(&self) -> ActionId {
        ActionId(QUERY_RUN)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: Args = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid query.run arguments: {e}")))?;
            let mut spec = parse_text(args.q.trim())?;
            spec.params.extend(args.params);
            if spec.as_of.is_some() {
                return Err(AppError::Validation(
                    "query.run reads current records only".into(),
                ));
            }
            // A hidden entity, or one not admitted to an MCP agent, is
            // answered like a missing one.
            let admission = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?;
            if ctx.security.require(&spec.entity, "read").is_err()
                || admission.is_some_and(|a| !a.admits(&spec.entity))
            {
                return Err(AppError::NotFound);
            }

            let mut plan = spec.clone();
            plan.explain = true;
            // The plan is validated like a run: a LIMIT over the page ceiling
            // would refuse it before the run below caps it.
            plan.page_size = plan.page_size.map(|n| n.clamp(1, MAX_ROWS));
            if let RunResponse::Explain(explained) =
                execute_spec(state, &ctx.security, plan).await?
                && explained.estimated_rows > EXPLAIN_FIRST_ROWS
            {
                return Ok(ActionResult::plain(json!({
                    "status": "too_broad",
                    "message": format!(
                        "the query is estimated at {} rows, over {EXPLAIN_FIRST_ROWS}; \
                         narrow it with a WHERE condition or a GROUP BY and run it again",
                        explained.estimated_rows
                    ),
                    "plan": serde_json::to_value(&explained).map_err(AppError::internal)?,
                })));
            }

            spec.page_size = Some(spec.page_size.map_or(MAX_ROWS, |n| n.clamp(1, MAX_ROWS)));
            let value = match execute_spec(state, &ctx.security, spec).await? {
                RunResponse::Rows(page) => json!({
                    "status": "rows",
                    "more": page.next_cursor.is_some(),
                    "rows": page.items.into_iter().map(|row| Value::Object(row.0)).collect::<Vec<_>>(),
                }),
                RunResponse::Aggregate(result) => {
                    let groups =
                        serde_json::to_value(&result.groups).map_err(AppError::internal)?;
                    json!({ "status": "groups", "groups": groups })
                }
                RunResponse::Explain(_) | RunResponse::Export(_) => {
                    return Err(AppError::internal("query.run ran a plan or an export"));
                }
            };
            Ok(ActionResult::plain(value))
        })
    }
}
