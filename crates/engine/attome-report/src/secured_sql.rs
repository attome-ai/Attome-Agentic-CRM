//! P2-T1 (V2-D1416): an author's SQL, run so it can read only what the
//! author can read.
//!
//! No parser decides what the SQL may touch; PostgreSQL's privileges do. In
//! one transaction that is always rolled back:
//!
//! 1. For each entity whose name appears in the SQL text and that the author
//!    may read, a temporary view with the entity's own name is created
//!    (`pg_temp` is searched first, so `FROM account` reads it). It selects
//!    the columns a bulk read shows the author (`field_gate::bulk_columns`:
//!    the system columns, the primary name and the fields their roles list,
//!    a sensitive field only with its grant) from the rows a list shows them
//!    (the same `rls_predicate` as `query/execute`, its values written in as
//!    literals, since a view takes no parameters). The view runs with its
//!    owner's rights, the application's.
//! 2. The transaction turns read-only, a statement timeout is set, and
//!    inside a savepoint the session switches to `attome_user_sql`
//!    (migration 0344): a role with no privilege on any schema or table,
//!    granted SELECT on this run's views only.
//! 3. The SQL runs as one statement, wrapped as a subquery and capped in
//!    rows. A schema-qualified name, an entity the author may not read, a
//!    function that reads a table by name (`query_to_xml`) or a second
//!    statement fails on privileges or on the wrapping, not on a word list.
//! 4. The savepoint is rolled back (back to the application's role), any
//!    session advisory lock the SQL took is released, and the transaction is
//!    rolled back, which drops the views.
//!
//! Polymorphic children and the audit family (notes, activities, audit
//! rows) are gated by the record they point at, which a single-table view
//! cannot express; for anyone but an administrator they get no view, as a
//! custom query in `query/execute` refuses them.
//!
//! The SQL text reaches PostgreSQL as written: that is the feature. Every
//! string this module builds from it runs only as `attome_user_sql`.

use std::collections::BTreeSet;

use attome_core::{EngineState, quote_ident};
use attome_records::entity_crud::{POLYMORPHIC_AUDIT_ENTITIES, POLYMORPHIC_CHILD_ENTITIES};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Column, Connection, Executor};
use utoipa::ToSchema;

use crate::auth::SqlAuthor;

/// The role an author's SQL runs as (migration 0344).
pub const USER_SQL_ROLE: &str = "attome_user_sql";
/// The longest SQL text a run takes.
pub const MAX_SQL_CHARS: usize = 20_000;
/// The most entities one run makes views for.
pub const MAX_ENTITIES: usize = 20;
/// The most rows a run returns.
pub const MAX_ROWS: i64 = 1_000;
/// How long the author's statement may run.
pub const TIMEOUT_MS: u64 = 10_000;

/// What a run returns.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct SqlRun {
    /// The result's column names, in order.
    pub columns: Vec<String>,
    /// One object per row, keyed by column name.
    #[schema(value_type = Vec<Object>)]
    pub rows: Vec<Value>,
    /// More rows matched than the cap returned.
    pub truncated: bool,
    /// `EXPLAIN (FORMAT JSON)` of the statement, when asked for.
    #[schema(value_type = Option<Object>)]
    pub plan: Option<Value>,
}

/// How a run is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    pub max_rows: i64,
    pub timeout_ms: u64,
    pub explain: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            max_rows: MAX_ROWS,
            timeout_ms: TIMEOUT_MS,
            explain: false,
        }
    }
}

/// The SQL as it will run: trimmed, one trailing `;` dropped. Empty or
/// overlong text is refused. Pure.
pub fn normalise(sql: &str) -> Result<String, AppError> {
    let trimmed = sql.trim();
    let trimmed = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    if trimmed.is_empty() {
        return Err(AppError::Validation("the SQL is empty".into()));
    }
    if trimmed.chars().count() > MAX_SQL_CHARS {
        return Err(AppError::Validation(format!(
            "the SQL is limited to {MAX_SQL_CHARS} characters"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Every name the SQL may use for a table: each unquoted word, lowercased,
/// and the text of each double-quoted identifier. A superset is harmless:
/// a word that is not an entity gets no view. Pure.
pub fn referenced_names(sql: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut chars = sql.chars().peekable();
    let mut word = String::new();
    let flush = |word: &mut String, names: &mut BTreeSet<String>| {
        if !word.is_empty() {
            names.insert(word.to_ascii_lowercase());
            word.clear();
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                flush(&mut word, &mut names);
                let mut quoted = String::new();
                while let Some(q) = chars.next() {
                    if q == '"' {
                        if chars.peek() == Some(&'"') {
                            chars.next();
                            quoted.push('"');
                        } else {
                            break;
                        }
                    } else {
                        quoted.push(q);
                    }
                }
                if !quoted.is_empty() {
                    names.insert(quoted);
                }
            }
            '\'' => {
                // A string literal names no table.
                flush(&mut word, &mut names);
                while let Some(q) = chars.next() {
                    if q == '\'' {
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
            }
            c if c.is_ascii_alphanumeric() || c == '_' => word.push(c),
            _ => flush(&mut word, &mut names),
        }
    }
    flush(&mut word, &mut names);
    names
}

/// A PostgreSQL string literal of `value`: single quotes doubled, under
/// `standard_conforming_strings` (on since PostgreSQL 9.1, and the views are
/// created before the author's SQL can change any setting). Pure.
fn literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push('\'');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// `fragment` with each placeholder `$first`, `$first + 1`, … replaced by
/// the matching value of `params` as a literal. Every placeholder of an RLS
/// fragment carries its own `::type` cast, so a text literal reads back as
/// the type the fragment expects. A placeholder outside the range is left
/// as it is. Pure.
pub fn inline_binds(fragment: &str, first: usize, params: &[String]) -> String {
    let mut out = String::with_capacity(fragment.len() + params.len() * 40);
    let bytes = fragment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let digits = bytes[i + 1..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if digits > 0 {
                let number: usize = fragment[i + 1..i + 1 + digits].parse().unwrap_or(0);
                if let Some(value) = number.checked_sub(first).and_then(|at| params.get(at)) {
                    out.push_str(&literal(value));
                    i += 1 + digits;
                    continue;
                }
            }
        }
        let c = fragment[i..].chars().next().unwrap_or_default();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// One entity's view for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EntityView {
    entity: String,
    /// The SELECT list, from `field_gate::bulk_columns`.
    columns: String,
    /// `AND (...)` with its values written in, or empty.
    predicate: String,
}

/// The views a run makes for `names`: the entities among them the author
/// may read, each with the columns and rows a bulk read shows them.
async fn entity_views(
    state: &EngineState,
    ctx: &SecurityContext,
    names: &BTreeSet<String>,
) -> Result<Vec<EntityView>, AppError> {
    // Copied out of the registry first: its guard is not held across an await.
    let candidates: Vec<(
        String,
        uuid::Uuid,
        Vec<attome_core::AttrInfo>,
        Option<String>,
    )> = {
        let registry = state.entities.load();
        names
            .iter()
            .filter_map(|name| {
                registry.get(name).map(|meta| {
                    (
                        name.clone(),
                        meta.entity_id,
                        meta.attrs.clone(),
                        meta.primary_name_attribute.clone(),
                    )
                })
            })
            .collect()
    };
    let mut views = Vec::new();
    for (name, entity_id, attrs, primary_name) in &candidates {
        if ctx.require(name, "read").is_err() {
            continue;
        }
        if !ctx.is_admin
            && (POLYMORPHIC_AUDIT_ENTITIES.contains(&name.as_str())
                || POLYMORPHIC_CHILD_ENTITIES.contains(&name.as_str()))
        {
            continue;
        }
        if views.len() >= MAX_ENTITIES {
            return Err(AppError::Validation(format!(
                "a SQL report reads at most {MAX_ENTITIES} entities"
            )));
        }
        let level = attome_security::resolve_entity_access_level(
            &state.base.db,
            ctx.user_id,
            *entity_id,
            name,
            RecordAction::Read,
        )
        .await?;
        let predicate = attome_security::rls_predicate(
            ctx,
            *entity_id,
            "t",
            level,
            RecordAction::Read.share_capability(),
            1,
        )
        .map(|p| inline_binds(&p.sql, 1, &p.binds.to_text_params()))
        .unwrap_or_default();
        let columns =
            attome_security::field_gate::bulk_columns(ctx, name, attrs, primary_name.as_deref());
        views.push(EntityView {
            entity: name.clone(),
            columns,
            predicate,
        });
    }
    Ok(views)
}

/// Maps a failure of the author's statement: what is wrong with their SQL
/// (a syntax or name error, a type or value error, a missing privilege, a
/// timeout) is theirs to read; anything else is logged and masked.
fn statement_error(error: sqlx::Error) -> AppError {
    let Some(db) = error.as_database_error() else {
        return AppError::internal(error);
    };
    let code = db.code().map(|c| c.into_owned()).unwrap_or_default();
    if code == "57014" {
        return AppError::Validation("the query ran past its time limit".into());
    }
    if code.starts_with("42") || code.starts_with("22") || code == "0A000" || code == "21000" {
        return AppError::Validation(format!("the query failed: {}", db.message()));
    }
    AppError::internal(error)
}

/// Runs `sql` as `ctx` (see the module docs). Never commits.
pub async fn run(
    state: &EngineState,
    ctx: &SecurityContext,
    sql: &str,
    options: RunOptions,
) -> Result<SqlRun, AppError> {
    let sql = normalise(sql)?;
    let views = entity_views(state, ctx, &referenced_names(&sql)).await?;
    let max_rows = options.max_rows.clamp(1, MAX_ROWS);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let schema: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    // While the views are made, the application's schema comes before
    // pg_temp, so a view's row filter never reads an earlier view of the
    // same name; a view keeps the tables it resolved at creation.
    sqlx::query("SELECT set_config('search_path', $1, true)")
        .bind(quote_ident(&schema) + ", pg_temp")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for view in &views {
        let create = format!(
            "CREATE TEMP VIEW {name} AS SELECT {columns} FROM {schema}.{table} AS t WHERE true {predicate}",
            name = quote_ident(&view.entity),
            columns = view.columns,
            schema = quote_ident(&schema),
            table = quote_ident(&view.entity),
            predicate = view.predicate,
        );
        sqlx::query(&create)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let grant = format!(
            "GRANT SELECT ON pg_temp.{name} TO {role}",
            name = quote_ident(&view.entity),
            role = USER_SQL_ROLE,
        );
        sqlx::query(&grant)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    // The author's SQL sees this run's views and pg_catalog, nothing else.
    sqlx::query("SELECT set_config('search_path', 'pg_temp', true)")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(options.timeout_ms.clamp(100, TIMEOUT_MS).to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // The author's statement runs inside a savepoint, as the user SQL role;
    // rolling the savepoint back returns the session to the application's
    // role whether the statement worked or not.
    let outcome = {
        let mut author = Connection::begin(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let switched = sqlx::query("SET LOCAL ROLE attome_user_sql")
            .execute(&mut *author)
            .await
            .map_err(AppError::internal);
        let result = match switched {
            Ok(_) => run_statement(&mut author, &sql, max_rows, options.explain).await,
            Err(error) => Err(error),
        };
        author.rollback().await.map_err(AppError::internal)?;
        result
    };
    // A session advisory lock outlives the rollback; the author's SQL may
    // have taken one, and a pooled connection must not keep it.
    sqlx::query("SELECT pg_advisory_unlock_all()")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.rollback().await.map_err(AppError::internal)?;
    outcome
}

/// The author's statement, already inside the restricted savepoint.
async fn run_statement(
    conn: &mut sqlx::PgConnection,
    sql: &str,
    max_rows: i64,
    explain: bool,
) -> Result<SqlRun, AppError> {
    // As a subquery the text must be one query: no second statement, no
    // data-modifying WITH, no utility command.
    let wrapped = format!("SELECT * FROM ({sql}\n) AS author_query");
    let described = (&mut *conn)
        .describe(&wrapped)
        .await
        .map_err(statement_error)?;
    let columns: Vec<String> = described
        .columns()
        .iter()
        .map(|c| c.name().to_owned())
        .collect();
    let plan = if explain {
        let explain_sql = String::from("EXPLAIN (FORMAT JSON) ") + &wrapped;
        let plan: Value = sqlx::query_scalar(&explain_sql)
            .fetch_one(&mut *conn)
            .await
            .map_err(statement_error)?;
        Some(plan)
    } else {
        None
    };
    let rows_sql = format!("SELECT row_to_json(q)::text FROM ({wrapped}) AS q LIMIT $1");
    let texts: Vec<String> = sqlx::query_scalar(&rows_sql)
        .bind(max_rows + 1)
        .fetch_all(&mut *conn)
        .await
        .map_err(statement_error)?;
    let truncated = i64::try_from(texts.len()).unwrap_or(i64::MAX) > max_rows;
    let rows = texts
        .iter()
        .take(usize::try_from(max_rows).unwrap_or(usize::MAX))
        .map(|text| serde_json::from_str(text).map_err(AppError::internal))
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(SqlRun {
        columns,
        rows,
        truncated,
        plan,
    })
}

/// The body of `POST /api/v1/reports/sql/run`.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct SqlRunRequest {
    /// One SELECT (a WITH query too). Entities are named as tables.
    sql: String,
    /// Also return `EXPLAIN (FORMAT JSON)` of the statement.
    #[serde(default)]
    explain: bool,
    /// At most this many rows, up to 1000 (the default).
    max_rows: Option<i64>,
}

/// Run an SQL report
///
/// Test-runs an author's SQL (P2-T1, P2-T2): one SELECT over the entities
/// the author may read, each seen as the author sees it in a list (their
/// rows, their readable fields), as a role with no other access, in a
/// read-only transaction that is rolled back. Returns the columns, up to
/// 1000 rows and, when asked, the plan. A statement error (syntax, an
/// unknown or unreadable table, a type error, the 10-second limit) is a 422
/// with PostgreSQL's message. Needs `attome_report.author_sql`.
#[utoipa::path(
    post,
    path = "/api/v1/reports/sql/run",
    tag = "report",
    request_body = SqlRunRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "runs the author's SELECT in a read-only transaction that is always rolled back",
    )))),
    responses(
        (status = 200, description = "The result", body = SqlRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks attome_report.author_sql", body = ErrorResponse),
        (status = 422, description = "The SQL is empty, too long or failed; PostgreSQL's message says why", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn run_sql(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SqlAuthor>>,
    Json(request): Json<SqlRunRequest>,
) -> Result<Json<SqlRun>, AppError> {
    let options = RunOptions {
        max_rows: request.max_rows.unwrap_or(MAX_ROWS),
        explain: request.explain,
        ..RunOptions::default()
    };
    let started = std::time::Instant::now();
    let result = run(&state, ctx.get(), &request.sql, options).await;
    tracing::info!(
        user_id = %ctx.user_id,
        chars = request.sql.chars().count(),
        ok = result.is_ok(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "sql report run"
    );
    result.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/reports/sql/run", post(run_sql))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(run_sql), components(schemas(SqlRun, SqlRunRequest)))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_trims_one_semicolon_and_refuses_empty() {
        assert_eq!(normalise("  select 1 ;  ").unwrap(), "select 1");
        assert!(normalise(" ; ").is_err());
        assert!(normalise(&"x".repeat(MAX_SQL_CHARS + 1)).is_err());
    }

    #[test]
    fn referenced_names_reads_words_and_quoted_names_but_not_strings() {
        let names = referenced_names(
            "SELECT a.name FROM Account a JOIN \"Weird \"\"x\" w ON w.id = a.id WHERE a.note = 'contact'",
        );
        assert!(names.contains("account"));
        assert!(names.contains("Weird \"x"));
        assert!(names.contains("name"));
        assert!(!names.contains("contact"), "{names:?}");
    }

    #[test]
    fn inline_binds_writes_values_as_literals() {
        let params = vec!["o'brien".to_owned(), "{a,b}".to_owned()];
        assert_eq!(
            inline_binds(
                "AND (x = $3::text OR y = ANY($4::uuid[]) OR z = $9)",
                3,
                &params
            ),
            "AND (x = 'o''brien'::text OR y = ANY('{a,b}'::uuid[]) OR z = $9)"
        );
        assert_eq!(inline_binds("$1 $10", 1, &["a".to_owned()]), "'a' $10");
    }
}
