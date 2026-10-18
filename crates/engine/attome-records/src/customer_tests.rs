//! Customer tests (roadmap Z15-T12): a builder's given/when/expect check of
//! their own configuration, run through the same mutation primitives a
//! record write uses, inside one transaction that is always rolled back.
//!
//! - `given` records are created as the caller (the setup);
//! - `when` steps (create, update, delete) run as `as_role` when the test
//!   names one, otherwise as the caller, with the same privilege check and
//!   body validation the generic record routes apply first;
//! - `expect` reads attributes back in the same transaction, or names the
//!   error a step must have met (`validation`, `forbidden`, `conflict`,
//!   `not_found`).
//!
//! Nothing a test does is ever committed: the transaction is rolled back on
//! every path, and jobs a write enqueues roll back with it. The run's
//! outcome is recorded afterwards in `customer_test_run`, in its own short
//! transaction.
//!
//! **A role's context** carries the role's privileges and field grants; its
//! record-level scope (tier, teams, ownership) is the caller's, since that
//! is resolved per user. A test about who may see which rows needs a user
//! holding the role.

use std::collections::HashMap;

use attome_core::{EngineState, quote_ident};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::entity_mutation::{DeleteKind, DeleteOrigin, MutationMode};

/// One test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestDefinition {
    /// Run the `when` steps as this role (by name).
    #[serde(default)]
    pub as_role: Option<String>,
    #[serde(default)]
    pub given: Vec<GivenRecord>,
    #[serde(default)]
    pub when: Vec<Step>,
    #[serde(default)]
    pub expect: Vec<Expectation>,
}

/// A record the test starts from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GivenRecord {
    pub entity: String,
    /// The name later steps and expectations use for it.
    #[serde(rename = "ref", default)]
    pub reference: Option<String>,
    pub record: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Create,
    Update,
    Delete,
}

/// One write under test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub op: Op,
    pub entity: String,
    /// The record to update or delete, or the name a create gives its record.
    #[serde(rename = "ref", default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub values: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Validation,
    Forbidden,
    Conflict,
    NotFound,
    Other,
}

/// What must hold after the steps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expectation {
    /// A step met this error.
    Error { error: ErrorKind },
    /// A record's attribute holds this value.
    Value {
        entity: String,
        #[serde(rename = "ref")]
        reference: String,
        attribute: String,
        equals: Value,
    },
}

/// What a run found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TestOutcome {
    pub passed: bool,
    pub failures: Vec<String>,
}

fn kind_of(error: &AppError) -> ErrorKind {
    match error {
        AppError::Validation(_)
        | AppError::FieldValidation(_)
        | AppError::AttributeNotWritable(_)
        | AppError::RuleViolation { .. }
        | AppError::TransitionNotAllowed(_) => ErrorKind::Validation,
        AppError::Forbidden | AppError::FieldLocked { .. } => ErrorKind::Forbidden,
        AppError::Conflict(_)
        | AppError::VersionConflict
        | AppError::VersionConflictAt { .. }
        | AppError::DuplicateDetected { .. } => ErrorKind::Conflict,
        AppError::NotFound => ErrorKind::NotFound,
        _ => ErrorKind::Other,
    }
}

/// The caller's context narrowed to `role`'s privileges and field grants.
async fn role_context(
    tx: &mut attome_db::Tx<'_>,
    caller: &SecurityContext,
    role: &str,
) -> Result<SecurityContext, AppError> {
    let role_id: Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(role)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::Validation(format!("no role named {role}")))?;
    let privileges: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.key FROM privilege p \
         JOIN role_mm_privilege rp ON rp.privilege_ref = p.id \
         WHERE rp.role_ref = $1 AND rp.is_deleted = false AND p.is_active = true",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let fields: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT DISTINCT f.entity_logicalname, f.field_logicalname, f.can_read, f.can_update \
         FROM field_security_profile_field f \
         JOIN role_mm_field_security_profile rp ON rp.profile_ref = f.profile_ref \
         WHERE rp.role_ref = $1 AND rp.is_deleted = false",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let mut context = caller.as_service_principal();
    context.service_principal = false;
    context.is_admin = privileges.iter().any(|p| p == "system.admin");
    context.privileges = privileges.into_iter().collect();
    context.field_grants = fields
        .iter()
        .filter(|f| f.2)
        .map(|(e, f, _, _)| format!("{e}.{f}"))
        .collect();
    context.field_write_grants = fields
        .iter()
        .filter(|f| f.3)
        .map(|(e, f, _, _)| format!("{e}.{f}"))
        .collect();
    context.role_ids = Some(vec![role_id]);
    Ok(context)
}

/// A record's whole row, read in the test's transaction.
async fn read_row(
    tx: &mut attome_db::Tx<'_>,
    entity: &str,
    id: Uuid,
) -> Result<Option<Value>, AppError> {
    let sql = format!(
        "SELECT to_jsonb(t) FROM {} t WHERE t.id = $1",
        quote_ident(entity)
    );
    sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// Values compare as JSON, or as text when either side is a number or a
/// string holding one (a numeric column reads back as a JSON number).
fn same(actual: &Value, expected: &Value) -> bool {
    if actual == expected {
        return true;
    }
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    match (text(actual).parse::<f64>(), text(expected).parse::<f64>()) {
        (Ok(a), Ok(b)) => (a - b).abs() < 1e-9,
        _ => text(actual) == text(expected),
    }
}

struct Run<'a> {
    state: &'a EngineState,
    refs: HashMap<String, (String, Uuid)>,
}

impl Run<'_> {
    async fn create(
        &mut self,
        tx: &mut attome_db::Tx<'_>,
        ctx: &SecurityContext,
        entity: &str,
        values: &Map<String, Value>,
        reference: Option<&str>,
    ) -> Result<Uuid, AppError> {
        ctx.require(entity, "create")?;
        let meta = self
            .state
            .entities
            .load()
            .get(entity)
            .cloned()
            .ok_or(AppError::NotFound)?;
        crate::entity_mutation::validate_body(&meta.attrs, values, true)?;
        let actor = crate::mutation_ring::MutationActor::fetch(self.state, ctx.user_id).await;
        let result = crate::entity_mutation::create_one(
            tx,
            self.state,
            ctx,
            entity,
            &meta.attrs,
            values,
            ctx.user_id,
            actor.org_ref,
            MutationMode::Strict,
        )
        .await?;
        if let Some(name) = reference {
            self.refs
                .insert(name.to_owned(), (entity.to_owned(), result.record_id));
        }
        Ok(result.record_id)
    }

    fn record(&self, reference: Option<&str>, entity: &str) -> Result<Uuid, AppError> {
        let name = reference.ok_or_else(|| {
            AppError::Validation(format!("an update or delete of {entity} names its ref"))
        })?;
        self.refs
            .get(name)
            .map(|(_, id)| *id)
            .ok_or_else(|| AppError::Validation(format!("no record named {name}")))
    }

    async fn step(
        &mut self,
        tx: &mut attome_db::Tx<'_>,
        ctx: &SecurityContext,
        step: &Step,
    ) -> Result<(), AppError> {
        match step.op {
            Op::Create => {
                self.create(
                    tx,
                    ctx,
                    &step.entity,
                    &step.values,
                    step.reference.as_deref(),
                )
                .await?;
            }
            Op::Update => {
                ctx.require(&step.entity, "update")?;
                let id = self.record(step.reference.as_deref(), &step.entity)?;
                let meta = self
                    .state
                    .entities
                    .load()
                    .get(&step.entity)
                    .cloned()
                    .ok_or(AppError::NotFound)?;
                crate::entity_mutation::validate_body(&meta.attrs, &step.values, false)?;
                let version = read_row(tx, &step.entity, id)
                    .await?
                    .and_then(|row| row["row_version"].as_i64())
                    .ok_or(AppError::NotFound)?;
                crate::entity_mutation::update_one(
                    tx,
                    self.state,
                    ctx,
                    &step.entity,
                    meta.entity_id,
                    id,
                    &meta.attrs,
                    &step.values,
                    ctx.user_id,
                    version,
                    MutationMode::Strict,
                )
                .await?;
            }
            Op::Delete => {
                ctx.require(&step.entity, "delete")?;
                let id = self.record(step.reference.as_deref(), &step.entity)?;
                let entities = self.state.entities.load();
                let meta = entities.get(&step.entity).ok_or(AppError::NotFound)?;
                if meta.is_append_only {
                    return Err(AppError::Forbidden);
                }
                let dependents = entities.dependents_of(meta.entity_id);
                crate::entity_mutation::delete_one(
                    tx,
                    &step.entity,
                    &dependents,
                    id,
                    ctx.user_id,
                    None,
                    &DeleteOrigin {
                        kind: DeleteKind::Request,
                        operation_id: "customer-test".into(),
                        reason: None,
                    },
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// Runs one test as `ctx` in a transaction that is always rolled back.
pub async fn run_test(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &TestDefinition,
) -> TestOutcome {
    let mut failures = Vec::new();
    let mut tx = match attome_db::tx::begin(&state.base.db).await {
        Ok(tx) => tx,
        Err(e) => {
            return TestOutcome {
                passed: false,
                failures: vec![format!("could not start: {e}")],
            };
        }
    };
    let mut run = Run {
        state,
        refs: HashMap::new(),
    };
    let mut errors: Vec<ErrorKind> = Vec::new();
    let mut ready = true;
    for (n, given) in definition.given.iter().enumerate() {
        if let Err(e) = run
            .create(
                &mut tx,
                ctx,
                &given.entity,
                &given.record,
                given.reference.as_deref(),
            )
            .await
        {
            failures.push(format!("given {} ({}): {e}", n + 1, given.entity));
            ready = false;
            break;
        }
    }
    if ready {
        let actor = match &definition.as_role {
            Some(role) => match role_context(&mut tx, ctx, role).await {
                Ok(context) => Some(context),
                Err(e) => {
                    failures.push(format!("as_role {role}: {e}"));
                    None
                }
            },
            None => None,
        };
        if failures.is_empty() {
            let acting = actor.as_ref().unwrap_or(ctx);
            for step in &definition.when {
                // A savepoint, so a refused step leaves the rest runnable.
                let outcome = match sqlx::Acquire::begin(&mut *tx).await {
                    Ok(mut inner) => {
                        let result = run.step(&mut inner, acting, step).await;
                        let closed = if result.is_ok() {
                            attome_db::tx::commit(inner).await
                        } else {
                            inner.rollback().await.map_err(AppError::internal)
                        };
                        result.and(closed)
                    }
                    Err(e) => Err(AppError::internal(e)),
                };
                if let Err(e) = outcome {
                    errors.push(kind_of(&e));
                    // An error no expectation names is a failure.
                    let kind = kind_of(&e);
                    if !definition
                        .expect
                        .iter()
                        .any(|x| matches!(x, Expectation::Error { error } if *error == kind))
                    {
                        failures.push(format!("{:?} {}: {e}", step.op, step.entity));
                    }
                }
            }
            for expectation in &definition.expect {
                match expectation {
                    Expectation::Error { error } => {
                        if !errors.contains(error) {
                            failures.push(format!("expected a {error:?} error, none came"));
                        }
                    }
                    Expectation::Value {
                        entity,
                        reference,
                        attribute,
                        equals,
                    } => {
                        let Some((_, id)) = run.refs.get(reference) else {
                            failures.push(format!("no record named {reference}"));
                            continue;
                        };
                        match read_row(&mut tx, entity, *id).await {
                            Ok(Some(row)) => {
                                let actual = &row[attribute.as_str()];
                                if !same(actual, equals) {
                                    failures.push(format!(
                                        "{entity} {reference}.{attribute} is {actual}, expected {equals}"
                                    ));
                                }
                            }
                            Ok(None) => failures.push(format!("{entity} {reference} is gone")),
                            Err(e) => failures.push(format!("reading {entity} {reference}: {e}")),
                        }
                    }
                }
            }
        }
    }
    // Never committed, whatever happened above.
    if let Err(e) = tx.rollback().await {
        failures.push(format!("rolling back: {e}"));
    }
    TestOutcome {
        passed: failures.is_empty(),
        failures,
    }
}

/// Runs a stored test and records the run; the outcome and the run's id.
pub async fn run_and_record(
    state: &EngineState,
    ctx: &SecurityContext,
    test_id: Uuid,
) -> Result<(Uuid, TestOutcome), AppError> {
    let definition = load_definition(&state.base.db, test_id).await?;
    let started = chrono::Utc::now();
    let outcome = run_test(state, ctx, &definition).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let run = insert_run(&mut tx, test_id, started, &outcome).await?;
    attome_db::tx::commit(tx).await?;
    Ok((run, outcome))
}

// ── The publish guard (roadmap Z15-T14) ────────────────────────────────────

/// The deployment setting that turns the publish guard on (off by default).
pub const REQUIRE_PASS_SETTING: &str = "customer_tests.require_pass_before_publish";

/// Whether publishing must first pass the blocking tests.
pub fn require_pass(state: &EngineState) -> bool {
    let Some(descriptor) = attome_core::setting_registry().get(REQUIRE_PASS_SETTING) else {
        return false;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_bool().unwrap_or(false)
}

/// With the guard on, runs every active blocking test as `ctx` and refuses
/// with `customer_tests_failed` (naming them) when any fails; a definition
/// that no longer reads counts as a failure. With it off, does nothing.
/// The runs are not recorded: the guard is a check, not a test run.
pub async fn publish_guard(state: &EngineState, ctx: &SecurityContext) -> Result<(), AppError> {
    if !require_pass(state) {
        return Ok(());
    }
    let mut failed = Vec::new();
    for (_, name, definition) in active_tests(&state.base.db, true).await? {
        let passed = match definition {
            Ok(definition) => run_test(state, ctx, &definition).await.passed,
            Err(_) => false,
        };
        if !passed {
            failed.push(name);
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(AppError::CustomerTestsFailed(failed))
    }
}

// ── Storage (roadmap Z15-T13): the admin routes' reads and writes ──────────

/// A stored test.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct CustomerTest {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// The given/when/expect definition.
    #[schema(value_type = Object)]
    pub definition: Value,
    /// A blocking test can stop a publish (Z15-T14).
    pub blocking: bool,
    pub is_active: bool,
    pub row_version: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<Uuid>,
    /// The latest run's result, when the test has run.
    pub last_passed: Option<bool>,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A test to create, or one entry of an import.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CustomerTestBody {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[schema(value_type = Object)]
    pub definition: Value,
    #[serde(default)]
    pub blocking: bool,
}

/// The fields a PATCH may change; an absent field keeps its value.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct CustomerTestPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub definition: Option<Value>,
    pub blocking: Option<bool>,
    pub is_active: Option<bool>,
}

/// One recorded run.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct CustomerTestRun {
    pub id: Uuid,
    pub test_id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub passed: Option<bool>,
    /// The failure lines, empty when it passed.
    #[schema(value_type = Option<Vec<String>>)]
    pub failures: Option<Value>,
}

/// The portable form of a deployment's tests: `GET /export` answers it and
/// `POST /import` reads it. Tests only; configuration travels as changesets.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CustomerTestExport {
    /// Always `attome-customer-tests/v1`.
    pub format: String,
    pub tests: Vec<CustomerTestBody>,
}

/// The export document's format tag.
pub const EXPORT_FORMAT: &str = "attome-customer-tests/v1";

/// The most tests one import may carry.
pub const MAX_IMPORT: usize = 500;

/// Checks a test's name and that its definition reads.
pub fn validate(name: &str, definition: &Value) -> Result<TestDefinition, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation(
            "a customer test needs a name of 1 to 200 characters".into(),
        ));
    }
    serde_json::from_value(definition.clone())
        .map_err(|e| AppError::Validation(format!("the test definition does not read: {e}")))
}

const TEST_COLUMNS: &str = "t.id, t.name, t.description, t.definition, t.blocking, t.is_active, \
     t.row_version, t.created_at, t.updated_at, t.created_by, \
     r.passed AS last_passed, r.started_at AS last_run_at";

const LAST_RUN: &str = "LEFT JOIN LATERAL (SELECT passed, started_at FROM customer_test_run \
     WHERE test_id = t.id ORDER BY started_at DESC, id DESC LIMIT 1) r ON true";

/// A page of tests, by name, and the total.
pub async fn list_tests(
    db: &attome_db::DbPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<CustomerTest>, i64), AppError> {
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM customer_test")
        .fetch_one(db)
        .await
        .map_err(attome_db::classify)?;
    let items = sqlx::query_as(&format!(
        "SELECT {TEST_COLUMNS} FROM customer_test t {LAST_RUN} \
         ORDER BY t.name, t.id LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    Ok((items, total))
}

async fn fetch_test<'e>(
    exec: impl sqlx::PgExecutor<'e>,
    id: Uuid,
) -> Result<CustomerTest, AppError> {
    sqlx::query_as(&format!(
        "SELECT {TEST_COLUMNS} FROM customer_test t {LAST_RUN} WHERE t.id = $1"
    ))
    .bind(id)
    .fetch_optional(exec)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)
}

/// One test.
pub async fn get_test(db: &attome_db::DbPool, id: Uuid) -> Result<CustomerTest, AppError> {
    fetch_test(db, id).await
}

/// The latest runs of a test, newest first.
pub async fn list_runs(
    db: &attome_db::DbPool,
    test_id: Uuid,
    limit: i64,
) -> Result<Vec<CustomerTestRun>, AppError> {
    sqlx::query_as(
        "SELECT id, test_id, started_at, finished_at, passed, failures FROM customer_test_run \
         WHERE test_id = $1 ORDER BY started_at DESC, id DESC LIMIT $2",
    )
    .bind(test_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

/// Creates a test in the caller's transaction.
pub async fn insert_test(
    conn: &mut sqlx::PgConnection,
    body: &CustomerTestBody,
    by: Uuid,
) -> Result<CustomerTest, AppError> {
    validate(&body.name, &body.definition)?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO customer_test (id, name, description, definition, blocking, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(&body.description)
    .bind(&body.definition)
    .bind(body.blocking)
    .bind(by)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    fetch_test(&mut *conn, id).await
}

/// Changes a test at `row_version` (409 `version_conflict` when stale).
pub async fn update_test(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    row_version: i64,
    patch: &CustomerTestPatch,
) -> Result<CustomerTest, AppError> {
    let current = fetch_test(&mut *conn, id).await?;
    let name = patch.name.as_deref().unwrap_or(&current.name);
    let definition = patch.definition.as_ref().unwrap_or(&current.definition);
    validate(name, definition)?;
    let updated = sqlx::query(
        "UPDATE customer_test SET name = $3, description = $4, definition = $5, blocking = $6, \
                is_active = $7, row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND row_version = $2",
    )
    .bind(id)
    .bind(row_version)
    .bind(name.trim())
    .bind(patch.description.as_ref().or(current.description.as_ref()))
    .bind(definition)
    .bind(patch.blocking.unwrap_or(current.blocking))
    .bind(patch.is_active.unwrap_or(current.is_active))
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::VersionConflict);
    }
    fetch_test(&mut *conn, id).await
}

/// Deletes a test and its runs; `row_version`, when given, must be current.
pub async fn delete_test(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    row_version: Option<i64>,
) -> Result<(), AppError> {
    let deleted = sqlx::query(
        "DELETE FROM customer_test WHERE id = $1 AND ($2::bigint IS NULL OR row_version = $2)",
    )
    .bind(id)
    .bind(row_version)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    if deleted.rows_affected() == 0 {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM customer_test WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *conn)
                .await
                .map_err(attome_db::classify)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    }
    Ok(())
}

/// A stored active test's definition.
pub async fn load_definition(
    db: &attome_db::DbPool,
    test_id: Uuid,
) -> Result<TestDefinition, AppError> {
    let definition: Value = sqlx::query_scalar(
        "SELECT definition FROM customer_test WHERE id = $1 AND is_active = true",
    )
    .bind(test_id)
    .fetch_optional(db)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)?;
    serde_json::from_value(definition)
        .map_err(|e| AppError::Validation(format!("the test does not read: {e}")))
}

/// Every active test (`blocking_only`: just the blocking ones), with its
/// definition, by name. A definition that no longer reads comes back as an
/// `Err` so the run reports it rather than skipping the test.
pub async fn active_tests(
    db: &attome_db::DbPool,
    blocking_only: bool,
) -> Result<Vec<(Uuid, String, Result<TestDefinition, String>)>, AppError> {
    let rows: Vec<(Uuid, String, Value)> = sqlx::query_as(
        "SELECT id, name, definition FROM customer_test \
          WHERE is_active = true AND (blocking OR NOT $1) ORDER BY name, id",
    )
    .bind(blocking_only)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, definition)| {
            let read = serde_json::from_value(definition).map_err(|e| e.to_string());
            (id, name, read)
        })
        .collect())
}

/// Records one run in the caller's transaction; the run's id.
pub async fn insert_run(
    conn: &mut sqlx::PgConnection,
    test_id: Uuid,
    started: chrono::DateTime<chrono::Utc>,
    outcome: &TestOutcome,
) -> Result<Uuid, AppError> {
    let run = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO customer_test_run (id, test_id, started_at, finished_at, passed, failures) \
         VALUES ($1, $2, $3, now(), $4, $5)",
    )
    .bind(run)
    .bind(test_id)
    .bind(started)
    .bind(outcome.passed)
    .bind(serde_json::to_value(&outcome.failures).map_err(AppError::internal)?)
    .execute(conn)
    .await
    .map_err(attome_db::classify)?;
    Ok(run)
}

/// Every test, active or not, in the portable form.
pub async fn export_tests(db: &attome_db::DbPool) -> Result<CustomerTestExport, AppError> {
    let rows: Vec<(String, Option<String>, Value, bool)> = sqlx::query_as(
        "SELECT name, description, definition, blocking FROM customer_test ORDER BY name, id",
    )
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    Ok(CustomerTestExport {
        format: EXPORT_FORMAT.into(),
        tests: rows
            .into_iter()
            .map(
                |(name, description, definition, blocking)| CustomerTestBody {
                    name,
                    description,
                    definition,
                    blocking,
                },
            )
            .collect(),
    })
}

/// How an import went.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct CustomerTestImportResult {
    pub created: usize,
    /// Tests whose name was already here: their definition was replaced.
    pub updated: usize,
}

/// Imports `document` in the caller's transaction: a test whose name is
/// already here is replaced (its runs stay), any other is created. Every
/// entry is checked before anything is written, so a bad entry writes none.
pub async fn import_tests(
    conn: &mut sqlx::PgConnection,
    document: &CustomerTestExport,
    by: Uuid,
) -> Result<CustomerTestImportResult, AppError> {
    if document.format != EXPORT_FORMAT {
        return Err(AppError::Validation(format!(
            "an import is a {EXPORT_FORMAT} document"
        )));
    }
    if document.tests.len() > MAX_IMPORT {
        return Err(AppError::Validation(format!(
            "an import carries at most {MAX_IMPORT} tests"
        )));
    }
    let mut names = std::collections::HashSet::new();
    for (n, test) in document.tests.iter().enumerate() {
        validate(&test.name, &test.definition)
            .map_err(|e| AppError::Validation(format!("test {}: {e}", n + 1)))?;
        if !names.insert(test.name.trim().to_owned()) {
            return Err(AppError::Validation(format!(
                "test {}: the name {} is used twice",
                n + 1,
                test.name.trim()
            )));
        }
    }
    let mut result = CustomerTestImportResult::default();
    for test in &document.tests {
        let replaced = sqlx::query(
            "UPDATE customer_test SET description = $2, definition = $3, blocking = $4, \
                    row_version = row_version + 1, updated_at = now() \
              WHERE name = $1",
        )
        .bind(test.name.trim())
        .bind(&test.description)
        .bind(&test.definition)
        .bind(test.blocking)
        .execute(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
        if replaced.rows_affected() > 0 {
            result.updated += 1;
        } else {
            insert_test(&mut *conn, test, by).await?;
            result.created += 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_definition_reads() {
        let definition: TestDefinition = serde_json::from_value(json!({
            "as_role": "Accounts Receivable",
            "given": [{ "entity": "account", "ref": "a", "record": { "name": "Acme" } }],
            "when": [{ "op": "update", "entity": "account", "ref": "a", "values": { "name": "Acme 2" } }],
            "expect": [
                { "entity": "account", "ref": "a", "attribute": "name", "equals": "Acme 2" },
                { "error": "forbidden" }
            ]
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(definition.when[0].op, Op::Update);
        assert!(matches!(
            definition.expect[1],
            Expectation::Error {
                error: ErrorKind::Forbidden
            }
        ));
    }

    #[test]
    fn numbers_compare_by_value() {
        assert!(same(&json!(115), &json!("115.00")));
        assert!(same(&json!("open"), &json!("open")));
        assert!(!same(&json!("open"), &json!("closed")));
    }
}
