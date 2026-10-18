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
    let definition: Value = sqlx::query_scalar(
        "SELECT definition FROM customer_test WHERE id = $1 AND is_active = true",
    )
    .bind(test_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let definition: TestDefinition = serde_json::from_value(definition)
        .map_err(|e| AppError::Validation(format!("the test does not read: {e}")))?;
    let started = chrono::Utc::now();
    let outcome = run_test(state, ctx, &definition).await;
    let run = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO customer_test_run (id, test_id, started_at, finished_at, passed, failures) \
         VALUES ($1, $2, $3, now(), $4, $5)",
    )
    .bind(run)
    .bind(test_id)
    .bind(started)
    .bind(outcome.passed)
    .bind(serde_json::to_value(&outcome.failures).map_err(AppError::internal)?)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok((run, outcome))
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
