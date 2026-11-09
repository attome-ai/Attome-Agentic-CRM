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
//! - T7-T1: `expect` may also state a permission (`{"entity", "action",
//!   "allowed"}`: whether the acting role or caller holds the entity
//!   privilege) or a flow's outcome (`{"flow", "entity", "ref", "status",
//!   "reaches"}`: the published workflow simulated on the record as the
//!   test left it, through `EngineState::workflow_simulator`; nothing it
//!   would do happens).
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
    /// T7-T4: an acceptance script's steps, which a person runs and marks
    /// passed or failed. A test with a checklist has no given, when or
    /// expect, and no automatic run picks it up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checklist: Vec<String>,
}

impl TestDefinition {
    /// T7-T4: whether a person runs it (it has a checklist).
    pub fn is_acceptance_script(&self) -> bool {
        !self.checklist.is_empty()
    }
}

/// T7-T4: the most steps an acceptance script has.
pub const MAX_CHECKLIST_STEPS: usize = 100;

/// T7-T4: a SQL condition true for a `customer_test` row that runs by
/// itself (no checklist), for every automatic runner.
pub const AUTOMATED: &str = "CASE WHEN jsonb_typeof(definition->'checklist') = 'array' \
     THEN jsonb_array_length(definition->'checklist') = 0 ELSE true END";

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
    /// T7-T1: the acting role or caller may, or may not, do `action`
    /// (`read`, `create`, `update`, `delete`) on `entity`.
    Access {
        entity: String,
        action: String,
        allowed: bool,
    },
    /// T7-T1: the published workflow `flow`, simulated on the record, ends
    /// with `status` (`completed`, `would_wait`, `failed`) when given and
    /// reaches every node in `reaches`.
    Flow {
        flow: String,
        entity: String,
        #[serde(rename = "ref")]
        reference: String,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        reaches: Vec<String>,
    },
}

/// The actions an access expectation names.
const ACTIONS: [&str; 4] = ["read", "create", "update", "delete"];

/// What a flow expectation finds wrong with a simulation. Pure.
pub fn flow_failures(
    flow: &str,
    status: Option<&str>,
    reaches: &[String],
    simulated: &attome_core::WorkflowSimulation,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(expected) = status
        && expected != simulated.status
    {
        out.push(format!(
            "flow {flow} ended {}, expected {expected}",
            simulated.status
        ));
    }
    for node in reaches {
        if !simulated.reached.contains(node) {
            out.push(format!("flow {flow} did not reach {node}"));
        }
    }
    out
}

/// What a run found.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TestOutcome {
    pub passed: bool,
    pub failures: Vec<String>,
    /// M4-T2: per flow the test simulated, the nodes it reached.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub reached: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
}

/// M4-T2: draft flow graphs by workflow logical name. A test that simulates
/// one of these flows runs it on the draft, not on its published version.
pub type DraftFlows = std::collections::BTreeMap<String, Value>;

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

/// X3-T2: `values` with every `{"$ref": "<name>"}` replaced by the id of
/// the record the test named so, so a step can point a lookup at a record
/// made earlier, and `{"$ref": "@caller"}` by `caller`, the person the test
/// runs as (a requester or an owner). An unknown name is a validation
/// error. Pure.
pub fn resolve_refs(
    values: &Map<String, Value>,
    refs: &HashMap<String, (String, Uuid)>,
    caller: Uuid,
) -> Result<Map<String, Value>, AppError> {
    values
        .iter()
        .map(|(key, value)| {
            let resolved = match value
                .as_object()
                .filter(|o| o.len() == 1)
                .and_then(|o| o.get("$ref"))
            {
                Some(Value::String(name)) if name == "@caller" => Value::String(caller.to_string()),
                Some(Value::String(name)) => refs
                    .get(name)
                    .map(|(_, id)| Value::String(id.to_string()))
                    .ok_or_else(|| AppError::Validation(format!("no record named {name}")))?,
                _ => value.clone(),
            };
            Ok((key.clone(), resolved))
        })
        .collect()
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
        let values = &resolve_refs(values, &self.refs, ctx.user_id)?;
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
                let values = resolve_refs(&step.values, &self.refs, ctx.user_id)?;
                crate::entity_mutation::validate_body(&meta.attrs, &values, false)?;
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
                    &values,
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
    run_test_on(state, ctx, definition, &DraftFlows::new()).await
}

/// [`run_test`], with the flows in `drafts` simulated on their draft graph.
pub async fn run_test_on(
    state: &EngineState,
    ctx: &SecurityContext,
    definition: &TestDefinition,
    drafts: &DraftFlows,
) -> TestOutcome {
    if definition.is_acceptance_script() {
        return TestOutcome {
            passed: false,
            failures: vec![
                "an acceptance script is run by a person, from the acceptance scripts screen"
                    .to_owned(),
            ],
            ..TestOutcome::default()
        };
    }
    let mut failures = Vec::new();
    let mut reached =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    let mut tx = match attome_db::tx::begin(&state.base.db).await {
        Ok(tx) => tx,
        Err(e) => {
            return TestOutcome {
                passed: false,
                failures: vec![format!("could not start: {e}")],
                ..TestOutcome::default()
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
                    Expectation::Access {
                        entity,
                        action,
                        allowed,
                    } => {
                        if !ACTIONS.contains(&action.as_str()) {
                            failures.push(format!(
                                "access {entity}.{action}: the action is read, create, update or delete"
                            ));
                            continue;
                        }
                        let holds = acting.require(entity, action).is_ok();
                        if holds != *allowed {
                            failures.push(format!(
                                "{entity}.{action} is {}, expected {}",
                                if holds { "allowed" } else { "refused" },
                                if *allowed { "allowed" } else { "refused" }
                            ));
                        }
                    }
                    Expectation::Flow {
                        flow,
                        entity,
                        reference,
                        status,
                        reaches,
                    } => {
                        let Some(simulator) = state.workflow_simulator.as_ref() else {
                            failures.push(format!("flow {flow}: workflows are not available here"));
                            continue;
                        };
                        let Some((_, id)) = run.refs.get(reference) else {
                            failures.push(format!("no record named {reference}"));
                            continue;
                        };
                        let record = match read_row(&mut tx, entity, *id).await {
                            Ok(Some(row)) => row,
                            Ok(None) => {
                                failures.push(format!("{entity} {reference} is gone"));
                                continue;
                            }
                            Err(e) => {
                                failures.push(format!("reading {entity} {reference}: {e}"));
                                continue;
                            }
                        };
                        let payload = serde_json::json!({
                            "entity": entity,
                            "record_id": id.to_string(),
                            "record": record,
                        });
                        let simulated = match drafts.get(flow) {
                            Some(graph) => simulator.simulate_graph(state, graph, payload).await,
                            None => simulator.simulate(state, flow, payload).await,
                        };
                        match simulated {
                            Ok(simulated) => {
                                failures.extend(flow_failures(
                                    flow,
                                    status.as_deref(),
                                    reaches,
                                    &simulated,
                                ));
                                reached
                                    .entry(flow.clone())
                                    .or_default()
                                    .extend(simulated.reached);
                            }
                            Err(e) => failures.push(format!("flow {flow}: {e}")),
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
        reached,
    }
}

/// T7-T2: what a change can affect, or what a test touches: entities by
/// logical name and flows by their workflow's logical name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Impact {
    pub entities: std::collections::BTreeSet<String>,
    pub flows: std::collections::BTreeSet<String>,
}

impl Impact {
    /// Whether a test touching `self` can be affected by `changed`. Pure.
    pub fn meets(&self, changed: &Impact) -> bool {
        !self.entities.is_disjoint(&changed.entities) || !self.flows.is_disjoint(&changed.flows)
    }
}

/// The entities and flows a test touches: every entity its records, steps
/// and expectations name, and every flow it simulates. Pure.
pub fn touches(definition: &TestDefinition) -> Impact {
    let mut out = Impact::default();
    for given in &definition.given {
        out.entities.insert(given.entity.clone());
    }
    for step in &definition.when {
        out.entities.insert(step.entity.clone());
    }
    for expectation in &definition.expect {
        match expectation {
            Expectation::Error { .. } => {}
            Expectation::Value { entity, .. } | Expectation::Access { entity, .. } => {
                out.entities.insert(entity.clone());
            }
            Expectation::Flow { flow, entity, .. } => {
                out.entities.insert(entity.clone());
                out.flows.insert(flow.clone());
            }
        }
    }
    out
}

/// T7-T2: what publishing one metadata object can affect, from the L5
/// reference graph (`metadata_reference`, replaced on every save): the
/// entities the object reads, writes or triggers on, the entity itself when
/// it is one, and the flow itself when it is a workflow.
pub async fn publish_impact(
    db: &attome_db::DbPool,
    kind: &str,
    id: Uuid,
    logicalname: Option<&str>,
) -> Result<Impact, AppError> {
    let referenced: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT to_entity FROM metadata_reference \
          WHERE from_kind = $1 AND from_ref = $2 AND position(':' in to_entity) = 0",
    )
    .bind(kind)
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let mut out = Impact {
        entities: referenced.into_iter().collect(),
        flows: std::collections::BTreeSet::new(),
    };
    if let Some(name) = logicalname.filter(|n| !n.is_empty()) {
        match kind {
            "entity" => {
                out.entities.insert(name.to_owned());
            }
            "workflow" | "flow" => {
                out.flows.insert(name.to_owned());
            }
            _ => {}
        }
    }
    Ok(out)
}

/// One test's result in a publish preview.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AffectedTestResult {
    pub id: Uuid,
    pub name: String,
    pub blocking: bool,
    pub passed: bool,
    pub failures: Vec<String>,
}

/// T7-T2: every active test a change can affect, run as `ctx`.
pub async fn run_affected(
    state: &EngineState,
    ctx: &SecurityContext,
    changed: &Impact,
) -> Result<Vec<AffectedTestResult>, AppError> {
    let blocking: std::collections::HashSet<Uuid> = active_tests(&state.base.db, true)
        .await?
        .into_iter()
        .map(|(id, _, _)| id)
        .collect();
    let mut out = Vec::new();
    for (id, name, definition) in active_tests(&state.base.db, false).await? {
        let outcome = match definition {
            Ok(definition) if touches(&definition).meets(changed) => {
                run_test(state, ctx, &definition).await
            }
            Ok(_) => continue,
            Err(e) => TestOutcome {
                passed: false,
                failures: vec![format!("the definition no longer reads: {e}")],
                ..TestOutcome::default()
            },
        };
        out.push(AffectedTestResult {
            id,
            blocking: blocking.contains(&id),
            name,
            passed: outcome.passed,
            failures: outcome.failures,
        });
    }
    Ok(out)
}

/// T7-T2: [`publish_guard`] for a change whose impact is known: only the
/// blocking tests that change can affect run.
pub async fn publish_guard_for(
    state: &EngineState,
    ctx: &SecurityContext,
    changed: &Impact,
) -> Result<(), AppError> {
    publish_guard_on(state, ctx, changed, &DraftFlows::new()).await
}

/// M4-T2: [`publish_guard_for`], with the flows in `drafts` simulated on the
/// draft about to go live.
pub async fn publish_guard_on(
    state: &EngineState,
    ctx: &SecurityContext,
    changed: &Impact,
    drafts: &DraftFlows,
) -> Result<(), AppError> {
    if !require_pass(state) {
        return Ok(());
    }
    let mut failed = Vec::new();
    for (_, name, definition) in active_tests(&state.base.db, true).await? {
        let passed = match definition {
            Ok(definition) if touches(&definition).meets(changed) => {
                run_test_on(state, ctx, &definition, drafts).await.passed
            }
            Ok(_) => continue,
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

/// M4-T2: a flow's saved test cases (every active test that simulates it)
/// run on `graph`, and which of `nodes` they reached.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct FlowCoverage {
    pub tests: Vec<AffectedTestResult>,
    /// The nodes some test reached, in graph order.
    pub covered: Vec<String>,
    /// The nodes no test reached, in graph order: the paths still untested.
    pub uncovered: Vec<String>,
}

/// M4-T2: runs `flow`'s test cases on `graph` (its draft or published
/// graph), as `ctx`, nothing committed, and reports which of `nodes` (the
/// graph's node ids) no case reached.
pub async fn flow_coverage(
    state: &EngineState,
    ctx: &SecurityContext,
    flow: &str,
    graph: &Value,
    nodes: Vec<String>,
) -> Result<FlowCoverage, AppError> {
    let blocking: std::collections::HashSet<Uuid> = active_tests(&state.base.db, true)
        .await?
        .into_iter()
        .map(|(id, _, _)| id)
        .collect();
    let drafts = DraftFlows::from([(flow.to_owned(), graph.clone())]);
    let mut tests = Vec::new();
    let mut reached = std::collections::BTreeSet::new();
    for (id, name, definition) in active_tests(&state.base.db, false).await? {
        let Ok(definition) = definition else { continue };
        if !touches(&definition).flows.contains(flow) {
            continue;
        }
        let mut outcome = run_test_on(state, ctx, &definition, &drafts).await;
        if let Some(nodes) = outcome.reached.remove(flow) {
            reached.extend(nodes);
        }
        tests.push(AffectedTestResult {
            id,
            blocking: blocking.contains(&id),
            name,
            passed: outcome.passed,
            failures: outcome.failures,
        });
    }
    let (covered, uncovered) = split_coverage(nodes, &reached);
    Ok(FlowCoverage {
        tests,
        covered,
        uncovered,
    })
}

/// `nodes` split into those in `reached` and those not, order kept. Pure.
pub fn split_coverage(
    nodes: Vec<String>,
    reached: &std::collections::BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    nodes.into_iter().partition(|n| reached.contains(n))
}

/// T7-T4: a test drafted from one record the caller can read, as it stands:
/// `given` re-creates it from its copyable fields (as a copy would: no
/// system, numbered, file, computed or engine-set field), and `expect`
/// checks each of those fields still holds its value once saved, so a rule,
/// default or flow that would change it shows. The builder edits it from
/// there. Its suggested name, and the definition.
pub async fn draft_from_record(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record_id: Uuid,
) -> Result<(String, Value), AppError> {
    let record = crate::entity_crud::read_record(state, ctx, entity, record_id).await?;
    let data = record.data().as_object().cloned().unwrap_or_default();
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .ok_or(AppError::NotFound)?;
    let (body, _) =
        crate::entity_crud::clone::copyable(state, entity, &attrs, &data, &Map::new()).await?;
    let expect: Vec<Value> = body
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(attribute, value)| {
            serde_json::json!({
                "entity": entity, "ref": "record", "attribute": attribute, "equals": value
            })
        })
        .collect();
    let definition = serde_json::json!({
        "given": [{ "entity": entity, "ref": "record", "record": body }],
        "expect": expect,
    });
    let label = data
        .get("name")
        .or_else(|| data.get("title"))
        .and_then(Value::as_str)
        .map_or_else(|| record_id.to_string(), str::to_owned);
    let name: String = format!("{entity}: {label} as saved")
        .chars()
        .take(200)
        .collect();
    Ok((name, definition))
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

// ── Nightly checks (roadmap T7-T3) ──────────────────────────────────────────

/// The live-safe tests one night runs at most.
const NIGHTLY_LIMIT: i64 = 500;

/// What one night's run of the live-safe tests found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NightlyReport {
    pub ran: usize,
    /// The tests that failed, by name.
    pub failed: Vec<String>,
    /// The tests newly flagged flaky, by name.
    pub flaky: Vec<String>,
}

/// A live-safe test: id, name, author, flaky since.
type LiveSafeRow = (
    Uuid,
    String,
    Option<Uuid>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// T7-T3: every active live-safe test, run as the person who wrote it
/// against the live configuration (a test never commits, so the check is
/// read-only), recorded as a scheduled run. A test whose runs on one test
/// version and one configuration version both passed and failed is flagged
/// flaky (`flaky_since`) until someone edits it. The caller alerts on the
/// report.
pub async fn run_live_safe(state: &EngineState) -> Result<NightlyReport, AppError> {
    let tests: Vec<LiveSafeRow> = sqlx::query_as(&format!(
        "SELECT id, name, created_by, flaky_since FROM customer_test \
              WHERE is_active AND live_safe AND {AUTOMATED} ORDER BY name, id LIMIT $1"
    ))
    .bind(NIGHTLY_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let mut report = NightlyReport::default();
    for (id, name, author, flaky_since) in tests {
        let Some(author) = author else {
            tracing::warn!(test = %id, "customer test: a live-safe test has no author to run as");
            continue;
        };
        let ctx = match attome_security::resolve_uncached(&state.base.db, author).await {
            Ok(ctx) => ctx,
            Err(e) => {
                tracing::warn!(test = %id, error = %e, "customer test: its author cannot run it");
                continue;
            }
        };
        let (run, outcome) = run_and_record(state, &ctx, id).await?;
        sqlx::query("UPDATE customer_test_run SET scheduled = true WHERE id = $1")
            .bind(run)
            .execute(&state.base.db)
            .await
            .map_err(attome_db::classify)?;
        report.ran += 1;
        if !outcome.passed {
            report.failed.push(name.clone());
        }
        if flaky_since.is_none() && is_flaky(&state.base.db, id, run).await? {
            sqlx::query(
                "UPDATE customer_test SET flaky_since = now() WHERE id = $1 AND flaky_since IS NULL",
            )
            .bind(id)
            .execute(&state.base.db)
            .await
            .map_err(attome_db::classify)?;
            report.flaky.push(name);
        }
    }
    Ok(report)
}

/// Whether the runs of `test` on the same test and configuration version as
/// `run` both passed and failed.
async fn is_flaky(db: &attome_db::DbPool, test: Uuid, run: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT COALESCE(bool_or(r.passed) AND NOT bool_and(r.passed), false) \
           FROM customer_test_run r \
           JOIN customer_test_run this ON this.id = $2 \
          WHERE r.test_id = $1 AND r.passed IS NOT NULL \
            AND r.test_version = this.test_version AND r.config_version = this.config_version",
    )
    .bind(test)
    .bind(run)
    .fetch_one(db)
    .await
    .map_err(attome_db::classify)
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
    /// T7-T3: run every night against the live configuration.
    pub live_safe: bool,
    /// T7-T3: when its runs first both passed and failed on one test and
    /// configuration version; cleared when the test is edited.
    pub flaky_since: Option<chrono::DateTime<chrono::Utc>>,
    /// The latest run's result, when the test has run.
    pub last_passed: Option<bool>,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Y11-T13: the kind of the customisation the test guards.
    pub target_kind: Option<String>,
    /// Y11-T13: that customisation's key.
    pub target_key: Option<String>,
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
    /// T7-T3: run every night against the live configuration.
    #[serde(default)]
    pub live_safe: bool,
    /// Y11-T13: the customisation the test guards, if it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TestTarget>,
}

/// Y11-T13: the customisation a test guards: a model object by kind and key
/// (`form` / `account.main`, `extension` / `erp_sync`, `entity` /
/// `account`). Kept as text: the test survives the object being renamed or
/// removed, and then reads as guarding something that is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TestTarget {
    pub kind: String,
    pub key: String,
}

/// The longest target key accepted.
pub const MAX_TARGET_KEY: usize = 200;

/// A target is a lower-case kind (letters, digits, `_`, at most 63) and a
/// key of 1 to [`MAX_TARGET_KEY`] characters with no control characters.
/// Pure.
pub fn validate_target(target: &TestTarget) -> Result<(), AppError> {
    let kind = target.kind.trim();
    let kind_ok = !kind.is_empty()
        && kind.len() <= 63
        && kind.starts_with(|c: char| c.is_ascii_lowercase())
        && kind
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !kind_ok {
        return Err(AppError::Validation(
            "a test's target kind is lower-case letters, digits and `_`".into(),
        ));
    }
    let key = target.key.trim();
    if key.is_empty() || key.chars().count() > MAX_TARGET_KEY || key.chars().any(char::is_control) {
        return Err(AppError::Validation(format!(
            "a test's target key is 1 to {MAX_TARGET_KEY} characters"
        )));
    }
    Ok(())
}

/// `null` clears the target, an object sets it, absence keeps it.
fn set_or_clear<'de, D>(d: D) -> Result<Option<Option<TestTarget>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<TestTarget>::deserialize(d)?))
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
    #[serde(default)]
    pub live_safe: Option<bool>,
    /// Y11-T13: an object sets the target, `null` clears it.
    #[serde(default, deserialize_with = "set_or_clear")]
    #[schema(value_type = Option<TestTarget>)]
    pub target: Option<Option<TestTarget>>,
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
    let read: TestDefinition = serde_json::from_value(definition.clone())
        .map_err(|e| AppError::Validation(format!("the test definition does not read: {e}")))?;
    checklist_problem(&read).map_or(Ok(read), |problem| Err(AppError::Validation(problem)))
}

/// T7-T4: what is wrong with an acceptance script's checklist, if anything.
/// Pure.
pub fn checklist_problem(definition: &TestDefinition) -> Option<String> {
    if !definition.is_acceptance_script() {
        return None;
    }
    if !definition.given.is_empty() || !definition.when.is_empty() || !definition.expect.is_empty()
    {
        return Some(
            "an acceptance script has a checklist only, no given, when or expect".to_owned(),
        );
    }
    if definition.checklist.len() > MAX_CHECKLIST_STEPS {
        return Some(format!(
            "an acceptance script has at most {MAX_CHECKLIST_STEPS} steps"
        ));
    }
    definition
        .checklist
        .iter()
        .position(|step| step.trim().is_empty() || step.chars().count() > 500)
        .map(|n| format!("checklist step {} needs 1 to 500 characters", n + 1))
}

/// T7-T4: one step's mark in a person's run of an acceptance script.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct StepMark {
    pub passed: bool,
    /// What went wrong, for a failed step.
    #[serde(default)]
    pub note: Option<String>,
}

/// T7-T4: a person's marks as a run's outcome: passed when every step did,
/// with one failure line per failed step (its number, text and note).
/// Refuses marks that do not match the steps one for one. Pure.
pub fn checklist_outcome(steps: &[String], marks: &[StepMark]) -> Result<TestOutcome, AppError> {
    if steps.len() != marks.len() {
        return Err(AppError::Validation(format!(
            "the script has {} steps; mark each once",
            steps.len()
        )));
    }
    let failures: Vec<String> = steps
        .iter()
        .zip(marks)
        .enumerate()
        .filter(|(_, (_, mark))| !mark.passed)
        .map(|(n, (step, mark))| {
            let note: String = mark
                .note
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .chars()
                .take(1000)
                .collect();
            if note.is_empty() {
                format!("step {}: {step}", n + 1)
            } else {
                format!("step {}: {step}: {note}", n + 1)
            }
        })
        .collect();
    Ok(TestOutcome {
        passed: failures.is_empty(),
        failures,
        ..TestOutcome::default()
    })
}

/// T7-T4: one acceptance script as a person sees it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AcceptanceScript {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub steps: Vec<String>,
    /// The last run's result and time, by anyone.
    pub last_passed: Option<bool>,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
}

type ScriptRow = (
    Uuid,
    String,
    Option<String>,
    Value,
    Option<bool>,
    Option<chrono::DateTime<chrono::Utc>>,
    i64,
);

/// T7-T4: the active acceptance scripts, by name, a page and the total.
pub async fn list_acceptance_scripts(
    db: &attome_db::DbPool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<AcceptanceScript>, i64), AppError> {
    let rows: Vec<ScriptRow> = sqlx::query_as(&format!(
        "SELECT t.id, t.name, t.description, t.definition, r.passed, r.started_at, \
                count(*) OVER () \
           FROM customer_test t {LAST_RUN} \
          WHERE t.is_active AND NOT ({AUTOMATED}) \
          ORDER BY t.name, t.id LIMIT $1 OFFSET $2",
        AUTOMATED = AUTOMATED.replace("definition", "t.definition")
    ))
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    let total = rows.first().map_or(0, |r| r.6);
    let scripts = rows
        .into_iter()
        .map(
            |(id, name, description, definition, last_passed, last_run_at, _)| AcceptanceScript {
                id,
                name,
                description,
                steps: serde_json::from_value::<TestDefinition>(definition)
                    .map(|d| d.checklist)
                    .unwrap_or_default(),
                last_passed,
                last_run_at,
            },
        )
        .collect();
    Ok((scripts, total))
}

/// T7-T4: records a person's run of acceptance script `test_id` (active),
/// marked step by step, as `by`. The run's id and outcome.
pub async fn record_checklist_run(
    conn: &mut sqlx::PgConnection,
    test_id: Uuid,
    by: Uuid,
    marks: &[StepMark],
) -> Result<(Uuid, TestOutcome), AppError> {
    let definition: Value = sqlx::query_scalar(&format!(
        "SELECT definition FROM customer_test WHERE id = $1 AND is_active AND NOT ({AUTOMATED})"
    ))
    .bind(test_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)?;
    let definition: TestDefinition = serde_json::from_value(definition)
        .map_err(|e| AppError::Validation(format!("the script does not read: {e}")))?;
    let outcome = checklist_outcome(&definition.checklist, marks)?;
    let started = chrono::Utc::now();
    let run = insert_run(&mut *conn, test_id, started, &outcome).await?;
    sqlx::query("UPDATE customer_test_run SET run_by = $2 WHERE id = $1")
        .bind(run)
        .bind(by)
        .execute(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
    Ok((run, outcome))
}

const TEST_COLUMNS: &str = "t.id, t.name, t.description, t.definition, t.blocking, t.is_active, \
     t.row_version, t.created_at, t.updated_at, t.created_by, t.live_safe, t.flaky_since, \
     r.passed AS last_passed, r.started_at AS last_run_at, t.target_kind, t.target_key";

const LAST_RUN: &str = "LEFT JOIN LATERAL (SELECT passed, started_at FROM customer_test_run \
     WHERE test_id = t.id ORDER BY started_at DESC, id DESC LIMIT 1) r ON true";

/// A page of tests, by name, and the total.
pub async fn list_tests(
    db: &attome_db::DbPool,
    target: Option<&TestTarget>,
    limit: i64,
    offset: i64,
) -> Result<(Vec<CustomerTest>, i64), AppError> {
    // Y11-T13: only the tests guarding one customisation, when one is named.
    let kind = target.map(|t| t.kind.trim());
    let key = target.map(|t| t.key.trim());
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM customer_test t \
          WHERE ($1::text IS NULL OR (t.target_kind = $1 AND t.target_key = $2))",
    )
    .bind(kind)
    .bind(key)
    .fetch_one(db)
    .await
    .map_err(attome_db::classify)?;
    let items = sqlx::query_as(&format!(
        "SELECT {TEST_COLUMNS} FROM customer_test t {LAST_RUN} \
          WHERE ($3::text IS NULL OR (t.target_kind = $3 AND t.target_key = $4)) \
         ORDER BY t.name, t.id LIMIT $1 OFFSET $2"
    ))
    .bind(limit)
    .bind(offset)
    .bind(kind)
    .bind(key)
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
    if let Some(target) = &body.target {
        validate_target(target)?;
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO customer_test (id, name, description, definition, blocking, created_by, live_safe, \
                                    target_kind, target_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(&body.description)
    .bind(&body.definition)
    .bind(body.blocking)
    .bind(by)
    .bind(body.live_safe)
    .bind(body.target.as_ref().map(|t| t.kind.trim()))
    .bind(body.target.as_ref().map(|t| t.key.trim()))
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
    let target = match &patch.target {
        Some(Some(target)) => {
            validate_target(target)?;
            Some(target.clone())
        }
        Some(None) => None,
        None => current
            .target_kind
            .clone()
            .zip(current.target_key.clone())
            .map(|(kind, key)| TestTarget { kind, key }),
    };
    let updated = sqlx::query(
        "UPDATE customer_test SET name = $3, description = $4, definition = $5, blocking = $6, \
                is_active = $7, live_safe = $8, flaky_since = NULL, \
                target_kind = $9, target_key = $10, \
                row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND row_version = $2",
    )
    .bind(id)
    .bind(row_version)
    .bind(name.trim())
    .bind(patch.description.as_ref().or(current.description.as_ref()))
    .bind(definition)
    .bind(patch.blocking.unwrap_or(current.blocking))
    .bind(patch.is_active.unwrap_or(current.is_active))
    .bind(patch.live_safe.unwrap_or(current.live_safe))
    .bind(target.as_ref().map(|t| t.kind.trim()))
    .bind(target.as_ref().map(|t| t.key.trim()))
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
    let rows: Vec<(Uuid, String, Value)> = sqlx::query_as(&format!(
        "SELECT id, name, definition FROM customer_test \
          WHERE is_active = true AND (blocking OR NOT $1) AND {AUTOMATED} ORDER BY name, id"
    ))
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
        "INSERT INTO customer_test_run \
             (id, test_id, started_at, finished_at, passed, failures, test_version, config_version) \
         VALUES ($1, $2, $3, now(), $4, $5, \
                 (SELECT row_version FROM customer_test WHERE id = $2), \
                 (SELECT COALESCE(MAX(id), 0) FROM metadata_change_log))",
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

/// name, description, definition, blocking, target kind and key of one test.
type ExportRow = (String, Option<String>, Value, bool, Option<String>, Option<String>);

/// Every test, active or not, in the portable form.
pub async fn export_tests(db: &attome_db::DbPool) -> Result<CustomerTestExport, AppError> {
    let rows: Vec<ExportRow> = sqlx::query_as(
        "SELECT name, description, definition, blocking, target_kind, target_key \
               FROM customer_test ORDER BY name, id",
    )
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    Ok(CustomerTestExport {
        format: EXPORT_FORMAT.into(),
        tests: rows
            .into_iter()
            .map(
                |(name, description, definition, blocking, kind, key)| CustomerTestBody {
                    name,
                    description,
                    definition,
                    blocking,
                    live_safe: false,
                    target: kind.zip(key).map(|(kind, key)| TestTarget { kind, key }),
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
        if let Some(target) = &test.target {
            validate_target(target)
                .map_err(|e| AppError::Validation(format!("test {}: {e}", n + 1)))?;
        }
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
                    target_kind = $5, target_key = $6, \
                    row_version = row_version + 1, updated_at = now() \
              WHERE name = $1",
        )
        .bind(test.name.trim())
        .bind(&test.description)
        .bind(&test.definition)
        .bind(test.blocking)
        .bind(test.target.as_ref().map(|t| t.kind.trim()))
        .bind(test.target.as_ref().map(|t| t.key.trim()))
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
mod target_tests {
    use super::*;

    fn target(kind: &str, key: &str) -> TestTarget {
        TestTarget {
            kind: kind.into(),
            key: key.into(),
        }
    }

    #[test]
    fn a_target_names_a_kind_and_a_key() {
        assert!(validate_target(&target("form", "account.main")).is_ok());
        assert!(validate_target(&target("extension", "erp_sync")).is_ok());
        assert!(validate_target(&target("Form", "x")).is_err());
        assert!(validate_target(&target("", "x")).is_err());
        assert!(validate_target(&target("form", " ")).is_err());
        assert!(validate_target(&target("form", &"k".repeat(MAX_TARGET_KEY + 1))).is_err());
        assert!(validate_target(&target("form", "a\nb")).is_err());
    }

    #[test]
    fn a_patch_sets_clears_or_keeps_the_target() {
        let keep: CustomerTestPatch = serde_json::from_str("{}").unwrap();
        assert_eq!(keep.target, None);
        let clear: CustomerTestPatch = serde_json::from_str(r#"{"target": null}"#).unwrap();
        assert_eq!(clear.target, Some(None));
        let set: CustomerTestPatch =
            serde_json::from_str(r#"{"target": {"kind": "form", "key": "account.main"}}"#).unwrap();
        assert_eq!(set.target, Some(Some(target("form", "account.main"))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ref_value_points_at_a_record_named_earlier() {
        let id = Uuid::now_v7();
        let refs = HashMap::from([("acct".to_owned(), ("account".to_owned(), id))]);
        let values = json!({ "account_ref": { "$ref": "acct" }, "amount": 5, "meta": { "a": 1 } });
        let resolved =
            resolve_refs(values.as_object().expect("an object"), &refs, id).expect("resolved");
        assert_eq!(resolved["account_ref"], json!(id.to_string()));
        assert_eq!(resolved["amount"], json!(5));
        assert_eq!(resolved["meta"], json!({ "a": 1 }));
        let unknown = json!({ "account_ref": { "$ref": "nobody" } });
        assert!(resolve_refs(unknown.as_object().expect("an object"), &refs, id).is_err());
        let me = json!({ "requester_id": { "$ref": "@caller" } });
        let caller = Uuid::now_v7();
        assert_eq!(
            resolve_refs(me.as_object().expect("an object"), &refs, caller).expect("resolved")["requester_id"],
            json!(caller.to_string())
        );
    }

    #[test]
    fn an_acceptance_script_is_a_checklist_marked_step_by_step() {
        let script = validate(
            "Convert a lead",
            &json!({ "checklist": ["Open a lead", "Convert it"] }),
        )
        .expect("a checklist reads");
        assert!(script.is_acceptance_script());
        assert!(
            validate(
                "Mixed",
                &json!({ "checklist": ["a"], "given": [{ "entity": "lead", "record": {} }] })
            )
            .is_err()
        );
        assert!(validate("Blank", &json!({ "checklist": ["  "] })).is_err());

        let mark = |passed: bool, note: Option<&str>| StepMark {
            passed,
            note: note.map(str::to_owned),
        };
        let outcome = checklist_outcome(
            &script.checklist,
            &[mark(true, None), mark(false, Some("no Convert button"))],
        )
        .expect("one mark per step");
        assert!(!outcome.passed);
        assert_eq!(
            outcome.failures,
            vec!["step 2: Convert it: no Convert button"]
        );
        assert!(
            checklist_outcome(&script.checklist, &[mark(true, None)]).is_err(),
            "a mark per step"
        );
        assert!(
            checklist_outcome(&script.checklist, &[mark(true, None), mark(true, None)])
                .expect("marked")
                .passed
        );
    }

    #[test]
    fn access_and_flow_expectations_read_from_json() {
        let definition: TestDefinition = serde_json::from_value(json!({
            "expect": [
                { "entity": "deal", "action": "delete", "allowed": false },
                { "flow": "welcome", "entity": "contact", "ref": "c", "status": "completed",
                  "reaches": ["send_email"] },
                { "entity": "contact", "ref": "c", "attribute": "status", "equals": "new" }
            ]
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            definition.expect[0],
            Expectation::Access { allowed: false, .. }
        ));
        assert!(matches!(definition.expect[1], Expectation::Flow { .. }));
        assert!(matches!(definition.expect[2], Expectation::Value { .. }));
    }

    #[test]
    fn a_test_is_picked_by_the_entities_and_flows_it_touches() {
        let definition: TestDefinition = serde_json::from_value(json!({
            "given": [{ "entity": "account", "ref": "a", "record": {} }],
            "expect": [{ "flow": "welcome", "entity": "contact", "ref": "c" }]
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        let touched = touches(&definition);
        let by_entity = Impact {
            entities: ["contact".to_owned()].into(),
            ..Impact::default()
        };
        let by_flow = Impact {
            flows: ["welcome".to_owned()].into(),
            ..Impact::default()
        };
        let elsewhere = Impact {
            entities: ["invoice".to_owned()].into(),
            flows: ["other".to_owned()].into(),
        };
        assert!(touched.meets(&by_entity));
        assert!(touched.meets(&by_flow));
        assert!(!touched.meets(&elsewhere));
    }

    #[test]
    fn coverage_splits_the_nodes_no_test_reached() {
        let reached: std::collections::BTreeSet<String> =
            ["trigger".to_owned(), "approve".to_owned()].into();
        let (covered, uncovered) = split_coverage(
            vec!["trigger".into(), "reject".into(), "approve".into()],
            &reached,
        );
        assert_eq!(covered, vec!["trigger", "approve"]);
        assert_eq!(uncovered, vec!["reject"]);
    }

    #[test]
    fn a_flow_is_judged_by_its_status_and_the_nodes_it_reached() {
        let simulated = attome_core::WorkflowSimulation {
            status: "completed".into(),
            reached: vec!["trigger".into(), "send_email".into()],
        };
        assert!(
            flow_failures("w", Some("completed"), &["send_email".into()], &simulated).is_empty()
        );
        assert_eq!(
            flow_failures("w", Some("would_wait"), &[], &simulated).len(),
            1
        );
        assert_eq!(
            flow_failures("w", None, &["create_task".into()], &simulated).len(),
            1
        );
    }
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
