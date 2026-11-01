//! AH7-T1: the permission cases one agent must pass, generated from what
//! governs it rather than written by hand.
//!
//! From the agent's policy (its allow-list and risk ceiling), the actions
//! its capability packs grant (D-556), the privileges of the person it runs
//! for and the deployment's entities, [`negative_cases`] lists every call
//! the gate must stop:
//!
//! - an action outside the effective allow-list (the policy's list plus the
//!   packs' actions; a policy with no list allows every action) is refused;
//! - an allowed action above the policy's risk ceiling is refused;
//! - an allowed action needing a privilege the owner lacks is refused;
//! - an allowed Consequential action needs approval (N30);
//! - an allowed read that takes an `entity` argument is refused on every
//!   entity the owner cannot read.
//!
//! [`positive_cases`] lists the calls that must go through, so the report
//! also shows the agent is not over-restricted. Both are pure: the caller
//! resolves the policy, packs, privileges and entities. `system.admin`
//! holds every privilege and reads every entity, as at the gate.
//!
//! AH7-T2: [`run`] runs the cases for one agent definition without executing
//! anything. It resolves the definition the way a session start does
//! (`agent::resolve_start`: the caller is the owner, and the policy and its
//! packs narrow the widest start), builds the agent's context
//! (`ActionContext::agent` with the session's allow-list and ceiling), and
//! puts each case's action through `gate::evaluate`. A case about one entity
//! also checks the owner's read of that entity, which the executor applies
//! after the gate. A case fails when the gate lets through what must be
//! refused, or executes what must wait for approval. An expected-allowed
//! call that the gate stops is counted as over-restricted but is not a
//! failure. The run is stored in `ai_permission_test_run` (migration 0219)
//! against the definition's row version.
//!
//! AH7-T4: `POST /api/v1/admin/ai/agents/{id}/permission-test` runs it on
//! demand and answers the report (at most [`MAX_REPORTED_FAILURES`]
//! failures, flagged when cut; the stored run keeps them all), and
//! `GET /api/v1/admin/ai/agents/{id}/permission-tests` lists past runs,
//! newest first.

use std::collections::BTreeSet;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::agent::AgentPolicy;
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, RiskTier};
use crate::gate::GateDecision;
use crate::registry::ActionRegistry;

/// The privilege that holds every other.
const ADMIN: &str = "system.admin";
/// The most failures one answer lists.
pub const MAX_REPORTED_FAILURES: usize = 500;

/// What the gate must do with a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Allowed,
    Refused,
    NeedsApproval,
}

/// One call and what must happen to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Case {
    pub action_id: String,
    /// The entity the call names, for a case about one entity.
    pub entity: Option<String>,
    pub expect: Expect,
    /// Why, in a few words.
    pub reason: &'static str,
}

/// What governs one agent.
#[derive(Debug, Clone, Copy)]
pub struct Governance<'a> {
    pub policy: &'a AgentPolicy,
    /// The actions the policy's capability packs grant.
    pub pack_action_ids: &'a [String],
    /// The privileges of the person the agent runs for.
    pub owner_privileges: &'a [String],
    /// The deployment's entities.
    pub entities: &'a [String],
}

impl Governance<'_> {
    fn allow_list(&self) -> Option<BTreeSet<&str>> {
        let list = self.policy.allowed_action_ids.as_ref()?;
        Some(
            list.iter()
                .chain(self.pack_action_ids)
                .map(String::as_str)
                .collect(),
        )
    }

    fn holds(&self, privilege: &str) -> bool {
        self.owner_privileges
            .iter()
            .any(|p| p == privilege || p == ADMIN)
    }

    fn reads(&self, entity: &str) -> bool {
        self.holds(&format!("{entity}.read"))
    }
}

/// Whether an action's argument contract names an entity. Pure.
pub fn takes_entity(descriptor: &ActionDescriptor) -> bool {
    serde_json::from_str::<Value>(descriptor.input_schema)
        .ok()
        .and_then(|schema| schema.get("properties").cloned())
        .is_some_and(|props| props.get("entity").is_some())
}

fn case(id: &str, entity: Option<&str>, expect: Expect, reason: &'static str) -> Case {
    Case {
        action_id: id.to_owned(),
        entity: entity.map(str::to_owned),
        expect,
        reason,
    }
}

/// Why an allowed action is still refused, if it is.
fn refusal(g: &Governance<'_>, d: &ActionDescriptor) -> Option<&'static str> {
    if d.risk > g.policy.risk_ceiling {
        return Some("above the policy's risk ceiling");
    }
    if !d.required_privileges.iter().all(|p| g.holds(p)) {
        return Some("the owner lacks a privilege it needs");
    }
    None
}

/// Every call the gate must stop for this agent, in registry order.
pub fn negative_cases(g: &Governance<'_>, registry: &ActionRegistry) -> Vec<Case> {
    let allow = g.allow_list();
    let mut out = Vec::new();
    for d in registry.all() {
        let id = d.id.as_str();
        if allow.as_ref().is_some_and(|list| !list.contains(id)) {
            out.push(case(id, None, Expect::Refused, "not in the allow-list"));
            continue;
        }
        if let Some(reason) = refusal(g, d) {
            out.push(case(id, None, Expect::Refused, reason));
            continue;
        }
        if d.risk == RiskTier::Consequential {
            out.push(case(id, None, Expect::NeedsApproval, "consequential"));
        }
        if d.risk == RiskTier::Read && takes_entity(d) {
            for entity in g.entities.iter().filter(|e| !g.reads(e)) {
                out.push(case(
                    id,
                    Some(entity),
                    Expect::Refused,
                    "the owner cannot read this entity",
                ));
            }
        }
    }
    out
}

/// Every call that must go through without a person: allowed, within the
/// ceiling, privileges held, not Consequential. A read that takes an entity
/// is listed on each entity the owner can read.
pub fn positive_cases(g: &Governance<'_>, registry: &ActionRegistry) -> Vec<Case> {
    let allow = g.allow_list();
    let mut out = Vec::new();
    for d in registry.all() {
        let id = d.id.as_str();
        if allow.as_ref().is_some_and(|list| !list.contains(id))
            || refusal(g, d).is_some()
            || d.risk == RiskTier::Consequential
        {
            continue;
        }
        if d.risk == RiskTier::Read && takes_entity(d) {
            for entity in g.entities.iter().filter(|e| g.reads(e)) {
                out.push(case(id, Some(entity), Expect::Allowed, "allowed read"));
            }
        } else {
            out.push(case(id, None, Expect::Allowed, "allowed"));
        }
    }
    out
}

/// What the gate did with a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    NeedsApproval,
    Refused,
}

/// One case the gate got wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Failure {
    pub action_id: String,
    pub entity: Option<String>,
    pub expect: Expect,
    pub got: Outcome,
    pub reason: &'static str,
}

/// AH7-T2: one run's report.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Report {
    pub run_id: Uuid,
    pub agent_ref: Uuid,
    pub passed: bool,
    pub cases: usize,
    pub failures: Vec<Failure>,
    /// AH7-T4: whether `failures` was cut at 500 (the stored run keeps all).
    pub failures_truncated: bool,
    /// Expected-allowed calls the gate stopped.
    pub over_restricted: usize,
    /// AH7-T5: what the agent cannot do, in words.
    pub summary: CaseSummary,
}

/// AH7-T4: one stored run.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PermissionTestRun {
    pub id: Uuid,
    pub agent_ref: Uuid,
    /// The agent definition's row version the run tested.
    pub definition_row_version: i64,
    pub passed: bool,
    pub cases: i32,
    /// The failing cases.
    #[schema(value_type = Object)]
    pub failures: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Uuid,
}

/// The outcome a gate decision means for a case.
pub fn outcome_of(decision: &Result<GateDecision, crate::gate::GateRefusal>) -> Outcome {
    match decision {
        Ok(GateDecision::RequiresApproval) => Outcome::NeedsApproval,
        Ok(_) => Outcome::Allowed,
        Err(_) => Outcome::Refused,
    }
}

/// Whether `got` breaks `expect`: something through that must be refused,
/// or executed without the approval it needs.
pub fn is_failure(expect: Expect, got: Outcome) -> bool {
    match expect {
        Expect::Refused => got != Outcome::Refused,
        Expect::NeedsApproval => got == Outcome::Allowed,
        Expect::Allowed => false,
    }
}

/// AH7-T3: what one judgement of an agent's cases found.
#[derive(Debug, Clone)]
pub struct Judged {
    pub cases: usize,
    pub failures: Vec<Failure>,
    /// Expected-allowed calls the gate stopped.
    pub over_restricted: usize,
    /// AH7-T5: what the agent cannot do (shown on its form).
    pub summary: CaseSummary,
}

/// AH7-T5: the cases in words for a person: the actions the agent may not
/// call, the entities it may not read, and the actions that wait for a
/// person's approval. Each list sorted, at most [`MAX_LISTED`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct CaseSummary {
    pub cannot_do: Vec<String>,
    pub unreadable_entities: Vec<String>,
    pub needs_approval: Vec<String>,
}

/// The most items one summary list holds.
pub const MAX_LISTED: usize = 200;

/// The summary of `cases`. Pure.
pub fn summarise(cases: &[Case]) -> CaseSummary {
    let mut cannot = BTreeSet::new();
    let mut entities = BTreeSet::new();
    let mut approval = BTreeSet::new();
    for case in cases {
        match (case.expect, &case.entity) {
            (Expect::Refused, None) => {
                cannot.insert(case.action_id.clone());
            }
            (Expect::Refused, Some(entity)) => {
                entities.insert(entity.clone());
            }
            (Expect::NeedsApproval, _) => {
                approval.insert(case.action_id.clone());
            }
            (Expect::Allowed, _) => {}
        }
    }
    let take = |set: BTreeSet<String>| set.into_iter().take(MAX_LISTED).collect();
    CaseSummary {
        cannot_do: take(cannot),
        unreadable_entities: take(entities),
        needs_approval: take(approval),
    }
}

/// Puts every case for an agent whose owner is `security` and whose
/// session would hold `effective` through the gate, executing nothing.
/// The shared core of [`run`] and the activation check
/// (`crate::agent_activation`).
pub fn judge(
    state: &EngineState,
    security: &std::sync::Arc<attome_server::security::SecurityContext>,
    effective: &crate::agent::SessionConstraints,
) -> Judged {
    let policy = AgentPolicy {
        risk_ceiling: effective.risk_ceiling,
        allowed_action_ids: effective.allowed_action_ids.clone(),
        knowledge_source_refs: None,
        capability_pack_refs: None,
        max_invocations_per_session: 1,
        max_writes_per_day: 1,
        max_tokens_per_session: 1,
        max_session_duration_minutes: 1,
    };
    let mut privileges: Vec<String> = security.privileges.iter().cloned().collect();
    if security.is_admin {
        privileges.push(ADMIN.to_owned());
    }
    let entities: Vec<String> = state
        .entities
        .load()
        .iter()
        .map(|m| m.logicalname.clone())
        .collect();
    let governance = Governance {
        policy: &policy,
        pack_action_ids: &[],
        owner_privileges: &privileges,
        entities: &entities,
    };
    let registry = &*crate::engine::REGISTRY;
    let mut cases = negative_cases(&governance, registry);
    cases.extend(positive_cases(&governance, registry));

    let mut ctx = ActionContext::agent(security.clone(), effective.risk_ceiling);
    ctx.session_allowed_action_ids = effective.allowed_action_ids.clone();
    let mut failures = Vec::new();
    let mut over_restricted = 0;
    for case in &cases {
        let Some(descriptor) = registry.resolve(&case.action_id) else {
            continue;
        };
        let inputs = crate::engine::gate_inputs(state, descriptor.module);
        let mut got = outcome_of(&crate::gate::evaluate(descriptor, &ctx, &inputs));
        if let Some(entity) = &case.entity
            && got != Outcome::Refused
            && !(security.is_admin || security.privileges.contains(&format!("{entity}.read")))
        {
            got = Outcome::Refused;
        }
        if is_failure(case.expect, got) {
            failures.push(Failure {
                action_id: case.action_id.clone(),
                entity: case.entity.clone(),
                expect: case.expect,
                got,
                reason: case.reason,
            });
        } else if case.expect == Expect::Allowed && got == Outcome::Refused {
            over_restricted += 1;
        }
    }

    Judged {
        cases: cases.len(),
        summary: summarise(&cases),
        failures,
        over_restricted,
    }
}

/// AH7-T2: runs every case for the agent definition `agent_ref` as the
/// caller `actor` would start it, executing nothing, and stores the report.
pub async fn run(state: &EngineState, actor: Uuid, agent_ref: Uuid) -> Result<Report, AppError> {
    let security = state.base.security.resolve(actor).await?;
    let definition =
        attome_records::entity_crud::read_record(state, &security, "ai_agent", agent_ref).await?;
    let resolved = crate::agent::resolve_start(
        state,
        &security,
        agent_ref,
        crate::agent::SessionConstraints {
            risk_ceiling: RiskTier::Consequential,
            allowed_action_ids: None,
        },
    )
    .await?;
    let Judged {
        cases,
        failures,
        over_restricted,
        summary,
    } = judge(state, &security, &resolved.effective);

    let run_id = Uuid::now_v7();
    let passed = failures.is_empty();
    sqlx::query(
        "INSERT INTO ai_permission_test_run \
             (id, agent_ref, definition_row_version, passed, cases, failures, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(run_id)
    .bind(agent_ref)
    .bind(definition.row_version())
    .bind(passed)
    .bind(i32::try_from(cases).unwrap_or(i32::MAX))
    .bind(serde_json::to_value(&failures).map_err(AppError::internal)?)
    .bind(actor)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Report {
        run_id,
        agent_ref,
        passed,
        cases,
        failures,
        failures_truncated: false,
        over_restricted,
        summary,
    })
}

/// The answer's failures cut at [`MAX_REPORTED_FAILURES`]. Pure.
pub fn capped(mut report: Report) -> Report {
    if report.failures.len() > MAX_REPORTED_FAILURES {
        report.failures.truncate(MAX_REPORTED_FAILURES);
        report.failures_truncated = true;
    }
    report
}

/// Run an agent's permission test
///
/// Runs the agent definition's permission test as the caller would start
/// it, executing nothing, stores the run and answers its report (at most
/// 500 failures, flagged when cut). Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/agents/{id}/permission-test",
    tag = "action",
    params(("id" = Uuid, Path, description = "The ai_agent definition")),
    responses(
        (status = 200, description = "The run's report", body = Report),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such agent definition the caller can read", body = ErrorResponse),
        (status = 422, description = "The definition cannot start a session (no model or policy)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create),
    ])))),
)]
pub(crate) async fn post_permission_test(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Report>, AppError> {
    let report = run(&state, ctx.user_id, id).await?;
    attome_audit::write_business_event(
        &state,
        "ai_agent",
        id,
        AuditOperation::Create,
        "ai_agent.permission_test",
        ctx.user_id,
        None,
        None,
        format!(
            "permission test run {}: {} case(s), {} failure(s)",
            report.run_id,
            report.cases,
            report.failures.len()
        ),
    )
    .await;
    Ok(Json(capped(report)))
}

/// List an agent's permission test runs
///
/// The agent definition's stored permission test runs, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/permission-tests",
    tag = "action",
    params(("id" = Uuid, Path, description = "The ai_agent definition"), OnePageQuery),
    responses(
        (status = 200, description = "The runs, newest first", body = PaginatedResponse<PermissionTestRun>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_permission_tests(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PermissionTestRun>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = q.window();
    let items: Vec<PermissionTestRun> = sqlx::query_as(
        "SELECT id, agent_ref, definition_row_version, passed, cases, failures, created_at, \
                created_by \
           FROM ai_permission_test_run WHERE agent_ref = $1 \
          ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ai_permission_test_run WHERE agent_ref = $1")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// AH7-T4's routes.
pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/ai/agents/{id}/permission-test",
            post(post_permission_test),
        )
        .route(
            "/api/v1/admin/ai/agents/{id}/permission-tests",
            get(list_permission_tests),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_permission_test, list_permission_tests))]
struct ApiDocFragment;

/// AH7-T4's slice of the API document.
pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_lists_what_the_agent_cannot_do() {
        let case = |action: &str, entity: Option<&str>, expect: Expect| Case {
            action_id: action.into(),
            entity: entity.map(str::to_owned),
            expect,
            reason: "test",
        };
        let summary = summarise(&[
            case("email.send", None, Expect::Refused),
            case("record.get", Some("salary"), Expect::Refused),
            case("record.delete", None, Expect::NeedsApproval),
            case("record.get", None, Expect::Allowed),
            case("email.send", None, Expect::Refused),
        ]);
        assert_eq!(summary.cannot_do, vec!["email.send".to_owned()]);
        assert_eq!(summary.unreadable_entities, vec!["salary".to_owned()]);
        assert_eq!(summary.needs_approval, vec!["record.delete".to_owned()]);
    }

    #[test]
    fn the_answer_cuts_failures_at_500_and_says_so() {
        let failure = Failure {
            action_id: "email.send".into(),
            entity: None,
            expect: Expect::Refused,
            got: Outcome::Allowed,
            reason: "outside the allow-list",
        };
        let report = |n: usize| Report {
            run_id: Uuid::nil(),
            agent_ref: Uuid::nil(),
            passed: n == 0,
            cases: n,
            failures: vec![failure.clone(); n],
            failures_truncated: false,
            over_restricted: 0,
            summary: CaseSummary::default(),
        };
        let cut = capped(report(501));
        assert_eq!(cut.failures.len(), 500);
        assert!(cut.failures_truncated);
        let kept = capped(report(3));
        assert_eq!(kept.failures.len(), 3);
        assert!(!kept.failures_truncated);
    }

    fn policy(ceiling: RiskTier, allowed: Option<&[&str]>) -> AgentPolicy {
        AgentPolicy {
            risk_ceiling: ceiling,
            allowed_action_ids: allowed.map(strings),
            knowledge_source_refs: None,
            capability_pack_refs: None,
            max_invocations_per_session: 10,
            max_writes_per_day: 10,
            max_tokens_per_session: 10_000,
            max_session_duration_minutes: 10,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn has(cases: &[Case], id: &str, entity: Option<&str>, expect: Expect) -> bool {
        cases
            .iter()
            .any(|c| c.action_id == id && c.entity.as_deref() == entity && c.expect == expect)
    }

    fn ids(cases: &[Case], expect: Expect) -> BTreeSet<String> {
        cases
            .iter()
            .filter(|c| c.expect == expect && c.entity.is_none())
            .map(|c| c.action_id.clone())
            .collect()
    }

    #[test]
    fn permission_test_run_judges_gate_outcomes() {
        use crate::gate::GateRefusal;
        assert_eq!(
            outcome_of(&Ok(GateDecision::RequiresApproval)),
            Outcome::NeedsApproval
        );
        assert_eq!(outcome_of(&Ok(GateDecision::Execute)), Outcome::Allowed);
        assert_eq!(outcome_of(&Err(GateRefusal::Forbidden)), Outcome::Refused);
        assert!(is_failure(Expect::Refused, Outcome::Allowed));
        assert!(is_failure(Expect::Refused, Outcome::NeedsApproval));
        assert!(!is_failure(Expect::Refused, Outcome::Refused));
        assert!(is_failure(Expect::NeedsApproval, Outcome::Allowed));
        assert!(!is_failure(Expect::NeedsApproval, Outcome::Refused));
        assert!(
            !is_failure(Expect::Allowed, Outcome::Refused),
            "over-restriction is counted, not failed"
        );
    }

    #[test]
    fn negative_cases_list_every_action_outside_the_allow_list() {
        let registry = ActionRegistry::new();
        let p = policy(
            RiskTier::Consequential,
            Some(&["record.get", "record.update", "email.send"]),
        );
        let packs = strings(&["record.summarize"]);
        let privileges = strings(&["account.read", "account.update"]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &packs,
            owner_privileges: &privileges,
            entities: &strings(&["account", "invoice"]),
        };
        let cases = negative_cases(&g, &registry);
        let refused = ids(&cases, Expect::Refused);
        let allowed: BTreeSet<&str> = BTreeSet::from([
            "record.get",
            "record.update",
            "email.send",
            "record.summarize",
        ]);
        for d in registry.all() {
            let id = d.id.as_str();
            if !allowed.contains(id) {
                assert!(refused.contains(id), "{id} outside the list is not refused");
            }
        }
        assert!(!refused.contains("record.summarize"), "a pack grants it");
        assert!(
            ids(&cases, Expect::NeedsApproval).contains("email.send"),
            "every consequential action needs approval"
        );
    }

    #[test]
    fn negative_cases_list_every_consequential_action_without_a_list() {
        let registry = ActionRegistry::new();
        let p = policy(RiskTier::Consequential, None);
        let privileges = strings(&[ADMIN]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &[],
            owner_privileges: &privileges,
            entities: &[],
        };
        let cases = negative_cases(&g, &registry);
        let approval = ids(&cases, Expect::NeedsApproval);
        for d in registry.all() {
            if d.risk == RiskTier::Consequential {
                assert!(approval.contains(d.id.as_str()), "{}", d.id.as_str());
            }
        }
        assert!(
            ids(&cases, Expect::Refused).is_empty(),
            "an admin with no list is refused nothing"
        );
    }

    #[test]
    fn negative_cases_refuse_above_the_ceiling_and_unreadable_entities() {
        let registry = ActionRegistry::new();
        let p = policy(RiskTier::Read, Some(&["record.get", "record.update"]));
        let privileges = strings(&["account.read", "account.update"]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &[],
            owner_privileges: &privileges,
            entities: &strings(&["account", "invoice"]),
        };
        let cases = negative_cases(&g, &registry);
        assert!(has(&cases, "record.update", None, Expect::Refused));
        if registry.resolve("record.get").is_some_and(takes_entity) {
            assert!(has(&cases, "record.get", Some("invoice"), Expect::Refused));
            let positive = positive_cases(&g, &registry);
            let allowed = Expect::Allowed;
            assert!(has(&positive, "record.get", Some("account"), allowed));
            assert!(!has(&positive, "record.get", Some("invoice"), allowed));
        }
    }

    #[test]
    fn positive_cases_never_include_a_refused_or_consequential_call() {
        let registry = ActionRegistry::new();
        let p = policy(RiskTier::Consequential, None);
        let privileges = strings(&[ADMIN]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &[],
            owner_privileges: &privileges,
            entities: &strings(&["account"]),
        };
        let negative: BTreeSet<(String, Option<String>)> = negative_cases(&g, &registry)
            .into_iter()
            .map(|c| (c.action_id, c.entity))
            .collect();
        for c in positive_cases(&g, &registry) {
            assert_eq!(c.expect, Expect::Allowed);
            let key = (c.action_id.clone(), c.entity.clone());
            assert!(!negative.contains(&key), "{}", c.action_id);
        }
    }
}
