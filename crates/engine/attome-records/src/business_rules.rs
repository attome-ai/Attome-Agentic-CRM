//! D-789 (amended by D-791) — the business-rule write pipeline
//! (`document/general/BUSINESS-RULES-DESIGN.md` §3, §4, §9).
//!
//! `entity_mutation::create_one_as` / `update_one_as` run every business rule
//! that applies to the writer through [`WritePipeline`], in the order of
//! D-789 ruling 5:
//!
//! ```text
//! M0 = stored ⊕ body                     (create: body + engine initial values,
//!                                          state initial value, autovalue)
//! 1. conditions on M0   → the set_value policies that fire
//! 2. create: set_value 'default' on fields still empty in M0     → M1
//! 3. formula fields, then set_value 'always' (both read M1)      → M2
//! 4. conditions on M2   → the lock and error policies that fire
//! 5. lock check on the caller's own body; required-but-locked on M2
//! 6. error policies: severity 'error' refuses (422 rule_violation),
//!    severity 'warning' is returned to the caller and logged (D-791 rule 6)
//! ```
//!
//! This replaces the legacy `validation` / `calculation` / `default`
//! evaluation: the registry converts those kinds into business rules
//! (`RuleEntry::business`, migration 0530 on disk), and only the business
//! list is evaluated, so no rule runs twice.
//!
//! **Audience** ([`audience`]). A staff principal resolved for a user
//! (`SecurityContext::role_ids = Some`) is `Staff`; an API-key or S2S request
//! (`SecurityContext::service_principal`) is `Staff { interactive: false }`,
//! exempt from `hidden`/`disabled` (D-791 rule 3); a context built in code
//! (`role_ids = None`) is `System`; a portal user is `Portal` with its role.
//!
//! **Outcomes** (design §3.2). An unknown condition (null, non-boolean, a
//! permanent evaluation error, or a condition that no longer compiles) counts
//! as true for `hidden`, `disabled` and `error` — fail closed — and fails the
//! write for `set_value`. A transient evaluator trip (the wall-clock breaker)
//! answers a retryable 503 wherever it would block.
//!
//! **Caches** (design §9). Compiled conditions live in a process-local
//! bounded moka L1 ([`CONDITION_CACHE`]) keyed
//! `br:{rule_id}:{row_version}:{types}:cond`; compiled `set_value`
//! expressions live in `EngineState::rule_compiled` keyed
//! `br:{rule_id}:{row_version}:{types}:p{ordinal}`. `{types}` is
//! [`crate::rule_engine::entity_types_fingerprint`]. Source of truth: the
//! rule registry snapshot plus the entity's live attributes; an edit (a new
//! `row_version`) or a type change is a new key, so a stale program is never
//! reachable and no invalidation is needed; eviction is capacity-bounded
//! (10 000 entries, 24 h TTL); a cold start recompiles on first use; a
//! compile failure is never cached.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use attome_cache::{HotCache, create_hot_cache};
use attome_core::business_rules::{
    CompiledCondition, ConditionFieldKind, ConditionOutcome, Enforcement, FieldLock, PolicyEffect,
    RuleAudience, SetMode, SetValueSource, Severity, combine_locks, compile_condition,
    condition_context, condition_schema, condition_value,
};
use attome_core::{AttrInfo, BusinessRuleDef, EngineState};
use attome_rules::{Compiled, Type, Value as RulesValue};
use attome_types::{AppError, LockedField, RuleFailure, RuleViolationDetails};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::entity_mutation::Principal;

/// A `warning`-severity `error` policy that fired on a successful write
/// (D-791 rule 6). Returned in the write response's `warnings` list and
/// logged; it never blocks. Carries names and the rule's own message, never a
/// record value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleWarning {
    pub rule_id: Uuid,
    /// The rule's display name (its name when it has none).
    pub rule_name: String,
    /// The field the policy is attached to, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub message: String,
}

/// The business-rule audience of a writer (design §3.1, D-791 rule 3).
pub fn audience<'a>(principal: &Principal<'a>) -> RuleAudience<'a> {
    match *principal {
        Principal::Staff(ctx) => match ctx.role_ids.as_deref() {
            None => RuleAudience::System,
            Some(role_ids) => RuleAudience::Staff {
                role_ids,
                interactive: !ctx.service_principal,
            },
        },
        // A portal user without a role (its own-profile plan) matches no
        // portal-role rule: the nil id is never a role.
        Principal::Portal(plan) => RuleAudience::Portal {
            role_id: plan.role_id.unwrap_or(Uuid::nil()),
        },
    }
}

/// A3-T8: the channel a writer came in through, as the rejection log names
/// it.
fn channel(audience: &RuleAudience<'_>) -> &'static str {
    match audience {
        RuleAudience::System => "system",
        RuleAudience::Staff {
            interactive: true, ..
        } => "staff",
        RuleAudience::Staff { .. } => "service",
        RuleAudience::Portal { .. } => "portal",
    }
}

/// Compiled conditions (see the module doc for the cache contract).
static CONDITION_CACHE: LazyLock<HotCache<Arc<CompiledCondition>>> =
    LazyLock::new(|| create_hot_cache(10_000, 24 * 60 * 60));

fn condition_cache_key(rule: &BusinessRuleDef, types: u64) -> String {
    format!("br:{}:{}:{types:016x}:cond", rule.id, rule.row_version)
}

fn set_value_cache_key(rule: &BusinessRuleDef, ordinal: i32, types: u64) -> String {
    format!(
        "br:{}:{}:{types:016x}:p{ordinal}",
        rule.id, rule.row_version
    )
}

/// The attributes a condition is compiled against at write time: the live
/// attributes with `options.choices` removed, so a choice deleted after the
/// rule was written keeps the rule valid (design §8.3 — the stored value is
/// still in records; only authoring checks choice membership).
fn runtime_attrs(attrs: &[AttrInfo]) -> Vec<AttrInfo> {
    attrs
        .iter()
        .cloned()
        .map(|mut a| {
            if let Some(Value::Object(opts)) = a.options.as_mut() {
                opts.remove("choices");
            }
            a
        })
        .collect()
}

/// A condition as the pipeline sees it: compiled, or the reason it could
/// not be (which evaluates as unknown).
type ConditionSlot = Result<Arc<CompiledCondition>, String>;

async fn compile_condition_cached(
    rule: &BusinessRuleDef,
    attrs: &[AttrInfo],
    types: u64,
) -> ConditionSlot {
    let key = condition_cache_key(rule, types);
    if let Some(hit) = CONDITION_CACHE.get(&key).await {
        return Ok(hit);
    }
    match compile_condition(&rule.condition, &runtime_attrs(attrs)) {
        Ok(compiled) => {
            let compiled = Arc::new(compiled);
            CONDITION_CACHE.insert(key, Arc::clone(&compiled)).await;
            Ok(compiled)
        }
        Err(issues) => Err(issues
            .iter()
            .map(|i| i.code.as_str())
            .collect::<Vec<_>>()
            .join(",")),
    }
}

/// Whether an expression result of type `produced` can be stored in a field
/// of condition kind `target` (the same fit the admin API checks).
fn result_fits(produced: &Type, target: &Type) -> bool {
    produced.unify(target).is_some()
        || matches!(
            (produced, target),
            (Type::Choice, Type::Text) | (Type::Text, Type::Choice)
        )
}

/// Compiles a `set_value` expression against the entity's business-rule
/// schema and checks its result type against the target field. Cached in
/// `EngineState::rule_compiled` when a state is given.
async fn compile_set_value(
    state: Option<&EngineState>,
    rule: &BusinessRuleDef,
    ordinal: i32,
    field: &str,
    src: &str,
    attrs: &[AttrInfo],
    types: u64,
) -> Result<Arc<Compiled>, String> {
    let key = set_value_cache_key(rule, ordinal, types);
    if let Some(state) = state
        && let Some(hit) = state.rule_compiled.get(&key).await
    {
        return Ok(hit);
    }
    let target = attrs
        .iter()
        .find(|a| a.logicalname == field)
        .and_then(ConditionFieldKind::of_attr)
        .ok_or_else(|| format!("'{field}' can no longer be set by a rule"))?;
    if attrs
        .iter()
        .any(|a| a.logicalname == field && a.is_formula())
    {
        return Err(format!("'{field}' is a formula field"));
    }
    let compiled = attome_rules::compile(src, &condition_schema(attrs))
        .map_err(|e| format!("expression does not compile: {e}"))?;
    let target_type = target.rules_type();
    if !result_fits(compiled.result_type(), &target_type) {
        return Err(format!(
            "expression produces {} but '{field}' holds {target_type}",
            compiled.result_type()
        ));
    }
    let compiled = Arc::new(compiled);
    if let Some(state) = state {
        state.rule_compiled.insert(key, Arc::clone(&compiled)).await;
    }
    Ok(compiled)
}

/// The rules one write evaluates, for one writer.
pub(crate) struct WritePipeline<'a> {
    state: Option<&'a EngineState>,
    entity: &'a str,
    attrs: &'a [AttrInfo],
    audience: RuleAudience<'a>,
    /// Active rules whose audience includes the writer and that hold at
    /// least one policy binding it, in display order.
    rules: Vec<BusinessRuleDef>,
    types: u64,
    now: DateTime<Utc>,
    /// Compiled conditions, by rule id, filled on first use.
    conditions: HashMap<Uuid, ConditionSlot>,
    /// Outcomes on M0 (step 1), reused in step 4 when M2 equals M0.
    m0_outcomes: HashMap<Uuid, ConditionOutcome>,
    /// B4-T3: the tags the judged rules add (`true`) or remove, in rule
    /// order; applied once the record is written.
    tag_actions: Vec<(bool, String)>,
    /// A3-T4: the caller's reason to save past a refusing check, kept only
    /// when the caller holds the override privilege.
    override_reason: Option<String>,
    /// A3-T4: the refusing checks the last judgement let through on that
    /// reason; each becomes a security event once the record is written.
    overridden: Vec<RuleFailure>,
    /// A3-T8: how the writer came in, and the staff user, for the
    /// rejection log.
    channel: &'static str,
    user: Option<Uuid>,
    /// A11-T2: the stored row on an update, which a value expression's
    /// `prev(field)` and `changed(field)` read.
    previous: Option<Map<String, Value>>,
}

/// What step 1 decided: the rules whose `set_value` policies fire.
pub(crate) struct FiredSetValues(Vec<usize>);

impl<'a> WritePipeline<'a> {
    /// The pipeline for `principal` writing `entity`, or `None` when no
    /// business rule binds this writer (the entity pays nothing more).
    pub(crate) fn new(
        state: &'a EngineState,
        entity: &'a str,
        attrs: &'a [AttrInfo],
        principal: &Principal<'a>,
    ) -> Option<Self> {
        let audience = audience(principal);
        let rules: Vec<BusinessRuleDef> = {
            let registry = state.rules.load();
            let entry = registry.get(entity)?;
            if !entry.has_business_rules_for(&audience) {
                return None;
            }
            entry
                .business_rules_for(&audience)
                .filter(|r| r.policies_for(&audience).next().is_some())
                .cloned()
                .collect()
        };
        let mut pipeline = Self::with_rules(Some(state), entity, attrs, audience, rules);
        pipeline.override_reason = match *principal {
            Principal::Staff(ctx)
                if ctx.is_admin
                    || ctx
                        .privileges
                        .contains(attome_core::business_rules::OVERRIDE_PRIVILEGE) =>
            {
                attome_types::request_scope::override_reason()
            }
            _ => None,
        };
        pipeline.channel = channel(&pipeline.audience);
        pipeline.user = match *principal {
            Principal::Staff(ctx) => Some(ctx.user_id),
            Principal::Portal(_) => None,
        };
        Some(pipeline)
    }

    fn with_rules(
        state: Option<&'a EngineState>,
        entity: &'a str,
        attrs: &'a [AttrInfo],
        audience: RuleAudience<'a>,
        rules: Vec<BusinessRuleDef>,
    ) -> Self {
        Self {
            state,
            entity,
            attrs,
            audience,
            rules,
            types: crate::rule_engine::entity_types_fingerprint(attrs),
            now: Utc::now(),
            conditions: HashMap::new(),
            m0_outcomes: HashMap::new(),
            tag_actions: Vec::new(),
            override_reason: None,
            overridden: Vec::new(),
            channel: "system",
            user: None,
            previous: None,
        }
    }

    /// A11-T2: the row as stored before this update.
    pub(crate) fn set_previous(&mut self, stored: &Map<String, Value>) {
        self.previous = Some(stored.clone());
    }

    async fn outcome(&mut self, index: usize, record: &Map<String, Value>) -> ConditionOutcome {
        let rule = &self.rules[index];
        if !self.conditions.contains_key(&rule.id) {
            let slot = compile_condition_cached(rule, self.attrs, self.types).await;
            self.conditions.insert(rule.id, slot);
        }
        let outcome = match &self.conditions[&rule.id] {
            Ok(compiled) => compiled.evaluate(self.attrs, record, self.now),
            Err(_) => ConditionOutcome::Unknown {
                code: Some("condition_invalid"),
            },
        };
        match &outcome {
            ConditionOutcome::Unknown { code } => tracing::warn!(
                rule_id = %rule.id,
                rule = %rule.name,
                entity = %self.entity,
                code = code.unwrap_or("not_boolean"),
                reason = self.conditions[&rule.id].as_ref().err().map(String::as_str).unwrap_or(""),
                "business rule condition is unknown; treated as holding (fail closed)"
            ),
            ConditionOutcome::Transient => tracing::warn!(
                rule_id = %rule.id,
                rule = %rule.name,
                entity = %self.entity,
                "business rule condition hit the evaluator's wall-clock budget; retryable"
            ),
            ConditionOutcome::True | ConditionOutcome::False => {}
        }
        outcome
    }

    fn policies(&self, index: usize) -> impl Iterator<Item = PolicyEffect<'_>> + '_ {
        self.rules[index]
            .policies_for(&self.audience)
            .filter_map(|p| p.effect())
    }

    fn has_set_value(&self, index: usize, is_create: bool) -> bool {
        self.policies(index).any(|e| {
            matches!(e, PolicyEffect::SetValue { mode, .. }
                if mode == SetMode::Always || is_create)
        })
    }

    /// Step 1: evaluates, on M0, the condition of every rule with a
    /// `set_value` policy this write can use (`default` ones on create only).
    /// An unknown condition refuses the write (the value cannot be
    /// computed); a transient one answers 503.
    pub(crate) async fn fire_set_values(
        &mut self,
        m0: &Map<String, Value>,
        is_create: bool,
    ) -> Result<FiredSetValues, AppError> {
        let mut fired = Vec::new();
        for index in 0..self.rules.len() {
            if !self.has_set_value(index, is_create) {
                continue;
            }
            let outcome = self.outcome(index, m0).await;
            self.m0_outcomes
                .insert(self.rules[index].id, outcome.clone());
            match outcome {
                ConditionOutcome::True => fired.push(index),
                ConditionOutcome::False => {}
                ConditionOutcome::Unknown { .. } => {
                    let rule = &self.rules[index];
                    return Err(AppError::RuleViolation {
                        rule_id: rule.id,
                        message: format!(
                            "rule '{}' cannot decide whether to set a value: its condition could not be evaluated",
                            rule.label()
                        ),
                        details: None,
                    });
                }
                ConditionOutcome::Transient => {
                    return Err(AppError::Overloaded("business_rules.condition_wall_clock"));
                }
            }
        }
        Ok(FiredSetValues(fired))
    }

    /// Step 2 (create only): the `set_value` `default` values for fields
    /// still empty in M0, in rule then policy order (a later one wins). A
    /// value that cannot be computed is skipped with a `warn` — the legacy
    /// `default` posture.
    pub(crate) async fn default_values(
        &self,
        fired: &FiredSetValues,
        m0: &Map<String, Value>,
    ) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        for &index in &fired.0 {
            let rule = &self.rules[index];
            for policy in rule.policies_for(&self.audience) {
                let Some(PolicyEffect::SetValue {
                    field,
                    source,
                    mode: SetMode::Default,
                }) = policy.effect()
                else {
                    continue;
                };
                if !is_empty(m0.get(field)) {
                    continue;
                }
                match self.compute(rule, policy.ordinal, field, source, m0).await {
                    Ok(value) => out.push((field.to_owned(), value)),
                    Err(reason) => tracing::warn!(
                        rule_id = %rule.id,
                        rule = %rule.name,
                        entity = %self.entity,
                        field,
                        reason = %reason.reason,
                        "business rule default value could not be computed; skipped"
                    ),
                }
            }
        }
        out
    }

    /// Step 3: the `set_value` `always` values, all computed from M1 (no
    /// chaining between policies), in rule then policy order (the last
    /// writer of a field wins). A value that cannot be computed refuses the
    /// write (422 `rule_violation`, or 503 for a transient trip).
    pub(crate) async fn always_values(
        &self,
        fired: &FiredSetValues,
        m1: &Map<String, Value>,
    ) -> Result<Vec<(String, Value)>, AppError> {
        let mut out = Vec::new();
        for &index in &fired.0 {
            let rule = &self.rules[index];
            for policy in rule.policies_for(&self.audience) {
                let Some(PolicyEffect::SetValue {
                    field,
                    source,
                    mode: SetMode::Always,
                }) = policy.effect()
                else {
                    continue;
                };
                match self.compute(rule, policy.ordinal, field, source, m1).await {
                    Ok(value) => out.push((field.to_owned(), value)),
                    Err(failure) if failure.transient => {
                        tracing::warn!(
                            rule_id = %rule.id,
                            entity = %self.entity,
                            field,
                            "business rule value hit the evaluator's wall-clock budget; retryable"
                        );
                        return Err(AppError::Overloaded("business_rules.set_value_wall_clock"));
                    }
                    Err(failure) => {
                        return Err(AppError::RuleViolation {
                            rule_id: rule.id,
                            message: format!(
                                "rule '{}' failed to compute '{field}': {}",
                                rule.label(),
                                failure.reason
                            ),
                            details: None,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    async fn compute(
        &self,
        rule: &BusinessRuleDef,
        ordinal: i32,
        field: &str,
        source: SetValueSource<'_>,
        record: &Map<String, Value>,
    ) -> Result<Value, ComputeFailure> {
        match source {
            SetValueSource::Literal(v) => Ok(v.clone()),
            SetValueSource::Expression(src) => {
                let compiled = compile_set_value(
                    self.state, rule, ordinal, field, src, self.attrs, self.types,
                )
                .await
                .map_err(|reason| ComputeFailure {
                    reason,
                    transient: false,
                })?;
                let ctx = condition_context(self.attrs, record, self.now);
                let ctx = match &self.previous {
                    Some(before) => {
                        ctx.with_previous_from(&condition_context(self.attrs, before, self.now))
                    }
                    None => ctx,
                };
                compiled
                    .eval(&ctx)
                    .map(|v| crate::rule_engine::json_from_rules_value(&v))
                    .map_err(|e| ComputeFailure {
                        transient: e.is_transient(),
                        reason: e.to_string(),
                    })
            }
        }
    }

    /// Steps 4–6: re-evaluates the conditions of the rules carrying lock or
    /// error policies on the final record `m2` (reusing step 1's outcome when
    /// `m2_changed` is false), then refuses a write that changes a locked
    /// field (`body` — the caller's own fields; `stored` — the row before
    /// this write, on update; `baseline` — the values the engine itself
    /// would write on create), a required field locked and left empty, or a
    /// blocking `error` policy. Returns the `warning` policies that fired.
    pub(crate) async fn judge(
        &mut self,
        m2: &Map<String, Value>,
        m2_changed: bool,
        write: &WriteSides<'_>,
    ) -> Result<Vec<RuleWarning>, AppError> {
        let mut outcomes: HashMap<Uuid, ConditionOutcome> = HashMap::new();
        for index in 0..self.rules.len() {
            let judged = self.policies(index).any(|e| {
                matches!(
                    e,
                    PolicyEffect::Lock { .. }
                        | PolicyEffect::Error { .. }
                        | PolicyEffect::Required { .. }
                        | PolicyEffect::AllowedValues { .. }
                        | PolicyEffect::Tag { .. }
                )
            });
            if !judged {
                continue;
            }
            let id = self.rules[index].id;
            let reused = if m2_changed {
                None
            } else {
                self.m0_outcomes.get(&id).cloned()
            };
            let outcome = match reused {
                Some(outcome) => outcome,
                None => self.outcome(index, m2).await,
            };
            outcomes.insert(id, outcome);
        }
        let judged = judge_outcomes(
            &self.rules,
            &self.audience,
            &outcomes,
            self.attrs,
            self.entity,
            m2,
            write,
            &Staging {
                today: self.now.date_naive(),
                override_reason: self.override_reason.as_deref(),
            },
        )
        .inspect_err(|e| self.log_rejection(e))?;
        let warnings = judged.warnings;
        self.overridden = judged.overridden;
        // B4-T3: the tag outcomes of the rules that hold.
        self.tag_actions.clear();
        for rule in &self.rules {
            if !outcomes
                .get(&rule.id)
                .is_some_and(ConditionOutcome::holds_fail_closed)
            {
                continue;
            }
            for policy in rule.policies_for(&self.audience) {
                if let Some(PolicyEffect::Tag { add, name }) = policy.effect() {
                    self.tag_actions.push((add, name.trim().to_owned()));
                }
            }
        }
        Ok(warnings)
    }

    /// A3-T8: hands each check that refused this write to the rejection
    /// log (batched, off the request path).
    fn log_rejection(&self, error: &AppError) {
        let (
            Some(state),
            AppError::RuleViolation {
                details: Some(details),
                ..
            },
        ) = (self.state, error)
        else {
            return;
        };
        let log = crate::rejection_log::RejectionLog::shared(&state.base.db);
        for failure in &details.rules {
            log.record(crate::rejection_log::Rejection {
                rule_id: failure.rule_id,
                entity: self.entity.to_owned(),
                attribute: failure.field.clone(),
                channel: self.channel,
                user_ref: self.user,
                rejected_at: self.now,
            });
        }
    }

    /// A3-T4: records each refusing check the caller overrode, with the
    /// reason, as a security event in the write's own transaction.
    pub(crate) async fn write_overrides(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        record_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<(), AppError> {
        let (Some(state), Some(reason)) = (self.state, self.override_reason.as_deref()) else {
            return Ok(());
        };
        for failure in &self.overridden {
            attome_audit::security::write_security_event(
                tx,
                &attome_audit::audit_service(state),
                attome_audit::security::SecurityEvent::new(
                    attome_audit::security::MandatoryCategory::Access,
                    attome_audit::AuditOperation::Update,
                    actor.unwrap_or(Uuid::nil()),
                    self.entity,
                    Some(record_id),
                )
                .named("business_rule.override")
                .comment(format!(
                    "rule '{}' ({}) overridden on {} {record_id}{}: {reason}",
                    failure.rule_name,
                    failure.rule_id,
                    self.entity,
                    failure
                        .field
                        .as_deref()
                        .map(|f| format!(", field {f}"))
                        .unwrap_or_default(),
                )),
            )
            .await?;
        }
        Ok(())
    }

    /// B4-T3: applies the judged rules' tag outcomes to the written record,
    /// in the write's own transaction. A tag that does not exist yet is
    /// created as a shared tag; a merged tag's name leads to the tag it went
    /// into.
    pub(crate) async fn apply_tags(
        &self,
        tx: &mut sqlx::PgConnection,
        record_id: Uuid,
        user: Option<Uuid>,
    ) -> Result<(), AppError> {
        let by = user.unwrap_or(Uuid::nil());
        for (add, name) in &self.tag_actions {
            if *add {
                sqlx::query(
                    "INSERT INTO tag (name, created_by) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                )
                .bind(name)
                .bind(by)
                .execute(&mut *tx)
                .await
                .map_err(attome_db::classify)?;
                sqlx::query(
                    "INSERT INTO tag_link (tag_id, entity, record_id, created_by) \
                     SELECT COALESCE(t.merged_into, t.id), $2, $3, $4 FROM tag t \
                     WHERE t.normalized_name = normalize_ar($1) AND t.owner_user IS NULL \
                     ON CONFLICT (tag_id, entity, record_id) DO NOTHING",
                )
                .bind(name)
                .bind(self.entity)
                .bind(record_id)
                .bind(by)
                .execute(&mut *tx)
                .await
                .map_err(attome_db::classify)?;
            } else {
                sqlx::query(
                    "DELETE FROM tag_link WHERE entity = $2 AND record_id = $3 AND tag_id IN ( \
                         SELECT COALESCE(t.merged_into, t.id) FROM tag t \
                         WHERE t.normalized_name = normalize_ar($1) AND t.owner_user IS NULL)",
                )
                .bind(name)
                .bind(self.entity)
                .bind(record_id)
                .execute(&mut *tx)
                .await
                .map_err(attome_db::classify)?;
            }
        }
        Ok(())
    }
}

struct ComputeFailure {
    reason: String,
    transient: bool,
}

/// The two sides of a write a lock check compares.
pub(crate) struct WriteSides<'a> {
    /// The fields the caller's own body writes (before any engine or rule
    /// value), without the engine's own stamps.
    pub body: &'a Map<String, Value>,
    /// Update: the live row before this write.
    pub stored: Option<&'a Map<String, Value>>,
    /// Create: the value the engine itself writes when the caller leaves a
    /// field out (engine-managed initial values, the state model's initial
    /// state). A caller may send exactly that value for a locked field.
    pub baseline: &'a Map<String, Value>,
    pub is_create: bool,
}

/// Absent, null, a blank string or an empty list.
fn is_empty(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        Some(_) => false,
    }
}

/// Whether two values of `attr` are the same stored value, in the engine's
/// canonical form (numbers by value, dates by instant, multi-choice as a
/// set, absent = null).
fn same_value(attr: Option<&AttrInfo>, a: Option<&Value>, b: Option<&Value>) -> bool {
    let a = a.filter(|v| !v.is_null());
    let b = b.filter(|v| !v.is_null());
    let (a, b) = match (a, b) {
        (None, None) => return true,
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    if a == b {
        return true;
    }
    match attr.and_then(ConditionFieldKind::of_attr) {
        Some(ConditionFieldKind::MultiChoice) => {
            let set = |v: &Value| -> Option<HashSet<String>> {
                v.as_array().map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.as_str().map(str::to_owned))
                        .collect()
                })
            };
            matches!((set(a), set(b)), (Some(x), Some(y)) if x == y)
        }
        Some(kind) => {
            let (x, y) = (
                condition_value(kind, Some(a)),
                condition_value(kind, Some(b)),
            );
            x != RulesValue::Null && x == y
        }
        None => false,
    }
}

fn locked_field(field: &str, lock: &FieldLock) -> LockedField {
    LockedField {
        field: field.to_owned(),
        rule_id: lock.rule_id,
        rule_name: lock.rule_name.clone(),
        effect: lock.effect.as_str().to_owned(),
    }
}

/// Design §3.5: the body fields a lock refuses.
fn lock_refusals(
    locks: &BTreeMap<String, FieldLock>,
    attrs: &[AttrInfo],
    write: &WriteSides<'_>,
) -> Vec<LockedField> {
    let mut out = Vec::new();
    for (field, value) in write.body {
        let Some(lock) = locks.get(field) else {
            continue;
        };
        let attr = attrs.iter().find(|a| &a.logicalname == field);
        let allowed = if write.is_create {
            value.is_null() || same_value(attr, Some(value), write.baseline.get(field))
        } else {
            same_value(attr, Some(value), write.stored.and_then(|s| s.get(field)))
        };
        if !allowed {
            out.push(locked_field(field, lock));
        }
    }
    out
}

/// Design §3.4: required fields a lock leaves empty in the final record.
fn required_locked(
    locks: &BTreeMap<String, FieldLock>,
    attrs: &[AttrInfo],
    m2: &Map<String, Value>,
) -> Vec<LockedField> {
    attrs
        .iter()
        .filter(|a| a.is_required && is_empty(m2.get(&a.logicalname)))
        .filter_map(|a| {
            locks
                .get(&a.logicalname)
                .map(|l| locked_field(&a.logicalname, l))
        })
        .collect()
}

/// The pure half of steps 4–6, given each judged rule's outcome on M2.
/// A3-T4: the day staged checks are judged on, and the reason a caller with
/// the override privilege gave to save past a refusing one.
struct Staging<'a> {
    today: chrono::NaiveDate,
    override_reason: Option<&'a str>,
}

/// What judging found: the warnings to return, and the refusing checks let
/// through on an override reason.
struct Judged {
    warnings: Vec<RuleWarning>,
    overridden: Vec<RuleFailure>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "one call site; the pieces of one write"
)]
fn judge_outcomes(
    rules: &[BusinessRuleDef],
    audience: &RuleAudience<'_>,
    outcomes: &HashMap<Uuid, ConditionOutcome>,
    attrs: &[AttrInfo],
    entity: &str,
    m2: &Map<String, Value>,
    write: &WriteSides<'_>,
    staging: &Staging<'_>,
) -> Result<Judged, AppError> {
    let holds = |rule: &BusinessRuleDef, with_transient: bool| {
        outcomes.get(&rule.id).is_some_and(|o| {
            o.holds_fail_closed() || (with_transient && *o == ConditionOutcome::Transient)
        })
    };

    // Step 5: locks, for a writer subject to them.
    let mut transient_block = false;
    if audience.subject_to_locks() {
        let definite = combine_locks(rules.iter().filter(|r| holds(r, false)));
        let refused = lock_refusals(&definite, attrs, write);
        if !refused.is_empty() {
            return Err(AppError::FieldLocked {
                locks: refused,
                required: false,
            });
        }
        let required = required_locked(&definite, attrs, m2);
        if !required.is_empty() {
            return Err(AppError::FieldLocked {
                locks: required,
                required: true,
            });
        }
        let with_transient = combine_locks(rules.iter().filter(|r| holds(r, true)));
        transient_block = !lock_refusals(&with_transient, attrs, write).is_empty()
            || !required_locked(&with_transient, attrs, m2).is_empty();
    }

    // Step 6: error policies, in rule display order.
    let mut failures: Vec<RuleFailure> = Vec::new();
    let mut warnings: Vec<RuleWarning> = Vec::new();
    for rule in rules {
        let Some(outcome) = outcomes.get(&rule.id) else {
            continue;
        };
        for policy in rule.policies_for(audience) {
            // A11-T1: `required` and `allowed_values` fail like a blocking
            // error, and only when the record breaks them.
            let (field, message, severity) = match policy.effect() {
                Some(PolicyEffect::Error {
                    field,
                    message,
                    severity,
                }) => (field, message.map(str::to_owned), severity),
                Some(PolicyEffect::Required { field, message }) => {
                    if !is_empty(m2.get(field)) {
                        continue;
                    }
                    (
                        Some(field),
                        Some(message.map_or_else(|| format!("{field} is required"), str::to_owned)),
                        Severity::Error,
                    )
                }
                Some(PolicyEffect::AllowedValues {
                    field,
                    values,
                    message,
                }) => {
                    if attome_core::business_rules::value_allowed(m2.get(field), values) {
                        continue;
                    }
                    (
                        Some(field),
                        Some(message.map_or_else(
                            || format!("{field} has a value this rule does not allow"),
                            str::to_owned,
                        )),
                        Severity::Error,
                    )
                }
                _ => continue,
            };
            // A3-T4: a staged check reports, warns or refuses.
            let enforcement = policy.enforcement(severity, staging.today);
            if *outcome == ConditionOutcome::Transient {
                transient_block |= enforcement == Enforcement::Enforce;
                continue;
            }
            if !outcome.holds_fail_closed() {
                continue;
            }
            let message = message.unwrap_or_else(|| format!("rule '{}' failed", rule.label()));
            match enforcement {
                Enforcement::Enforce => failures.push(RuleFailure {
                    rule_id: rule.id,
                    rule_name: rule.label().to_owned(),
                    field: field.map(str::to_owned),
                    message,
                }),
                Enforcement::Warn => {
                    tracing::warn!(
                        rule_id = %rule.id,
                        rule = %rule.name,
                        entity,
                        "business rule warning fired (write allowed)"
                    );
                    warnings.push(RuleWarning {
                        rule_id: rule.id,
                        rule_name: rule.label().to_owned(),
                        field: field.map(str::to_owned),
                        message,
                    });
                }
                Enforcement::Report => tracing::info!(
                    rule_id = %rule.id,
                    rule = %rule.name,
                    entity,
                    field = field.unwrap_or_default(),
                    "business rule check failed (report only, write allowed)"
                ),
            }
        }
    }
    // A3-T4: a caller with the override privilege who gave a reason saves
    // anyway; each overridden check comes back as a warning and is audited.
    if !failures.is_empty()
        && let Some(reason) = staging.override_reason
    {
        for failure in &failures {
            warnings.push(RuleWarning {
                rule_id: failure.rule_id,
                rule_name: failure.rule_name.clone(),
                field: failure.field.clone(),
                message: format!("{} (overridden: {reason})", failure.message),
            });
        }
        if transient_block {
            return Err(AppError::Overloaded("business_rules.condition_wall_clock"));
        }
        return Ok(Judged {
            warnings,
            overridden: failures,
        });
    }
    if let Some(first) = failures.first() {
        return Err(AppError::RuleViolation {
            rule_id: first.rule_id,
            message: first.message.clone(),
            details: Some(RuleViolationDetails {
                field: first.field.clone(),
                rules: failures,
            }),
        });
    }
    if transient_block {
        return Err(AppError::Overloaded("business_rules.condition_wall_clock"));
    }
    Ok(Judged {
        warnings,
        overridden: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::business_rules::{AppliesTo, ConditionTree, PolicyDef, PolicyType, Severity};
    use attome_core::{DataClassification, OnTargetDelete};
    use serde_json::json;

    fn attr(name: &str, field_type_int: i32, required: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int,
            is_required: required,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            options: None,
        }
    }

    /// `status` text, `amount` number, `note` text (required), `total` number.
    fn attrs() -> Vec<AttrInfo> {
        vec![
            attr("status", 0, false),
            attr("amount", 1, false),
            attr("note", 0, true),
            attr("total", 1, false),
        ]
    }

    fn policy(v: Value, ordinal: i32) -> PolicyDef {
        let mut p: PolicyDef = serde_json::from_value(v).expect("policy");
        p.ordinal = ordinal;
        p
    }

    fn rule(name: &str, order: i32, condition: Value, policies: Vec<Value>) -> BusinessRuleDef {
        BusinessRuleDef {
            id: Uuid::now_v7(),
            entity_logicalname: "deal".to_owned(),
            name: name.to_owned(),
            display_name: None,
            is_active: true,
            display_order: order,
            version: 1,
            row_version: 1,
            applies_to: AppliesTo::All,
            role_ids: Vec::new(),
            portal_role_ids: Vec::new(),
            condition: serde_json::from_value::<ConditionTree>(condition).expect("tree"),
            policies: policies
                .into_iter()
                .enumerate()
                .map(|(i, p)| policy(p, i as i32))
                .collect(),
        }
    }

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().cloned().expect("object")
    }

    const STAFF: RuleAudience<'static> = RuleAudience::Staff {
        role_ids: &[],
        interactive: true,
    };

    fn pipeline<'a>(
        attrs: &'a [AttrInfo],
        audience: RuleAudience<'a>,
        rules: Vec<BusinessRuleDef>,
    ) -> WritePipeline<'a> {
        WritePipeline::with_rules(None, "deal", attrs, audience, rules)
    }

    fn closed_locks_amount(effect: &str) -> BusinessRuleDef {
        rule(
            "Closed deals",
            1,
            json!({"field": "status", "op": "eq", "value": "closed"}),
            vec![json!({"type": effect, "field": "amount"})],
        )
    }

    fn update<'a>(
        body: &'a Map<String, Value>,
        stored: &'a Map<String, Value>,
        baseline: &'a Map<String, Value>,
    ) -> WriteSides<'a> {
        WriteSides {
            body,
            stored: Some(stored),
            baseline,
            is_create: false,
        }
    }

    #[tokio::test]
    async fn a_locked_field_refuses_a_change_but_accepts_its_stored_value() {
        let attrs = attrs();
        let stored = map(json!({"status": "closed", "amount": 100}));
        let empty = Map::new();

        let changed = map(json!({"amount": 150}));
        let m2 = map(json!({"status": "closed", "amount": 150}));
        let mut p = pipeline(&attrs, STAFF, vec![closed_locks_amount("disabled")]);
        let err = p
            .judge(&m2, true, &update(&changed, &stored, &empty))
            .await
            .unwrap_err();
        match err {
            AppError::FieldLocked { locks, required } => {
                assert!(!required);
                assert_eq!(locks[0].field, "amount");
                assert_eq!(locks[0].rule_name, "Closed deals");
                assert_eq!(locks[0].effect, "disabled");
            }
            other => panic!("expected field_locked, got {other:?}"),
        }

        // Re-sending the stored value (as a float) is not a change.
        let same = map(json!({"amount": 100.0}));
        let m2 = map(json!({"status": "closed", "amount": 100.0}));
        let mut p = pipeline(&attrs, STAFF, vec![closed_locks_amount("hidden")]);
        assert!(
            p.judge(&m2, true, &update(&same, &stored, &empty))
                .await
                .is_ok()
        );
    }

    /// A writer may unlock a field by changing the condition field in the
    /// same request: the condition is judged on the record as it will be
    /// saved.
    #[tokio::test]
    async fn the_condition_is_judged_on_the_final_record() {
        let attrs = attrs();
        let stored = map(json!({"status": "closed", "amount": 100}));
        let body = map(json!({"status": "open", "amount": 150}));
        let m2 = map(json!({"status": "open", "amount": 150}));
        let empty = Map::new();
        let mut p = pipeline(&attrs, STAFF, vec![closed_locks_amount("disabled")]);
        assert!(
            p.judge(&m2, true, &update(&body, &stored, &empty))
                .await
                .is_ok()
        );
    }

    /// Design §3.1 + D-791 rule 3: a system context and an API-key/S2S
    /// principal skip locks; `error` policies still bind them.
    #[tokio::test]
    async fn system_and_service_writers_skip_locks_but_not_errors() {
        let attrs = attrs();
        let stored = map(json!({"status": "closed", "amount": 100}));
        let body = map(json!({"amount": 150}));
        let m2 = map(json!({"status": "closed", "amount": 150}));
        let empty = Map::new();
        let service = RuleAudience::Staff {
            role_ids: &[],
            interactive: false,
        };
        for audience in [RuleAudience::System, service] {
            let mut p = pipeline(&attrs, audience, vec![closed_locks_amount("hidden")]);
            assert!(
                p.judge(&m2, true, &update(&body, &stored, &empty))
                    .await
                    .is_ok(),
                "{audience:?} is not subject to locks"
            );
            let error = rule(
                "Cap",
                2,
                json!({"field": "amount", "op": "gt", "value": 120}),
                vec![json!({"type": "error", "severity": "error", "message": "too big"})],
            );
            let mut p = pipeline(&attrs, audience, vec![error]);
            assert!(matches!(
                p.judge(&m2, true, &update(&body, &stored, &empty)).await,
                Err(AppError::RuleViolation { .. })
            ));
        }
    }

    #[tokio::test]
    async fn a_create_may_send_null_or_the_engine_value_for_a_locked_field() {
        let attrs = attrs();
        let lock = rule(
            "Always locked",
            1,
            json!({"all": []}),
            vec![json!({"type": "disabled", "field": "status"})],
        );
        let baseline = map(json!({"status": "new"}));
        for (body, ok) in [
            (json!({"status": null}), true),
            (json!({"status": "new"}), true),
            (json!({"status": "won"}), false),
        ] {
            let body = map(body);
            let mut p = pipeline(&attrs, STAFF, vec![lock.clone()]);
            let sides = WriteSides {
                body: &body,
                stored: None,
                baseline: &baseline,
                is_create: true,
            };
            let m2 = map(json!({"status": "new", "note": "x"}));
            assert_eq!(p.judge(&m2, true, &sides).await.is_ok(), ok, "{body:?}");
        }
    }

    #[tokio::test]
    async fn a_required_field_locked_and_empty_names_field_and_rule() {
        let attrs = attrs();
        let lock = rule(
            "Hide note",
            1,
            json!({"all": []}),
            vec![json!({"type": "hidden", "field": "note"})],
        );
        let body = map(json!({"amount": 1}));
        let stored = map(json!({"amount": 1}));
        let m2 = map(json!({"amount": 1, "note": ""}));
        let empty = Map::new();
        let mut p = pipeline(&attrs, STAFF, vec![lock.clone()]);
        match p.judge(&m2, true, &update(&body, &stored, &empty)).await {
            Err(AppError::FieldLocked { locks, required }) => {
                assert!(required);
                assert_eq!(locks[0].field, "note");
                assert_eq!(locks[0].rule_name, "Hide note");
                assert_eq!(locks[0].effect, "hidden");
            }
            other => panic!("expected field_locked_required, got {other:?}"),
        }
        // A value (for example from a set_value policy) satisfies it.
        let filled = map(json!({"amount": 1, "note": "set by rule"}));
        let mut p = pipeline(&attrs, STAFF, vec![lock]);
        assert!(
            p.judge(&filled, true, &update(&body, &stored, &empty))
                .await
                .is_ok()
        );
    }

    /// Most restrictive wins across rules: hidden beats disabled, whichever
    /// comes first.
    #[tokio::test]
    async fn hidden_beats_disabled_across_rules() {
        let attrs = attrs();
        let disabled = rule(
            "Soft lock",
            1,
            json!({"all": []}),
            vec![json!({"type": "disabled", "field": "amount"})],
        );
        let hidden = rule(
            "Hard lock",
            2,
            json!({"all": []}),
            vec![json!({"type": "hidden", "field": "amount"})],
        );
        let body = map(json!({"amount": 5}));
        let stored = map(json!({"amount": 1}));
        let empty = Map::new();
        let mut p = pipeline(&attrs, STAFF, vec![disabled, hidden]);
        match p.judge(&body, true, &update(&body, &stored, &empty)).await {
            Err(AppError::FieldLocked { locks, .. }) => {
                assert_eq!(locks[0].effect, "hidden");
                assert_eq!(locks[0].rule_name, "Hard lock");
            }
            other => panic!("expected field_locked, got {other:?}"),
        }
    }

    /// Design §3.2: an unknown condition (here a null input to a comparison
    /// in an advanced leaf) holds for errors — the converted-validation
    /// parity `not (E)` relies on.
    #[tokio::test]
    async fn an_unknown_condition_fails_closed_for_errors() {
        let attrs = attrs();
        // Converted legacy validation `amount > 0`.
        let converted = rule(
            "Positive",
            1,
            json!({"expression": "not (amount > 0)"}),
            vec![
                json!({"type": "error", "severity": "error", "message": "amount must be positive", "field": "amount"}),
            ],
        );
        let empty = Map::new();
        for (record, blocks) in [
            (json!({"amount": 5}), false),
            (json!({"amount": -5}), true),
            (json!({"amount": null}), true),
            (json!({}), true),
        ] {
            let record = map(record);
            let mut p = pipeline(&attrs, RuleAudience::System, vec![converted.clone()]);
            let result = p
                .judge(&record, true, &update(&record, &record, &empty))
                .await;
            match (result, blocks) {
                (Ok(_), false) => {}
                (
                    Err(AppError::RuleViolation {
                        message, details, ..
                    }),
                    true,
                ) => {
                    assert_eq!(message, "amount must be positive");
                    let details = details.expect("business details");
                    assert_eq!(details.field.as_deref(), Some("amount"));
                    assert_eq!(details.rules.len(), 1);
                }
                (other, _) => panic!("{record:?}: unexpected {other:?}"),
            }
        }
    }

    /// D-791 rule 6: a warning never blocks and comes back to the caller.
    #[tokio::test]
    async fn a_warning_is_returned_not_blocking() {
        let attrs = attrs();
        let warn = rule(
            "Large deal",
            1,
            json!({"field": "amount", "op": "gt", "value": 1000}),
            vec![
                json!({"type": "error", "severity": "warning", "message": "check with finance", "field": "amount"}),
            ],
        );
        let record = map(json!({"amount": 5000}));
        let empty = Map::new();
        let mut p = pipeline(&attrs, STAFF, vec![warn.clone()]);
        let warnings = p
            .judge(&record, true, &update(&record, &record, &empty))
            .await
            .expect("a warning never blocks");
        assert_eq!(
            warnings,
            vec![RuleWarning {
                rule_id: warn.id,
                rule_name: "Large deal".to_owned(),
                field: Some("amount".to_owned()),
                message: "check with finance".to_owned(),
            }]
        );
        assert!(!Severity::Warning.blocks());
    }

    /// A3-T4: a staged check reports, warns, or refuses from its date.
    #[tokio::test]
    async fn a_staged_check_reports_warns_or_refuses_from_its_date() {
        let attrs = attrs();
        let record = map(json!({"amount": 5000}));
        let empty = Map::new();
        let staged = |stage: Value| {
            let mut policy =
                json!({"type": "required", "field": "status", "message": "status is needed"});
            if let (Some(policy), Some(extra)) = (policy.as_object_mut(), stage.as_object()) {
                policy.extend(extra.clone());
            }
            rule(
                "Status",
                1,
                json!({"field": "amount", "op": "gt", "value": 1000}),
                vec![policy],
            )
        };
        let judge = |rule: BusinessRuleDef| {
            let attrs = attrs.clone();
            let record = record.clone();
            let empty = empty.clone();
            async move {
                let mut p = pipeline(&attrs, STAFF, vec![rule]);
                p.judge(&record, true, &update(&record, &record, &empty))
                    .await
            }
        };

        let report = judge(staged(json!({"stage": "report"})))
            .await
            .expect("report never blocks");
        assert!(report.is_empty(), "report only logs: {report:?}");

        let warn = judge(staged(json!({"stage": "warn"})))
            .await
            .expect("warn never blocks");
        assert_eq!(warn.len(), 1);
        assert_eq!(warn[0].message, "status is needed");

        let later = judge(staged(
            json!({"stage": "enforce", "enforce_from": "2999-01-01"}),
        ))
        .await
        .expect("before its date an enforced check warns");
        assert_eq!(later.len(), 1);

        let now = judge(staged(
            json!({"stage": "enforce", "enforce_from": "2000-01-01"}),
        ))
        .await;
        assert!(
            matches!(now, Err(AppError::RuleViolation { .. })),
            "{now:?}"
        );
    }

    /// A3-T4: with an override reason a refusing check lets the write through,
    /// says so in a warning, and is kept for the security event.
    #[tokio::test]
    async fn an_override_reason_saves_past_a_refusing_check() {
        let attrs = attrs();
        let refuse = rule(
            "Large deal",
            1,
            json!({"field": "amount", "op": "gt", "value": 1000}),
            vec![
                json!({"type": "error", "severity": "error", "message": "too large", "field": "amount"}),
            ],
        );
        let record = map(json!({"amount": 5000}));
        let empty = Map::new();

        let mut refused = pipeline(&attrs, STAFF, vec![refuse.clone()]);
        assert!(
            refused
                .judge(&record, true, &update(&record, &record, &empty))
                .await
                .is_err()
        );

        let mut p = pipeline(&attrs, STAFF, vec![refuse.clone()]);
        p.override_reason = Some("signed off by finance".to_owned());
        let warnings = p
            .judge(&record, true, &update(&record, &record, &empty))
            .await
            .expect("an override saves");
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].message,
            "too large (overridden: signed off by finance)"
        );
        assert_eq!(p.overridden.len(), 1);
        assert_eq!(p.overridden[0].rule_id, refuse.id);
    }

    /// Every firing error is collected; `rule_id` names the first by display
    /// order.
    #[tokio::test]
    async fn every_error_is_collected_first_by_display_order() {
        let attrs = attrs();
        let a = rule(
            "A",
            1,
            json!({"all": []}),
            vec![json!({"type": "error", "severity": "error", "message": "first"})],
        );
        let b = rule(
            "B",
            2,
            json!({"all": []}),
            vec![
                json!({"type": "error", "severity": "error", "message": "second", "field": "status"}),
            ],
        );
        let record = map(json!({"amount": 1}));
        let empty = Map::new();
        let mut p = pipeline(&attrs, STAFF, vec![a.clone(), b]);
        match p
            .judge(&record, true, &update(&record, &record, &empty))
            .await
        {
            Err(AppError::RuleViolation {
                rule_id,
                message,
                details,
            }) => {
                assert_eq!(rule_id, a.id);
                assert_eq!(message, "first");
                let details = details.expect("details");
                assert_eq!(details.field, None);
                assert_eq!(details.rules.len(), 2);
                assert_eq!(details.rules[1].field.as_deref(), Some("status"));
            }
            other => panic!("expected rule_violation, got {other:?}"),
        }
    }

    /// Pipeline order: `set_value` runs before errors, so an error judges the
    /// value a rule computed (design §1.2 behaviour change 1); defaults fill
    /// only empty fields on create; `always` reads M1 (defaults included).
    #[tokio::test]
    async fn set_values_run_before_errors_and_errors_see_them() {
        let attrs = attrs();
        let default_amount = rule(
            "Default amount",
            1,
            json!({"all": []}),
            vec![json!({"type": "set_value", "field": "amount", "value": 10, "mode": "default"})],
        );
        let total = rule(
            "Total",
            2,
            json!({"all": []}),
            vec![
                json!({"type": "set_value", "field": "total", "expression": "amount * 2", "mode": "always"}),
            ],
        );
        let cap = rule(
            "Cap total",
            3,
            json!({"field": "total", "op": "gt", "value": 15}),
            vec![json!({"type": "error", "severity": "error", "message": "total too high"})],
        );
        let mut p = pipeline(
            &attrs,
            RuleAudience::System,
            vec![default_amount, total, cap],
        );
        let m0 = map(json!({"status": "open", "note": "x"}));
        let fired = p.fire_set_values(&m0, true).await.expect("conditions");
        let defaults = p.default_values(&fired, &m0).await;
        assert_eq!(defaults, vec![("amount".to_owned(), json!(10))]);
        let mut m1 = m0.clone();
        m1.extend(defaults);
        let always = p.always_values(&fired, &m1).await.expect("computes");
        assert_eq!(always, vec![("total".to_owned(), json!(20.0))]);
        let mut m2 = m1.clone();
        m2.extend(always);
        let empty = Map::new();
        let sides = WriteSides {
            body: &m0,
            stored: None,
            baseline: &empty,
            is_create: true,
        };
        match p.judge(&m2, true, &sides).await {
            Err(AppError::RuleViolation { message, .. }) => assert_eq!(message, "total too high"),
            other => panic!("the error must see the computed total, got {other:?}"),
        }

        // A caller-supplied amount is not overwritten by the default.
        let m0 = map(json!({"amount": 3}));
        let fired = p.fire_set_values(&m0, true).await.expect("conditions");
        assert!(p.default_values(&fired, &m0).await.is_empty());
    }

    /// Design §3.2: a `set_value` whose condition is unknown fails the write.
    #[tokio::test]
    async fn an_unknown_set_value_condition_fails_the_write() {
        let attrs = attrs();
        let r = rule(
            "Odd",
            1,
            json!({"expression": "amount > 0"}),
            vec![json!({"type": "set_value", "field": "total", "value": 1, "mode": "always"})],
        );
        let mut p = pipeline(&attrs, RuleAudience::System, vec![r]);
        let m0 = map(json!({"amount": null}));
        assert!(matches!(
            p.fire_set_values(&m0, false).await,
            Err(AppError::RuleViolation { .. })
        ));
    }

    /// Update never applies `default` policies.
    #[tokio::test]
    async fn default_policies_are_create_only() {
        let attrs = attrs();
        let r = rule(
            "Default",
            1,
            json!({"all": []}),
            vec![json!({"type": "set_value", "field": "amount", "value": 1, "mode": "default"})],
        );
        let p = pipeline(&attrs, RuleAudience::System, vec![r]);
        assert!(!p.has_set_value(0, false));
        assert!(p.has_set_value(0, true));
    }

    #[test]
    fn a_role_scoped_rule_follows_its_audience() {
        let role = Uuid::now_v7();
        let mut r = closed_locks_amount("hidden");
        r.applies_to = AppliesTo::Roles;
        r.role_ids = vec![role];
        let holder = [role];
        assert!(
            r.policies_for(&RuleAudience::Staff {
                role_ids: &holder,
                interactive: true
            })
            .next()
            .is_some()
        );
        assert!(r.policies_for(&STAFF).next().is_none());
        assert!(r.policies_for(&RuleAudience::System).next().is_none());
        assert_eq!(r.policies[0].policy_type, PolicyType::Hidden);
    }

    #[test]
    fn a_removed_choice_keeps_a_condition_compilable_at_write_time() {
        let mut status = attr("status", 7, false);
        status.options = Some(json!({"choices": ["open"], "multi": false}));
        let attrs = vec![status];
        let tree: ConditionTree =
            serde_json::from_value(json!({"field": "status", "op": "eq", "value": "closed"}))
                .expect("tree");
        assert!(
            compile_condition(&tree, &attrs).is_err(),
            "authoring refuses it"
        );
        assert!(compile_condition(&tree, &runtime_attrs(&attrs)).is_ok());
    }

    #[test]
    fn same_value_compares_canonical_forms() {
        let n = attr("amount", 1, false);
        assert!(same_value(Some(&n), Some(&json!(1)), Some(&json!(1.0))));
        assert!(!same_value(Some(&n), Some(&json!(1)), Some(&json!(2))));
        assert!(same_value(Some(&n), Some(&Value::Null), None));
        assert!(!same_value(Some(&n), Some(&json!(1)), None));
        let d = attr("due", 5, false);
        assert!(same_value(
            Some(&d),
            Some(&json!("2026-09-30T00:00:00Z")),
            Some(&json!("2026-09-30T00:00:00+00:00"))
        ));
    }

    #[test]
    fn audiences_come_from_the_principal() {
        let mut ctx = attome_server::security::SecurityContext {
            user_id: Uuid::nil(),
            is_admin: true,
            privileges: Default::default(),
            field_grants: Default::default(),
            field_write_grants: Default::default(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: Default::default(),
            role_ids: None,
            service_principal: false,
        };
        assert_eq!(audience(&Principal::Staff(&ctx)), RuleAudience::System);
        ctx.role_ids = Some(Vec::new());
        assert!(audience(&Principal::Staff(&ctx)).subject_to_locks());
        ctx.service_principal = true;
        assert!(!audience(&Principal::Staff(&ctx)).subject_to_locks());
    }
}
