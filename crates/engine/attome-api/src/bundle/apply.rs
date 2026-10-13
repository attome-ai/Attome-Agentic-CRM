//! Apply: close the diff a persisted plan describes, as a durable, resumable
//! job (P-environment-promotion §4 "Durable job with a ledger, not one giant
//! transaction" / §5 step 12).
//!
//! [`run_apply_job`] is the worker entry `EngineJob::ApplyMetadataBundle
//! { plan_id }` dispatches to (`crates/server/src/jobs.rs`). It claims the
//! ledger row (CAS, stale-claim timeout — [`super::ledger::claim`]), walks
//! the bundle's objects in dependency order, and for each one calls the
//! matching *reconcile primitive* — `attome_metadata::provision::reconcile_*` for
//! entities and attributes, the admin service functions of this crate for
//! queries, views and sidebar items, `attome_security::reconcile::*` for roles,
//! privileges and field-security profiles. **Nothing in this file issues
//! schema statements of its own** (D-003; the `bundle-engine-no-ddl` CI
//! grep): every physical change happens inside those primitives, each of
//! which is its own short transaction holding the metadata write lock and
//! appending the change log as its last statement.
//!
//! **Order.** privileges → entities → attributes (non-lookup first, then
//! lookups, so a lookup's target column exists before the FK is installed)
//! → queries → views (a view names its query) → sidebar (parents before
//! children: sorted by path length) → field-security profiles → roles (a
//! role links to profiles, privileges and entities, so it comes last among
//! the upserts) → retires, children before parents: sidebar (deepest path
//! first), views, queries, attributes, entities, roles, profiles. Role grants
//! / entity-access rows and profile fields are *set semantics inside their
//! parent* — `reconcile_role` / `reconcile_field_security_profile` take the
//! whole desired object — so their own plan lines (`role_grant`,
//! `role_entity_access`, `profile_field`, including their retires) are
//! folded into one step for the parent.
//!
//! **What a step does with the plan.** The persisted plan is the reviewed,
//! approved artifact, and its `basis_hash` was re-checked against live
//! metadata when the row was queued and again when this job first claims it
//! (see `check_basis`). A step whose plan line is `noop` is therefore
//! skipped without touching the database (the reconcile primitives are
//! compare-first anyway, so re-running it would be a read, but skipping it
//! keeps a 2 000-object bundle's apply proportional to its *diff*). Every
//! other line — `create`, `update`, and a retire — is executed through the
//! primitive, which decides for itself what is actually different. Resume
//! relies on exactly that idempotence: the ledger `cursor` is the number of
//! steps completed, a restarted worker skips that many and re-runs the rest,
//! and a step that had already landed before the crash reconciles as
//! `Unchanged`.
//!
//! **Resume and the basis check.** On a fresh start (`cursor == 0`) the live
//! export must still hash to the plan's `basis_hash`; if it does not the row
//! is marked `failed` ("basis changed since plan") and nothing is written —
//! the 409 the apply route gives, one hop later. On a resume (`cursor > 0`)
//! live metadata has *by construction* moved away from the basis (the
//! earlier steps moved it), so the check is not repeated; the plan was bound
//! when it started.
//!
//! **Expensive attribute contract changes.** `reconcile_attribute` refuses a
//! `is_required`/`max_length` change that crosses the size gate with
//! `Conflict("schema change requires async plan")` and writes nothing. The
//! engine then does what the admin PATCH does for the same case: applies
//! every *other* field of the attribute now (re-running the primitive with
//! the contract fields held at their live values), records the target
//! contract on the metadata row and queues the existing
//! `ApplySchemaChangePlan` durable job in the same short transaction, so the
//! physical constraint lands asynchronously through the proven backfill →
//! validate path — never an unbounded scan on this job's thread. Counted
//! separately in the summary (`deferred_schema_changes`).
//!
//! **Doorbell.** Exactly one `notify_metadata_change` per run, after the
//! ledger row has reached its terminal state — on success *and* on a failure
//! that had already committed some objects, so no node is left waiting on
//! its reconnect re-check for changes that are already in the log. Never one
//! per object (§4 "Cache invalidation is a bulk concern").

use std::collections::HashMap;
use std::time::Duration;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
    fetch_audit_ctx,
};
use attome_core::EngineState;
use attome_core::changeset::Layer;
use attome_db::DbPool;
use attome_metadata::provision::{
    self as provision, AttributeDesc, EntityDesc, ReconcileOutcome, ReconcilePolicy,
};
use attome_security::reconcile as security;
use attome_types::AppError;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use super::canonical::bundle_hash;
use super::derived_id::derived_id;
use super::export::export_bundle;
use super::ledger::{self, PlanRow};
use super::model::*;
use super::plan::PlanAction;

/// Size gate for the index build that follows a created/updated attribute
/// (mirrors `admin/attribute.rs::ATTRIBUTE_INDEX_INLINE_ROW_LIMIT`, private
/// there; same value, same posture).
const ATTRIBUTE_INDEX_INLINE_ROW_LIMIT: i64 = 100_000;

/// How many times one step is retried when it loses the non-blocking
/// metadata-write lock to a concurrent admin write, and the base of the
/// linear backoff between attempts. The job is background work, so waiting a
/// few hundred milliseconds beats failing a 200-object apply over one
/// unlucky collision; the bound keeps a genuinely stuck lock from turning
/// into an endless spin.
const LOCK_RETRY_ATTEMPTS: u32 = 5;
const LOCK_RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// The message `reconcile_attribute` uses for the size-gate refusal. Matched
/// by value — `AppError::Conflict` carries a `&'static str`, not a code.
const SCHEMA_CHANGE_NEEDS_PLAN: &str = "schema change requires async plan";

/// What one run did, for the structured `info` line and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplySummary {
    /// Steps walked this run (excluding the ones the cursor skipped).
    pub steps: u32,
    pub created: u32,
    pub updated: u32,
    pub unchanged: u32,
    /// `noop` plan lines skipped without a database call.
    pub skipped_noop: u32,
    pub retired: u32,
    /// Attribute contract changes handed to `ApplySchemaChangePlan`.
    pub deferred_schema_changes: u32,
}

impl ApplySummary {
    fn record(&mut self, outcome: ReconcileOutcome) {
        match outcome {
            ReconcileOutcome::Created => self.created += 1,
            ReconcileOutcome::Updated => self.updated += 1,
            ReconcileOutcome::Unchanged | ReconcileOutcome::SkippedCustomized => {
                self.unchanged += 1;
            }
        }
    }

    /// Objects actually written this run — what the ledger's
    /// `applied_count` accumulates.
    fn written(&self) -> u32 {
        self.created + self.updated + self.retired + self.deferred_schema_changes
    }
}

// ── Worker entry ─────────────────────────────────────────────────────────────

/// The worker entry for `EngineJob::ApplyMetadataBundle { plan_id }`.
///
/// Returns `Ok(())` without doing anything when the row cannot be claimed
/// (already taken by another worker, or not in a claimable state). On a
/// step failure the row is marked `failed` with the object key and the
/// error, the doorbell fires if anything had been written, and the error is
/// returned so the job shows up in the dead-letter view like
/// `ApplySchemaChangePlan` does — a retry is harmless (the row is no longer
/// claimable) and the ledger row is the durable record either way.
pub async fn run_apply_job(state: &EngineState, plan_id: Uuid) -> Result<(), AppError> {
    let worker = format!("pid-{}:{}", std::process::id(), Uuid::now_v7());
    let Some(row) = ledger::claim(&state.base.db, plan_id, &worker).await? else {
        tracing::info!(
            plan_id = %plan_id,
            "bundle apply: plan is not claimable (already claimed, finished, or not queued); nothing to do"
        );
        return Ok(());
    };

    let mut summary = ApplySummary::default();
    let result = apply_claimed(state, &row, &mut summary).await;

    let result = match result {
        Ok(()) => {
            ledger::mark_succeeded(&state.base.db, plan_id).await?;
            // P-environment-promotion §5 step 20 — recompute the
            // configuration hash now that this apply changed live metadata.
            // Best-effort, same posture as the boot-time computation in
            // `system.rs`: a failed re-export must never fail an otherwise-
            // successful apply — `/version` just keeps reporting the
            // previous hash until the next successful computation.
            match export_bundle(&state.base.db).await {
                Ok(bundle) => state
                    .base
                    .configuration_version
                    .store(Some(std::sync::Arc::new(bundle_hash(&bundle)))),
                Err(error) => tracing::warn!(
                    plan_id = %plan_id,
                    %error,
                    "bundle apply succeeded but re-computing the configuration hash failed"
                ),
            }
            tracing::info!(
                plan_id = %plan_id,
                bundle_hash = %row.bundle_hash,
                resumed_from = row.cursor,
                steps = summary.steps,
                created = summary.created,
                updated = summary.updated,
                unchanged = summary.unchanged,
                skipped_noop = summary.skipped_noop,
                retired = summary.retired,
                deferred_schema_changes = summary.deferred_schema_changes,
                "bundle apply succeeded"
            );
            Ok(())
        }
        Err(failure) => {
            // A lost claim means another worker owns the row now (it was
            // reclaimed after a stale-claim timeout); marking it failed would
            // stamp *their* run. Leave the ledger to them.
            if !failure.lost_claim {
                ledger::mark_failed(&state.base.db, plan_id, &failure.message).await?;
            }
            tracing::warn!(
                plan_id = %plan_id,
                bundle_hash = %row.bundle_hash,
                resumed_from = row.cursor,
                steps = summary.steps,
                written = summary.written(),
                error = %failure.message,
                "bundle apply failed"
            );
            Err(failure.error)
        }
    };

    // One doorbell per run, after the terminal ledger state — see module doc.
    if result.is_ok() || summary.written() > 0 {
        crate::admin::notify_metadata_change(&state.base.redis).await;
    }

    result
}

/// Why a run stopped: the error itself, and the message the ledger keeps —
/// the object key plus the error's display form (masked for `Internal`, so
/// no raw database text reaches the status endpoint).
struct ApplyFailure {
    message: String,
    error: AppError,
    /// `ledger::advance` refused: the row is no longer this worker's.
    lost_claim: bool,
}

impl From<AppError> for ApplyFailure {
    fn from(error: AppError) -> Self {
        ApplyFailure {
            message: error.to_string(),
            error,
            lost_claim: false,
        }
    }
}

/// Runs the plan `row` describes from its stored cursor. Pure orchestration:
/// decides the step list, checks the basis, loops, advances the ledger.
async fn apply_claimed(
    state: &EngineState,
    row: &PlanRow,
    summary: &mut ApplySummary,
) -> Result<(), ApplyFailure> {
    let bundle = stored_bundle(row)?;
    let stored_plan = StoredPlan::from_value(&row.plan)?;
    if !stored_plan.blocked.is_empty() {
        return Err(AppError::Validation(format!(
            "plan has {} blocked entr{}; it cannot be applied",
            stored_plan.blocked.len(),
            if stored_plan.blocked.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ))
        .into());
    }

    // Live metadata is read once per run: on a fresh start it is the basis
    // check; on both paths it is what retire steps resolve their targets
    // against (an object already gone from it is already retired).
    let live = export_bundle(&state.base.db_migrator).await?;
    if row.cursor == 0 {
        check_basis(&live, &row.basis_hash)?;
    }

    let steps = build_steps(&bundle, &stored_plan);
    let start = usize::try_from(row.cursor).unwrap_or(0);
    if start > steps.len() {
        return Err(AppError::Validation(format!(
            "stored cursor {} is beyond the plan's {} steps",
            row.cursor,
            steps.len()
        ))
        .into());
    }

    let mut ctx = ApplyContext {
        state,
        policy_actor: row.requested_by,
        entity_ids: HashMap::new(),
        live: &live,
        additive_only: stored_plan.additive_only,
    };
    let mut applied_count = row.applied_count;

    // Refreshed once, immediately before the first record step — never in the
    // step loop's hot path, and never for a bundle that writes no records.
    //
    // `Step::Record` goes through `entity_mutation::create_one`, which resolves
    // every lookup against the **in-memory** `state.entities` registry, not the
    // database. That registry is only refreshed by the Redis doorbell this
    // function rings *after* the run (see this module's doc comment), so a
    // record referencing an entity provisioned earlier in the same boot — by an
    // earlier step here, or by an earlier bundle whose doorbell has not been
    // observed yet — resolved against a snapshot that predates it and failed
    // with `lookup target entity does not exist`.
    //
    // It never showed on an existing database, where the registry loaded at
    // startup already contained every entity from previous boots. It showed on
    // an empty one — a new customer deployment, D-002 — where
    // `attome-ai-provider-data`'s rows reference `authentication_type`
    // provisioned minutes earlier in the same boot. Swapping the snapshot here
    // is exactly what the doorbell handler does, just eagerly and locally; the
    // doorbell still fires afterwards for the other nodes.
    let mut registry_refreshed = false;

    for (index, step) in steps.iter().enumerate().skip(start) {
        if !registry_refreshed && matches!(step.step, Step::Record { .. }) {
            let registry = attome_core::meta_registry::build_registry(&state.base.db)
                .await
                .map_err(|error| ApplyFailure {
                    message: format!("refreshing entity metadata before record steps: {error}"),
                    error,
                    lost_claim: false,
                })?;
            ctx.state.entities.swap(registry);
            registry_refreshed = true;
        }

        let before = summary.written();
        if let Err(error) = run_step(&mut ctx, step, summary).await {
            tracing::warn!(
                component = step.component,
                key = %step.key,
                error = %error,
                "bundle apply: step failed"
            );
            return Err(ApplyFailure {
                message: format!("{} {}: {error}", step.component, step.key),
                error,
                lost_claim: false,
            });
        }
        summary.steps += 1;
        applied_count += i32::try_from(summary.written() - before).unwrap_or(i32::MAX);
        let cursor = i32::try_from(index + 1).unwrap_or(i32::MAX);
        ledger::advance(&state.base.db, row.id, cursor, applied_count)
            .await
            .map_err(|error| ApplyFailure {
                message: error.to_string(),
                lost_claim: matches!(error, AppError::Conflict(_)),
                error,
            })?;
    }
    Ok(())
}

/// The plan was computed against `basis_hash`; a fresh start must still see
/// that exact metadata (§4 "Plan and apply are separate calls").
fn check_basis(live: &Bundle, basis_hash: &str) -> Result<(), AppError> {
    if bundle_hash(live) != basis_hash {
        return Err(AppError::Conflict("basis changed since plan"));
    }
    Ok(())
}

fn stored_bundle(row: &PlanRow) -> Result<Bundle, AppError> {
    let mut bundle: Bundle = serde_json::from_value(row.bundle.clone()).map_err(|e| {
        AppError::Validation(format!(
            "stored bundle on plan {} does not parse: {e}",
            row.id
        ))
    })?;
    bundle.normalize();
    Ok(bundle)
}

// ── The persisted plan, read back ────────────────────────────────────────────

/// One line of the persisted plan. `PlanEntry` itself is serialize-only (its
/// `component` is a `&'static str`), so the stored JSON is read back into
/// this owned shape.
#[derive(Clone, Debug, Deserialize)]
struct StoredEntry {
    component: String,
    key: String,
    action: PlanAction,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StoredPlan {
    #[serde(default)]
    entries: Vec<StoredEntry>,
    #[serde(default)]
    retires: Vec<StoredEntry>,
    #[serde(default)]
    blocked: Vec<StoredEntry>,
    /// [`super::plan::BundlePlan::additive_only`], read back out of the
    /// ledger's stored `plan_json` — see [`ApplyContext::additive_only`]'s
    /// doc comment for why a query step needs this at apply time.
    #[serde(default)]
    additive_only: bool,
}

impl StoredPlan {
    fn from_value(value: &serde_json::Value) -> Result<Self, AppError> {
        serde_json::from_value(value.clone())
            .map_err(|e| AppError::Validation(format!("stored plan does not parse: {e}")))
    }

    /// `(component, key) -> action` over `entries` (create/update/noop).
    fn actions(&self) -> HashMap<(&str, &str), PlanAction> {
        self.entries
            .iter()
            .map(|e| ((e.component.as_str(), e.key.as_str()), e.action))
            .collect()
    }

    /// `true` when any `entries`/`retires` line of `component` whose key
    /// starts with `prefix` is not a noop — used to fold a role's grant /
    /// entity-access lines and a profile's field lines into the parent step.
    fn has_child_change(&self, component: &str, prefix: &str) -> bool {
        self.entries.iter().chain(&self.retires).any(|e| {
            e.component == component && e.key.starts_with(prefix) && e.action != PlanAction::Noop
        })
    }
}

// ── Steps ────────────────────────────────────────────────────────────────────

enum Step<'a> {
    Privilege(&'a PrivilegeDef),
    Entity(&'a EntityDef),
    Attribute {
        entity: &'a EntityDef,
        attr: &'a AttributeDef,
    },
    /// [`AttributePatch`] — same primitive as `Attribute`, but `entity` is
    /// carried as a logicalname (never a full [`EntityDef`]: a patch does
    /// not own the entity's definition, only augments it — see that
    /// struct's doc comment).
    AttributePatch {
        entity: &'a str,
        attr: &'a AttributeDef,
    },
    Query(&'a QueryDef),
    View(&'a ViewDef),
    /// D-404 / M83 Phase 1.
    Calendar(&'a CalendarDef),
    Sidebar(&'a SidebarDef),
    Profile(&'a FieldSecurityProfileDef),
    Role(&'a RoleDef),
    /// M07 Phase 1 (D-405/D-406). Transitions are set semantics inside their
    /// parent, same as `Profile`'s fields — no separate `Step` per edge.
    StateModel(&'a StateModelDef),
    /// M01 Core P3 gap (D-455).
    Relationship(&'a RelationshipDef),
    /// M65 Phase 1 (D-467).
    App(&'a AppDef),
    /// M45 Phase 2 (D-472).
    Rule(&'a RuleDef),
    /// Phase 3 — one row of a `RecordSet`, resolved by its declared key.
    Record {
        entity: &'a str,
        key_fields: &'a [String],
        row: &'a serde_json::Map<String, serde_json::Value>,
    },
    /// A live object absent from the bundle; resolved against the live
    /// export when the step runs.
    Retire,
}

struct PlannedStep<'a> {
    component: &'static str,
    key: String,
    action: PlanAction,
    step: Step<'a>,
}

/// The deterministic step list for `(bundle, stored plan)` — the same list on
/// every run of the same plan row, which is what makes the ledger cursor
/// meaningful across a restart.
fn build_steps<'a>(bundle: &'a Bundle, plan: &'a StoredPlan) -> Vec<PlannedStep<'a>> {
    let actions = plan.actions();
    let action_of = |component: &'static str, key: &str| -> PlanAction {
        // An object the planner did not list (cannot happen for a plan this
        // binary wrote) is treated as Create: the primitive is compare-first,
        // so the worst case is one read.
        actions
            .get(&(component, key))
            .copied()
            .unwrap_or(PlanAction::Create)
    };
    let mut steps = Vec::new();

    for p in &bundle.privileges {
        steps.push(PlannedStep {
            component: COMPONENT_PRIVILEGE,
            key: p.key.clone(),
            action: action_of(COMPONENT_PRIVILEGE, &p.key),
            step: Step::Privilege(p),
        });
    }

    for e in &bundle.entities {
        steps.push(PlannedStep {
            component: COMPONENT_ENTITY,
            key: e.logicalname.clone(),
            action: action_of(COMPONENT_ENTITY, &e.logicalname),
            step: Step::Entity(e),
        });
    }

    // Plain attributes first (every entity), then lookups: a lookup's
    // target entity and its table exist by then, whatever the bundle order.
    // Formula fields (B-R6, D-604) come last: reconcile compiles a formula
    // against the entity's live fields, so every field it can read (lookups
    // included) must already exist, whatever order the bundle lists them.
    for pass in ["plain", "lookup", "formula"] {
        for e in &bundle.entities {
            for a in e.attributes.iter().filter(|a| {
                let kind = match a.field_type.as_str() {
                    "lookup" => "lookup",
                    "formula" => "formula",
                    _ => "plain",
                };
                kind == pass
            }) {
                let key = format!("{}.{}", e.logicalname, a.logicalname);
                steps.push(PlannedStep {
                    component: COMPONENT_ATTRIBUTE,
                    action: action_of(COMPONENT_ATTRIBUTE, &key),
                    key,
                    step: Step::Attribute { entity: e, attr: a },
                });
            }
        }
    }

    // Attribute patches after every entity's own attributes — a patch's
    // target entity is guaranteed live by `diff_attribute_patches` (never
    // created by this bundle), so it is always already provisioned by the
    // time a patch step runs, whatever order the two sections appear in the
    // bundle file.
    for p in &bundle.attribute_patches {
        let key = format!("{}.{}", p.entity, p.attribute.logicalname);
        steps.push(PlannedStep {
            component: COMPONENT_ATTRIBUTE_PATCH,
            action: action_of(COMPONENT_ATTRIBUTE_PATCH, &key),
            key,
            step: Step::AttributePatch {
                entity: &p.entity,
                attr: &p.attribute,
            },
        });
    }

    for q in &bundle.queries {
        let key = q.key().display();
        steps.push(PlannedStep {
            component: COMPONENT_QUERY,
            action: action_of(COMPONENT_QUERY, &key),
            key,
            step: Step::Query(q),
        });
    }

    for v in &bundle.views {
        let key = format!("{}.{}", v.entity, v.name);
        steps.push(PlannedStep {
            component: COMPONENT_VIEW,
            action: action_of(COMPONENT_VIEW, &key),
            key,
            step: Step::View(v),
        });
    }

    for c in &bundle.calendars {
        let key = c.name.clone();
        steps.push(PlannedStep {
            component: COMPONENT_CALENDAR,
            action: action_of(COMPONENT_CALENDAR, &key),
            key,
            step: Step::Calendar(c),
        });
    }

    // Parents before children. `normalize` already sorted by path, so the
    // stable sort keeps siblings in key order within each depth.
    let mut sidebar: Vec<&SidebarDef> = bundle.sidebar.iter().collect();
    sidebar.sort_by_key(|s| s.path.len());
    for s in sidebar {
        let key = s.path_display();
        steps.push(PlannedStep {
            component: COMPONENT_SIDEBAR,
            action: action_of(COMPONENT_SIDEBAR, &key),
            key,
            step: Step::Sidebar(s),
        });
    }

    for p in &bundle.field_security_profiles {
        let mut action = action_of(COMPONENT_FIELD_SECURITY_PROFILE, &p.name);
        if action == PlanAction::Noop
            && plan.has_child_change(COMPONENT_PROFILE_FIELD, &format!("{}:", p.name))
        {
            action = PlanAction::Update;
        }
        steps.push(PlannedStep {
            component: COMPONENT_FIELD_SECURITY_PROFILE,
            key: p.name.clone(),
            action,
            step: Step::Profile(p),
        });
    }

    for r in &bundle.roles {
        let mut action = action_of(COMPONENT_ROLE, &r.name);
        if action == PlanAction::Noop {
            let prefix = format!("{}:", r.name);
            if plan.has_child_change(COMPONENT_ROLE_GRANT, &prefix)
                || plan.has_child_change(COMPONENT_ROLE_ENTITY_ACCESS, &prefix)
            {
                action = PlanAction::Update;
            }
        }
        steps.push(PlannedStep {
            component: COMPONENT_ROLE,
            key: r.name.clone(),
            action,
            step: Step::Role(r),
        });
    }

    for m in &bundle.state_models {
        let mut action = action_of(COMPONENT_STATE_MODEL, &m.entity_logicalname);
        if action == PlanAction::Noop
            && plan.has_child_change(
                COMPONENT_STATE_TRANSITION,
                &format!("{}:", m.entity_logicalname),
            )
        {
            action = PlanAction::Update;
        }
        steps.push(PlannedStep {
            component: COMPONENT_STATE_MODEL,
            key: m.entity_logicalname.clone(),
            action,
            step: Step::StateModel(m),
        });
    }

    for r in &bundle.relationships {
        let action = action_of(COMPONENT_RELATIONSHIP, &r.name);
        steps.push(PlannedStep {
            component: COMPONENT_RELATIONSHIP,
            key: r.name.clone(),
            action,
            step: Step::Relationship(r),
        });
    }

    // M65 Phase 1 (D-467). Flat: `AppDef` carries no entity reference at all
    // (guidelines §9 "apps only filter, never authorize" — nothing here to
    // resolve against provisioning). Placed after relationships and before
    // record sets, same spot `diff_bundles` runs `diff_apps` in. (Forms are
    // code, D-788/D-790: a bundle carries none.)
    for a in &bundle.apps {
        steps.push(PlannedStep {
            component: COMPONENT_APP,
            key: a.name.clone(),
            action: action_of(COMPONENT_APP, &a.name),
            step: Step::App(a),
        });
    }

    // M45 Phase 2 (D-472). Same spot `diff_bundles` runs `diff_rules` in —
    // after apps, before record sets.
    for r in &bundle.rules {
        let key = r.key();
        steps.push(PlannedStep {
            component: COMPONENT_RULE,
            action: action_of(COMPONENT_RULE, &key),
            key,
            step: Step::Rule(r),
        });
    }

    // Record sets last among the upserts — after every metadata component,
    // so the entity/attribute a row targets already exists whatever the
    // bundle's own ordering. One step per row, in bundle order (the row's
    // own order within a record set, then record-set order) — the same
    // granularity the ledger cursor resumes at for every other component.
    for rs in &bundle.record_sets {
        for row in &rs.rows {
            let key = super::record_sets::record_key(&rs.entity, &rs.key_fields, row);
            steps.push(PlannedStep {
                component: COMPONENT_RECORD,
                action: action_of(COMPONENT_RECORD, &key),
                key,
                step: Step::Record {
                    entity: &rs.entity,
                    key_fields: &rs.key_fields,
                    row,
                },
            });
        }
    }

    // Retires last, children before parents. The child lines of a role /
    // profile are already folded into the parent's step above.
    let retire_order: &[&str] = &[
        COMPONENT_SIDEBAR,
        COMPONENT_VIEW,
        COMPONENT_CALENDAR,
        COMPONENT_QUERY,
        // Pre-existing gap fixed here: COMPONENT_RELATIONSHIP (D-455) was
        // never listed, so a relationship's own retire plan line matched no
        // component here and silently produced no step — `run_retire`
        // already has a `COMPONENT_RELATIONSHIP` arm below, it was just
        // unreachable via `build_steps`. Apps (D-467) added in the same
        // pass, same "children before the entity they reference" spot
        // relationships already occupy.
        COMPONENT_RELATIONSHIP,
        COMPONENT_APP,
        // M45 Phase 2 (D-472). A rule names an entity/target_field but is
        // not itself referenced by anything else in this list, so its retire
        // position only needs to be before the entity it targets — same
        // spot apps take.
        COMPONENT_RULE,
        COMPONENT_ATTRIBUTE,
        COMPONENT_ENTITY,
        COMPONENT_ROLE,
        COMPONENT_FIELD_SECURITY_PROFILE,
        COMPONENT_STATE_MODEL,
    ];
    for component in retire_order {
        let mut group: Vec<&StoredEntry> = plan
            .retires
            .iter()
            .filter(|r| r.action == PlanAction::Retire && r.component == *component)
            .collect();
        if *component == COMPONENT_SIDEBAR {
            // Deepest first so a child is retired before its parent.
            group.sort_by_key(|r| std::cmp::Reverse(r.key.matches('/').count()));
        }
        for r in group {
            steps.push(PlannedStep {
                component: static_component(&r.component),
                key: r.key.clone(),
                action: PlanAction::Retire,
                step: Step::Retire,
            });
        }
    }

    steps
}

/// Maps a stored component name back onto the `COMPONENT_*` constant (the
/// plan lines were written from those constants, so the list is closed).
fn static_component(name: &str) -> &'static str {
    match name {
        COMPONENT_SIDEBAR => COMPONENT_SIDEBAR,
        COMPONENT_VIEW => COMPONENT_VIEW,
        COMPONENT_CALENDAR => COMPONENT_CALENDAR,
        COMPONENT_QUERY => COMPONENT_QUERY,
        COMPONENT_ATTRIBUTE => COMPONENT_ATTRIBUTE,
        COMPONENT_ENTITY => COMPONENT_ENTITY,
        COMPONENT_ROLE => COMPONENT_ROLE,
        COMPONENT_FIELD_SECURITY_PROFILE => COMPONENT_FIELD_SECURITY_PROFILE,
        COMPONENT_STATE_MODEL => COMPONENT_STATE_MODEL,
        COMPONENT_PRIVILEGE => COMPONENT_PRIVILEGE,
        COMPONENT_ROLE_GRANT => COMPONENT_ROLE_GRANT,
        COMPONENT_ROLE_ENTITY_ACCESS => COMPONENT_ROLE_ENTITY_ACCESS,
        COMPONENT_PROFILE_FIELD => COMPONENT_PROFILE_FIELD,
        COMPONENT_RELATIONSHIP => COMPONENT_RELATIONSHIP,
        COMPONENT_APP => COMPONENT_APP,
        COMPONENT_RULE => COMPONENT_RULE,
        _ => COMPONENT_BUNDLE,
    }
}

// ── Execution ────────────────────────────────────────────────────────────────

struct ApplyContext<'a> {
    state: &'a EngineState,
    /// `requested_by` of the plan row — the actor a stored-query publish and
    /// a queued schema-change plan are attributed to.
    policy_actor: Option<Uuid>,
    /// logicalname → id for entities seen this run (filled by entity steps,
    /// lazily by lookup for entities the cursor skipped or that were noop).
    entity_ids: HashMap<String, Uuid>,
    live: &'a Bundle,
    /// [`super::plan::PlanOptions::additive_only`], carried through the
    /// ledger (`super::plan::BundlePlan::additive_only` -> `StoredPlan`).
    /// `true` only for a platform bundle (`apply_platform_bundle`, D-478):
    /// compiled-in, developer-authored content, the same trust level as the
    /// binary itself. A `Step::Query` create/update reads this to decide
    /// whether `query_admin::reconcile_query` should run its full EXPLAIN-
    /// based containment lint (a pulled/admin-uploaded bundle, `false`) or
    /// skip it the way `attome_metadata::provision::ensure_default_query`'s seed
    /// callers always have (`true`) — see `reconcile_query`'s own doc
    /// comment for why a partitioned entity's platform-seeded query needs
    /// this (P-stored-query-containment addendum §11(a) precedent).
    additive_only: bool,
}

impl<'a> ApplyContext<'a> {
    /// The provisioning pool (what the admin handlers and seeds write
    /// through). Returned with the state's own lifetime, not `self`'s, so a
    /// step can hold it across a later `&mut self` call.
    fn provisioning_pool(&self) -> &'a DbPool {
        &self.state.base.db_migrator
    }

    async fn entity_id(&mut self, logicalname: &str) -> Result<Uuid, AppError> {
        if let Some(id) = self.entity_ids.get(logicalname) {
            return Ok(*id);
        }
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(logicalname)
        .fetch_optional(self.provisioning_pool())
        .await
        .map_err(AppError::internal)?;
        let id = id.ok_or_else(|| {
            AppError::Validation(format!(
                "entity {logicalname} is not live on this deployment"
            ))
        })?;
        self.entity_ids.insert(logicalname.to_owned(), id);
        Ok(id)
    }
}

/// Which reconcile contract a step runs under.
///
/// A platform bundle (`additive_only`, D-478) is the declarative form of
/// the boot seed it replaced, so it applies under [`ReconcilePolicy::Seed`]
/// — exactly the contract every `*::seed::seed(db)` it superseded ran
/// under: an `Option` field the bundle leaves out (`category`,
/// `primary_name_attribute`, `lookup_entity`, `options`, `max_length`,
/// `purpose`, a query's `table_definition`) means "this bundle does not
/// manage that column — leave whatever is there alone", and a row an
/// admin has customized (`is_customized = true`) is skipped, never
/// overwritten (D-375). Under `Bundle { is_customized }` — the contract a
/// whole-deployment bundle (`pull::sync`, the admin routes, `bundle-tool`)
/// needs — `None` is the exact desired state (NULL) and the customized
/// marker is set to what the bundle carries. Applying a platform bundle
/// under that second contract was the D-478 first-pass defect that nulled
/// every boot-backfilled entity `category` and would have clobbered admin
/// customizations on the next re-apply; `plan.rs`'s `diff_*` functions
/// mirror the same rule so a plan says exactly what apply will do.
fn policy(additive_only: bool, is_customized: bool) -> ReconcilePolicy {
    if additive_only {
        ReconcilePolicy::Seed
    } else {
        ReconcilePolicy::Bundle { is_customized }
    }
}

/// Solution 7 (D-785, design §1.4): the `owner_layer` a row created outside
/// a policy-taking primitive gets — the same layer [`policy`]'s primitives
/// stamp: a platform-bundle seed writes `platform`, a bundle import `project`.
fn apply_layer(additive_only: bool) -> Layer {
    if additive_only {
        Layer::Platform
    } else {
        Layer::Project
    }
}

/// `true` for the `Conflict` a non-blocking provisioning lock returns when a
/// concurrent admin write holds it (`pg_try_advisory_xact_lock` → "… already
/// in progress") — the one error worth a bounded retry. The size-gate
/// `Conflict` and everything else are not.
fn is_lock_busy(err: &AppError) -> bool {
    matches!(err, AppError::Conflict(msg) if msg.contains("already in progress"))
}

/// Evaluates `$op` (an `.await`ed expression yielding `Result<T, AppError>`)
/// up to `LOCK_RETRY_ATTEMPTS + 1` times while it fails with a busy lock,
/// sleeping a growing backoff in between, and yields the last result.
///
/// A macro rather than an `AsyncFnMut` helper on purpose: an async closure
/// that borrows its captures puts a higher-ranked `Send` obligation into the
/// worker's job future, which the compiler cannot discharge (rust-lang
/// #110338) and `server/src/bin/worker.rs`'s `build_fn` then refuses.
macro_rules! with_lock_retry {
    ($op:expr) => {{
        let mut attempt: u32 = 0;
        loop {
            let result = $op;
            match &result {
                Err(err) if is_lock_busy(err) && attempt < LOCK_RETRY_ATTEMPTS => {
                    attempt += 1;
                    tracing::debug!(attempt, error = %err, "bundle apply: lock busy, retrying");
                    tokio::time::sleep(LOCK_RETRY_BACKOFF * attempt).await;
                }
                _ => break result,
            }
        }
    }};
}

async fn run_step(
    ctx: &mut ApplyContext<'_>,
    planned: &PlannedStep<'_>,
    summary: &mut ApplySummary,
) -> Result<(), AppError> {
    match (&planned.step, planned.action) {
        // An entity that is itself unchanged still has to be known by id for
        // its attribute steps — a read, not a write.
        (Step::Entity(e), PlanAction::Noop) => {
            summary.skipped_noop += 1;
            ctx.entity_id(&e.logicalname).await.map(|_| ())
        }
        (_, PlanAction::Noop) => {
            summary.skipped_noop += 1;
            Ok(())
        }
        (Step::Retire, _) => run_retire(ctx, planned, summary).await,
        (Step::Privilege(p), _) => {
            let desc = security::PrivilegeDesc {
                key: p.key.clone(),
                name: p.name.clone(),
                description: p.description.clone(),
            };
            let db = ctx.provisioning_pool();
            let desired_id = derived_id(COMPONENT_PRIVILEGE, &p.key);
            let layer = apply_layer(ctx.additive_only);
            let (_, outcome) = with_lock_retry!(
                security::reconcile_privilege(db, &desc, Some(desired_id), layer).await
            )?;
            summary.record(outcome);
            Ok(())
        }
        (Step::Entity(e), _) => {
            let desc = EntityDesc {
                logicalname: e.logicalname.clone(),
                display_name: e.display_name.clone(),
                primary_name_attribute: e.primary_name_attribute.clone(),
                is_append_only: e.is_append_only,
                is_audited: e.is_audited,
                category: e.category.clone(),
            };
            let db = ctx.provisioning_pool();
            let pol = policy(ctx.additive_only, e.is_customized);
            let desired_id = derived_id(COMPONENT_ENTITY, &e.logicalname);
            let (id, outcome) = with_lock_retry!(
                provision::reconcile_entity_with_id(db, &desc, pol, Some(desired_id)).await
            )?;
            ctx.entity_ids.insert(e.logicalname.clone(), id);
            if wrote(outcome) {
                // What `admin::create_entity` does right after provisioning:
                // the per-entity `{entity}.{read,create,update,delete,bulk}`
                // privileges. Idempotent, and a bundle exported from a
                // deployment that minted them carries them anyway — this is
                // for a hand-authored bundle that did not, so the entity is
                // not readable by `system.admin` alone.
                attome_security::entity_privileges::ensure_entity_privileges(
                    db,
                    &e.logicalname,
                    apply_layer(ctx.additive_only),
                )
                .await?;
                let (operation, event_name) = match outcome {
                    ReconcileOutcome::Created => (AuditOperation::Create, Some("entity_created")),
                    _ => (AuditOperation::Update, None),
                };
                audit_entity_change(ctx, &e.logicalname, id, operation, event_name).await?;
            }
            summary.record(outcome);
            Ok(())
        }
        (Step::Attribute { entity, attr }, _) => {
            apply_attribute(ctx, &entity.logicalname, attr, summary).await
        }
        // Same primitive as `Step::Attribute` — `plan.rs::diff_attribute_patches`
        // already guarantees `entity` exists live before this step is ever
        // reached (a missing target entity is `Blocked`, never a step), so
        // `apply_attribute`'s own `ctx.entity_id` lookup below is a
        // belt-and-suspenders re-check, not the primary guard.
        (Step::AttributePatch { entity, attr }, _) => {
            apply_attribute(ctx, entity, attr, summary).await
        }
        (Step::Query(q), _) => {
            let state = ctx.state;
            let actor = ctx.policy_actor;
            let pol = policy(ctx.additive_only, q.is_customized);
            // D-477 (T3-2): attome-records::query_admin::reconcile_query
            // takes its own minimal QueryDef twin, not this bundle-model
            // shape — see that type's doc comment for why.
            let desc = attome_records::query_admin::QueryDef {
                entity: q.entity.clone(),
                name: q.name.clone(),
                sql: q.sql.clone(),
                table_definition: q.table_definition.clone(),
                required_privilege: q.required_privilege.clone(),
                is_report: q.is_report,
                entity_mappings: q
                    .entity_mappings
                    .iter()
                    .map(|m| attome_records::query_admin::QueryEntityMapping {
                        entity: m.entity.clone(),
                        id_column: m.id_column.clone(),
                    })
                    .collect(),
            };
            let desired_id = derived_id(COMPONENT_QUERY, &q.key().display());
            let (_, outcome) = with_lock_retry!({
                attome_records::query_admin::reconcile_query(
                    state,
                    &desc,
                    pol,
                    actor,
                    ctx.additive_only,
                    Some(desired_id),
                )
                .await
            })?;
            summary.record(outcome);
            Ok(())
        }
        (Step::View(v), _) => {
            let state = ctx.state;
            let pol = policy(ctx.additive_only, v.is_customized);
            let desired_id = derived_id(COMPONENT_VIEW, &format!("{}.{}", v.entity, v.name));
            let (_, outcome) = with_lock_retry!(
                crate::view_admin::reconcile_view(state, v, pol, Some(desired_id)).await
            )?;
            summary.record(outcome);
            Ok(())
        }
        (Step::Calendar(c), _) => {
            let state = ctx.state;
            let pol = policy(ctx.additive_only, c.is_customized);
            let (_, outcome) =
                with_lock_retry!(crate::calendar_admin::reconcile_calendar(state, c, pol).await)?;
            summary.record(outcome);
            Ok(())
        }
        (Step::Sidebar(s), _) => {
            let state = ctx.state;
            let pol = policy(ctx.additive_only, s.is_customized);
            let desired_id = derived_id(COMPONENT_SIDEBAR, &s.path_display());
            let (_, outcome) = with_lock_retry!({
                crate::sidebar::reconcile_sidebar_item(state, s, pol, Some(desired_id)).await
            })?;
            summary.record(outcome);
            Ok(())
        }
        (Step::Profile(p), _) => {
            let desc = security::FieldSecurityProfileDesc {
                name: p.name.clone(),
                description: p.description.clone(),
                fields: p
                    .fields
                    .iter()
                    .map(|f| security::ProfileFieldDesc {
                        entity: f.entity.clone(),
                        field: f.field.clone(),
                        can_read: f.can_read,
                        can_update: f.can_update,
                    })
                    .collect(),
            };
            let db = ctx.provisioning_pool();
            let pol = policy(ctx.additive_only, p.is_customized);
            let desired_id = derived_id(COMPONENT_FIELD_SECURITY_PROFILE, &p.name);
            let (profile_id, outcome) = with_lock_retry!({
                security::reconcile_field_security_profile(db, &desc, pol, Some(desired_id)).await
            })?;
            if wrote(outcome) {
                security::invalidate_profile_holders(db, &ctx.state.base.security, profile_id)
                    .await?;
            }
            summary.record(outcome);
            Ok(())
        }
        (Step::Role(r), _) => {
            let desc = role_desc(r);
            let db = ctx.provisioning_pool();
            let pol = policy(ctx.additive_only, r.is_customized);
            let desired_id = derived_id(COMPONENT_ROLE, &r.name);
            let (role_id, outcome) =
                with_lock_retry!(security::reconcile_role(db, &desc, pol, Some(desired_id)).await)?;
            if wrote(outcome) {
                security::invalidate_role_holders(db, &ctx.state.base.security, role_id).await?;
            }
            summary.record(outcome);
            Ok(())
        }
        (Step::StateModel(m), _) => {
            let desc = attome_state::reconcile::StateModelDesc {
                entity_logicalname: m.entity_logicalname.clone(),
                name: m.name.clone(),
                state_field: m.state_field.clone(),
                initial_state: m.initial_state.clone(),
                is_active: m.is_active,
                transitions: m
                    .transitions
                    .iter()
                    .map(|t| attome_state::reconcile::TransitionDesc {
                        from_state: t.from_state.clone(),
                        to_state: t.to_state.clone(),
                        name: t.name.clone(),
                        required_privilege: t.required_privilege.clone(),
                        guard_expression: t.guard_expression.clone(),
                        entry_actions: t.entry_actions.clone(),
                        exit_actions: t.exit_actions.clone(),
                        display_order: t.display_order,
                        approval_plan: t.approval_plan.clone(),
                        pending_state: t.pending_state.clone(),
                        on_reject_state: t.on_reject_state.clone(),
                    })
                    .collect(),
            };
            let pol = policy(ctx.additive_only, false);
            let (_, outcome) = with_lock_retry!({
                attome_state::reconcile::reconcile_state_model(ctx.state, &desc, pol).await
            })?;
            summary.record(outcome);
            Ok(())
        }
        (Step::Relationship(r), _) => {
            // M01 Core P3 gap (D-455). `entity_a`/`entity_b` must already be
            // DB-trusted logicalnames before reaching the provisioning
            // primitive: `attome-metadata` cannot depend on `attome-api`'s
            // `entity_crud::resolve_entity` (layering, guidelines §1), so
            // `reconcile_relationship` never validates its own FK-shaped
            // string fields the way an HTTP admin caller's request gets
            // validated first — `ctx.entity_id` doubles as that existence
            // check here, same as every other component's FK-shaped
            // reference (e.g. `Query`'s `entity_mappings`).
            ctx.entity_id(&r.entity_a).await?;
            ctx.entity_id(&r.entity_b).await?;
            let desc = attome_metadata::provision::RelationshipDesc {
                name: r.name.clone(),
                entity_a: r.entity_a.clone(),
                entity_b: r.entity_b.clone(),
                role_a: r.role_a.clone(),
                role_b: r.role_b.clone(),
                cascade: attome_core::RelationshipCascade::from_db_str(&r.cascade),
                is_active: r.is_active,
            };
            let pol = policy(ctx.additive_only, false);
            let (_, outcome) = with_lock_retry!({
                attome_metadata::provision::reconcile_relationship(ctx.state, &desc, pol, None)
                    .await
            })?;
            summary.record(outcome);
            Ok(())
        }
        (Step::App(a), _) => {
            let pol = policy(ctx.additive_only, false);
            let (_, outcome) =
                with_lock_retry!(crate::app_admin::reconcile_app(ctx.state, a, pol).await)?;
            summary.record(outcome);
            Ok(())
        }
        (Step::Rule(r), _) => {
            // M45 Phase 2 (D-472). `RuleDef` carries no `is_customized`
            // field (same posture `RelationshipDef` above takes) —
            // a bundle-authored rule is never "hand customized" on the
            // target deployment.
            let pol = policy(ctx.additive_only, false);
            let (_, outcome) =
                with_lock_retry!(crate::rule_admin::reconcile_rule(ctx.state, r, pol).await)?;
            summary.record(outcome);
            Ok(())
        }
        (
            Step::Record {
                entity,
                key_fields,
                row,
            },
            _,
        ) => {
            let actor = ctx.policy_actor.unwrap_or(Uuid::nil());
            let outcome =
                super::record_sets::apply_record(ctx.state, actor, entity, key_fields, row).await?;
            summary.record(outcome);
            Ok(())
        }
    }
}

fn wrote(outcome: ReconcileOutcome) -> bool {
    matches!(
        outcome,
        ReconcileOutcome::Created | ReconcileOutcome::Updated
    )
}

/// Bundle-apply parity with `admin/entity.rs`'s own audit writes for the
/// same operations (Phase 1, `document/xrm/pending_full_plan/plan.md`) — a
/// schema change applied by a bundle gets the same `AuditCategory::Entity`
/// trail an equivalent admin-API call already gets, distinguished only by
/// `AuditSource::Import` (this write came from a bundle import, not a
/// direct API call) and `event_name` (`None` here, same as an admin-API
/// PATCH; only entity *creation* names an `event_name`, matching
/// `admin/entity.rs::create_entity`'s `"entity_created"`).
///
/// Only call this when `wrote(outcome)` is true — a bundle apply walks many
/// objects that turn out to be `Noop`/`Unchanged`/`SkippedCustomized`, and
/// auditing those would fabricate a change event for something that did not
/// actually change. Attributes and attribute-patch retires are audited
/// under the owning entity's `entity_name`, matching how the admin
/// attribute endpoints attribute their own writes to the entity, not the
/// field, at the audit-category level.
///
/// **Skips platform-bundle boot seeding (`ctx.additive_only`), and this is
/// load-bearing, not a style choice.** Found the hard way: `write_in_tx`'s
/// synchronous append path (`config.audit.chainer_enabled = false`, the
/// posture a single-writer/dev/test deployment opts into) writes through
/// `attome_core::crud::append_only_insert`, which resolves `"entity"` by
/// name against the *live* entity registry — but a platform bundle applies
/// during `EngineSystem::build()`, before that registry has ever been warmed,
/// so the very first entity a fresh boot creates (`audit_header`, from
/// `platform-bundles/attome-audit.json` — the first platform bundle applied)
/// cannot resolve itself as an audit target yet. Reproduced live: a fresh
/// throwaway database with `chainer_enabled: false` fails boot outright with
/// `AppError::NotFound` from inside this same function, the first time it
/// tried to audit `audit_header`'s own creation. Under the production
/// default (`chainer_enabled: true`), boot never hits this: that path
/// (`write_ingest`) is a plain `INSERT` with no entity-registry lookup at
/// all, so the bug is latent there — but the fix is the same either way,
/// because platform-bundle seeding was never meant to produce audit events
/// to begin with. A platform bundle is the declarative form of the old
/// imperative `*::seed::seed()` functions it replaced (D-478), which never
/// audited their own boot-time provisioning; `ReconcilePolicy::Seed`
/// already marks this same distinction for the reconcile primitives
/// themselves (`policy()`, below). Real bundle imports
/// (`ReconcilePolicy::Bundle`, `additive_only: false`) are the only case
/// Phase 1 was ever about, and those always run after boot, with a warm
/// registry.
async fn audit_entity_change(
    ctx: &ApplyContext<'_>,
    entity_name: &str,
    record_id: Uuid,
    operation: AuditOperation,
    event_name: Option<&str>,
) -> Result<(), AppError> {
    if ctx.additive_only {
        return Ok(());
    }
    let actor = ctx.policy_actor.unwrap_or(Uuid::nil());
    let (user_context, organization_ref) = fetch_audit_ctx(ctx.state, actor).await;
    let mut tx = attome_db::tx::begin(&ctx.state.base.db_migrator).await?;
    audit_service(ctx.state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref,
                category: AuditCategory::Entity,
                entity_name: Some(entity_name.to_owned()),
                record_id: Some(record_id),
                operation,
                version_before: None,
                version_after: None,
                user_context,
                changed_on: Utc::now(),
                source: AuditSource::Import,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: event_name.map(str::to_owned),
                event_comment: None,
                changed_fields: vec![],
                snapshot_json: None,
            },
        )
        .await?;
    tx.commit().await.map_err(AppError::internal)
}

/// Newest row by name (live first) — for the authz invalidation that
/// follows a role / profile retire, which the retire primitive itself does
/// not do (it has no resolver handle).
async fn row_id_by_name(
    db: &DbPool,
    table: RoleOrProfile,
    name: &str,
) -> Result<Option<Uuid>, AppError> {
    let sql = match table {
        RoleOrProfile::Role => {
            "SELECT id FROM role WHERE name = $1 \
             ORDER BY is_deleted ASC, created_at DESC, id DESC LIMIT 1"
        }
        RoleOrProfile::Profile => {
            "SELECT id FROM field_security_profile WHERE name = $1 \
             ORDER BY is_deleted ASC, created_at DESC, id DESC LIMIT 1"
        }
    };
    sqlx::query_scalar(sql)
        .bind(name)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)
}

#[derive(Clone, Copy)]
enum RoleOrProfile {
    Role,
    Profile,
}

fn role_desc(r: &RoleDef) -> security::RoleDesc {
    security::RoleDesc {
        name: r.name.clone(),
        description: r.description.clone(),
        access_level: r.access_level,
        position_hierarchy_enabled: r.position_hierarchy_enabled,
        privileges: r
            .privileges
            .iter()
            .map(|g| security::RoleGrantDesc {
                privilege: g.privilege.clone(),
                conditions: g
                    .conditions
                    .iter()
                    .map(|c| security::GrantConditionDesc {
                        field: c.field.clone(),
                        operator: c.operator,
                        value: c.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
        entity_access: r
            .entity_access
            .iter()
            .map(|a| security::RoleEntityAccessDesc {
                entity: a.entity.clone(),
                read_access_level: a.read_access_level,
                write_access_level: a.write_access_level,
                delete_access_level: a.delete_access_level,
                read_owner_visible: a.read_owner_visible,
                write_owner_visible: a.write_owner_visible,
                delete_owner_visible: a.delete_owner_visible,
            })
            .collect(),
        field_security_profiles: r.field_security_profiles.clone(),
    }
}

fn attribute_desc(a: &AttributeDef) -> AttributeDesc {
    AttributeDesc {
        logicalname: a.logicalname.clone(),
        display_name: a.display_name.clone(),
        field_type: a.field_type.clone(),
        is_required: a.is_required,
        is_sensitive: a.is_sensitive,
        is_write_restricted: Some(a.is_write_restricted),
        is_sortable: a.is_sortable,
        is_filterable: a.is_filterable,
        lookup_entity: a.lookup_entity.clone(),
        options: a.options.clone(),
        max_length: a.max_length,
        on_target_delete: Some(a.on_target_delete.clone()),
        data_classification: Some(a.data_classification.clone()),
        purpose: a.purpose.clone(),
    }
}

// ── Attributes ───────────────────────────────────────────────────────────────

/// `entity_logicalname` rather than `&EntityDef`: this is shared by
/// `Step::Attribute` (which has a full [`EntityDef`] to hand) and
/// `Step::AttributePatch` (which deliberately does not own one — see
/// [`AttributePatch`]'s doc comment) — nothing below ever reads a field of
/// the entity's own definition besides its name.
async fn apply_attribute(
    ctx: &mut ApplyContext<'_>,
    entity_logicalname: &str,
    attr: &AttributeDef,
    summary: &mut ApplySummary,
) -> Result<(), AppError> {
    let entity_id = ctx.entity_id(entity_logicalname).await?;
    let desc = attribute_desc(attr);
    let pol = policy(ctx.additive_only, attr.is_customized);
    let db = ctx.provisioning_pool();
    let desired_id = derived_id(
        COMPONENT_ATTRIBUTE,
        &format!("{entity_logicalname}.{}", attr.logicalname),
    );

    let first = with_lock_retry!(
        provision::reconcile_attribute_with_id(db, entity_id, &desc, pol, Some(desired_id)).await
    );
    let (attr_id, outcome) = match first {
        Ok((attr_id, outcome)) => (attr_id, outcome),
        Err(AppError::Conflict(msg)) if msg == SCHEMA_CHANGE_NEEDS_PLAN => {
            let (attr_id, outcome) =
                defer_contract_change(ctx, entity_id, entity_logicalname, attr, pol).await?;
            summary.deferred_schema_changes += 1;
            (attr_id, outcome)
        }
        Err(e) => return Err(e),
    };
    summary.record(outcome);

    // Bundle-apply audit parity with `admin/attribute.rs`'s own
    // `attribute_created`/attribute-update writes — see `audit_entity_change`'s
    // doc comment. Covers `Step::AttributePatch` too (shared function).
    if wrote(outcome) {
        let (operation, event_name) = match outcome {
            ReconcileOutcome::Created => (AuditOperation::Create, Some("attribute_created")),
            _ => (AuditOperation::Update, None),
        };
        audit_entity_change(ctx, entity_logicalname, attr_id, operation, event_name).await?;
    }

    // Index synchronization for `is_sortable`/`is_filterable` is the caller's
    // job, as it always was for `ensure_attribute` (reconcile.rs module doc);
    // mirror `admin/attribute.rs`: only when the flag pair actually toggled
    // (the live export read at run start is the "before"; a created or
    // reactivated attribute has no live row and counts as un-indexed),
    // inline under the size gate, the durable `BuildAttributeIndex` job
    // above it — so a no-op or unrelated update never issues a CONCURRENTLY
    // statement against a live table.
    let live = ctx.live;
    let had_index = live
        .entities
        .iter()
        .find(|e| e.logicalname == entity_logicalname)
        .and_then(|e| {
            e.attributes
                .iter()
                .find(|a| a.logicalname == attr.logicalname)
        })
        .is_some_and(|a| a.is_sortable || a.is_filterable);
    let wanted = attr.is_sortable || attr.is_filterable;
    if wrote(outcome) && had_index != wanted {
        let async_build = provision::attribute_index_requires_async(
            db,
            entity_logicalname,
            ATTRIBUTE_INDEX_INLINE_ROW_LIMIT,
        )
        .await?;
        if async_build {
            attome_jobs::enqueue_dedup(
                db,
                attome_core::jobs::EngineJob::BuildAttributeIndex {
                    entity_logicalname: entity_logicalname.to_owned(),
                    field_logicalname: attr.logicalname.clone(),
                },
                &format!("attribute-index:{entity_logicalname}:{}", attr.logicalname),
            )
            .await
            .map_err(AppError::internal)?;
        } else {
            provision::sync_attribute_index(
                ctx.state.base.config.as_ref(),
                entity_logicalname,
                &attr.logicalname,
                wanted,
            )
            .await?;
        }
    }
    Ok(())
}

/// The live attribute row's own id, for the `SoftDelete` audit event a
/// retire writes — resolved before the retire flips `is_active`, matching
/// `ApplyContext::entity_id`'s own live-row predicate. `None` only in the
/// already-`Unchanged`-by-the-time-we-get-here race (another writer retired
/// it first, between the plan's live export and this step running), in
/// which case there is nothing to audit either.
async fn live_attribute_id(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 \
         AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Live `required`/`max_length` of the attribute row `reconcile_attribute`
/// would update — the same preference it has (live row, else the newest
/// retired one with the same key), so the "previous" values recorded on the
/// schema-change plan are the ones it will revert to on failure.
#[derive(sqlx::FromRow)]
struct ContractRow {
    required: bool,
    max_length: Option<i32>,
}

async fn live_contract(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
) -> Result<Option<ContractRow>, AppError> {
    sqlx::query_as(
        "SELECT COALESCE(required, false) AS required, max_length \
         FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 \
         ORDER BY (is_active IS NULL OR is_active = true) DESC, \
                  created_at DESC NULLS LAST, id DESC \
         LIMIT 1",
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// The size-gate path (module doc "Expensive attribute contract changes"):
/// land everything but the contract now, then record the target contract and
/// queue `ApplySchemaChangePlan` through `attome_metadata::provision::
/// queue_contract_change` — the exact same primitive `admin/attribute.rs::
/// update_attribute` calls for the same case (generalized from what used to
/// be two separate copies of this UPDATE, P-environment-promotion §5 step 24
/// follow-up), so the plan job finds the metadata row already carrying the
/// target values it expects and reverts to the recorded previous ones on
/// failure. This crate directory issues no schema statement of its own
/// either way (D-003; the `bundle-engine-no-ddl` CI grep) — the primitive's
/// one direct `attribute_info` write is the contract pair of a row
/// `reconcile_attribute` has just reconciled, needed because that primitive
/// deliberately refuses the Expensive case without writing.
async fn defer_contract_change(
    ctx: &mut ApplyContext<'_>,
    entity_id: Uuid,
    entity_logicalname: &str,
    attr: &AttributeDef,
    pol: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let db = ctx.provisioning_pool();
    let previous = live_contract(db, entity_id, &attr.logicalname).await?;
    let (previous_required, previous_max_length) = match &previous {
        Some(row) => (row.required, row.max_length),
        None => (false, None),
    };

    // Everything except the contract, now.
    let mut relaxed = attribute_desc(attr);
    relaxed.is_required = previous_required;
    relaxed.max_length = previous_max_length;
    let desired_id = derived_id(
        COMPONENT_ATTRIBUTE,
        &format!("{entity_logicalname}.{}", attr.logicalname),
    );
    let (attr_id, outcome) = with_lock_retry!({
        provision::reconcile_attribute_with_id(db, entity_id, &relaxed, pol, Some(desired_id)).await
    })?;

    if previous_required == attr.is_required && previous_max_length == attr.max_length {
        // Nothing left to defer (a concurrent writer already landed it).
        return Ok((attr_id, outcome));
    }

    let created_by = ctx.policy_actor.unwrap_or(Uuid::nil());
    // C-22: a multi-valued (`choice`/`file`) column can't support
    // `max_length` (its `char_length` CHECK is undefined against
    // `TEXT[]`/`JSONB`) — `queue_contract_change` -> `queue_schema_change_plan_in_tx`
    // refuses this with a 422 rather than reaching Postgres, but a bundle
    // carrying such a combination is malformed regardless of this path, so
    // there is nothing this call site needs to pre-check beyond passing the
    // real value through.
    let is_multi = provision::is_multi_valued(&attr.field_type, attr.options.as_ref());
    with_lock_retry!(
        provision::queue_contract_change(
            db,
            // Constructed inside the macro on purpose: `with_lock_retry!`
            // re-evaluates this expression per attempt, and a struct bound
            // outside would be moved by the first one.
            provision::SchemaChangePlanRequest {
                entity_id,
                attribute_id: attr_id,
                entity_logicalname,
                field_logicalname: &attr.logicalname,
                field_type: &attr.field_type,
                target_required: attr.is_required,
                target_max_length: attr.max_length,
                previous_required,
                previous_max_length,
                backfill_default: None,
                is_multi,
                created_by,
            },
        )
        .await
    )?;

    tracing::info!(
        entity = %entity_logicalname,
        field = %attr.logicalname,
        is_required = attr.is_required,
        max_length = ?attr.max_length,
        "bundle apply: attribute contract change crosses the size gate; queued ApplySchemaChangePlan"
    );
    // The attribute row itself was written (the contract columns, at least).
    let outcome = match outcome {
        ReconcileOutcome::Created => ReconcileOutcome::Created,
        _ => ReconcileOutcome::Updated,
    };
    Ok((attr_id, outcome))
}

// ── Retires ──────────────────────────────────────────────────────────────────

/// Soft-retires the object a plan line names. The target is resolved against
/// the live export read at the start of this run; an object that is no longer
/// in it was retired already (by an earlier, crashed attempt of this same
/// plan, or by hand) and the step is a no-op — which is what makes a resume
/// safe to re-run past a retire it had already done.
async fn run_retire(
    ctx: &mut ApplyContext<'_>,
    planned: &PlannedStep<'_>,
    summary: &mut ApplySummary,
) -> Result<(), AppError> {
    let state = ctx.state;
    let db = ctx.provisioning_pool();
    let key = planned.key.as_str();
    let outcome = match planned.component {
        COMPONENT_ENTITY => {
            if !ctx.live.entities.iter().any(|e| e.logicalname == key) {
                ReconcileOutcome::Unchanged
            } else {
                // Resolved before the retire flips `is_active`, or
                // `entity_id`'s own live-row predicate would miss it.
                let entity_id = ctx.entity_id(key).await?;
                let outcome = with_lock_retry!(provision::retire_entity(db, key).await)?;
                if wrote(outcome) {
                    audit_entity_change(ctx, key, entity_id, AuditOperation::SoftDelete, None)
                        .await?;
                }
                outcome
            }
        }
        COMPONENT_ATTRIBUTE => {
            // Entity logicalnames cannot contain '.', so the first dot splits.
            let Some((entity, field)) = key.split_once('.') else {
                return Err(AppError::Validation(format!(
                    "malformed attribute key '{key}'"
                )));
            };
            let live_has = ctx.live.entities.iter().any(|e| {
                e.logicalname == entity && e.attributes.iter().any(|a| a.logicalname == field)
            });
            if !live_has {
                ReconcileOutcome::Unchanged
            } else {
                let entity_id = ctx.entity_id(entity).await?;
                // Same reasoning as the entity branch above: resolved before
                // the retire flips `is_active`.
                let attr_id = live_attribute_id(db, entity_id, field).await?;
                let outcome =
                    with_lock_retry!(provision::retire_attribute(db, entity_id, field).await)?;
                if wrote(outcome)
                    && let Some(attr_id) = attr_id
                {
                    audit_entity_change(ctx, entity, attr_id, AuditOperation::SoftDelete, None)
                        .await?;
                }
                outcome
            }
        }
        COMPONENT_QUERY => {
            let Some((entity, name)) = key.split_once('.') else {
                return Err(AppError::Validation(format!("malformed query key '{key}'")));
            };
            let entity = (entity != "*").then_some(entity);
            let live_has = ctx
                .live
                .queries
                .iter()
                .any(|q| q.entity.as_deref() == entity && q.name == name);
            if !live_has {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!({
                    attome_records::query_admin::retire_query(state, entity, name).await
                })?
            }
        }
        COMPONENT_VIEW => {
            let Some((entity, name)) = key.split_once('.') else {
                return Err(AppError::Validation(format!("malformed view key '{key}'")));
            };
            let live_has = ctx
                .live
                .views
                .iter()
                .any(|v| v.entity == entity && v.name == name);
            if !live_has {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!(crate::view_admin::retire_view(state, entity, name).await)?
            }
        }
        COMPONENT_CALENDAR => {
            let live_has = ctx.live.calendars.iter().any(|c| c.name == key);
            if !live_has {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!(crate::calendar_admin::retire_calendar(state, key).await)?
            }
        }
        COMPONENT_SIDEBAR => {
            // The key is the '/'-joined path; resolve it back to the real
            // path through the live export (a name may itself contain '/').
            match ctx.live.sidebar.iter().find(|s| s.path_display() == key) {
                None => ReconcileOutcome::Unchanged,
                Some(item) => {
                    let path = item.path.as_slice();
                    with_lock_retry!(crate::sidebar::retire_sidebar_item(state, path).await)?
                }
            }
        }
        COMPONENT_ROLE => {
            if !ctx.live.roles.iter().any(|r| r.name == key) {
                ReconcileOutcome::Unchanged
            } else {
                let role_id = row_id_by_name(db, RoleOrProfile::Role, key).await?;
                let outcome = with_lock_retry!(security::retire_role(db, key).await)?;
                if let Some(role_id) = role_id
                    && wrote(outcome)
                {
                    security::invalidate_role_holders(db, &state.base.security, role_id).await?;
                }
                outcome
            }
        }
        COMPONENT_FIELD_SECURITY_PROFILE => {
            if !ctx
                .live
                .field_security_profiles
                .iter()
                .any(|p| p.name == key)
            {
                ReconcileOutcome::Unchanged
            } else {
                let profile_id = row_id_by_name(db, RoleOrProfile::Profile, key).await?;
                let outcome =
                    with_lock_retry!({ security::retire_field_security_profile(db, key).await })?;
                if let Some(profile_id) = profile_id
                    && wrote(outcome)
                {
                    security::invalidate_profile_holders(db, &state.base.security, profile_id)
                        .await?;
                }
                outcome
            }
        }
        COMPONENT_STATE_MODEL => {
            if !ctx
                .live
                .state_models
                .iter()
                .any(|m| m.entity_logicalname == key)
            {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!(attome_state::reconcile::retire_state_model(state, key).await)?
            }
        }
        COMPONENT_RELATIONSHIP => {
            if !ctx.live.relationships.iter().any(|r| r.name == key) {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!(
                    attome_metadata::provision::retire_relationship_by_name(state, key).await
                )?
            }
        }
        COMPONENT_APP => {
            if !ctx.live.apps.iter().any(|a| a.name == key) {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!(crate::app_admin::retire_app(state, key).await)?
            }
        }
        COMPONENT_RULE => {
            // Key is `RuleDef::key()` — `"{entity}:{name}"`. An entity
            // logicalname cannot contain ':' (validated at entity creation);
            // `name` is validated non-empty, same assumption every other
            // split_once-keyed retire above already makes for its own parts.
            let Some((entity, name)) = key.split_once(':') else {
                return Err(AppError::Validation(format!("malformed rule key '{key}'")));
            };
            let live_has = ctx
                .live
                .rules
                .iter()
                .any(|r| r.entity_logicalname == entity && r.name == name);
            if !live_has {
                ReconcileOutcome::Unchanged
            } else {
                with_lock_retry!(crate::rule_admin::retire_rule(state, entity, name).await)?
            }
        }
        other => {
            return Err(AppError::Validation(format!(
                "retire of component '{other}' is not something apply knows how to do"
            )));
        }
    };
    match outcome {
        ReconcileOutcome::Unchanged | ReconcileOutcome::SkippedCustomized => {
            summary.unchanged += 1;
        }
        ReconcileOutcome::Created | ReconcileOutcome::Updated => summary.retired += 1,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(name: &str, attrs: &[(&str, &str)]) -> EntityDef {
        EntityDef {
            logicalname: name.to_owned(),
            display_name: name.to_uppercase(),
            primary_name_attribute: None,
            is_append_only: false,
            is_audited: false,
            category: None,
            is_customized: false,
            attributes: attrs
                .iter()
                .map(|(n, t)| AttributeDef {
                    logicalname: (*n).to_owned(),
                    display_name: (*n).to_owned(),
                    field_type: (*t).to_owned(),
                    is_required: false,
                    is_sensitive: false,
                    is_write_restricted: false,
                    is_sortable: false,
                    is_filterable: false,
                    lookup_entity: (*t == "lookup").then(|| "target".to_owned()),
                    options: None,
                    max_length: None,
                    on_target_delete: "orphan".to_owned(),
                    data_classification: "general".to_owned(),
                    purpose: None,
                    is_customized: false,
                })
                .collect(),
        }
    }

    fn sidebar(path: &[&str]) -> SidebarDef {
        SidebarDef {
            path: path.iter().map(|p| (*p).to_owned()).collect(),
            route: None,
            icon: None,
            color: None,
            display_order: 0,
            is_container: path.len() == 1,
            entity: None,
            module_key: None,
            is_disabled: false,
            privileges: Vec::new(),
            is_customized: false,
        }
    }

    fn plan_with(entries: &[(&str, &str, PlanAction)], retires: &[(&str, &str)]) -> StoredPlan {
        StoredPlan {
            entries: entries
                .iter()
                .map(|(c, k, a)| StoredEntry {
                    component: (*c).to_owned(),
                    key: (*k).to_owned(),
                    action: *a,
                })
                .collect(),
            retires: retires
                .iter()
                .map(|(c, k)| StoredEntry {
                    component: (*c).to_owned(),
                    key: (*k).to_owned(),
                    action: PlanAction::Retire,
                })
                .collect(),
            blocked: Vec::new(),
            additive_only: false,
        }
    }

    #[test]
    fn steps_follow_dependency_order_and_fold_child_lines() {
        let mut bundle = Bundle::empty(Requires {
            platform_version: ">=0.0.0".into(),
            schema_version: 0,
            modules: vec![],
            depends_on_bundles: vec![],
        });
        bundle.entities = vec![
            entity("source", &[("owner", "lookup"), ("title", "text")]),
            entity("target", &[("name", "text")]),
        ];
        bundle.sidebar = vec![sidebar(&["Group", "Item"]), sidebar(&["Group"])];
        bundle.roles = vec![RoleDef {
            name: "editor".into(),
            description: None,
            access_level: 3,
            position_hierarchy_enabled: false,
            is_customized: false,
            privileges: vec![],
            entity_access: vec![],
            field_security_profiles: vec![],
        }];
        bundle.normalize();

        let plan = plan_with(
            &[
                (COMPONENT_ENTITY, "source", PlanAction::Noop),
                (COMPONENT_ENTITY, "target", PlanAction::Create),
                (COMPONENT_ATTRIBUTE, "source.owner", PlanAction::Update),
                (COMPONENT_ATTRIBUTE, "source.title", PlanAction::Noop),
                (COMPONENT_ATTRIBUTE, "target.name", PlanAction::Create),
                (COMPONENT_SIDEBAR, "Group", PlanAction::Noop),
                (COMPONENT_SIDEBAR, "Group/Item", PlanAction::Create),
                (COMPONENT_ROLE, "editor", PlanAction::Noop),
                (
                    COMPONENT_ROLE_GRANT,
                    "editor:target.read",
                    PlanAction::Create,
                ),
            ],
            &[
                (COMPONENT_ENTITY, "old"),
                (COMPONENT_SIDEBAR, "A"),
                (COMPONENT_SIDEBAR, "A/B"),
                (COMPONENT_ATTRIBUTE, "source.gone"),
            ],
        );

        let steps = build_steps(&bundle, &plan);
        let keys: Vec<(&str, &str, PlanAction)> = steps
            .iter()
            .map(|s| (s.component, s.key.as_str(), s.action))
            .collect();
        assert_eq!(
            keys,
            vec![
                (COMPONENT_ENTITY, "source", PlanAction::Noop),
                (COMPONENT_ENTITY, "target", PlanAction::Create),
                // non-lookups first, then the lookup
                (COMPONENT_ATTRIBUTE, "source.title", PlanAction::Noop),
                (COMPONENT_ATTRIBUTE, "target.name", PlanAction::Create),
                (COMPONENT_ATTRIBUTE, "source.owner", PlanAction::Update),
                // parent before child
                (COMPONENT_SIDEBAR, "Group", PlanAction::Noop),
                (COMPONENT_SIDEBAR, "Group/Item", PlanAction::Create),
                // the grant line folds into the role as an Update
                (COMPONENT_ROLE, "editor", PlanAction::Update),
                // retires: sidebar deepest-first, then attribute, then entity
                (COMPONENT_SIDEBAR, "A/B", PlanAction::Retire),
                (COMPONENT_SIDEBAR, "A", PlanAction::Retire),
                (COMPONENT_ATTRIBUTE, "source.gone", PlanAction::Retire),
                (COMPONENT_ENTITY, "old", PlanAction::Retire),
            ]
        );
    }

    #[test]
    fn stored_plan_reads_back_what_the_planner_writes() {
        let value = serde_json::json!({
            "plan_id": "00000000-0000-0000-0000-000000000000",
            "basis_hash": "x", "bundle_hash": "y",
            "entries": [{"component": "entity", "key": "a", "action": "create", "changes": ["n: 1 -> 2"]}],
            "retires": [{"component": "view", "key": "a.v", "action": "retire", "reason": "gone"}],
            "blocked": [],
            "summary": {"creates": 1, "updates": 0, "retires": 1, "noops": 0, "blocked": 0}
        });
        let plan = StoredPlan::from_value(&value).expect("parses");
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].action, PlanAction::Create);
        assert_eq!(plan.retires[0].component, "view");
        assert!(plan.blocked.is_empty());
    }

    #[test]
    fn basis_check_compares_canonical_hash() {
        let live = Bundle::empty(Requires {
            platform_version: ">=0.0.0".into(),
            schema_version: 0,
            modules: vec![],
            depends_on_bundles: vec![],
        });
        assert!(check_basis(&live, &bundle_hash(&live)).is_ok());
        assert!(matches!(
            check_basis(&live, "not-the-hash"),
            Err(AppError::Conflict(_))
        ));
    }
}
