//! Plan: desired [`Bundle`] vs live metadata → per-object
//! `create|update|retire|noop|blocked` (P-environment-promotion §5 step 10).
//!
//! The plan is the reviewable artifact a four-eyes approver signs off on, so
//! it is computed from one consistent picture of the target — a live export
//! — and bound to it by `basis_hash`: apply refuses to run once live metadata
//! no longer hashes to that value (§4 "Plan and apply are separate calls").
//!
//! **This module writes nothing.** No DB writes, no persisted plan row — the
//! `plan_id` is minted here so the apply side has a stable handle, and a
//! later step persists it.
//!
//! The comparison itself ([`diff_bundles`]) is pure so it can be tested
//! without a database; [`plan_bundle`] is the thin DB-aware wrapper that
//! exports live, runs the diff, and runs the bundle-level `requires` checks.
//!
//! **Blocked reasons** (each its own entry, never silently dropped):
//! - field type change — D-055 has no cast/migrate path, so it is surfaced;
//! - lookup target missing — neither live nor in the bundle;
//! - unknown field type — not in [`KNOWN_FIELD_TYPES`];
//! - license module absent — `requires.modules` resolved through
//!   `attome_modules::MODULE_MAP` / `ModuleSet::has_module`, or a module
//!   name the map does not know;
//! - schema floor unmet — `requires.schema_version` above the applied max;
//! - platform floor unmet — `requires.platform_version` above this binary;
//! - bundle format newer than this binary;
//! - a retire is needed but `allow_retire` is false.
//!
//! **Retire.** An object that is live but absent from the bundle is a
//! `Retire` (soft-retire, `is_active = false`) for: entity, attribute, query,
//! view, sidebar, role, role grant, role entity access, field-security
//! profile, profile field. **Privileges are never retired**: they are minted
//! per entity by the platform (`{entity}.read` … via `ensure_privilege`) and
//! referenced by user grants this bundle deliberately does not carry, so a
//! bundle that omits one is silent about it, not a request to remove it.
//! When a parent is retired (entity, role, profile) its children are not
//! listed separately — they go with it.

use std::collections::{BTreeMap, BTreeSet};

use attome_db::DbPool;
use attome_modules::{MODULE_MAP, ModuleSet};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::canonical::bundle_hash;
use super::export::{PLATFORM_VERSION, applied_schema_version, export_bundle};
use super::model::*;

/// What apply would do to one object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    Create,
    Update,
    Retire,
    Noop,
    Blocked,
}

/// One object's line in the plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PlanEntry {
    /// One of the `COMPONENT_*` names in `model.rs`.
    pub component: &'static str,
    /// Human key, e.g. `account.email`, `Group/Item`, `editor:account.read`.
    pub key: String,
    pub action: PlanAction,
    /// Why, for `Blocked`; a short note for `Retire`; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `"field: live -> desired"` lines for `Update`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
}

impl PlanEntry {
    /// `pub(crate)` (not module-private) so `bundle::record_sets` — the only
    /// caller outside this file — builds its `PlanEntry`s the identical way
    /// every other component does, rather than a second constructor.
    pub(crate) fn new(component: &'static str, key: impl Into<String>, action: PlanAction) -> Self {
        PlanEntry {
            component,
            key: key.into(),
            action,
            reason: None,
            changes: Vec::new(),
        }
    }

    pub(crate) fn blocked(
        component: &'static str,
        key: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        PlanEntry {
            component,
            key: key.into(),
            action: PlanAction::Blocked,
            reason: Some(reason.into()),
            changes: Vec::new(),
        }
    }
}

/// Counts per action across `entries`, `retires`, and `blocked`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanSummary {
    pub creates: usize,
    pub updates: usize,
    pub retires: usize,
    pub noops: usize,
    pub blocked: usize,
}

/// The whole plan. `entries` holds `Create`/`Update`/`Noop`; `retires` is
/// its own section (§4); `blocked` is everything apply must not attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct BundlePlan {
    pub plan_id: Uuid,
    /// Hash of the live export this plan was computed against.
    pub basis_hash: String,
    /// Hash of the bundle that was planned.
    pub bundle_hash: String,
    pub entries: Vec<PlanEntry>,
    pub retires: Vec<PlanEntry>,
    pub blocked: Vec<PlanEntry>,
    pub summary: PlanSummary,
    /// Carries [`PlanOptions::additive_only`] through into the ledger's
    /// stored `plan_json` (`apply.rs`'s `StoredPlan` reads it back out as
    /// `ApplyContext::additive_only`) — a platform-bundle query step needs to
    /// know at *apply* time, not just at plan time, that it should skip
    /// `query_admin.rs`'s EXPLAIN-based containment lint the same way
    /// `attome_metadata::provision::ensure_default_query`'s seed callers always
    /// have (developer-authored, code-shipped content, not admin/API input —
    /// see that function's own doc comment for the seven pre-existing call
    /// sites sharing this trust boundary). A regular pulled/admin-uploaded
    /// bundle plan always carries `false` here, so its queries keep the full
    /// lint.
    #[serde(default)]
    pub additive_only: bool,
}

impl BundlePlan {
    /// `true` when apply could run this plan to completion — nothing blocked.
    pub fn is_applicable(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// Caller choices that change what the plan contains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PlanOptions {
    /// Without it every would-be `Retire` is reported as `Blocked`
    /// ("retire requires allow_retire") — the guard that matters in test/CI
    /// where no approver exists (§4).
    #[serde(default)]
    pub allow_retire: bool,
    /// A live object absent from the bundle is never even considered for
    /// retirement — not `Retire`, not `Blocked`, no [`PlanEntry`] at all.
    /// Set by [`super::platform::apply_platform_bundle`]: a platform bundle
    /// is deliberately a narrow, single-module slice (`platform-bundles/
    /// <module>.json` only lists that module's own objects), while
    /// [`super::export::export_bundle`] — reused unchanged for this call —
    /// always snapshots the *entire* live deployment. Without this flag,
    /// every other module's already-provisioned objects read as "live, not
    /// in this bundle" and the plan comes back full of `Blocked: retire
    /// requires allow_retire` entries for entities/sidebar items/etc. this
    /// bundle never claimed to own — a boot-time false positive, not a real
    /// disagreement (D-478's own platform.rs doc: "a platform bundle only
    /// ever adds or updates"). Leave `false` for a whole-deployment bundle
    /// (`bundle::pull::sync`, the admin plan/apply/rollback routes,
    /// `bundle-tool`) where "live but undeclared" genuinely does mean stale.
    ///
    /// Also selects the reconcile contract: a platform bundle applies under
    /// `ReconcilePolicy::Seed` (`apply.rs::policy`), so here an `Option`
    /// field the bundle leaves as `None` is dropped from the comparison
    /// rather than read as "set it to NULL" — see [`unmanaged`].
    #[serde(default)]
    pub additive_only: bool,
}

/// The pure output of [`diff_bundles`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub entries: Vec<PlanEntry>,
    pub retires: Vec<PlanEntry>,
    pub blocked: Vec<PlanEntry>,
}

impl Diff {
    fn push(&mut self, entry: PlanEntry) {
        match entry.action {
            PlanAction::Retire => self.retires.push(entry),
            PlanAction::Blocked => self.blocked.push(entry),
            _ => self.entries.push(entry),
        }
    }

    /// Retire, or Blocked when retiring is not allowed — or no entry at all
    /// when `opts.additive_only` puts this object outside the bundle's
    /// scope (see [`PlanOptions::additive_only`]).
    fn retire(&mut self, opts: PlanOptions, component: &'static str, key: impl Into<String>) {
        if opts.additive_only {
            return;
        }
        if opts.allow_retire {
            let mut e = PlanEntry::new(component, key, PlanAction::Retire);
            e.reason = Some("present live, absent from bundle".to_owned());
            self.push(e);
        } else {
            self.push(PlanEntry::blocked(
                component,
                key,
                "retire requires allow_retire",
            ));
        }
    }

    pub fn summary(&self) -> PlanSummary {
        let mut s = PlanSummary::default();
        for e in self
            .entries
            .iter()
            .chain(&self.retires)
            .chain(&self.blocked)
        {
            match e.action {
                PlanAction::Create => s.creates += 1,
                PlanAction::Update => s.updates += 1,
                PlanAction::Retire => s.retires += 1,
                PlanAction::Noop => s.noops += 1,
                PlanAction::Blocked => s.blocked += 1,
            }
        }
        s
    }
}

// ── DB-aware entry point ─────────────────────────────────────────────────────

/// Exports live metadata from `db`, diffs `bundle` against it, and runs the
/// bundle-level checks (format, `requires`) against `license`, the applied
/// schema version, and this binary's version. Reads only.
pub async fn plan_bundle(
    db: &DbPool,
    license: &ModuleSet,
    bundle: &Bundle,
    opts: PlanOptions,
) -> Result<BundlePlan, AppError> {
    let live = export_bundle(db).await?;
    let applied_schema = applied_schema_version(db).await?;
    let mut plan = build_plan(
        &live,
        bundle,
        opts,
        license,
        applied_schema,
        PLATFORM_VERSION,
    );

    // M92 Phase 1: `requires.depends_on_bundles` needs the ledger ("has
    // bundle X ever been applied here, at what version"), so — like the
    // record-set diff just below — it cannot live in `build_plan`, which
    // stays pure and DB-free for its own unit tests.
    let dep_blocked = check_bundle_dependencies(db, bundle).await?;
    plan.summary.blocked += dep_blocked.len();
    plan.blocked.extend(dep_blocked);

    // Phase 3 (record sets, §5 step 24): the only DB-aware half of planning
    // — record data is never part of the export `build_plan` diffs against
    // (`RecordSet`'s doc comment), so each row is resolved against the live
    // table directly. Merged in here (not `build_plan`, which stays pure and
    // DB-free for its own unit tests) and folded into the summary the same
    // way `Diff::summary` computes it for everything else.
    let record_diff = super::record_sets::plan_record_sets(db, &live, bundle).await?;
    plan.summary.creates += record_diff
        .entries
        .iter()
        .filter(|e| e.action == PlanAction::Create)
        .count();
    plan.summary.updates += record_diff
        .entries
        .iter()
        .filter(|e| e.action == PlanAction::Update)
        .count();
    plan.summary.noops += record_diff
        .entries
        .iter()
        .filter(|e| e.action == PlanAction::Noop)
        .count();
    plan.summary.blocked += record_diff.blocked.len();
    plan.entries.extend(record_diff.entries);
    plan.blocked.extend(record_diff.blocked);

    Ok(plan)
}

/// Everything [`plan_bundle`] does after the reads — pure, for tests and for
/// a caller that already holds a live export.
pub fn build_plan(
    live: &Bundle,
    desired: &Bundle,
    opts: PlanOptions,
    license: &ModuleSet,
    applied_schema: i64,
    platform_version: &str,
) -> BundlePlan {
    let mut diff = Diff::default();
    for b in check_requires(desired, license, applied_schema, platform_version) {
        diff.push(b);
    }
    let object_diff = diff_bundles(live, desired, opts);
    diff.entries.extend(object_diff.entries);
    diff.retires.extend(object_diff.retires);
    diff.blocked.extend(object_diff.blocked);
    let summary = diff.summary();
    BundlePlan {
        plan_id: Uuid::now_v7(),
        basis_hash: bundle_hash(live),
        bundle_hash: bundle_hash(desired),
        entries: diff.entries,
        retires: diff.retires,
        blocked: diff.blocked,
        summary,
        additive_only: opts.additive_only,
    }
}

// ── Bundle-level checks ──────────────────────────────────────────────────────

/// Format, platform floor, schema floor, and license modules. Every failure
/// is a `Blocked` entry under [`COMPONENT_BUNDLE`].
pub fn check_requires(
    desired: &Bundle,
    license: &ModuleSet,
    applied_schema: i64,
    platform_version: &str,
) -> Vec<PlanEntry> {
    let mut out = Vec::new();

    if let Err(e) = check_format(&desired.format) {
        out.push(PlanEntry::blocked(
            COMPONENT_BUNDLE,
            "format",
            e.to_string(),
        ));
    }

    match parse_version_floor(&desired.requires.platform_version) {
        Some(floor) => match parse_semver(platform_version) {
            Some(mine) if mine < floor => out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                "requires.platform_version",
                format!(
                    "bundle requires platform {} but this server is {platform_version}",
                    desired.requires.platform_version
                ),
            )),
            Some(_) => {}
            None => out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                "requires.platform_version",
                format!("server version '{platform_version}' is not MAJOR.MINOR.PATCH"),
            )),
        },
        None => out.push(PlanEntry::blocked(
            COMPONENT_BUNDLE,
            "requires.platform_version",
            format!(
                "'{}' is not a version floor (expected >=MAJOR.MINOR.PATCH)",
                desired.requires.platform_version
            ),
        )),
    }

    if desired.requires.schema_version > applied_schema {
        out.push(PlanEntry::blocked(
            COMPONENT_BUNDLE,
            "requires.schema_version",
            format!(
                "bundle requires schema {} but {applied_schema} is applied; run migrations first",
                desired.requires.schema_version
            ),
        ));
    }

    for module in &desired.requires.modules {
        match MODULE_MAP.iter().find(|(name, _)| name == module) {
            Some((_, id)) if license.has(*id) => {}
            Some(_) => out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                format!("requires.modules:{module}"),
                format!("module '{module}' is not included in this deployment's license"),
            )),
            None => out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                format!("requires.modules:{module}"),
                format!("module '{module}' is not a module this server knows"),
            )),
        }
    }

    out
}

/// M92 Phase 1 — `requires.depends_on_bundles`: for each declared
/// dependency, the highest version of that named bundle ([`Bundle::name`])
/// ever `succeeded` in this deployment's own ledger must meet the declared
/// floor. DB-aware (unlike [`check_requires`]) because that question can
/// only be answered from [`super::ledger::succeeded_bundles_by_name`]; kept
/// as its own function, called from [`plan_bundle`] rather than folded into
/// [`check_requires`], so [`build_plan`]/[`check_requires`] stay pure and
/// DB-free for their own unit tests.
///
/// Each failure is its own `Blocked` entry under [`COMPONENT_BUNDLE`], the
/// same convention `check_requires` uses for `requires.platform_version` /
/// `requires.modules`.
pub(crate) async fn check_bundle_dependencies(
    db: &DbPool,
    desired: &Bundle,
) -> Result<Vec<PlanEntry>, AppError> {
    let mut out = Vec::new();
    for dep in &desired.requires.depends_on_bundles {
        let key = format!("requires.depends_on_bundles:{}", dep.name);
        let Some(floor) = parse_version_floor(&dep.min_version) else {
            out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                key,
                format!(
                    "'{}' is not a version floor (expected >=MAJOR.MINOR.PATCH)",
                    dep.min_version
                ),
            ));
            continue;
        };
        let applied = super::ledger::succeeded_bundles_by_name(db, &dep.name).await?;
        if applied.is_empty() {
            out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                key,
                format!(
                    "bundle '{}' has never been successfully applied to this deployment",
                    dep.name
                ),
            ));
            continue;
        }
        let highest = applied
            .iter()
            .filter_map(|row| {
                row.bundle
                    .get("version")
                    .and_then(serde_json::Value::as_str)
            })
            .filter_map(parse_semver)
            .max();
        match highest {
            None => out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                key,
                format!(
                    "bundle '{}' has been applied, but none of its recorded versions is \
                     MAJOR.MINOR.PATCH",
                    dep.name
                ),
            )),
            Some(v) if v < floor => out.push(PlanEntry::blocked(
                COMPONENT_BUNDLE,
                key,
                format!(
                    "requires bundle '{}' >= {} but the highest applied version is {}.{}.{}",
                    dep.name, dep.min_version, v.0, v.1, v.2
                ),
            )),
            Some(_) => {}
        }
    }
    Ok(out)
}

/// `">=1.2.3"` or `"1.2.3"` → `(1, 2, 3)`.
pub(crate) fn parse_version_floor(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim();
    let s = s.strip_prefix(">=").unwrap_or(s).trim();
    parse_semver(s)
}

/// `"1.2.3"` → `(1, 2, 3)`; a trailing pre-release/build tag is ignored.
pub(crate) fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

// ── Object-level diff ────────────────────────────────────────────────────────

/// Compares `desired` against `live` object by object. Pure.
pub fn diff_bundles(live: &Bundle, desired: &Bundle, opts: PlanOptions) -> Diff {
    let mut live = live.clone();
    let mut desired = desired.clone();
    live.normalize();
    desired.normalize();

    let mut diff = Diff::default();
    diff_privileges(&live, &desired, &mut diff);
    diff_entities(&live, &desired, &mut diff, opts);
    diff_queries(&live, &desired, &mut diff, opts);
    diff_views(&live, &desired, &mut diff, opts);
    diff_calendars(&live, &desired, &mut diff, opts);
    diff_sidebar(&live, &desired, &mut diff, opts);
    diff_roles(&live, &desired, &mut diff, opts);
    diff_profiles(&live, &desired, &mut diff, opts);
    diff_state_models(&live, &desired, &mut diff, opts);
    diff_relationships(&live, &desired, &mut diff, opts);
    diff_apps(&live, &desired, &mut diff, opts);
    diff_rules(&live, &desired, &mut diff, opts);
    diff_attribute_patches(&live, &desired, &mut diff);
    diff
}

/// `"field: live -> desired"` for every top-level scalar that differs between
/// two serializable objects, skipping the named keys (nested collections
/// that are diffed as their own components).
fn scalar_changes<T: Serialize>(live: &T, desired: &T, skip: &[&str]) -> Vec<String> {
    let (Ok(serde_json::Value::Object(l)), Ok(serde_json::Value::Object(d))) =
        (serde_json::to_value(live), serde_json::to_value(desired))
    else {
        return Vec::new();
    };
    let keys: BTreeSet<&String> = l.keys().chain(d.keys()).collect();
    let mut out = Vec::new();
    for key in keys {
        if skip.contains(&key.as_str()) {
            continue;
        }
        let lv = l.get(key).cloned().unwrap_or(serde_json::Value::Null);
        let dv = d.get(key).cloned().unwrap_or(serde_json::Value::Null);
        if lv != dv {
            out.push(format!("{key}: {lv} -> {dv}"));
        }
    }
    out
}

/// Create / Update / Noop for one keyed object.
/// Platform-bundle (`additive_only`) plans apply under
/// `ReconcilePolicy::Seed` (`apply.rs::policy`), where an `Option` field
/// the bundle leaves as `None` means "not managed by this bundle — leave
/// the live value alone". Drop such a key from the scalar comparison so
/// the plan reports exactly what apply will do; a whole-deployment bundle
/// (`Bundle` policy, `None` = NULL) keeps the raw comparison.
fn unmanaged(skip: &mut Vec<&'static str>, key: &'static str, desired_is_none: bool) {
    if desired_is_none {
        skip.push(key);
    }
}

/// `attome_records::query_admin::reconcile_query` stores and compares
/// `table_definition` as `unwrap_or("[]")`, so a query that omits it and one
/// that carries the empty column list are the same desired state — compare
/// them that way here too, on either side, or every bundled list-view query
/// reads as `table_definition: "[]" -> null` against the row it created.
fn with_default_table_definition(q: &QueryDef) -> QueryDef {
    let mut q = q.clone();
    if q.table_definition.is_none() {
        q.table_definition = Some("[]".to_owned());
    }
    q
}

fn upsert_entry<T: Serialize>(
    component: &'static str,
    key: String,
    live: Option<&T>,
    desired: &T,
    skip: &[&str],
) -> PlanEntry {
    match live {
        None => PlanEntry::new(component, key, PlanAction::Create),
        Some(l) => {
            let changes = scalar_changes(l, desired, skip);
            if changes.is_empty() {
                PlanEntry::new(component, key, PlanAction::Noop)
            } else {
                let mut e = PlanEntry::new(component, key, PlanAction::Update);
                e.changes = changes;
                e
            }
        }
    }
}

fn diff_privileges(live: &Bundle, desired: &Bundle, diff: &mut Diff) {
    let live_by_key: BTreeMap<&str, &PrivilegeDef> = live
        .privileges
        .iter()
        .map(|p| (p.key.as_str(), p))
        .collect();
    for p in &desired.privileges {
        diff.push(upsert_entry(
            COMPONENT_PRIVILEGE,
            p.key.clone(),
            live_by_key.get(p.key.as_str()).copied(),
            p,
            &[],
        ));
    }
    // Never retired — see the module doc.
}

fn diff_entities(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_name: BTreeMap<&str, &EntityDef> = live
        .entities
        .iter()
        .map(|e| (e.logicalname.as_str(), e))
        .collect();
    let desired_names: BTreeSet<&str> = desired
        .entities
        .iter()
        .map(|e| e.logicalname.as_str())
        .collect();
    let known_entity = |name: &str| desired_names.contains(name) || live_by_name.contains_key(name);

    for e in &desired.entities {
        let live_entity = live_by_name.get(e.logicalname.as_str()).copied();
        let mut entity_skip = vec!["attributes"];
        if opts.additive_only {
            unmanaged(&mut entity_skip, "category", e.category.is_none());
            unmanaged(
                &mut entity_skip,
                "primary_name_attribute",
                e.primary_name_attribute.is_none(),
            );
        }
        diff.push(upsert_entry(
            COMPONENT_ENTITY,
            e.logicalname.clone(),
            live_entity,
            e,
            &entity_skip,
        ));

        let live_attrs: BTreeMap<&str, &AttributeDef> = live_entity
            .map(|le| {
                le.attributes
                    .iter()
                    .map(|a| (a.logicalname.as_str(), a))
                    .collect()
            })
            .unwrap_or_default();
        for a in &e.attributes {
            let key = format!("{}.{}", e.logicalname, a.logicalname);
            if !KNOWN_FIELD_TYPES.contains(&a.field_type.as_str()) {
                diff.push(PlanEntry::blocked(
                    COMPONENT_ATTRIBUTE,
                    key,
                    format!("unknown field type '{}'", a.field_type),
                ));
                continue;
            }
            // A lookup with no target (`lookup_entity_ref IS NULL`) is a legal,
            // seeded shape — a plain UUID column (the audit/s2s engines use
            // it) — so only a *named* target that resolves nowhere blocks.
            if let Some(target) = a.lookup_entity.as_deref()
                && !known_entity(target)
            {
                diff.push(PlanEntry::blocked(
                    COMPONENT_ATTRIBUTE,
                    key,
                    format!(
                        "lookup target entity '{target}' exists neither live nor in the bundle"
                    ),
                ));
                continue;
            }
            let live_attr = live_attrs.get(a.logicalname.as_str()).copied();
            if let Some(la) = live_attr
                && la.field_type != a.field_type
            {
                diff.push(PlanEntry::blocked(
                    COMPONENT_ATTRIBUTE,
                    key,
                    format!(
                        "field type change {} -> {} has no migration path (D-055); add a new field instead",
                        la.field_type, a.field_type
                    ),
                ));
                continue;
            }
            let mut attr_skip = Vec::new();
            if opts.additive_only {
                unmanaged(&mut attr_skip, "lookup_entity", a.lookup_entity.is_none());
                unmanaged(&mut attr_skip, "options", a.options.is_none());
                unmanaged(&mut attr_skip, "max_length", a.max_length.is_none());
                unmanaged(&mut attr_skip, "purpose", a.purpose.is_none());
            }
            diff.push(upsert_entry(
                COMPONENT_ATTRIBUTE,
                key,
                live_attr,
                a,
                &attr_skip,
            ));
        }

        // Attributes live but absent from the bundle.
        if let Some(le) = live_entity {
            let desired_attrs: BTreeSet<&str> = e
                .attributes
                .iter()
                .map(|a| a.logicalname.as_str())
                .collect();
            for la in &le.attributes {
                if !desired_attrs.contains(la.logicalname.as_str()) {
                    diff.retire(
                        opts,
                        COMPONENT_ATTRIBUTE,
                        format!("{}.{}", e.logicalname, la.logicalname),
                    );
                }
            }
        }
    }

    for le in &live.entities {
        if !desired_names.contains(le.logicalname.as_str()) {
            diff.retire(opts, COMPONENT_ENTITY, le.logicalname.clone());
        }
    }
}

/// [`AttributePatch`] — additive-only field promotion onto an entity this
/// bundle does not otherwise define. The one rule that makes this different
/// from an ordinary attribute inside [`diff_entities`]: **a patch never
/// creates its target entity.** If `entity` does not exist live, the patch
/// is `Blocked`, not `Create` — applying it must never bring a stub entity
/// into existence on a deployment that lacks the module that actually owns
/// `entity`'s full definition (the M77/M78/M82/M74 gap this component
/// exists to close). Never retired — additive-only for v1; retiring a field
/// belongs to whoever owns the entity's full definition, not a patch.
fn diff_attribute_patches(live: &Bundle, desired: &Bundle, diff: &mut Diff) {
    let live_entities: BTreeMap<&str, &EntityDef> = live
        .entities
        .iter()
        .map(|e| (e.logicalname.as_str(), e))
        .collect();
    let desired_entities: BTreeSet<&str> = desired
        .entities
        .iter()
        .map(|e| e.logicalname.as_str())
        .collect();
    let known_entity =
        |name: &str| desired_entities.contains(name) || live_entities.contains_key(name);

    for p in &desired.attribute_patches {
        let key = format!("{}.{}", p.entity, p.attribute.logicalname);
        let Some(live_entity) = live_entities.get(p.entity.as_str()).copied() else {
            diff.push(PlanEntry::blocked(
                COMPONENT_ATTRIBUTE_PATCH,
                key,
                format!(
                    "target entity '{}' does not exist — a patch never creates an entity, \
                     only augments one",
                    p.entity
                ),
            ));
            continue;
        };

        if !KNOWN_FIELD_TYPES.contains(&p.attribute.field_type.as_str()) {
            diff.push(PlanEntry::blocked(
                COMPONENT_ATTRIBUTE_PATCH,
                key,
                format!("unknown field type '{}'", p.attribute.field_type),
            ));
            continue;
        }
        if let Some(target) = p.attribute.lookup_entity.as_deref()
            && !known_entity(target)
        {
            diff.push(PlanEntry::blocked(
                COMPONENT_ATTRIBUTE_PATCH,
                key,
                format!("lookup target entity '{target}' exists neither live nor in the bundle"),
            ));
            continue;
        }
        let live_attr = live_entity
            .attributes
            .iter()
            .find(|a| a.logicalname == p.attribute.logicalname);
        if let Some(la) = live_attr
            && la.field_type != p.attribute.field_type
        {
            diff.push(PlanEntry::blocked(
                COMPONENT_ATTRIBUTE_PATCH,
                key,
                format!(
                    "field type change {} -> {} has no migration path (D-055); add a new field instead",
                    la.field_type, p.attribute.field_type
                ),
            ));
            continue;
        }
        diff.push(upsert_entry(
            COMPONENT_ATTRIBUTE_PATCH,
            key,
            live_attr,
            &p.attribute,
            &[],
        ));
    }
}

fn diff_queries(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_key: BTreeMap<QueryRef, &QueryDef> =
        live.queries.iter().map(|q| (q.key(), q)).collect();
    let desired_keys: BTreeSet<QueryRef> = desired.queries.iter().map(QueryDef::key).collect();
    for q in &desired.queries {
        let live_q = live_by_key
            .get(&q.key())
            .map(|lq| with_default_table_definition(lq));
        diff.push(upsert_entry(
            COMPONENT_QUERY,
            q.key().display(),
            live_q.as_ref(),
            &with_default_table_definition(q),
            &[],
        ));
    }
    for lq in &live.queries {
        if !desired_keys.contains(&lq.key()) {
            diff.retire(opts, COMPONENT_QUERY, lq.key().display());
        }
    }
}

fn diff_views(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let view_key = |v: &ViewDef| (v.entity.clone(), v.name.clone());
    let live_by_key: BTreeMap<(String, String), &ViewDef> =
        live.views.iter().map(|v| (view_key(v), v)).collect();
    let desired_keys: BTreeSet<(String, String)> = desired.views.iter().map(view_key).collect();
    for v in &desired.views {
        diff.push(upsert_entry(
            COMPONENT_VIEW,
            format!("{}.{}", v.entity, v.name),
            live_by_key.get(&view_key(v)).copied(),
            v,
            &[],
        ));
    }
    for lv in &live.views {
        if !desired_keys.contains(&view_key(lv)) {
            diff.retire(opts, COMPONENT_VIEW, format!("{}.{}", lv.entity, lv.name));
        }
    }
}

/// D-404 / M83 Phase 1. Keyed by `name` alone (calendars are not
/// entity-scoped, unlike views). `holidays` diffs as one opaque nested value
/// within `scalar_changes` (via `upsert_entry`), same granularity `ViewDef.
/// table_definition` already gets — a change anywhere in the holiday list
/// shows as one "holidays: [...] -> [...]" line rather than a per-holiday one.
/// `exceptions` diffs the same way; a bundle that omits them (D-592) leaves
/// the live ones alone, so they drop out of the comparison.
fn diff_calendars(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_key: BTreeMap<&str, &CalendarDef> = live
        .calendars
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();
    let desired_keys: BTreeSet<&str> = desired.calendars.iter().map(|c| c.name.as_str()).collect();
    for c in &desired.calendars {
        let mut skip = Vec::new();
        unmanaged(&mut skip, "exceptions", c.exceptions.is_none());
        // Z12-T6: inheritance, country, Arabic name, rules and seasons a
        // bundle leaves out are left alone, so they do not show as changes.
        unmanaged(&mut skip, "parent", c.parent.is_none());
        unmanaged(&mut skip, "country_code", c.country_code.is_none());
        unmanaged(&mut skip, "name_ar", c.name_ar.is_none());
        unmanaged(&mut skip, "rules", c.rules.is_none());
        unmanaged(&mut skip, "seasons", c.seasons.is_none());
        diff.push(upsert_entry(
            COMPONENT_CALENDAR,
            c.name.clone(),
            live_by_key.get(c.name.as_str()).copied(),
            c,
            &skip,
        ));
    }
    for lc in &live.calendars {
        if !desired_keys.contains(lc.name.as_str()) {
            diff.retire(opts, COMPONENT_CALENDAR, lc.name.clone());
        }
    }
}

fn diff_sidebar(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_path: BTreeMap<&[String], &SidebarDef> = live
        .sidebar
        .iter()
        .map(|s| (s.path.as_slice(), s))
        .collect();
    let desired_paths: BTreeSet<&[String]> =
        desired.sidebar.iter().map(|s| s.path.as_slice()).collect();
    for s in &desired.sidebar {
        diff.push(upsert_entry(
            COMPONENT_SIDEBAR,
            s.path_display(),
            live_by_path.get(s.path.as_slice()).copied(),
            s,
            &[],
        ));
    }
    for ls in &live.sidebar {
        if !desired_paths.contains(ls.path.as_slice()) {
            diff.retire(opts, COMPONENT_SIDEBAR, ls.path_display());
        }
    }
}

fn diff_roles(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_name: BTreeMap<&str, &RoleDef> =
        live.roles.iter().map(|r| (r.name.as_str(), r)).collect();
    let desired_names: BTreeSet<&str> = desired.roles.iter().map(|r| r.name.as_str()).collect();

    for r in &desired.roles {
        let live_role = live_by_name.get(r.name.as_str()).copied();
        diff.push(upsert_entry(
            COMPONENT_ROLE,
            r.name.clone(),
            live_role,
            r,
            &["privileges", "entity_access"],
        ));

        // Grants (+ conditions, compared as part of the grant).
        let live_grants: BTreeMap<&str, &RoleGrant> = live_role
            .map(|lr| {
                lr.privileges
                    .iter()
                    .map(|g| (g.privilege.as_str(), g))
                    .collect()
            })
            .unwrap_or_default();
        for g in &r.privileges {
            diff.push(upsert_entry(
                COMPONENT_ROLE_GRANT,
                format!("{}:{}", r.name, g.privilege),
                live_grants.get(g.privilege.as_str()).copied(),
                g,
                &[],
            ));
        }
        if let Some(lr) = live_role {
            let desired_grants: BTreeSet<&str> =
                r.privileges.iter().map(|g| g.privilege.as_str()).collect();
            for lg in &lr.privileges {
                if !desired_grants.contains(lg.privilege.as_str()) {
                    diff.retire(
                        opts,
                        COMPONENT_ROLE_GRANT,
                        format!("{}:{}", r.name, lg.privilege),
                    );
                }
            }
        }

        // Entity access rows.
        let live_access: BTreeMap<&str, &RoleEntityAccess> = live_role
            .map(|lr| {
                lr.entity_access
                    .iter()
                    .map(|a| (a.entity.as_str(), a))
                    .collect()
            })
            .unwrap_or_default();
        for a in &r.entity_access {
            diff.push(upsert_entry(
                COMPONENT_ROLE_ENTITY_ACCESS,
                format!("{}:{}", r.name, a.entity),
                live_access.get(a.entity.as_str()).copied(),
                a,
                &[],
            ));
        }
        if let Some(lr) = live_role {
            let desired_access: BTreeSet<&str> =
                r.entity_access.iter().map(|a| a.entity.as_str()).collect();
            for la in &lr.entity_access {
                if !desired_access.contains(la.entity.as_str()) {
                    diff.retire(
                        opts,
                        COMPONENT_ROLE_ENTITY_ACCESS,
                        format!("{}:{}", r.name, la.entity),
                    );
                }
            }
        }
    }

    for lr in &live.roles {
        if !desired_names.contains(lr.name.as_str()) {
            diff.retire(opts, COMPONENT_ROLE, lr.name.clone());
        }
    }
}

fn diff_profiles(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_name: BTreeMap<&str, &FieldSecurityProfileDef> = live
        .field_security_profiles
        .iter()
        .map(|p| (p.name.as_str(), p))
        .collect();
    let desired_names: BTreeSet<&str> = desired
        .field_security_profiles
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    for p in &desired.field_security_profiles {
        let live_profile = live_by_name.get(p.name.as_str()).copied();
        diff.push(upsert_entry(
            COMPONENT_FIELD_SECURITY_PROFILE,
            p.name.clone(),
            live_profile,
            p,
            &["fields"],
        ));

        let field_key = |f: &ProfileField| (f.entity.clone(), f.field.clone());
        let live_fields: BTreeMap<(String, String), &ProfileField> = live_profile
            .map(|lp| lp.fields.iter().map(|f| (field_key(f), f)).collect())
            .unwrap_or_default();
        for f in &p.fields {
            diff.push(upsert_entry(
                COMPONENT_PROFILE_FIELD,
                format!("{}:{}.{}", p.name, f.entity, f.field),
                live_fields.get(&field_key(f)).copied(),
                f,
                &[],
            ));
        }
        if let Some(lp) = live_profile {
            let desired_fields: BTreeSet<(String, String)> =
                p.fields.iter().map(field_key).collect();
            for lf in &lp.fields {
                if !desired_fields.contains(&field_key(lf)) {
                    diff.retire(
                        opts,
                        COMPONENT_PROFILE_FIELD,
                        format!("{}:{}.{}", p.name, lf.entity, lf.field),
                    );
                }
            }
        }
    }

    for lp in &live.field_security_profiles {
        if !desired_names.contains(lp.name.as_str()) {
            diff.retire(opts, COMPONENT_FIELD_SECURITY_PROFILE, lp.name.clone());
        }
    }
}

/// M07 Phase 1 (D-405/D-406) — same shape as `diff_profiles` above:
/// transitions are set semantics inside their parent model.
fn diff_state_models(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_entity: BTreeMap<&str, &StateModelDef> = live
        .state_models
        .iter()
        .map(|m| (m.entity_logicalname.as_str(), m))
        .collect();
    let desired_entities: BTreeSet<&str> = desired
        .state_models
        .iter()
        .map(|m| m.entity_logicalname.as_str())
        .collect();

    for m in &desired.state_models {
        let live_model = live_by_entity.get(m.entity_logicalname.as_str()).copied();
        diff.push(upsert_entry(
            COMPONENT_STATE_MODEL,
            m.entity_logicalname.clone(),
            live_model,
            m,
            &["transitions"],
        ));

        let edge_key = |t: &StateTransitionDef| (t.from_state.clone(), t.to_state.clone());
        let live_edges: BTreeMap<(String, String), &StateTransitionDef> = live_model
            .map(|lm| lm.transitions.iter().map(|t| (edge_key(t), t)).collect())
            .unwrap_or_default();
        for t in &m.transitions {
            diff.push(upsert_entry(
                COMPONENT_STATE_TRANSITION,
                format!("{}:{}->{}", m.entity_logicalname, t.from_state, t.to_state),
                live_edges.get(&edge_key(t)).copied(),
                t,
                &[],
            ));
        }
        if let Some(lm) = live_model {
            let desired_edges: BTreeSet<(String, String)> =
                m.transitions.iter().map(edge_key).collect();
            for lt in &lm.transitions {
                if !desired_edges.contains(&edge_key(lt)) {
                    diff.retire(
                        opts,
                        COMPONENT_STATE_TRANSITION,
                        format!(
                            "{}:{}->{}",
                            m.entity_logicalname, lt.from_state, lt.to_state
                        ),
                    );
                }
            }
        }
    }

    for lm in &live.state_models {
        if !desired_entities.contains(lm.entity_logicalname.as_str()) {
            diff.retire(opts, COMPONENT_STATE_MODEL, lm.entity_logicalname.clone());
        }
    }
}

/// M01 Core P3 gap (D-455) — flat, no nested children, same shape
/// `diff_privileges` uses, but retirable (a relationship's own admin CRUD
/// supports `DELETE`, unlike a privilege).
fn diff_relationships(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_name: BTreeMap<&str, &RelationshipDef> = live
        .relationships
        .iter()
        .map(|r| (r.name.as_str(), r))
        .collect();
    let desired_names: BTreeSet<&str> = desired
        .relationships
        .iter()
        .map(|r| r.name.as_str())
        .collect();

    for r in &desired.relationships {
        diff.push(upsert_entry(
            COMPONENT_RELATIONSHIP,
            r.name.clone(),
            live_by_name.get(r.name.as_str()).copied(),
            r,
            &[],
        ));
    }
    for lr in &live.relationships {
        if !desired_names.contains(lr.name.as_str()) {
            diff.retire(opts, COMPONENT_RELATIONSHIP, lr.name.clone());
        }
    }
}

/// M65 Phase 1 (D-467) — flat, no nested children, keyed by `name`, same
/// shape `diff_relationships` uses.
fn diff_apps(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_name: BTreeMap<&str, &AppDef> =
        live.apps.iter().map(|a| (a.name.as_str(), a)).collect();
    let desired_names: BTreeSet<&str> = desired.apps.iter().map(|a| a.name.as_str()).collect();

    for a in &desired.apps {
        diff.push(upsert_entry(
            COMPONENT_APP,
            a.name.clone(),
            live_by_name.get(a.name.as_str()).copied(),
            a,
            &[],
        ));
    }
    for la in &live.apps {
        if !desired_names.contains(la.name.as_str()) {
            diff.retire(opts, COMPONENT_APP, la.name.clone());
        }
    }
}

/// M45 Phase 2 (D-472) — flat, no nested children, same shape `diff_apps`
/// uses immediately above. Keyed by `RuleDef::key()` (`"{entity}:{name}"`),
/// not plain `name`, because a rule's name is only unique within one entity.
///
/// Both sides compare in their stored shape ([`RuleDef::as_stored`]): a
/// legacy `validation`/`calculation`/`default` definition in an old bundle is
/// what 0530 and `reconcile_rule` turn into a business rule (D-789), so it
/// plans as `noop` against the converted live row.
fn diff_rules(live: &Bundle, desired: &Bundle, diff: &mut Diff, opts: PlanOptions) {
    let live_by_key: BTreeMap<String, RuleDef> = live
        .rules
        .iter()
        .map(|r| (r.key(), r.as_stored()))
        .collect();
    let desired_keys: BTreeSet<String> = desired.rules.iter().map(RuleDef::key).collect();

    for r in &desired.rules {
        let stored = r.as_stored();
        diff.push(upsert_entry(
            COMPONENT_RULE,
            r.key(),
            live_by_key.get(&r.key()),
            &stored,
            &[],
        ));
    }
    for lr in &live.rules {
        if !desired_keys.contains(&lr.key()) {
            diff.retire(opts, COMPONENT_RULE, lr.key());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str, field_type: &str) -> AttributeDef {
        AttributeDef {
            logicalname: name.to_owned(),
            display_name: name.to_uppercase(),
            field_type: field_type.to_owned(),
            is_required: false,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity: None,
            options: None,
            max_length: None,
            on_target_delete: "orphan".to_owned(),
            data_classification: "general".to_owned(),
            purpose: None,
            is_customized: false,
        }
    }

    fn entity(name: &str, attrs: Vec<AttributeDef>) -> EntityDef {
        EntityDef {
            logicalname: name.to_owned(),
            display_name: name.to_uppercase(),
            primary_name_attribute: None,
            is_append_only: false,
            is_audited: false,
            category: None,
            is_customized: false,
            attributes: attrs,
        }
    }

    fn role(name: &str, privileges: &[&str]) -> RoleDef {
        RoleDef {
            name: name.to_owned(),
            description: None,
            access_level: 3,
            position_hierarchy_enabled: false,
            is_customized: false,
            privileges: privileges
                .iter()
                .map(|p| RoleGrant {
                    privilege: (*p).to_owned(),
                    conditions: vec![],
                })
                .collect(),
            entity_access: vec![],
            field_security_profiles: vec![],
        }
    }

    fn requires() -> Requires {
        Requires {
            platform_version: ">=0.0.0".to_owned(),
            schema_version: 0,
            modules: vec!["core".to_owned()],
            depends_on_bundles: vec![],
        }
    }

    fn live() -> Bundle {
        let mut b = Bundle::empty(requires());
        b.entities = vec![
            entity("account", vec![attr("email", "text"), attr("name", "text")]),
            entity("contact", vec![attr("name", "text")]),
        ];
        b.roles = vec![role("editor", &["account.read", "account.write"])];
        b.privileges = vec![PrivilegeDef {
            key: "account.read".to_owned(),
            name: "Read".to_owned(),
            description: None,
        }];
        b
    }

    fn all_modules() -> ModuleSet {
        ModuleSet::from_bits([u64::MAX; 4])
    }

    fn no_modules() -> ModuleSet {
        ModuleSet::from_bits([0; 4])
    }

    fn allow() -> PlanOptions {
        PlanOptions {
            allow_retire: true,
            additive_only: false,
        }
    }

    fn find<'a>(v: &'a [PlanEntry], component: &str, key: &str) -> &'a PlanEntry {
        v.iter()
            .find(|e| e.component == component && e.key == key)
            .unwrap_or_else(|| panic!("no entry {component} {key} in {v:#?}"))
    }

    #[test]
    fn identical_bundles_are_all_noop() {
        let l = live();
        let d = Diff::default();
        assert_eq!(d.summary(), PlanSummary::default());
        let d = diff_bundles(&l, &l, PlanOptions::default());
        assert!(d.retires.is_empty(), "{:?}", d.retires);
        assert!(d.blocked.is_empty(), "{:?}", d.blocked);
        assert!(
            d.entries.iter().all(|e| e.action == PlanAction::Noop),
            "{:#?}",
            d.entries
        );
        let s = d.summary();
        assert_eq!(s.creates + s.updates + s.retires + s.blocked, 0);
        assert!(s.noops > 0);
    }

    /// Platform-bundle plans (`additive_only`) apply under `Seed` semantics:
    /// an `Option` the bundle leaves out is not a change, and a query's
    /// missing `table_definition` is the same as the `"[]"` the engine
    /// stores. A whole-deployment plan keeps the exact comparison.
    #[test]
    fn additive_only_treats_omitted_options_as_unmanaged() {
        let mut live_b = live();
        live_b.entities[0].category = Some("Core Platform".to_owned());
        live_b.entities[0].attributes[0].options = Some(serde_json::json!({"x": 1}));
        live_b.queries.push(QueryDef {
            entity: Some("account".to_owned()),
            name: "Active Accounts".to_owned(),
            sql: "SELECT id FROM account".to_owned(),
            table_definition: Some("[]".to_owned()),
            required_privilege: Some("account.read".to_owned()),
            is_report: false,
            entity_mappings: vec![],
            is_customized: false,
        });
        let mut desired = live_b.clone();
        desired.entities[0].category = None;
        desired.entities[0].attributes[0].options = None;
        desired.queries[0].table_definition = None;

        let platform = diff_bundles(
            &live_b,
            &desired,
            PlanOptions {
                allow_retire: false,
                additive_only: true,
            },
        );
        assert!(
            platform
                .entries
                .iter()
                .all(|e| e.action == PlanAction::Noop),
            "{:#?}",
            platform.entries
        );

        let whole = diff_bundles(&live_b, &desired, allow());
        assert_eq!(
            find(&whole.entries, COMPONENT_ENTITY, "account").action,
            PlanAction::Update
        );
        assert_eq!(
            find(&whole.entries, COMPONENT_ATTRIBUTE, "account.email").action,
            PlanAction::Update
        );
        // `table_definition` is engine-defaulted on every path, so it is a
        // no-op even for a whole-deployment plan.
        assert_eq!(
            find(&whole.entries, COMPONENT_QUERY, "account.Active Accounts").action,
            PlanAction::Noop
        );
    }

    #[test]
    fn create_update_noop_are_classified() {
        let l = live();
        let mut d = live();
        // update: relabel account.email
        d.entities[0].attributes[0].display_name = "E-mail".to_owned();
        // create: new entity with a lookup to an entity in the bundle
        let mut la = attr("owner", "lookup");
        la.lookup_entity = Some("contact".to_owned());
        d.entities.push(entity("deal", vec![la]));
        // update entity scalar
        d.entities[1].is_audited = true;

        let diff = diff_bundles(&l, &d, PlanOptions::default());
        assert!(diff.blocked.is_empty(), "{:#?}", diff.blocked);
        assert!(diff.retires.is_empty());
        let e = find(&diff.entries, COMPONENT_ATTRIBUTE, "account.email");
        assert_eq!(e.action, PlanAction::Update);
        assert_eq!(e.changes, vec![r#"display_name: "EMAIL" -> "E-mail""#]);
        assert_eq!(
            find(&diff.entries, COMPONENT_ENTITY, "deal").action,
            PlanAction::Create
        );
        assert_eq!(
            find(&diff.entries, COMPONENT_ATTRIBUTE, "deal.owner").action,
            PlanAction::Create
        );
        assert_eq!(
            find(&diff.entries, COMPONENT_ENTITY, "contact").action,
            PlanAction::Update
        );
        assert_eq!(
            find(&diff.entries, COMPONENT_ENTITY, "account").action,
            PlanAction::Noop
        );
        assert_eq!(
            find(&diff.entries, COMPONENT_ATTRIBUTE, "account.name").action,
            PlanAction::Noop
        );
    }

    #[test]
    fn absent_objects_retire_only_with_allow_retire() {
        let l = live();
        let mut d = live();
        d.entities[0]
            .attributes
            .retain(|a| a.logicalname != "email");
        d.entities.retain(|e| e.logicalname != "contact");
        d.roles[0]
            .privileges
            .retain(|g| g.privilege != "account.write");
        d.privileges.clear(); // privileges are never retired

        let blocked = diff_bundles(&l, &d, PlanOptions::default());
        assert!(blocked.retires.is_empty());
        assert_eq!(blocked.blocked.len(), 3, "{:#?}", blocked.blocked);
        assert!(
            blocked
                .blocked
                .iter()
                .all(|e| e.reason.as_deref() == Some("retire requires allow_retire"))
        );

        let allowed = diff_bundles(&l, &d, allow());
        assert!(allowed.blocked.is_empty(), "{:#?}", allowed.blocked);
        assert_eq!(allowed.retires.len(), 3, "{:#?}", allowed.retires);
        assert_eq!(
            find(&allowed.retires, COMPONENT_ATTRIBUTE, "account.email").action,
            PlanAction::Retire
        );
        assert_eq!(
            find(&allowed.retires, COMPONENT_ENTITY, "contact").action,
            PlanAction::Retire
        );
        assert_eq!(
            find(
                &allowed.retires,
                COMPONENT_ROLE_GRANT,
                "editor:account.write"
            )
            .action,
            PlanAction::Retire
        );
        // Retiring an entity does not also list its attributes.
        assert!(!allowed.retires.iter().any(|e| e.key == "contact.name"));
        assert_eq!(allowed.summary().retires, 3);
    }

    #[test]
    fn field_type_change_is_blocked() {
        let l = live();
        let mut d = live();
        d.entities[0].attributes[0].field_type = "number".to_owned();
        let diff = diff_bundles(&l, &d, allow());
        let b = find(&diff.blocked, COMPONENT_ATTRIBUTE, "account.email");
        assert!(b.reason.as_deref().unwrap_or("").contains("D-055"), "{b:?}");
        assert!(!diff.entries.iter().any(|e| e.key == "account.email"));
    }

    #[test]
    fn unknown_field_type_and_missing_lookup_target_are_blocked() {
        let l = live();
        let mut d = live();
        d.entities[0].attributes.push(attr("weird", "geo"));
        let mut la = attr("owner", "lookup");
        la.lookup_entity = Some("nowhere".to_owned());
        d.entities[0].attributes.push(la);
        let mut no_target = attr("blank", "lookup");
        no_target.lookup_entity = None;
        d.entities[0].attributes.push(no_target);
        // A lookup to a *live* entity not in the bundle is fine.
        let mut live_target = attr("contact_ref", "lookup");
        live_target.lookup_entity = Some("contact".to_owned());
        d.entities[0].attributes.push(live_target);
        d.entities.retain(|e| e.logicalname != "contact");

        let diff = diff_bundles(&l, &d, allow());
        assert!(
            find(&diff.blocked, COMPONENT_ATTRIBUTE, "account.weird")
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("unknown field type")
        );
        assert!(
            find(&diff.blocked, COMPONENT_ATTRIBUTE, "account.owner")
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("nowhere")
        );
        // A target-less lookup is a legal seeded shape (plain UUID column).
        assert_eq!(
            find(&diff.entries, COMPONENT_ATTRIBUTE, "account.blank").action,
            PlanAction::Create
        );
        assert_eq!(
            find(&diff.entries, COMPONENT_ATTRIBUTE, "account.contact_ref").action,
            PlanAction::Create
        );
    }

    #[test]
    fn role_grant_conditions_count_as_grant_changes() {
        let l = live();
        let mut d = live();
        d.roles[0].privileges[0].conditions.push(GrantCondition {
            field: "ownerid".to_owned(),
            operator: 0,
            value: serde_json::json!("me"),
        });
        let diff = diff_bundles(&l, &d, allow());
        let e = find(&diff.entries, COMPONENT_ROLE_GRANT, "editor:account.read");
        assert_eq!(e.action, PlanAction::Update);
        assert!(e.changes[0].starts_with("conditions:"), "{:?}", e.changes);
        assert_eq!(
            find(&diff.entries, COMPONENT_ROLE, "editor").action,
            PlanAction::Noop
        );
    }

    #[test]
    fn requires_checks_block_at_bundle_level() {
        let mut d = live();
        d.format = "attome-bundle/v2".to_owned();
        d.requires.schema_version = 999;
        d.requires.platform_version = ">=99.0.0".to_owned();
        d.requires.modules = vec!["core".to_owned(), "nope".to_owned()];

        let blocked = check_requires(&d, &no_modules(), 131, "4.0.1");
        let keys: Vec<&str> = blocked.iter().map(|e| e.key.as_str()).collect();
        assert!(keys.contains(&"format"), "{keys:?}");
        assert!(keys.contains(&"requires.schema_version"), "{keys:?}");
        assert!(keys.contains(&"requires.platform_version"), "{keys:?}");
        // There are no licences, so a module is never "unlicensed": only a
        // name no module has is blocked.
        assert!(!keys.contains(&"requires.modules:core"), "{keys:?}");
        assert!(keys.contains(&"requires.modules:nope"), "{keys:?}"); // unknown
        assert!(blocked.iter().all(|e| e.component == COMPONENT_BUNDLE));
        assert!(blocked.iter().all(|e| e.action == PlanAction::Blocked));

        // Satisfied floors produce nothing.
        let ok = live();
        assert!(check_requires(&ok, &all_modules(), 131, "4.0.1").is_empty());
        let mut exact = live();
        exact.requires.platform_version = ">=4.0.1".to_owned();
        exact.requires.schema_version = 131;
        assert!(check_requires(&exact, &all_modules(), 131, "4.0.1").is_empty());
        let mut bare = live();
        bare.requires.platform_version = "4.0.0".to_owned();
        assert!(check_requires(&bare, &all_modules(), 131, "4.0.1-rc1").is_empty());
        let mut garbage = live();
        garbage.requires.platform_version = "latest".to_owned();
        assert_eq!(
            check_requires(&garbage, &all_modules(), 131, "4.0.1").len(),
            1
        );
    }

    #[test]
    fn build_plan_hashes_both_sides_and_summarizes() {
        let l = live();
        let mut d = live();
        d.entities[0].attributes[0].display_name = "E-mail".to_owned();
        d.entities.retain(|e| e.logicalname != "contact");
        let plan = build_plan(&l, &d, PlanOptions::default(), &all_modules(), 131, "4.0.1");
        assert_eq!(plan.basis_hash, bundle_hash(&l));
        assert_eq!(plan.bundle_hash, bundle_hash(&d));
        assert_ne!(plan.basis_hash, plan.bundle_hash);
        assert_eq!(plan.summary.updates, 1);
        assert_eq!(plan.summary.blocked, 1); // contact retire without allow_retire
        assert!(!plan.is_applicable());
        let plan2 = build_plan(&l, &d, allow(), &all_modules(), 131, "4.0.1");
        assert_eq!(plan2.summary.retires, 1);
        assert!(plan2.is_applicable());
        assert_ne!(plan.plan_id, plan2.plan_id);
        // Self-plan is all-noop and applicable.
        let self_plan = build_plan(&l, &l, PlanOptions::default(), &all_modules(), 131, "4.0.1");
        assert_eq!(self_plan.basis_hash, self_plan.bundle_hash);
        assert!(self_plan.is_applicable());
        assert_eq!(
            self_plan.summary.retires + self_plan.summary.creates + self_plan.summary.updates,
            0
        );
    }

    #[test]
    fn diff_is_order_independent() {
        let l = live();
        let mut d = live();
        d.entities.reverse();
        d.entities[1].attributes.reverse();
        d.roles[0].privileges.reverse();
        let diff = diff_bundles(&l, &d, PlanOptions::default());
        assert!(
            diff.entries.iter().all(|e| e.action == PlanAction::Noop),
            "{:#?}",
            diff.entries
        );
    }
}
