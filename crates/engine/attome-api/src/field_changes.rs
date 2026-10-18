//! Solution 7 Phase 2 (D-788; `SOLUTION-7-PHASE-2-DESIGN.md` §3.1–§3.5, §6.4,
//! §7.5) — the executors of the structure changes, shared by the admin routes
//! and the changeset applier (the D-375 one-implementation rule):
//!
//! - [`rename_field`] — `rename_field`: the column is renamed in place and
//!   every reference follows through the hook registry, one transaction.
//! - [`delete_field`] — `delete_field`: values archived (encrypted, 30 days),
//!   references removed (ours must be gone first: blockers; customer objects
//!   adjusted and reported), column dropped, attribute row deleted.
//! - [`change_field_type`] — `change_field_type`: in-place conversion; values
//!   that do not convert become null and are archived. At or under the size
//!   gate one transaction; above it a shadow column with a sync trigger,
//!   batches and a swap, as a `data_step_run` (`RunDataStep` job).
//! - [`add_choice`] / [`remove_choice`] — `add_choice_value` /
//!   `remove_choice_value`: no data step; stored values stay.
//!
//! Each change records its one op (via the request's [`Recording`]; the
//! applier's `Recording::Applying` records nothing) as the last statement
//! before commit, then fires the metadata doorbell and the caches the hooks
//! touched ([`after_commit`]: every refresh is retried once, a failure is
//! logged at `error` and labelled on the result, and every stale path fails
//! closed — security review M4). The report drafts are returned in
//! [`FieldChangeResult::report`], logged, and stored as release-report items
//! (design §10): into the apply run's report when a changeset apply drives
//! the change, else a standalone report (`source = 'change'`). An archive-
//! backed item (`field_deleted`, `conversion_nulled`) is linked to its
//! archive rows so the report's Restore finds them.
//!
//! **Size gate first (security review M5).** Every change asks the bounded
//! size probe before any count. At or under
//! [`FIELD_CHANGE_INLINE_ROW_LIMIT`] rows the counts are exact and the
//! change runs inline; above it no full scan runs on the request thread:
//! a delete reports the planner's estimate of the values it archives, a
//! conversion reports its non-convertible values from the run, and the work
//! goes to the durable run (`RunDataStep`, `data_step_run`), whose
//! final step scans under `SHARE` (writers wait, readers do not) and takes
//! `ACCESS EXCLUSIVE` only for the catalog DDL.
//!
//! **Grant conditions on a deleted field (security review M3, Topic 16).**
//! A grant condition of ours blocks the delete (Topic 15 #3). A customer
//! condition revokes its grant only when the grant, every live condition of
//! it and the change itself are all the customer layer; the revocation is
//! written in the delete's own transaction with an `Access`/`Revoke`
//! security event (L2). Any other customer condition blocks the delete,
//! naming the grant (a later release-report lane turns this into a report
//! item).

use attome_core::EngineState;
use attome_core::changeset::field_hooks::{
    Blocker, CacheTouch, FieldRef, HookOutcome, ReportItemDraft,
};
use attome_core::changeset::{Layer, Op, RecordedOp, Recording};
use attome_core::recovery_archive::{self, ArchiveReason};
use attome_db::Tx;
use attome_metadata::provision::{self, field_change as fc};
use attome_types::AppError;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::field_hooks;

/// The size gate (rows) above which a delete's archive copy and a type
/// conversion run in batches as a durable run.
pub const FIELD_CHANGE_INLINE_ROW_LIMIT: i64 = provision::RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT;

/// Who is changing what, and how it is recorded.
pub struct ChangeCtx<'a> {
    pub recording: &'a Recording,
    pub actor: Uuid,
    /// `(changeset id, op seq)` when an applied changeset op drives the
    /// change (archive rows and runs carry it); `None` on the admin route.
    pub op: Option<(Uuid, i32)>,
    /// `admin` | `apply` | `replay` (the run ledger's `source`).
    pub source: &'static str,
}

impl std::fmt::Debug for ChangeCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeCtx").finish_non_exhaustive()
    }
}

/// What a structure change did, or (dry run / blocked) would do.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct FieldChangeResult {
    /// `rename_field` | `delete_field` | `change_field_type` |
    /// `add_choice_value` | `remove_choice_value`.
    pub op: &'static str,
    pub entity: String,
    pub field: String,
    pub dry_run: bool,
    /// The change committed (or, for a large table, was queued: see `run_id`).
    pub applied: bool,
    /// A stable refusal code when the change is blocked
    /// (`rename_blocked_by_reference`, `field_referenced`, `field_in_use`,
    /// `archive_key_missing`, ...); `blockers` lists why.
    pub error: Option<&'static str>,
    #[schema(value_type = Vec<Object>)]
    pub references: Vec<FieldRef>,
    #[schema(value_type = Vec<Object>)]
    pub blockers: Vec<Blocker>,
    /// Non-null values the delete archives (dry run: would archive).
    pub values_to_archive: Option<i64>,
    /// Values that do not convert (dry run: would become empty).
    pub not_convertible: Option<i64>,
    /// Up to ten record ids of non-convertible values (ids only).
    pub sample_record_ids: Vec<Uuid>,
    /// Values archived by this call (0 while a large run is still going).
    pub archived: u64,
    /// Values nulled by a conversion (0 while a large run is still going).
    pub nulled: u64,
    /// Records that keep a removed choice value (shown empty).
    pub records_with_value: Option<i64>,
    /// The batched run of a large table (`GET .../data-steps/{run_id}` lane
    /// P2-C/E; the run row is `data_step_run`).
    pub run_id: Option<Uuid>,
    /// Release-report items (also stored in the report): breaking API changes,
    /// adjusted/removed customer objects, archived/nulled values.
    #[schema(value_type = Vec<Object>)]
    pub report: Vec<ReportItemDraft>,
    /// Labels applied by these changes: "runs without business rules or
    /// workflows" on a conversion.
    pub labels: Vec<&'static str>,
}

impl FieldChangeResult {
    fn new(op: &'static str, entity: &str, field: &str, dry_run: bool) -> Self {
        Self {
            op,
            entity: entity.to_owned(),
            field: field.to_owned(),
            dry_run,
            ..Self::default()
        }
    }

    fn blocked(mut self, code: &'static str) -> Self {
        self.error = Some(code);
        self.applied = false;
        self
    }
}

fn parse_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| {
        AppError::internal(format!("unknown owner_layer {value:?} on a metadata row"))
    })
}

fn breaking(entity: &str, field: &str, detail: Value) -> ReportItemDraft {
    ReportItemDraft {
        kind: "breaking_api_change",
        entity: entity.to_owned(),
        field: Some(field.to_owned()),
        object_kind: None,
        object_ref: None,
        detail,
    }
}

fn log_report(result: &FieldChangeResult) {
    for item in &result.report {
        tracing::info!(
            kind = item.kind,
            entity = %item.entity,
            field = ?item.field,
            object_kind = ?item.object_kind,
            object_ref = ?item.object_ref,
            op = result.op,
            "structure change: release-report item"
        );
    }
}

/// The layer this change stamps, when it is known. A dry run that could not
/// resolve its changeset (a request not preflighted, `changeset_required`
/// with nothing open) has none: the layer-dependent checks then take the
/// conservative branch (a customer grant condition is reported as blocking).
async fn change_layer(
    state: &EngineState,
    ctx: &ChangeCtx<'_>,
    dry_run: bool,
) -> Result<Option<Layer>, AppError> {
    match ctx.recording.preflight(&state.base.db_migrator).await {
        Ok(resolved) => Ok(Some(resolved.layer)),
        // A dry run writes nothing; it must not 500 or 409 because no
        // changeset is open (the structure routes skip preflight for a dry
        // run, and `check_owner` needs it: open verification question 3).
        Err(_) if dry_run => Ok(None),
        Err(e) => Err(e),
    }
}

/// Opens the change's transaction: metadata write lock, the field row
/// locked, the owner-layer rule, the provisioning lock, `field_busy`.
async fn open<'a>(
    state: &'a EngineState,
    ctx: &ChangeCtx<'_>,
    entity_id: Uuid,
    attr_id: Uuid,
    dry_run: bool,
) -> Result<(Tx<'a>, fc::FieldRow), AppError> {
    let layer = change_layer(state, ctx, dry_run).await?;
    let mut tx = attome_db::tx::begin(&state.base.db_migrator).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
    if layer.is_some() {
        ctx.recording.check_owner(parse_layer(&row.owner_layer)?)?;
    }
    fc::lock_provisioning_in_tx(&mut tx, &row).await?;
    if fc::field_busy(&mut tx, &row).await? {
        return Err(AppError::Conflict(
            "field_busy: a schema change or a data step on this field is still running",
        ));
    }
    Ok((tx, row))
}

async fn record(
    tx: &mut Tx<'_>,
    ctx: &ChangeCtx<'_>,
    op: Op,
    row: &fc::FieldRow,
    field: &str,
    snapshot: Value,
) -> Result<(), AppError> {
    ctx.recording
        .record(
            tx,
            RecordedOp {
                op,
                object_kind: "attribute",
                object_ref: Some(row.attribute_id),
                target: provision::changeset::field_target(&row.entity, field),
                snapshot,
                changed: vec![],
            },
        )
        .await
}

/// Attempts per cache refresh or doorbell after a commit (security review
/// M4: one retry before a failure is reported).
const AFTER_COMMIT_ATTEMPTS: usize = 2;

/// What [`after_commit`] could not converge.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AfterCommitFailures {
    /// Security caches (role holders, profile holders) that were not
    /// invalidated: holders may keep their old (never wider) authorization
    /// state until the 60 s TTL.
    pub security: Vec<String>,
    /// Ordinary caches (forms, rules, state models, labels) whose local
    /// reload or cross-node doorbell failed.
    pub other: Vec<String>,
}

impl AfterCommitFailures {
    pub fn is_empty(&self) -> bool {
        self.security.is_empty() && self.other.is_empty()
    }
}

/// Runs `step` up to [`AFTER_COMMIT_ATTEMPTS`] times; `Err` with the last
/// failure's text.
async fn with_retry<F, Fut>(mut step: F) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut last = String::new();
    for _ in 0..AFTER_COMMIT_ATTEMPTS {
        match step().await {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// After commit: the metadata doorbell, then every cache the hooks touched,
/// once each. The change is committed whatever happens here; nothing is
/// silent (security review M4): every refresh and doorbell is retried once,
/// and a failure is logged at `error` with the change it belongs to. The
/// stale path stays safe: a stale grant condition renders to `FALSE` and a
/// stale field grant is an allow-list (nothing opens up), the security cache
/// entries expire in 60 s, other nodes catch metadata up from the change
/// log, and the returned [`AfterCommitFailures`] is labelled on the result
/// so the admin is told.
pub async fn after_commit(
    state: &EngineState,
    caches: &[CacheTouch],
    what: &str,
) -> AfterCommitFailures {
    let mut failures = AfterCommitFailures::default();
    crate::admin::notify_metadata_change(&state.base.redis).await;
    let publish = |channel: &'static str| async move {
        with_retry(|| async move {
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                state.base.redis.publish(channel, "1"),
            )
            .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("timed out".to_owned()),
            }
        })
        .await
        .map_err(|e| format!("{channel} doorbell: {e}"))
    };
    let db = &state.base.db;
    for touch in caches {
        let outcome: Result<(), String> = match touch {
            CacheTouch::Rules => {
                let reload = with_retry(|| async move {
                    let fresh = attome_core::rule_registry::load(db)
                        .await
                        .map_err(|e| e.to_string())?;
                    state.rules.swap(fresh);
                    Ok(())
                })
                .await
                .map_err(|e| format!("rule reload: {e}"));
                let sent = publish(attome_core::RULE_VERSION_CHANNEL).await;
                reload.and(sent)
            }
            CacheTouch::StateModels => {
                let reload = with_retry(|| async move {
                    let fresh = attome_core::state_registry::load(db)
                        .await
                        .map_err(|e| e.to_string())?;
                    state.state_models.swap(fresh);
                    Ok(())
                })
                .await
                .map_err(|e| format!("state-model reload: {e}"));
                let sent = publish(attome_core::STATE_MODEL_VERSION_CHANNEL).await;
                reload.and(sent)
            }
            CacheTouch::Labels => with_retry(|| async move {
                let fresh = attome_core::label_store::load_all(db)
                    .await
                    .map_err(|e| e.to_string())?;
                state.labels.swap(fresh);
                Ok(())
            })
            .await
            .map_err(|e| format!("label reload: {e}")),
            CacheTouch::Views => Ok(()),
            CacheTouch::SecurityProfile(profile) => {
                let invalidated = with_retry(|| async move {
                    attome_security::reconcile::invalidate_profile_holders(
                        db,
                        &state.base.security,
                        *profile,
                    )
                    .await
                    .map_err(|e| e.to_string())
                })
                .await;
                if let Err(e) = invalidated {
                    tracing::error!(error = %e, %profile, change = what,
                        "structure change: field-security profile holders' cache NOT invalidated \
                         (committed; holders may keep old field grants up to the 60 s TTL)");
                    failures.security.push(format!("profile {profile}"));
                }
                continue;
            }
            CacheTouch::SecurityRole(role) => {
                let invalidated = with_retry(|| async move {
                    attome_security::reconcile::invalidate_role_holders(
                        db,
                        &state.base.security,
                        *role,
                    )
                    .await
                    .map_err(|e| e.to_string())
                })
                .await;
                if let Err(e) = invalidated {
                    tracing::error!(error = %e, %role, change = what,
                        "structure change: role holders' cache NOT invalidated \
                         (committed; holders may keep old grants up to the 60 s TTL)");
                    failures.security.push(format!("role {role}"));
                }
                continue;
            }
        };
        if let Err(e) = outcome {
            tracing::error!(error = %e, cache = ?touch, change = what,
                "structure change: cache refresh or doorbell failed after commit \
                 (committed; other nodes catch up from the change log)");
            failures.other.push(e);
        }
    }
    failures
}

// ── rename_field ────────────────────────────────────────────────────────────

/// `rename_conflicts_open_changeset` (design §3.1): another open changeset
/// has recorded an op on the entity; its snapshots carry the old name.
async fn other_open_changeset_touches(
    conn: &mut sqlx::PgConnection,
    ctx: &ChangeCtx<'_>,
    db: &attome_db::DbPool,
    entity: &str,
    dry_run: bool,
) -> Result<bool, AppError> {
    let Recording::Request(_) = ctx.recording else {
        return Ok(false);
    };
    let mine = match ctx.recording.preflight(db).await {
        Ok(resolved) => resolved.changeset_id,
        // A dry run with no resolvable changeset reports what it can.
        Err(_) if dry_run => None,
        Err(e) => return Err(e),
    };
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM changeset_operation o \
         JOIN changeset c ON c.id = o.changeset_ref \
         WHERE c.status = 'open' AND ($2::uuid IS NULL OR c.id <> $2) \
           AND o.target->>'entity' = $1)",
    )
    .bind(entity)
    .bind(mine)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Renames the field in place (design §3.1). `Ok` with `error` set when the
/// rename is blocked by references in our layers (nothing written).
pub async fn rename_field(
    state: &EngineState,
    ctx: &ChangeCtx<'_>,
    entity_id: Uuid,
    attr_id: Uuid,
    new_name: &str,
    dry_run: bool,
) -> Result<FieldChangeResult, AppError> {
    let (mut tx, row) = open(state, ctx, entity_id, attr_id, dry_run).await?;
    let mut result = FieldChangeResult::new("rename_field", &row.entity, &row.field, dry_run);
    fc::check_rename_target(&mut tx, &row, new_name).await?;
    if other_open_changeset_touches(&mut tx, ctx, &state.base.db_migrator, &row.entity, dry_run)
        .await?
    {
        return Err(AppError::Conflict(
            "rename_conflicts_open_changeset: another open changeset has recorded changes to this \
             entity; close or abandon it first",
        ));
    }
    let scan = field_hooks::registry()
        .scan(&mut tx, &row.entity, &row.field, true)
        .await?;
    result.references = scan.refs;
    result.blockers = scan.blockers;
    result.report.push(breaking(
        &row.entity,
        &row.field,
        json!({ "change": "renamed", "to": new_name,
                "alias_days": fc::RENAME_ALIAS_DAYS,
                "note": "the record API accepts the old name, with a Deprecation header, for the \
                         alias period; integrations must move to the new name before it ends" }),
    ));
    if !result.blockers.is_empty() {
        return Ok(result.blocked("rename_blocked_by_reference"));
    }
    if dry_run {
        return Ok(result);
    }
    fc::set_ddl_bounds_in_tx(&mut tx).await?;
    fc::rename_column_in_tx(&mut tx, &row, new_name).await?;
    let outcome = field_hooks::registry()
        .rename(&mut tx, &row.entity, &row.field, new_name)
        .await?;
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    record(
        &mut tx,
        ctx,
        Op::RenameField,
        &row,
        &row.field,
        json!({ "new_name": new_name }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        entity = %row.entity, old = %row.field, new = %new_name,
        "structure change: field renamed in place"
    );
    finish(state, &mut result, outcome).await;
    Ok(result)
}

/// Label on a large table's delete: `values_to_archive` is the planner's
/// estimate, not a count (M5).
pub const LABEL_ESTIMATED: &str =
    "large table: values_to_archive is the planner's estimate; the run archives every value";
/// Label on a large table's conversion: the run counts the values it nulls
/// (`rows_nulled`), so `not_convertible` is not reported up front (M5).
pub const LABEL_COUNTED_BY_RUN: &str =
    "large table: non-convertible values are counted by the run (rows_nulled)";

/// Label on a large table's choice removal: the records that keep the value
/// are not counted on the request thread (M5).
pub const LABEL_NOT_COUNTED: &str =
    "large table: records_with_value is not counted; stored values stay in place";

/// Label on a result whose security cache did not converge after commit.
pub const LABEL_SECURITY_CACHE_STALE: &str = "committed, but the authorization cache did not \
     converge: holders may keep their old access (never wider) for up to 60 s";
/// Label on a result whose release-report items could not be stored.
pub const LABEL_REPORT_NOT_STORED: &str =
    "committed, but the release-report items were not stored: they are listed in `report` only";
/// Label on a result whose form/rule/state/label cache or doorbell failed.
pub const LABEL_CACHE_STALE: &str =
    "committed, but a cache refresh failed: other nodes catch up from the change log";

/// After a commit: the report, then [`after_commit`]. A cache that did not
/// converge is logged at `error` there and labelled on the result, so the
/// admin who made the change is told (security review M4). It is not turned
/// into a 500: the change and its hooks are committed, and failing the
/// response would skip the route's post-commit audit event. Every stale path
/// of these changes fails closed (a renamed or deleted field's stale grant
/// matches no column; a stale grant condition renders to `FALSE`,
/// `attome_security::conditions`), so nothing opens up while the cache catches
/// up.
async fn finish(state: &EngineState, result: &mut FieldChangeResult, outcome: HookOutcome) {
    result.applied = true;
    result.report.extend(outcome.report);
    log_report(result);
    // Release report (design §10): into the apply run's report, else a
    // standalone one. Its own short transaction after the change committed:
    // a failure is logged and labelled, never a failure of the change.
    let release = format!("{} {}.{}", result.op, result.entity, result.field);
    if let Err(error) = attome_core::release_report::record_drafts(
        &state.base.db,
        recovery_archive::ring(state.base.config.as_ref()),
        &result.report,
        &release,
    )
    .await
    {
        tracing::error!(%error, change = %release,
            "structure change committed, but its release-report items were not stored \
             (they are in this response and the log)");
        result.labels.push(LABEL_REPORT_NOT_STORED);
    }
    let what = format!("{} {}.{}", result.op, result.entity, result.field);
    let failures = after_commit(state, &outcome.caches, &what).await;
    if !failures.security.is_empty() {
        result.labels.push(LABEL_SECURITY_CACHE_STALE);
    }
    if !failures.other.is_empty() {
        result.labels.push(LABEL_CACHE_STALE);
    }
}

// ── delete_field ────────────────────────────────────────────────────────────

/// Plan-time blocks of a delete (design §3.2): the entity's primary name,
/// a formula that computes from it, our references (hooks), and the grant
/// conditions that name it (security review M3: see the module doc). Returns
/// the refusal code, if any, and the customer grants the delete revokes
/// (all of them the customer layer, as the change is).
async fn delete_blockers(
    tx: &mut Tx<'_>,
    row: &fc::FieldRow,
    layer: Option<Layer>,
    result: &mut FieldChangeResult,
) -> Result<(Option<&'static str>, Vec<field_hooks::RevocableGrant>), AppError> {
    let mut code = None;
    if row.primary_name_attribute.as_deref() == Some(row.field.as_str()) {
        result.blockers.push(Blocker {
            hook: "entity",
            object_kind: "entity".into(),
            object_ref: Some(row.entity_id),
            name: row.entity.clone(),
            reason: "field_in_use: the field is the entity's primary name attribute".into(),
        });
        code = Some("field_in_use");
    }
    for (id, name) in fc::formula_dependents(tx, row).await? {
        result.blockers.push(Blocker {
            hook: "entity",
            object_kind: "formula_field".into(),
            object_ref: Some(id),
            name,
            reason: "field_in_use: a formula field computes from it".into(),
        });
        code = code.or(Some("field_in_use"));
    }
    let scan = field_hooks::registry()
        .scan(tx, &row.entity, &row.field, false)
        .await?;
    result.references = scan.refs;
    let (grant_blockers, revocable) =
        field_hooks::customer_grant_conditions(tx, &row.entity, &row.field, layer).await?;
    let mut blockers = scan.blockers;
    blockers.extend(grant_blockers);
    if !blockers.is_empty() {
        let in_use = blockers
            .iter()
            .any(|b| b.reason.starts_with("field_in_use"));
        result.blockers.extend(blockers);
        code = code.or(Some(if in_use {
            "field_in_use"
        } else {
            "field_referenced"
        }));
    }
    Ok((code, revocable))
}

/// The consequence writes of a delete, in its transaction just before the
/// drop: the hooks' removals, then the customer grants a customer-layer
/// delete revokes (with their `Access` security events).
async fn remove_references(
    state: &EngineState,
    tx: &mut Tx<'_>,
    row: &fc::FieldRow,
    revocable: &[field_hooks::RevocableGrant],
    actor: Uuid,
) -> Result<HookOutcome, AppError> {
    let mut outcome = field_hooks::registry()
        .remove(tx, &row.entity, &row.field)
        .await?;
    let audit = attome_audit::audit_service(state);
    outcome.merge(
        field_hooks::revoke_customer_grants(tx, &audit, &row.entity, &row.field, revocable, actor)
            .await?,
    );
    Ok(outcome)
}

/// Deletes the field for real (design §3.2). The size gate is asked first
/// (M5). At or under it: exact counts, one transaction. Above it: no scan
/// on the request thread — the result reports the planner's estimate of the
/// values to archive, and the archive copy runs as a batched run whose final
/// step drops the column (admin: queued as `RunDataStep`, `run_id` set;
/// apply: run inline in the apply job).
pub async fn delete_field(
    state: &EngineState,
    ctx: &ChangeCtx<'_>,
    entity_id: Uuid,
    attr_id: Uuid,
    dry_run: bool,
) -> Result<FieldChangeResult, AppError> {
    let layer = change_layer(state, ctx, dry_run).await?;
    let (mut tx, row) = open(state, ctx, entity_id, attr_id, dry_run).await?;
    let mut result = FieldChangeResult::new("delete_field", &row.entity, &row.field, dry_run);
    if fc::is_system_column(&row.field) {
        return Ok(result.blocked("field_in_use"));
    }
    let (block, revocable) = delete_blockers(&mut tx, &row, layer, &mut result).await?;
    let large = fc::row_count_exceeds_in_tx(&mut tx, &row, FIELD_CHANGE_INLINE_ROW_LIMIT).await?;
    let values = if large {
        result.labels.push(LABEL_ESTIMATED);
        fc::estimate_non_null(&mut tx, &row).await?
    } else {
        Some(fc::count_non_null(&mut tx, &row).await?)
    };
    result.values_to_archive = values;
    let ring = recovery_archive::ring(state.base.config.as_ref());
    result.report.push(breaking(
        &row.entity,
        &row.field,
        json!({ "change": "removed", "note": "API integrations that use the field must change" }),
    ));
    if let Some(code) = block {
        return Ok(result.blocked(code));
    }
    // A large table's count is an estimate: without a ring it is refused
    // unless it certainly holds no value (the run would fail closed anyway).
    let may_hold_values = if large {
        values != Some(0)
    } else {
        values.unwrap_or(0) > 0
    };
    if may_hold_values && ring.is_none() {
        return Ok(result.blocked("archive_key_missing"));
    }
    if dry_run {
        return Ok(result);
    }
    if large {
        let run_id = fc::create_run_in_tx(
            &mut tx,
            fc::NewRun {
                changeset_op: ctx.op,
                apply_ref: None,
                source: ctx.source,
                entity: &row.entity,
                kind: "archive",
                // `layer`: the final step revokes customer grants only for a
                // customer-layer change (M3), so the run keeps the layer.
                spec: json!({ "field": row.field, "attribute_id": row.attribute_id,
                              "entity_id": row.entity_id,
                              "layer": layer.map(Layer::as_str) }),
                rows_estimate: values,
                created_by: Some(ctx.actor),
            },
        )
        .await?;
        if ctx.source == "admin" {
            attome_jobs::enqueue_in_tx(
                &mut tx,
                attome_core::jobs::EngineJob::RunDataStep { run_id },
            )
            .await
            .map_err(AppError::internal)?;
        }
        // A step that continues as a job records at queue time (the intent,
        // design §4.4); the run records nothing.
        record(&mut tx, ctx, Op::DeleteField, &row, &row.field, json!({})).await?;
        attome_db::tx::commit(tx).await?;
        result.run_id = Some(run_id);
        result.applied = true;
        if ctx.source != "admin" {
            run_field_run(state, run_id).await?;
        }
        return Ok(result);
    }
    fc::set_ddl_bounds_in_tx(&mut tx).await?;
    fc::lock_table_exclusive_in_tx(&mut tx, &row).await?;
    if values.unwrap_or(0) > 0 {
        let ring = ring.ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))?;
        let event = fc::archive_event(ArchiveReason::FieldDeleted, &row, ctx.op, None);
        let (archived, _) = fc::archive_values(&mut tx, ring, &event, &row, None, None).await?;
        result.archived = archived;
    }
    let outcome = remove_references(state, &mut tx, &row, &revocable, ctx.actor).await?;
    fc::drop_column_in_tx(&mut tx, &row).await?;
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    record(&mut tx, ctx, Op::DeleteField, &row, &row.field, json!({})).await?;
    attome_db::tx::commit(tx).await?;
    if result.archived > 0 {
        result.report.push(ReportItemDraft {
            kind: "field_deleted",
            entity: row.entity.clone(),
            field: Some(row.field.clone()),
            object_kind: None,
            object_ref: None,
            detail: json!({ "archived": result.archived, "attribute_id": row.attribute_id,
                            "expires_in_days": 30 }),
        });
    }
    tracing::info!(
        entity = %row.entity, field = %row.field, archived = result.archived,
        "structure change: field deleted (column dropped, values archived)"
    );
    finish(state, &mut result, outcome).await;
    Ok(result)
}

// ── change_field_type ───────────────────────────────────────────────────────

fn conversion_snapshot(conv: &fc::Conversion) -> Value {
    let mut c = json!({ "from_type": conv.from_type });
    if let Some(map) = c.as_object_mut() {
        if let Some(f) = &conv.format {
            map.insert("format".into(), json!(f));
        }
        if let Some(t) = &conv.true_values {
            map.insert("true_values".into(), json!(t));
        }
        if let Some(f) = &conv.false_values {
            map.insert("false_values".into(), json!(f));
        }
        if let Some(m) = &conv.map {
            map.insert("map".into(), json!(m));
        }
    }
    json!({ "field_type": conv.to_type, "conversion": c })
}

/// Converts the field's type in place (design §3.4, §6.4). `conv.to_type`
/// is the target; `conv.from_type`, when set by the caller, must equal the
/// live type (`type_drift` otherwise).
pub async fn change_field_type(
    state: &EngineState,
    ctx: &ChangeCtx<'_>,
    entity_id: Uuid,
    attr_id: Uuid,
    mut conv: fc::Conversion,
    dry_run: bool,
) -> Result<FieldChangeResult, AppError> {
    let (mut tx, row) = open(state, ctx, entity_id, attr_id, dry_run).await?;
    let mut result = FieldChangeResult::new("change_field_type", &row.entity, &row.field, dry_run);
    result
        .labels
        .push("runs without business rules or workflows");
    fc::refuse_system_column(&row)?;
    if !conv.from_type.is_empty() && conv.from_type != row.field_type {
        return Ok(result.blocked("type_drift"));
    }
    conv.from_type = row.field_type.clone();
    if row.is_multi() {
        return Err(AppError::Validation(
            "conversion_not_defined: a multi-valued field cannot change type".into(),
        ));
    }
    conv.check()?;
    // D-789 §8.3: every business rule on the field re-validated against the
    // new type; ours that fail block, customer ones are turned off on apply.
    let rule_scan = crate::business_rule_hooks::retype_scan(
        &mut tx,
        state,
        &row.entity,
        &row.field,
        &conv.to_type,
    )
    .await?;
    if !rule_scan.blockers.is_empty() {
        result.blockers.extend(rule_scan.blockers.iter().cloned());
        return Ok(result.blocked("field_referenced"));
    }
    // M5: the size gate first; a large table's non-convertible values are
    // counted by the run, never by a scan on the request thread.
    let large = conv.changes_values()
        && fc::row_count_exceeds_in_tx(&mut tx, &row, FIELD_CHANGE_INLINE_ROW_LIMIT).await?;
    let ring = recovery_archive::ring(state.base.config.as_ref());
    result.report.push(breaking(
        &row.entity,
        &row.field,
        json!({ "change": "type", "from": conv.from_type, "to": conv.to_type }),
    ));
    if large {
        result.labels.push(LABEL_COUNTED_BY_RUN);
        if conv.can_null() && ring.is_none() {
            return Ok(result.blocked("archive_key_missing"));
        }
    } else {
        let (count, sample) = fc::count_not_convertible(&mut tx, &row, &conv, 10).await?;
        result.not_convertible = Some(count);
        result.sample_record_ids = sample;
        if count > 0 && ring.is_none() {
            return Ok(result.blocked("archive_key_missing"));
        }
    }
    if dry_run {
        return Ok(result);
    }
    let snapshot = conversion_snapshot(&conv);
    fc::set_ddl_bounds_in_tx(&mut tx).await?;
    if large {
        let run_id = Uuid::now_v7();
        let suffix = fc::shadow_suffix(run_id);
        let run_id = fc::create_run_in_tx(
            &mut tx,
            fc::NewRun {
                changeset_op: ctx.op,
                apply_ref: None,
                source: ctx.source,
                entity: &row.entity,
                kind: "retype",
                spec: json!({ "field": row.field, "attribute_id": row.attribute_id,
                              "entity_id": row.entity_id, "suffix": suffix,
                              "conversion": conv }),
                rows_estimate: None,
                created_by: Some(ctx.actor),
            },
        )
        .await?;
        let suffix = run_suffix(&mut tx, run_id).await?;
        sqlx::query(&format!(
            "ALTER TABLE {} ALTER COLUMN {} DROP NOT NULL",
            attome_core::quote_ident(&row.entity),
            attome_core::quote_ident(&row.field)
        ))
        .execute(&mut *tx)
        .await
        .map_err(fc::map_ddl_error)?;
        fc::retype_prepare_in_tx(&mut tx, &row, &conv, &suffix).await?;
        let rule_outcome =
            crate::business_rule_hooks::retype_apply(&mut tx, &row.entity, &row.field, &rule_scan)
                .await?;
        if ctx.source == "admin" {
            attome_jobs::enqueue_in_tx(
                &mut tx,
                attome_core::jobs::EngineJob::RunDataStep { run_id },
            )
            .await
            .map_err(AppError::internal)?;
        }
        record(
            &mut tx,
            ctx,
            Op::ChangeFieldType,
            &row,
            &row.field,
            snapshot,
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        result.run_id = Some(run_id);
        finish(state, &mut result, rule_outcome).await;
        if ctx.source != "admin" {
            run_field_run(state, run_id).await?;
        }
        return Ok(result);
    }
    let event = fc::archive_event(ArchiveReason::ConversionNulled, &row, ctx.op, None);
    let nulled = fc::retype_inline_in_tx(&mut tx, ring, &event, &row, &conv).await?;
    let rule_outcome =
        crate::business_rule_hooks::retype_apply(&mut tx, &row.entity, &row.field, &rule_scan)
            .await?;
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    record(
        &mut tx,
        ctx,
        Op::ChangeFieldType,
        &row,
        &row.field,
        snapshot,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    result.nulled = nulled;
    result.archived = nulled;
    if nulled > 0 {
        result.report.push(ReportItemDraft {
            kind: "conversion_nulled",
            entity: row.entity.clone(),
            field: Some(row.field.clone()),
            object_kind: None,
            object_ref: None,
            detail: json!({ "nulled": nulled, "from": conv.from_type, "to": conv.to_type,
                            "attribute_id": row.attribute_id, "sample_record_ids": result.sample_record_ids }),
        });
    }
    finish(state, &mut result, rule_outcome).await;
    Ok(result)
}

async fn run_suffix(conn: &mut sqlx::PgConnection, run_id: Uuid) -> Result<String, AppError> {
    let spec: Value = sqlx::query_scalar("SELECT spec FROM data_step_run WHERE id = $1")
        .bind(run_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    spec.get("suffix")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("data-step run without a shadow suffix"))
}

// ── choices ─────────────────────────────────────────────────────────────────

/// The deployment's label locale when the caller names none.
pub const DEFAULT_LABEL_LOCALE: &str = "en";

fn check_choice_namespace(ctx: &ChangeCtx<'_>, value: &str) -> Result<(), AppError> {
    check_choice_namespace_for(ctx.recording.stamp()?, value)
}

fn check_choice_namespace_for(layer: Layer, value: &str) -> Result<(), AppError> {
    let ours = value.starts_with("cust_");
    if layer == Layer::Customer && !ours {
        return Err(AppError::Validation(
            "a customer-layer change adds and removes only cust_* choice values (D-787 rule 5)"
                .into(),
        ));
    }
    if layer != Layer::Customer && ours {
        return Err(AppError::Validation(
            "cust_* is the reserved customer choice namespace (D-787 rule 5)".into(),
        ));
    }
    Ok(())
}

/// Adds a choice value (design §3.5); re-adding a removed value is allowed.
#[allow(clippy::too_many_arguments)]
pub async fn add_choice(
    state: &EngineState,
    ctx: &ChangeCtx<'_>,
    entity_id: Uuid,
    attr_id: Uuid,
    value: &str,
    label: &str,
    after: Option<&str>,
    style: Option<&Value>,
    locale: &str,
) -> Result<FieldChangeResult, AppError> {
    check_choice_namespace(ctx, value)?;
    if label.is_empty() || label.chars().count() > 200 {
        return Err(AppError::Validation(
            "label must be 1..200 characters".into(),
        ));
    }
    // `args.style` of add_choice_value: `{color, icon}`, short strings only
    // (the schema closes it, so a recorded op must too).
    if let Some(style) = style {
        let ok = style.as_object().is_some_and(|m| {
            m.iter().all(|(k, v)| {
                let limit = match k.as_str() {
                    "color" => 40,
                    "icon" => 60,
                    _ => return false,
                };
                v.as_str()
                    .is_some_and(|s| !s.is_empty() && s.chars().count() <= limit)
            })
        });
        if !ok {
            return Err(AppError::Validation(
                "style must be {color?: 1..40 chars, icon?: 1..60 chars}".into(),
            ));
        }
    }
    let (mut tx, row) = open(state, ctx, entity_id, attr_id, false).await?;
    let mut result = FieldChangeResult::new("add_choice_value", &row.entity, &row.field, false);
    let changed = fc::add_choice_in_tx(&mut tx, &row, value, after, style).await?;
    let label_changed = label != value;
    if label_changed {
        let applying = Recording::Applying {
            layer: ctx.recording.stamp()?,
        };
        crate::metadata_label_admin::write_label_in_tx(
            &mut tx,
            &applying,
            "choice_option",
            &format!("{}.{}.{value}", row.entity, row.field),
            locale,
            label,
            None,
        )
        .await?;
    }
    if !changed && !label_changed {
        return Ok(result);
    }
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    let mut snapshot = json!({ "value": value, "label": label });
    if let Some(map) = snapshot.as_object_mut() {
        if let Some(a) = after {
            map.insert("after".into(), json!(a));
        }
        if let Some(s) = style {
            map.insert("style".into(), s.clone());
        }
    }
    record(&mut tx, ctx, Op::AddChoiceValue, &row, &row.field, snapshot).await?;
    attome_db::tx::commit(tx).await?;
    let caches = if label_changed {
        vec![CacheTouch::Labels]
    } else {
        vec![]
    };
    finish(
        state,
        &mut result,
        HookOutcome {
            caches,
            ..HookOutcome::default()
        },
    )
    .await;
    Ok(result)
}

/// Removes a choice value (design §3.5): stored values stay (shown empty);
/// the result counts the records that keep it.
pub async fn remove_choice(
    state: &EngineState,
    ctx: &ChangeCtx<'_>,
    entity_id: Uuid,
    attr_id: Uuid,
    value: &str,
    dry_run: bool,
) -> Result<FieldChangeResult, AppError> {
    // A dry run need not have a resolvable changeset (it writes nothing):
    // the namespace rule is checked when the layer is known.
    if let Some(layer) = change_layer(state, ctx, dry_run).await? {
        check_choice_namespace_for(layer, value)?;
    }
    let (mut tx, row) = open(state, ctx, entity_id, attr_id, dry_run).await?;
    let mut result =
        FieldChangeResult::new("remove_choice_value", &row.entity, &row.field, dry_run);
    // M5: the records that keep the value are counted only under the size
    // gate; a large table's count is left out (labelled), never scanned here.
    let in_use =
        if fc::row_count_exceeds_in_tx(&mut tx, &row, FIELD_CHANGE_INLINE_ROW_LIMIT).await? {
            result.labels.push(LABEL_NOT_COUNTED);
            None
        } else {
            Some(fc::count_choice_in_use(&mut tx, &row, value).await?)
        };
    result.records_with_value = in_use;
    let in_use = in_use.unwrap_or(0);
    if dry_run {
        return Ok(result);
    }
    let removed = fc::remove_choice_in_tx(&mut tx, &row, value).await?;
    if !removed {
        return Ok(result);
    }
    let label_ref = format!("{}.{}.{value}", row.entity, row.field);
    let locales: Vec<String> = sqlx::query_scalar(
        "UPDATE metadata_label SET is_deleted = true, row_version = row_version + 1, \
         updated_at = NOW() \
         WHERE object_kind = 'choice_option' AND object_ref = $1 AND is_deleted = false \
         RETURNING locale",
    )
    .bind(&label_ref)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for locale in &locales {
        attome_core::label_store::append_label_change_log(
            &mut tx,
            "choice_option",
            &label_ref,
            locale,
            true,
        )
        .await?;
    }
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    record(
        &mut tx,
        ctx,
        Op::RemoveChoiceValue,
        &row,
        &row.field,
        json!({ "value": value }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    if in_use > 0 {
        result.report.push(ReportItemDraft {
            kind: "choice_removed_in_use",
            entity: row.entity.clone(),
            field: Some(row.field.clone()),
            object_kind: None,
            object_ref: None,
            detail: json!({ "value": value, "records": in_use }),
        });
    }
    let caches = if locales.is_empty() {
        vec![]
    } else {
        vec![CacheTouch::Labels]
    };
    finish(
        state,
        &mut result,
        HookOutcome {
            caches,
            ..HookOutcome::default()
        },
    )
    .await;
    Ok(result)
}

// ── Batched runs (large tables) ─────────────────────────────────────────────

/// `EngineJob::RunDataStep { run_id }` — continues a large delete's
/// archive copy (then drops the column) or a large type change's backfill
/// (then swaps), from the run's cursor. Resumable; a run another worker
/// holds is left alone.
pub async fn run_field_run(state: &EngineState, run_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let worker = format!("pid-{}:{}", std::process::id(), Uuid::now_v7());
    let Some(run) = fc::claim_run(db, run_id, &worker).await? else {
        tracing::info!(%run_id, "field run: not claimable (running elsewhere or finished)");
        return Ok(());
    };
    let outcome = match run.kind.as_str() {
        "archive" => continue_delete(state, &run).await,
        "retype" => continue_retype(state, &run).await,
        "orphan_scan" => crate::admin::orphans::continue_scan(state, &run).await,
        other => Err(AppError::internal(format!(
            "field run {run_id}: kind {other} has no executor in this release"
        ))),
    };
    if let Err(error) = &outcome {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        fc::finish_run(&mut conn, run_id, Some(&error.to_string())).await?;
        tracing::error!(%run_id, kind = %run.kind, %error, "field run failed; the cursor is kept for a retry");
    }
    outcome
}

fn spec_uuid(run: &fc::RunRow, key: &str) -> Result<Uuid, AppError> {
    run.spec
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal(format!("field run {}: spec.{key} missing", run.id)))
}

fn run_op(run: &fc::RunRow) -> Option<(Uuid, i32)> {
    run.changeset_id.zip(run.op_seq)
}

async fn continue_delete(state: &EngineState, run: &fc::RunRow) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let entity_id = spec_uuid(run, "entity_id")?;
    let attr_id = spec_uuid(run, "attribute_id")?;
    let ring = recovery_archive::ring(state.base.config.as_ref());
    // The layer and actor of the change that queued the run (M3: customer
    // grants are revoked only for a customer-layer change; `None` for a run
    // queued before the run kept its layer blocks on them instead).
    let layer = run
        .spec
        .get("layer")
        .and_then(Value::as_str)
        .and_then(Layer::parse);
    let actor = run.created_by.unwrap_or(Uuid::nil());
    // Without a ring the run may only proceed when the column holds nothing;
    // asked once (bounded: stops at the first value), not per batch (M5).
    if ring.is_none() {
        let mut tx = attome_db::tx::begin(db).await?;
        let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
        let has_values = fc::has_non_null(&mut tx, &row).await?;
        attome_db::tx::commit(tx).await?;
        if has_values {
            return Err(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING));
        }
    }
    let mut cursor = run.cursor;
    // Batches, each its own transaction with the cursor.
    if let Some(ring) = ring {
        loop {
            if fc::run_stopped(db, run.id).await? {
                tracing::info!(run_id = %run.id, "field run: paused or cancelled; stopped between batches");
                return Ok(());
            }
            let mut tx = attome_db::tx::begin(db).await?;
            let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
            let event =
                fc::archive_event(ArchiveReason::FieldDeleted, &row, run_op(run), Some(run.id));
            let (n, last) = fc::archive_values(
                &mut tx,
                ring,
                &event,
                &row,
                cursor,
                Some(fc::FIELD_CHANGE_BATCH),
            )
            .await?;
            fc::advance_run(&mut tx, run.id, last, n, n, 0).await?;
            attome_db::tx::commit(tx).await?;
            cursor = last;
            if i64::try_from(n).unwrap_or(0) < fc::FIELD_CHANGE_BATCH {
                break;
            }
        }
    }
    // Final, one transaction. The catch-up scan runs under SHARE (writers
    // wait, readers do not) in bounded batches, and the run's archive rows
    // whose value is gone are pruned (L6); only then the metadata write lock
    // (a try-lock: a busy metadata writer fails this attempt, the job
    // retries), the blockers, and ACCESS EXCLUSIVE for the catalog-only drop
    // (M5).
    let mut tx = attome_db::tx::begin(db).await?;
    fc::set_ddl_bounds_in_tx(&mut tx).await?;
    let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
    fc::lock_table_share_in_tx(&mut tx, &row).await?;
    let event = fc::archive_event(ArchiveReason::FieldDeleted, &row, run_op(run), Some(run.id));
    if let Some(ring) = ring {
        fc::archive_changed_since(&mut tx, ring, &event, &row, run.created_at).await?;
    }
    fc::prune_run_archive(&mut tx, run.id, &row, &fc::delete_still_lost(&row)).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let mut blocked = FieldChangeResult::default();
    let (code, revocable) = delete_blockers(&mut tx, &row, layer, &mut blocked).await?;
    if let Some(code) = code {
        return Err(AppError::Validation(format!(
            "{code}: the field gained references while its values were archived: {}",
            blocked
                .blockers
                .iter()
                .map(|b| format!("{} {}", b.object_kind, b.name))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    fc::lock_table_exclusive_in_tx(&mut tx, &row).await?;
    let outcome = remove_references(state, &mut tx, &row, &revocable, actor).await?;
    fc::drop_column_in_tx(&mut tx, &row).await?;
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    fc::finish_run(&mut tx, run.id, None).await?;
    attome_db::tx::commit(tx).await?;
    let mut result = FieldChangeResult::new("delete_field", &row.entity, &row.field, false);
    result.run_id = Some(run.id);
    finish(state, &mut result, outcome).await;
    tracing::info!(run_id = %run.id, entity = %row.entity, field = %row.field,
        "structure change: large field delete finished (column dropped)");
    Ok(())
}

async fn continue_retype(state: &EngineState, run: &fc::RunRow) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let entity_id = spec_uuid(run, "entity_id")?;
    let attr_id = spec_uuid(run, "attribute_id")?;
    let suffix = run
        .spec
        .get("suffix")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("retype run without a shadow suffix"))?;
    let conv: fc::Conversion = run
        .spec
        .get("conversion")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::internal("retype run without a conversion"))?;
    let ring = recovery_archive::ring(state.base.config.as_ref());
    let mut cursor = run.cursor;
    loop {
        if fc::run_stopped(db, run.id).await? {
            tracing::info!(run_id = %run.id, "field run: paused or cancelled; stopped between batches");
            return Ok(());
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
        let event = fc::archive_event(
            ArchiveReason::ConversionNulled,
            &row,
            run_op(run),
            Some(run.id),
        );
        let (rows, nulled, last) =
            fc::retype_batch_in_tx(&mut tx, ring, &event, &row, &conv, &suffix, cursor).await?;
        fc::advance_run(&mut tx, run.id, last, rows, rows, nulled).await?;
        attome_db::tx::commit(tx).await?;
        cursor = last;
        if rows == 0 {
            break;
        }
    }
    // Final, one transaction: the catch-up under SHARE, then the metadata
    // write lock (a try-lock; the job retries), then ACCESS EXCLUSIVE for
    // the catalog-only swap (M5).
    let mut tx = attome_db::tx::begin(db).await?;
    fc::set_ddl_bounds_in_tx(&mut tx).await?;
    let row = fc::lock_field_in_tx(&mut tx, entity_id, attr_id).await?;
    let event = fc::archive_event(
        ArchiveReason::ConversionNulled,
        &row,
        run_op(run),
        Some(run.id),
    );
    let caught_up = fc::retype_catch_up_in_tx(&mut tx, ring, &event, &row, &suffix).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    fc::retype_swap_in_tx(&mut tx, &row, &conv, &suffix).await?;
    fc::advance_run(&mut tx, run.id, cursor, 0, 0, caught_up).await?;
    attome_core::append_change_log(
        &mut tx,
        row.entity_id,
        &row.entity,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    fc::finish_run(&mut tx, run.id, None).await?;
    attome_db::tx::commit(tx).await?;
    if row.is_sortable || row.is_filterable {
        provision::sync_attribute_index(state.base.config.as_ref(), &row.entity, &row.field, true)
            .await?;
    }
    let nulled: i64 = sqlx::query_scalar("SELECT rows_nulled FROM data_step_run WHERE id = $1")
        .bind(run.id)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    let mut result = FieldChangeResult::new("change_field_type", &row.entity, &row.field, false);
    result.run_id = Some(run.id);
    result.nulled = u64::try_from(nulled).unwrap_or(0);
    if nulled > 0 {
        result.report.push(ReportItemDraft {
            kind: "conversion_nulled",
            entity: row.entity.clone(),
            field: Some(row.field.clone()),
            object_kind: None,
            object_ref: None,
            detail: json!({ "nulled": nulled, "to": conv.to_type, "run_id": run.id,
                            "finished_at": Utc::now() }),
        });
    }
    finish(state, &mut result, HookOutcome::default()).await;
    Ok(())
}

// ── Changeset apply: the Phase 2 field ops ──────────────────────────────────

/// Plans one Phase 2 field op against live metadata (design §3.1–§3.5
/// "Apply" paragraphs): `(action, reason)` where action is
/// `update | delete | noop | blocked`. Reads only.
pub async fn plan_field_op(
    conn: &mut sqlx::PgConnection,
    op: Op,
    entity: &str,
    field: &str,
    args: Option<&Value>,
) -> Result<(String, Option<String>), AppError> {
    let arg = |k: &str| args.and_then(|a| a.get(k));
    let live = fc::resolve_field(conn, entity, field).await?;
    Ok(match op {
        Op::RenameField => {
            let new = arg("new_name").and_then(Value::as_str).unwrap_or_default();
            let target = fc::resolve_field(conn, entity, new).await?;
            match (live, target) {
                (Some(_), None) => ("update".into(), None),
                (None, Some(_)) => ("noop".into(), None),
                (Some(_), Some(_)) => (
                    "blocked".into(),
                    Some("rename_target_exists: both the old and the new name exist".into()),
                ),
                (None, None) => (
                    "blocked".into(),
                    Some("field_not_found: neither the old nor the new name exists".into()),
                ),
            }
        }
        Op::DeleteField => match live {
            Some(_) => ("delete".into(), None),
            None => ("noop".into(), None),
        },
        Op::ChangeFieldType => {
            let Some((_, attr_id)) = live else {
                return Ok(("blocked".into(), Some("field_not_found".into())));
            };
            let live_type: i32 = sqlx::query_scalar(
                "SELECT COALESCE(\"type\", 3) FROM attribute_info WHERE id = $1",
            )
            .bind(attr_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            let live_type = attome_core::FieldType::from_int(live_type)
                .unwrap_or(attome_core::FieldType::Text)
                .as_str();
            let want = arg("field_type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let from = arg("conversion")
                .and_then(|c| c.get("from_type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if live_type == want {
                ("noop".into(), None)
            } else if live_type == from {
                ("update".into(), None)
            } else {
                (
                    "blocked".into(),
                    Some(format!(
                        "type_drift: the field is {live_type} here, the changeset converts from {from}"
                    )),
                )
            }
        }
        Op::AddChoiceValue | Op::RemoveChoiceValue => {
            let Some((_, attr_id)) = live else {
                return Ok(("blocked".into(), Some("field_not_found".into())));
            };
            let options: Option<Value> =
                sqlx::query_scalar("SELECT options FROM attribute_info WHERE id = $1")
                    .bind(attr_id)
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(AppError::internal)?;
            let value = arg("value").and_then(Value::as_str).unwrap_or_default();
            let present = fc::choices_of(options.as_ref()).iter().any(|c| c == value);
            match (op, present) {
                (Op::AddChoiceValue, false) => ("update".into(), None),
                (Op::RemoveChoiceValue, true) => ("retire".into(), None),
                _ => ("noop".into(), None),
            }
        }
        _ => ("update".into(), None),
    })
}

/// Applies one Phase 2 field op through the executors above (the applier's
/// `run_op` arm). `Ok(false)` when the op was already in effect (noop).
#[allow(clippy::too_many_arguments)]
pub async fn apply_field_op(
    state: &EngineState,
    layer: Layer,
    actor: Uuid,
    changeset_op: (Uuid, i32),
    op: Op,
    entity: &str,
    field: &str,
    args: Option<&Value>,
) -> Result<bool, AppError> {
    let recording = Recording::Applying { layer };
    let ctx = ChangeCtx {
        recording: &recording,
        actor,
        op: Some(changeset_op),
        source: "apply",
    };
    let arg = |k: &str| args.and_then(|a| a.get(k));
    let mut conn = state
        .base
        .db_migrator
        .acquire()
        .await
        .map_err(AppError::internal)?;
    let (action, reason) = plan_field_op(&mut conn, op, entity, field, args).await?;
    if action == "noop" {
        return Ok(false);
    }
    if action == "blocked" {
        return Err(AppError::Validation(
            reason.unwrap_or_else(|| "blocked".into()),
        ));
    }
    let Some((entity_id, attr_id)) = fc::resolve_field(&mut conn, entity, field).await? else {
        return Ok(false);
    };
    drop(conn);
    let result = match op {
        Op::RenameField => {
            let new = arg("new_name").and_then(Value::as_str).unwrap_or_default();
            rename_field(state, &ctx, entity_id, attr_id, new, false).await?
        }
        Op::DeleteField => delete_field(state, &ctx, entity_id, attr_id, false).await?,
        Op::ChangeFieldType => {
            let mut conv: fc::Conversion = arg("conversion")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| AppError::Validation(format!("args.conversion: {e}")))?
                .unwrap_or_default();
            conv.to_type = arg("field_type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            change_field_type(state, &ctx, entity_id, attr_id, conv, false).await?
        }
        Op::AddChoiceValue => {
            let value = arg("value").and_then(Value::as_str).unwrap_or_default();
            let label = arg("label").and_then(Value::as_str).unwrap_or(value);
            add_choice(
                state,
                &ctx,
                entity_id,
                attr_id,
                value,
                label,
                arg("after").and_then(Value::as_str),
                arg("style"),
                DEFAULT_LABEL_LOCALE,
            )
            .await?
        }
        Op::RemoveChoiceValue => {
            let value = arg("value").and_then(Value::as_str).unwrap_or_default();
            remove_choice(state, &ctx, entity_id, attr_id, value, false).await?
        }
        other => {
            return Err(AppError::internal(format!(
                "apply_field_op: {} is not a field op",
                other.as_str()
            )));
        }
    };
    if let Some(code) = result.error {
        return Err(AppError::Validation(format!(
            "{code}: {}",
            result
                .blockers
                .iter()
                .map(|b| format!("{} {} ({})", b.object_kind, b.name, b.reason))
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    Ok(result.applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_after_commit_step_is_retried_once_then_reported() {
        // Security review M4: a transient failure converges on the retry...
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let outcome = with_retry(|| {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err("down".to_owned())
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(outcome, Ok(()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        // ...and a persistent one is returned (then logged and labelled),
        // never swallowed.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let outcome = with_retry(|| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err("still down".to_owned()) }
        })
        .await;
        assert_eq!(outcome, Err("still down".to_owned()));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            AFTER_COMMIT_ATTEMPTS
        );
    }

    #[test]
    fn a_customer_change_touches_only_the_customer_choice_namespace() {
        assert!(check_choice_namespace_for(Layer::Customer, "cust_gold").is_ok());
        assert!(check_choice_namespace_for(Layer::Customer, "gold").is_err());
        assert!(check_choice_namespace_for(Layer::Project, "cust_gold").is_err());
        assert!(check_choice_namespace_for(Layer::Platform, "gold").is_ok());
    }
}
