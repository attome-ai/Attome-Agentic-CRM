//! Shared transaction-scoped entity mutation primitives.
//!
//! Interactive CRUD, bulk processing, and staged imports all use this module
//! for the actual entity-table mutation.  The caller owns the transaction and
//! the audit event; this module owns validation, concurrency, lookup/hierarchy
//! guards, and delete policy so those invariants cannot drift between routes.
//!
//! `pub` (not `pub(crate)`) so `attome-workflow`'s Create/Update Record node
//! types reuse this exact path (guidelines §9: reuse established mutation
//! primitives, don't bypass with route-local SQL) instead of duplicating
//! validation/lookup/hierarchy logic — see P-workflow-engine.md §4.4
//! mechanism 1. `attome-workflow` depends on this crate for that reuse; the
//! reverse edge (`attome-server`'s own `[dev-dependencies]` on `attome-workflow`,
//! for the full-system license-gating test) is dev-only, so this is not a
//! real dependency cycle.

use std::collections::{HashMap, HashSet};

use attome_core::{AttrInfo, EngineState, OnTargetDelete, quote_ident};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

/// The two non-strict modes each relax exactly one narrow, named check —
/// never bundled, because each exists for an unrelated reason and widening
/// one to cover the other's use case would be a real, silent authorization
/// change for whichever mode picked up the extra slack.
///
/// `ApprovedStagedImport` is used by an explicitly approved staged import. It
/// is deliberately not exposed by the normal bulk request contract, and skips
/// lookup-liveness only — hierarchy locking/cycle guards and the file-session
/// check always run, same as the interactive path. Lookup-liveness and
/// hierarchy-cycle protection are independently toggleable for the same
/// reason: staged import exists specifically for legacy data with **dangling
/// lookup references**, which has nothing to do with hierarchy integrity.
///
/// `MirroredFileWrite` is used by exactly one caller:
/// `entity_crud/mutations.rs::sync_file_field_documents`, the generic
/// file-field-to-`attome_document` mirror (D-36x). It skips
/// `lock_file_field_sessions` only — the file key being written already
/// passed that same check once, against the upload session scoped to the
/// *source* field it's mirroring (a different entity/record/field triple
/// than the `attome_document` row being written here), so re-checking it against
/// this row's own triple would reject a value that already earned its
/// authorization, not catch a forged one. Lookup-liveness stays enforced
/// (irrelevant in practice today — `attome_document` declares no `lookup`-typed
/// attributes — but left on rather than silently widened for a future field
/// that adds one).
///
/// `BundleRecordSet` is used by exactly one caller:
/// `bundle::record_sets`'s apply step for a Phase 3 record set
/// (P-environment-promotion §5 step 24). It skips `lock_file_field_sessions`
/// only, same narrow reasoning as `MirroredFileWrite`: a record set has no
/// interactive upload session to check a file-typed field's key against — the
/// whole point of the bundle engine is that nothing here is interactive, so
/// the check has nothing meaningful to verify. Lookup-liveness stays
/// enforced: a record set that names a dangling lookup target should fail,
/// not silently write garbage — the opposite of the legacy-data exemption
/// `ApprovedStagedImport` grants, so this is its own named mode rather than
/// reusing either existing one.
///
/// Its payload (D-374 amendment, bundle-derived ids) is the deterministic id
/// [`create_one`] should bind explicitly for a brand-new row instead of
/// leaving `id` to the table's column default — `record_sets::apply_record`
/// supplies `Some(derived_id)` only on its create path; every other caller
/// (including `update_one` calls under this same mode, which never touch
/// `id`) passes `None`.
///
/// `ApprovalFlow(request_id)` (M07 Phase F, D-770) is the one way a record
/// leaves a transition's `pending_state`: the approval executor (to the
/// target), a rejection (to `on_reject_state`) and a cancel or release (to
/// the origin), all in `attome_state::approval`. It replaces the state graph
/// check for that one move with a check against the request itself, read in
/// the write's own transaction: the request must be the latest
/// `state.transition` request regarding this record, the record must be in
/// the request's `pending_state`, the write may name only the state field,
/// and the target must be the one the request's status allows
/// (`executing` -> `to`, `rejected` -> `on_reject_state`,
/// `cancelled`/`expired`/`invalidated` -> `from`). Anything else is refused,
/// so holding the mode grants nothing a closed request did not decide.
/// Lookup-liveness stays on; file sessions are skipped (the write names no
/// file field).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationMode {
    Strict,
    ApprovedStagedImport,
    MirroredFileWrite,
    BundleRecordSet(Option<Uuid>),
    ApprovalFlow(Uuid),
}

impl MutationMode {
    fn enforce_lookup_liveness(&self) -> bool {
        matches!(
            self,
            Self::Strict
                | Self::MirroredFileWrite
                | Self::BundleRecordSet(_)
                | Self::ApprovalFlow(_)
        )
    }

    fn enforce_file_session_ownership(&self) -> bool {
        matches!(self, Self::Strict | Self::ApprovedStagedImport)
    }
}

/// Result of one mutation, used by callers to construct their own audit event
/// and, for interactive writes, the response body.
pub struct MutationResult {
    pub record_id: Uuid,
    pub old_row: Option<Value>,
    pub new_row: Option<Value>,
    pub cascade_summary: Vec<String>,
    /// M07 Phase F (D-770): `Some` when this update asked for a transition
    /// that carries an approval plan — the record went to the transition's
    /// `pending_state` instead of the requested state, and this request was
    /// submitted in the same transaction. `None` for every other write.
    pub approval: Option<ApprovalSubmitted>,
    /// D-791 rule 6: the `warning`-severity business-rule `error` policies
    /// that fired on this (successful) write, in rule display order. The
    /// generic write responses return them; empty for every write without
    /// one.
    pub warnings: Vec<crate::business_rules::RuleWarning>,
}

impl std::fmt::Debug for MutationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationResult").finish_non_exhaustive()
    }
}

/// The approval request an update submitted instead of performing the
/// transition it asked for (M07 Phase F).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalSubmitted {
    pub request_id: Uuid,
    /// The origin state.
    pub from: String,
    /// The state the write asked for, reached only once the request is
    /// approved.
    pub requested: String,
    /// The state the record now sits in.
    pub pending_state: String,
}

/// D-078 (F004): multi-select Choice values are bound as PostgreSQL array
/// literals and need an explicit text-array cast. C-16 (M01 §7): the
/// int<->[`attome_core::FieldType`] and cast maps themselves live once on
/// the type; this is just the `&AttrInfo` adapter every caller here already
/// has in hand.
pub fn sql_cast(attr: &AttrInfo) -> &'static str {
    // Storage type (U9): a formula binds as its result type, rich text as
    // text, an image as a file key.
    let ft = attr.storage_type();
    ft.sql_cast(ft.is_multi_valued(attr.options.as_ref().unwrap_or(&Value::Null)))
}

/// `options.multi` (`attome_field::ChoiceOptions`/`FileOptions`) — shared by
/// `choice` (`TEXT[]`) and `file` (`JSONB`); which physical type it picks is
/// `sql_cast`'s job, this only reads the one flag both options structs carry.
///
/// `pub(crate)` (not module-private) so `entity_crud/mutations.rs::hard_delete_record`
/// can reuse the same single/multi distinction when walking a deleted row's
/// file-typed columns for storage cleanup — one flag read, not a second copy.
pub(crate) fn is_multi_valued(attr: &AttrInfo) -> bool {
    let ft = attr.storage_type();
    attr.options.as_ref().is_some_and(|o| ft.is_multi_valued(o))
}

/// A3-T2: the body with each value normalised for its field
/// ([`attome_field::normalize`]: trimmed text, E.164-shaped phones,
/// lower-case emails, Western digits where a field expects them), or `None`
/// when nothing changes. Unknown fields are left for [`validate_body`].
pub fn normalize_body(
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Option<serde_json::Map<String, Value>> {
    let mut out: Option<serde_json::Map<String, Value>> = None;
    for attr in attrs {
        let Some(value) = obj.get(&attr.logicalname) else {
            continue;
        };
        let field_type = attome_core::FieldType::from_int(attr.field_type_int)
            .unwrap_or(attome_core::FieldType::Text);
        if let Some(normal) = attome_field::normalize(&field_type, value, attr.options.as_ref()) {
            out.get_or_insert_with(|| obj.clone())
                .insert(attr.logicalname.clone(), normal);
        }
    }
    out
}

use attome_core::defaults_scope::defaults_skipped;
/// A28-T3: see [`attome_core::defaults_scope`].
pub use attome_core::defaults_scope::with_defaults;

/// A28-T1: the body with each empty attribute that declares a default
/// (`options.default`) filled, or `None` when nothing changes. A default is
/// `{"kind": "fixed", "value": ...}`, `{"kind": "today"}` (the deployment's
/// local date), `{"kind": "now"}` or `{"kind": "current_user"}` (the creating
/// person's id, for a lookup to `user_account`). A value the caller sent,
/// even `false` or `0`, is never replaced; `null` and `""` are empty.
pub fn apply_defaults(
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    actor: Option<uuid::Uuid>,
    now: chrono::DateTime<chrono::FixedOffset>,
) -> Option<serde_json::Map<String, Value>> {
    let mut out: Option<serde_json::Map<String, Value>> = None;
    for attr in attrs {
        let Some(default) = attr.options.as_ref().and_then(|o| o.get("default")) else {
            continue;
        };
        let empty = match obj.get(&attr.logicalname) {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => s.is_empty(),
            Some(_) => false,
        };
        if !empty {
            continue;
        }
        let value = match default.get("kind").and_then(Value::as_str) {
            Some("fixed") => default.get("value").cloned(),
            Some("today") => Some(Value::String(now.date_naive().to_string())),
            Some("now") => Some(Value::String(now.to_rfc3339())),
            Some("current_user") => actor.map(|id| Value::String(id.to_string())),
            _ => None,
        };
        if let Some(value) = value.filter(|v| !v.is_null()) {
            out.get_or_insert_with(|| obj.clone())
                .insert(attr.logicalname.clone(), value);
        }
    }
    out
}

/// Runs semantic and schema validation before any SQL is built, and answers
/// with every failing field at once (A3-T1): one `FieldValidation` 422 whose
/// `details` names each field, its `code` (`unknown_field`, `required`,
/// `invalid`, `too_long`) and the message.
///
/// `pub` (not `pub(crate)`) — R-07 (`document/module-master-plans/
/// M26-dashboard-remediation.md`): `attome-dashboard`'s `layout.rs` writes its
/// page/section/breakpoint/widget tree with bound SQL directly (Tier 2 —
/// the tree materialization must stay inside one transaction under the
/// dashboard advisory lock, so it cannot route each node through
/// `create_one`/`update_one`'s own transaction-per-call shape) but still
/// wants generic CRUD's own validator so a hand-built row can never disagree
/// with what `create_record`/`update_record` would have accepted for the
/// same entity. `attome-workflow`'s Create/Update Record nodes already justify
/// this module being `pub`; this is the same reuse rule (guidelines §9)
/// applied to a second, narrower caller.
pub fn validate_body(
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    require_all: bool,
) -> Result<(), AppError> {
    let known: HashSet<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
    let mut failures = Vec::new();
    let mut fail = |field: &str, code: &str, message: String| {
        failures.push(attome_types::types::FieldError {
            field: field.to_owned(),
            code: code.to_owned(),
            message,
        });
    };
    for name in obj.keys().filter(|name| !known.contains(name.as_str())) {
        fail(name, "unknown_field", format!("{name}: unknown field"));
    }

    for attr in attrs {
        let name = attr.logicalname.as_str();
        let value = obj.get(name);
        if attr.is_required
            && (value.is_some_and(Value::is_null) || (require_all && value.is_none()))
        {
            fail(name, "required", format!("{name}: field is required"));
            continue;
        }
        let Some(val) = value.filter(|v| !v.is_null()) else {
            continue;
        };
        match attome_field::validate(
            &attome_core::FieldType::from_int(attr.field_type_int)
                .unwrap_or(attome_core::FieldType::Text),
            val,
            attr.options.as_ref(),
        ) {
            Ok(()) => {}
            Err(AppError::Validation(msg)) => fail(name, "invalid", format!("{name}: {msg}")),
            Err(other) => return Err(other),
        }
        if let (Some(max), Some(text)) = (attr.max_length, val.as_str())
            && text.chars().count() > max as usize
        {
            fail(
                name,
                "too_long",
                format!("{name}: length must not exceed {max}"),
            );
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::FieldValidation(failures))
    }
}

/// P-field-write-security (D-141, widened by D-507): rejects the whole
/// mutation if the payload sets any field whose
/// [`AttrInfo::requires_field_write_grant`] is true — `is_sensitive` or
/// `is_write_restricted` — and the caller holds no `can_update` grant for it.
/// Called right after `validate_body` (so an unknown-field/type error still
/// wins) and before any SQL is built, from every mutation entry point —
/// interactive create/update, bulk, staged import, and upsert — so the check
/// cannot be bypassed by routing through a different path into the same
/// table. Rejects the entire request rather than silently dropping the
/// offending field: a caller who submits a value and gets a 200 back with
/// that field quietly unchanged is a worse outcome than an explicit 403 —
/// the same "no silent partial application" posture `merge_records`'
/// dependent-redirect authorization (D-139) already applies. A non-sensitive
/// field is never gated by this check, matching `has_field_read_grant`'s
/// call sites' existing convention (F013/F135, D-111).
/// Who is writing through the shared mutation primitives (D-576 item 5).
///
/// `Staff` is every existing caller, unchanged: the `create_one`/`update_one`
/// /`delete_one` signatures still take a `SecurityContext` and wrap the `_as`
/// functions with `Principal::Staff`. `Portal` is a web portal user acting
/// under an [`AccessPlan`](crate::access_plan::AccessPlan): there is no
/// `SecurityContext` anywhere on that path, and none is ever built for it.
/// The three places the engine consults the writer differ as follows:
///
/// - **Field writes.** Staff: the D-111/D-141/D-507 grants on sensitive and
///   write-restricted fields. Portal: *every* written field must be on the
///   plan's writable allowlist (D-575, default-deny).
/// - **File fields.** Staff: upload-session ownership. Portal: refused outright
///   (no portal file writes until a portal file route exists).
/// - **State transitions.** Staff: `required_privilege` against its grants.
///   Portal: holds no privilege, so a privileged transition is refused.
#[derive(Clone, Copy)]
pub enum Principal<'a> {
    Staff(&'a SecurityContext),
    Portal(&'a crate::access_plan::AccessPlan),
}

impl std::fmt::Debug for Principal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal").finish_non_exhaustive()
    }
}

impl Principal<'_> {
    /// Whether the writer holds `privilege` (state-model transitions).
    fn holds(&self, privilege: &str) -> bool {
        match self {
            Principal::Staff(ctx) => ctx.is_admin || ctx.privileges.contains(privilege),
            Principal::Portal(_) => false,
        }
    }
}

/// The system columns a created row is stamped with. A staff create stamps
/// the creator (D-137); a portal create stamps **no** staff id: `created_by`
/// and `modified_by` stay NULL and the owner is the portal's owning team
/// (D-579), so a portal user's id can never be read as a staff user's.
#[derive(Clone, Copy, Debug)]
pub struct CreateStamp {
    pub created_by: Option<Uuid>,
    pub org_ref: Uuid,
    pub owner_ref: Uuid,
    /// 0 = user, 1 = team (the `record_share` principal convention).
    pub owner_type: i16,
}

impl CreateStamp {
    pub fn staff(user_id: Uuid, org_ref: Uuid) -> Self {
        Self {
            created_by: Some(user_id),
            org_ref,
            owner_ref: user_id,
            owner_type: 0,
        }
    }
}

fn validate_principal_field_writes(
    principal: Principal<'_>,
    entity_name: &str,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    match principal {
        Principal::Staff(ctx) => validate_field_write_grants(ctx, entity_name, attrs, obj),
        Principal::Portal(plan) => {
            // Every written field must be allowlisted, except the engine's own
            // stamp of the portal user field (`access_plan::plan_create`).
            if obj
                .iter()
                .any(|(key, value)| !plan.writable.contains(key) && !plan.is_own_stamp(key, value))
            {
                return Err(AppError::Forbidden);
            }
            Ok(())
        }
    }
}

/// Who owns an upload session or a file version (D-774): exactly one of a staff
/// user or a portal user, as the tables' one-owner `CHECK` enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOwner {
    Staff(Uuid),
    Portal(Uuid),
}

impl FileOwner {
    /// From a row's `(staff, portal)` owner columns.
    pub fn from_columns(staff: Option<Uuid>, portal: Option<Uuid>) -> Result<Self, AppError> {
        match (staff, portal) {
            (Some(id), None) => Ok(Self::Staff(id)),
            (None, Some(id)) => Ok(Self::Portal(id)),
            _ => Err(AppError::internal(
                "a file row has both or neither owner (the one-owner check was bypassed)",
            )),
        }
    }

    /// The `(staff, portal)` owner columns for this owner.
    pub fn columns(self) -> (Option<Uuid>, Option<Uuid>) {
        match self {
            Self::Staff(id) => (Some(id), None),
            Self::Portal(id) => (None, Some(id)),
        }
    }
}

/// Who is writing a file field, for [`lock_file_field_sessions`].
#[derive(Clone, Copy)]
pub(crate) enum FileWriter {
    /// A staff user, and whether they may use anyone's session (an admin).
    Staff { user_id: Uuid, is_admin: bool },
    /// A portal user, who may use only their own sessions.
    Portal(Uuid),
}

async fn lock_file_fields_for(
    tx: &mut Transaction<'_, Postgres>,
    principal: Principal<'_>,
    entity_name: &str,
    record_id: Option<Uuid>,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    mode: MutationMode,
) -> Result<(), AppError> {
    match principal {
        Principal::Staff(ctx) => {
            if mode.enforce_file_session_ownership() {
                let writer = FileWriter::Staff {
                    user_id: ctx.user_id,
                    is_admin: ctx.is_admin,
                };
                lock_file_field_sessions(tx, writer, entity_name, record_id, attrs, obj).await?;
            }
            Ok(())
        }
        // D-774: a portal write that names a file must name a clean session
        // the portal user owns, in every mode (a portal only writes Strict).
        // Whether the field is writable at all is the plan's check, before
        // this.
        Principal::Portal(plan) => {
            let writer = FileWriter::Portal(plan.portal_user_id);
            lock_file_field_sessions(tx, writer, entity_name, record_id, attrs, obj).await
        }
    }
}

pub(crate) fn validate_field_write_grants(
    ctx: &SecurityContext,
    entity_name: &str,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let denied = attrs.iter().any(|attr| {
        attr.requires_field_write_grant()
            && obj.contains_key(&attr.logicalname)
            && !ctx.has_field_write_grant(entity_name, &attr.logicalname)
    });
    if denied {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// R-03 (`document/module-master-plans/M26-dashboard-remediation.md`) —
/// rejects a `MutationMode::Strict` write that tries to set a field a model
/// declared via `EngineModel::engine_managed_fields` (frozen into
/// `state.engine_managed_fields` at boot, D-383's declare/collect/enforce
/// shape — see `attome_core::model::EngineModel::engine_managed_fields`'s own
/// doc comment). Those fields are ordinary Choice/Text attributes as far as
/// `validate_body` is concerned — it has no way to know one of them is
/// actually a state machine's field, guarded by a bespoke route's advisory
/// lock, D-195 four-eyes gate, ledger row and audit event that a plain
/// generic-CRUD write would silently skip (e.g.
/// `attome_dashboard.lifecycle_status` / `lifecycle.rs::do_publish_dashboard`,
/// `dashboard_decision.status` / `decision.rs::do_approve`).
///
/// **Update-time half only.** Creation is covered by
/// [`apply_engine_managed_initial_values`] (D-524), which cannot simply reuse
/// this rejection: `dashboard_decision.status` is a *required* attribute
/// with no bespoke create route, so refusing the field outright on create
/// would make such a record impossible to create. The create-time rule
/// instead allows exactly the owning engine's declared initial value and
/// writes it when the field is omitted, on every mutation mode.
pub(crate) fn validate_engine_managed_fields(
    state: &EngineState,
    entity_name: &str,
    obj: &serde_json::Map<String, Value>,
    mode: MutationMode,
) -> Result<(), AppError> {
    if mode != MutationMode::Strict {
        return Ok(());
    }
    for key in obj.keys() {
        if state
            .engine_managed_fields
            .contains(&(entity_name.to_owned(), key.clone()))
        {
            return Err(AppError::Validation(format!(
                "'{key}' is managed by the {entity_name} engine; use its lifecycle routes"
            )));
        }
    }
    Ok(())
}

/// Entities whose rows are addressed to one user, and the lookup field that
/// names that user (basic-units plan U4, D-602). A non-admin may only create
/// or retarget such a row **for themselves**: a reminder is set by its own
/// recipient, and only an administrator may set one for somebody else.
///
/// Enforced here, in the shared create/update primitives, so the generic API,
/// bulk, upsert and every other mutation path apply it alike. A portal
/// principal never writes these rows.
pub const SELF_ADDRESSED_ENTITIES: &[(&str, &str)] = &[("reminder", "user_ref")];

/// The [`SELF_ADDRESSED_ENTITIES`] rule for one write. `is_create` also
/// requires the field to be present: a create that names no recipient is
/// refused rather than left for the required-field check to explain.
pub(crate) fn validate_self_addressed(
    principal: Principal<'_>,
    entity_name: &str,
    obj: &serde_json::Map<String, Value>,
    is_create: bool,
) -> Result<(), AppError> {
    let Some((_, field)) = SELF_ADDRESSED_ENTITIES
        .iter()
        .find(|(entity, _)| *entity == entity_name)
    else {
        return Ok(());
    };
    let ctx = match principal {
        Principal::Staff(ctx) => ctx,
        Principal::Portal(_) => return Err(AppError::Forbidden),
    };
    if ctx.is_admin {
        return Ok(());
    }
    let named = match obj.get(*field) {
        None if !is_create => return Ok(()),
        None | Some(Value::Null) => None,
        Some(value) => value.as_str().and_then(|s| Uuid::parse_str(s.trim()).ok()),
    };
    match named {
        Some(user) if user == ctx.user_id => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

/// Dashboard 10/10 Phase 2.1 — runs every validator a model declared for
/// `entity_name` (`EngineModel::record_validators`) over the submitted body, on
/// every mutation mode. A no-op for an entity with none.
pub fn validate_model_record_validators(
    state: &EngineState,
    entity_name: &str,
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let Some(validators) = state.record_validators.get(entity_name) else {
        return Ok(());
    };
    let registry = state.entities.load();
    for validator in validators {
        validator(obj, &registry).map_err(AppError::Validation)?;
    }
    Ok(())
}

/// D-535: refuses a generic write that would create, change or restore a
/// record of an entity a model declared through
/// `EngineModel::engine_owned_entities` (frozen into
/// `state.engine_owned_entities`). Today that is `api_key`, which only
/// `POST /api/v1/auth/api-keys` may mint, behind D-510's step-up guard.
///
/// Unlike [`validate_engine_managed_fields`], it ignores the caller and the
/// mutation mode. No admin, workflow, bundle, bulk, import, merge or migration
/// context may mint the credential around the owning route. Generic delete is
/// not checked: it only removes access.
pub fn validate_engine_owned_entity(
    state: &EngineState,
    entity_name: &str,
) -> Result<(), AppError> {
    if state.engine_owned_entities.contains(entity_name) {
        return Err(AppError::Validation(format!(
            "{entity_name} records are managed by their owning engine; use its routes"
        )));
    }
    Ok(())
}

/// The physical system columns no request body may ever bind, on any mutation
/// path. One list, shared by `build_insert_binds` and `build_update_binds`
/// (SEC-1): a column that create refuses to take from the caller must not be
/// writable through update either, or the exclusion is decorative — an
/// ordinary `{entity}.update` holder could `PATCH` `organization_ref` to move
/// a record across the RLS boundary `attome_security::rls` reads it for, `PATCH`
/// `owner_ref`/`owner_type` to reassign ownership around the admin-gated
/// `reassign-owner` endpoint, `PATCH` `created_by`/`created_at` to forge audit
/// attribution, or `PATCH` `is_active` to soft-delete without the delete
/// path's audit event and dependent-cascade policy. That is exactly the
/// "do not trust a client-supplied user, organization, privilege, role,
/// license, or ownership value" rule in coding-guidelines §7.
///
/// The list itself is `attome_core::ALL_SYSTEM_COLS` — the same constant
/// `select_columns` builds its projection from, i.e. the full
/// `provision::table` `CREATE TABLE` system-column shape (D-005). Deliberately
/// not a second hand-maintained copy: a system column added to the table shape
/// and forgotten here is precisely how the update path drifted open in the
/// first place, so the two are the same list by construction.
///
/// Each column, and why the body cannot own it:
///
/// - `created_by`, `modified_by`, `organization_ref`, `owner_ref`, `owner_type`
///   are spliced into every insert by `create_one` from the authenticated
///   caller's context (D-137 for the owner pair). Emitting them from the body
///   as well would also name them twice in the INSERT column list — Postgres
///   42701, surfacing to the client as a bare 500. `organization_ref` is the
///   live case: it is a real metadata attribute on `user_account`, so
///   every metadata-driven form posts it back and every such create failed.
/// - `modified_at`, `modified_by` and `row_version` are likewise spliced into
///   every UPDATE by `update_one`/`merge_records`
///   (`SET {sets}, row_version = row_version + 1, modified_at = NOW(),
///   modified_by = $2`), so a body-supplied value produced the same 42701/500
///   there. That accident was the *only* thing protecting those three on the
///   update path; the other columns had nothing.
/// - `id` is the primary key the `WHERE id = $1` selector matched on. A body
///   that rewrites it repoints every dependent lookup at a row that no longer
///   exists under that id.
/// - `created_at` has a `DEFAULT NOW()` and is audit provenance, not a field.
/// - `is_active` is the platform's soft-delete flag (D-021), not an ordinary
///   field, and it is the one column whose value decides whether the row is
///   visible to every later read: `get_record`, `update_record`,
///   `delete_record`, and `require_record_access` all filter
///   `is_active = true`. On insert the only two things a client value can
///   express are "live" (already the column's `DEFAULT TRUE`) and "born
///   deleted", which is not a state generic create may produce; deletion has
///   its own endpoint, its own audit event, and its own dependent-cascade
///   policy, and restore has `restore_record`.
///
///   `NULL` is the case that actually bit: a JSON `null` binds as SQL NULL,
///   which *overrides* the column default, and NULL never matches
///   `is_active = true`. The record was created dead on arrival — invisible to
///   GET, un-PATCHable, un-DELETEable, and not even restorable (`restore_record`
///   matches `is_active IS NOT TRUE` now precisely so the rows already written
///   this way can be recovered). Any metadata-driven form posts exactly that:
///   a form control the user never touched submits `null`, and `is_active` is a
///   registered attribute on `user_account`, so every user created
///   through the generic form 404'd the moment it was saved.
///
/// Skipping — rather than rejecting the whole request — is what both builders
/// already did for the insert five, and it is what keeps a metadata-driven
/// form working: the form posts the whole row back, system columns included,
/// and has no way to know which of its own registered attributes the engine
/// owns. It is also the only option that is safe for both table shapes:
/// append-only entities have no `is_active` column at all (`provision::table`
/// deliberately omits it), so naming it in a statement would be a 42703
/// undefined-column error, while a mutable registered entity always has the
/// column *and* `DEFAULT TRUE` (`provision::table`'s
/// `ALTER COLUMN is_active SET DEFAULT TRUE` backfill guarantees it, including
/// on the legacy `*` bootstrap tables whose original DDL had no
/// default).
///
/// A caller that submits *only* system columns gets the builders' existing
/// "no recognised fields" validation error, not a silent no-op write.
pub(crate) fn is_system_managed_column(logicalname: &str) -> bool {
    attome_core::ALL_SYSTEM_COLS.contains(&logicalname)
}

pub(crate) fn build_insert_binds(
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    start_param: usize,
) -> (Vec<String>, Vec<String>, Vec<Option<String>>) {
    let mut cols = Vec::new();
    let mut placeholders = Vec::new();
    let mut values = Vec::new();
    let mut p = start_param;

    for attr in attrs {
        if is_system_managed_column(&attr.logicalname) {
            continue;
        }
        if let Some(val) = obj.get(&attr.logicalname) {
            cols.push(quote_ident(&attr.logicalname));
            placeholders.push(format!("${p}{}", sql_cast(attr)));
            values.push(json_to_str(val, attr));
            p += 1;
        }
    }
    (cols, placeholders, values)
}

pub(crate) fn build_update_binds(
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    start_param: usize,
) -> (Vec<String>, Vec<Option<String>>) {
    let mut set_parts = Vec::new();
    let mut values = Vec::new();
    let mut p = start_param;

    for attr in attrs {
        // SEC-1 — the same exclusion `build_insert_binds` applies, for the
        // same reasons. See `is_system_managed_column`.
        if is_system_managed_column(&attr.logicalname) {
            continue;
        }
        if let Some(val) = obj.get(&attr.logicalname) {
            set_parts.push(format!(
                "{} = ${p}{}",
                quote_ident(&attr.logicalname),
                sql_cast(attr)
            ));
            values.push(json_to_str(val, attr));
            p += 1;
        }
    }
    (set_parts, values)
}

/// `Value::Array` serializes two different ways depending which physical
/// type `sql_cast(attr)` picked for this attribute: a multi-choice `TEXT[]`
/// column needs a Postgres array literal (`{"a","b"}`); a multi-file `JSONB`
/// column needs actual JSON syntax (`["a","b"]`) — the two are not
/// interchangeable, so which one runs is driven by the same `options.multi`
/// read `sql_cast` already made, not re-derived from the value's shape.
pub fn json_to_str(v: &Value, attr: &AttrInfo) -> Option<String> {
    match v {
        Value::Null => None,
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.to_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Array(_) if attr.is_file_backed() && is_multi_valued(attr) => Some(v.to_string()),
        Value::Array(items) => Some(pg_text_array_literal(items)),
        other => Some(other.to_string()),
    }
}

fn pg_text_array_literal(items: &[Value]) -> String {
    let mut out = String::from("{");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let s = match item {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push('"');
        for c in s.chars() {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
    }
    out.push('}');
    out
}

/// Read-time preflight used by interactive handlers and staged-import review.
/// The mutation entry points repeat the decisive check under the writer
/// transaction through `lock_lookup_targets`.
pub(crate) async fn validate_lookup_targets(
    state: &EngineState,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let registry = state.entities.load();
    let mut by_target: HashMap<Uuid, Vec<(String, Uuid)>> = HashMap::new();
    for attr in attrs {
        if attr.field_type_int != 11 {
            continue;
        }
        let Some(target_id) = attr.lookup_entity_ref else {
            continue;
        };
        let Some(val) = obj.get(&attr.logicalname) else {
            continue;
        };
        if val.is_null() {
            continue;
        }
        let Some(record_id) = val.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
            continue;
        };
        by_target
            .entry(target_id)
            .or_default()
            .push((attr.logicalname.clone(), record_id));
    }
    if by_target.is_empty() {
        return Ok(());
    }

    let mut queries = Vec::new();
    for (target_id, fields) in by_target {
        let Some(target_meta) = registry.get_by_id(target_id) else {
            let field = fields.first().map(|(f, _)| f.clone()).unwrap_or_default();
            return Err(AppError::Validation(format!(
                "{field}: lookup target does not exist or is deleted"
            )));
        };
        queries.push((target_meta.logicalname.clone(), fields));
    }
    drop(registry);

    for (target_logicalname, fields) in queries {
        let target_table = quote_ident(&target_logicalname);
        let ids: Vec<Uuid> = fields.iter().map(|(_, id)| *id).collect();
        let live_ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {target_table} WHERE id = ANY($1) AND (is_active IS NULL OR is_active = TRUE)"
        ))
        .bind(&ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let live: HashSet<Uuid> = live_ids.into_iter().collect();
        for (field, id) in fields {
            if !live.contains(&id) {
                return Err(AppError::Validation(format!(
                    "{field}: lookup target does not exist or is deleted"
                )));
            }
        }
    }
    Ok(())
}

/// Final lookup liveness check and parent lock inside the writer transaction.
///
/// P-lookup-lock-batching: this used to issue one `SELECT ... FOR KEY SHARE`
/// per lookup *field*, so a record with N lookups (a common CRM shape —
/// owner/account/contact/campaign/parent) took N sequential round trips while
/// already holding row locks from earlier in the same transaction. Grouped
/// by target table the same way the read-time `validate_lookup_targets`
/// preflight above already does: one `WHERE id = ANY($1) ... FOR KEY SHARE`
/// per *distinct target entity* referenced by this write, not per field —
/// two lookups pointing at the same target table (e.g. two contact fields)
/// now lock in a single round trip instead of two.
pub(crate) async fn lock_lookup_targets(
    tx: &mut PgConnection,
    state: &EngineState,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let mut by_target: HashMap<Uuid, Vec<(String, Uuid)>> = HashMap::new();
    for attr in attrs.iter().filter(|a| a.field_type_int == 11) {
        let Some(value) = obj.get(&attr.logicalname) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let Some(target_entity_id) = attr.lookup_entity_ref else {
            return Err(AppError::Validation(format!(
                "{}: lookup target entity is not configured",
                attr.logicalname
            )));
        };
        let target_id = value
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AppError::Validation(format!("{}: invalid UUID", attr.logicalname)))?;
        by_target
            .entry(target_entity_id)
            .or_default()
            .push((attr.logicalname.clone(), target_id));
    }
    if by_target.is_empty() {
        return Ok(());
    }

    let mut queries = Vec::with_capacity(by_target.len());
    {
        let registry = state.entities.load();
        for (target_entity_id, fields) in by_target {
            let target = registry.get_by_id(target_entity_id).ok_or_else(|| {
                let field = fields.first().map(|(f, _)| f.clone()).unwrap_or_default();
                AppError::Validation(format!("{field}: lookup target entity does not exist"))
            })?;
            queries.push((target.logicalname.clone(), fields));
        }
    }

    for (target_logicalname, fields) in queries {
        let table = quote_ident(&target_logicalname);
        let ids: Vec<Uuid> = fields.iter().map(|(_, id)| *id).collect();
        let live_ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE id = ANY($1) AND is_active = TRUE FOR KEY SHARE"
        ))
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let live: HashSet<Uuid> = live_ids.into_iter().collect();
        for (field, id) in fields {
            if !live.contains(&id) {
                return Err(AppError::Validation(format!(
                    "{field}: lookup target does not exist or is deleted"
                )));
            }
        }
    }
    Ok(())
}

/// P-file-upload-pipeline — the trust anchor for `file`-typed field values
/// (field_type_int 12/13). `attome_field::validate`'s `File` arm only checks
/// "is this a string" (it's a pure, DB-free crate); this is the actual gate:
/// a file-field value is only accepted when it names a `clean`, owned
/// `upload_session` (migrations/0058) scoped to this exact
/// entity/record/field.
///
/// `record_id` is `None` at create time — no session can possibly exist yet
/// for a record that hasn't been assigned an id (upload sessions are created
/// against an already-existing record, `POST .../{entity}/{id}/files/...`),
/// so any non-null file-field value on create is rejected outright rather
/// than queried for. This is a deliberate refinement of the original plan
/// (which sketched a create-time check as if a session could pre-exist): the
/// two-step "create the record, then attach a file" flow is the only one
/// that can ever be valid given how sessions are scoped.
///
/// Matching `quarantine_key` in addition to `final_key` is deliberately
/// permissive for the brief pre-promotion window — a client that finalizes
/// and immediately PATCHes before the async scan completes gets a clear 422
/// either way, since `status = 'clean'` is the actual gate; the OR only
/// improves which string a legitimate post-promotion PATCH is allowed to
/// carry, not a security relaxation.
///
/// A multi-file field (`options.multi`, JSONB array column) carries a JSON
/// array of keys instead of one — `attome_field::validate_multi_file` already
/// rejected any shape but an array of strings before this runs, so each
/// element is checked exactly like a single-file value, in a loop.
pub(crate) async fn lock_file_field_sessions(
    tx: &mut PgConnection,
    writer: FileWriter,
    entity_name: &str,
    record_id: Option<Uuid>,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    for attr in attrs.iter().filter(|a| a.is_file_backed()) {
        let Some(value) = obj.get(&attr.logicalname) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let keys: Vec<&str> = match value {
            Value::String(s) => vec![s.as_str()],
            Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
            _ => continue, // shape already rejected by validate_body
        };
        if keys.is_empty() {
            continue;
        }
        let Some(record_id) = record_id else {
            return Err(AppError::Validation(format!(
                "{}: file fields cannot be set at creation — create the record first, then upload",
                attr.logicalname
            )));
        };
        for key in keys {
            // Staff: their own session, or any (an admin). A portal user:
            // only their own (D-774); never a staff one.
            let (owner_clause, owner, any) = match writer {
                FileWriter::Staff { user_id, is_admin } => {
                    ("(owner_user_ref = $5 OR $6)", user_id, is_admin)
                }
                // Only the promoted key: a portal user knows their quarantine
                // key (their PUT URL) and could re-PUT it after the scan.
                FileWriter::Portal(portal_user_id) => (
                    "(owner_portal_user_ref = $5 AND NOT $6 AND final_key = $1)",
                    portal_user_id,
                    false,
                ),
            };
            let found: Option<i32> = sqlx::query_scalar(&format!(
                "SELECT 1 FROM upload_session
                  WHERE (quarantine_key = $1 OR final_key = $1)
                    AND status = 'clean'
                    AND entity_logicalname = $2 AND record_id = $3 AND field_logicalname = $4
                    AND {owner_clause}
                    AND is_deleted = false
                  FOR KEY SHARE"
            ))
            .bind(key)
            .bind(entity_name)
            .bind(record_id)
            .bind(&attr.logicalname)
            .bind(owner)
            .bind(any)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if found.is_none() {
                return Err(AppError::Validation(format!(
                    "{}: file reference is not backed by a completed upload session",
                    attr.logicalname
                )));
            }
        }
    }
    Ok(())
}

/// P-bulk-batch-integrity Gap B: a plain Postgres unique-violation (SQLSTATE
/// `23505`) from `create_one`/`update_one`'s own INSERT/UPDATE must not be
/// classified the same way as a genuine transient database failure. Before
/// this helper existed, every `sqlx::Error` from those two call sites went
/// through `.map_err(AppError::internal)`, so `bulk.rs::process`'s
/// retry-vs-fail branch (`matches!(&error, AppError::Internal(_))`) could not
/// tell "the connection dropped" from "two rows in this batch permanently
/// collide on a unique key" and re-threw both the same way — a deterministic
/// collision reproduces on every retry, so Apalis would redeliver a job that
/// can never succeed. A constraint violation is deterministic and
/// client-actionable, so it becomes `AppError::Conflict`, which
/// `bulk.rs::process`/`process_staged_import` already route through
/// `mark_item_failed`/`mark_staged_item_failed` as an ordinary terminal
/// per-item failure instead of an infinite-retry signal. No `sqlx::Error`
/// `Display` text is ever forwarded here — same discipline as every other
/// `AppError::internal` call site, there is just no secret in this
/// particular error class either way.
///
/// M01 Core C-23: the 23505 check above keeps this function's own,
/// already-tested message ("unique constraint violated") unchanged; every
/// other `sqlx::Error` now falls through to `attome_db::classify` instead of a
/// blanket `AppError::internal`, so a foreign-key violation (23503) or a
/// serialization/deadlock conflict (40001/40P01) from the same INSERT/UPDATE
/// gets the same deterministic, terminal-per-item treatment `bulk.rs`
/// already gives a unique violation — not an endless Apalis retry of a
/// mutation that can never succeed. Unrecognized codes still mask to
/// `Internal`, identical to this function's behavior before `classify`
/// existed.
pub fn classify_db_error(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("unique constraint violated")
    } else {
        attome_db::classify(error)
    }
}

pub(crate) const MAX_HIERARCHY_DEPTH: u32 = 100;

/// True when `obj` sets a value on one of `entity_id`'s self-referencing
/// (hierarchy-shaped) lookup fields — the condition that makes a mutation
/// "hierarchy-touching" and therefore subject to the entity-level lock below.
fn touches_hierarchy_field(
    entity_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> bool {
    attrs.iter().any(|attr| {
        attr.field_type_int == 11
            && attr.lookup_entity_ref == Some(entity_id)
            && obj.contains_key(&attr.logicalname)
    })
}

/// Non-blocking, transaction-scoped advisory lock over *every* hierarchy
/// write against `entity_name`, not just the record being written.
///
/// P-hierarchy-mutation-locking: the per-record predecessor of this function
/// (`{entity}:hierarchy:{record_id}`, D-095) let two concurrent transactions
/// doing `A.parent = B` and `B.parent = A` take non-contending locks, each
/// read the other's pre-commit parent chain, and both pass
/// `guard_hierarchy_cycles` — committing a genuine cycle. Locking the whole
/// entity's hierarchy namespace (`"attome-metadata/hierarchy:{entity}"`, guidelines
/// §2 `"{crate}/{operation}:{resource}"` convention) instead of one record
/// serializes every hierarchy-touching write for that entity against every
/// other, closing the
/// cross-record race at the cost of concurrency that is not, today, a
/// measured bottleneck (hierarchy-field writes are a small fraction of total
/// entity writes — see the plan's §4/§8 for the alternative considered and
/// rejected).
pub(crate) async fn lock_hierarchy_entity(
    tx: &mut PgConnection,
    entity_name: &str,
    entity_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    if !touches_hierarchy_field(entity_id, attrs, obj) {
        return Ok(());
    }
    lock_hierarchy_entity_unconditional(tx, entity_name).await
}

/// Same lock, taken unconditionally — for call sites (F028 merge redirect)
/// that already know, by construction, that they are about to touch the
/// entity's hierarchy field and have no per-record `obj` to test.
pub(crate) async fn lock_hierarchy_entity_unconditional(
    tx: &mut PgConnection,
    entity_name: &str,
) -> Result<(), AppError> {
    // `attome-metadata`'s namespace, not this crate's — the key lives under the
    // `"attome-metadata/…"` prefix (L-1 / TODO-027).
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_metadata::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-metadata/hierarchy:{entity_name}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "hierarchy update already in progress for this entity",
        ));
    }
    Ok(())
}

pub(crate) async fn guard_hierarchy_cycles(
    tx: &mut PgConnection,
    entity_name: &str,
    entity_id: Uuid,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> Result<(), AppError> {
    let table = quote_ident(entity_name);
    for attr in attrs
        .iter()
        .filter(|a| a.field_type_int == 11 && a.lookup_entity_ref == Some(entity_id))
    {
        let Some(val) = obj.get(&attr.logicalname) else {
            continue;
        };
        if val.is_null() {
            continue;
        }
        let Some(current) = val.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
            continue;
        };
        if current == record_id {
            return Err(AppError::Validation(format!(
                "{}: a record cannot be its own parent",
                attr.logicalname
            )));
        }

        let field_ident = quote_ident(&attr.logicalname);
        let (contains_record, max_depth, reached_root): (bool, i32, bool) =
            sqlx::query_as(&format!(
                "WITH RECURSIVE chain(id, depth) AS ( \
                    SELECT {field_ident}, 1::integer FROM {table} WHERE id = $1 \
                    UNION ALL \
                    SELECT t.{field_ident}, chain.depth + 1 \
                    FROM {table} t JOIN chain ON t.id = chain.id \
                    WHERE chain.depth < $2 \
                 ) \
                 SELECT COALESCE(bool_or(id = $3), false), \
                        COALESCE(max(depth), 0), \
                        COALESCE(bool_or(id IS NULL), false) \
                 FROM chain"
            ))
            .bind(current)
            .bind(MAX_HIERARCHY_DEPTH as i32)
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

        if contains_record {
            return Err(AppError::Validation(format!(
                "{}: would create a cycle in the hierarchy",
                attr.logicalname
            )));
        }
        if max_depth >= MAX_HIERARCHY_DEPTH as i32 && !reached_root {
            return Err(AppError::Validation(format!(
                "{}: hierarchy chain exceeds {MAX_HIERARCHY_DEPTH} levels — refusing to guess whether this is a cycle",
                attr.logicalname
            )));
        }
    }
    Ok(())
}

/// F028 merge-redirect variant of `guard_hierarchy_cycles`. A merge's
/// dependent-redirect step rewrites *every* row in `entity_name` whose
/// self-referencing hierarchy field currently equals the retired duplicate id
/// to point at `new_parent` (the merge's canonical record) instead — one
/// batch `UPDATE`, not a single-record write, so the ordinary per-record
/// guard doesn't apply directly. This generalizes the same "walk the new
/// parent's ancestor chain, reject if it re-enters a record being rewritten"
/// shape from one `record_id` to the whole `redirected_ids` set the caller's
/// own preflight `SELECT` produced (the rows the redirect `UPDATE` is about
/// to touch). Caller must hold `lock_hierarchy_entity`/
/// `lock_hierarchy_entity_unconditional` for `entity_name` before calling —
/// this function only validates, it does not lock.
pub(crate) async fn guard_hierarchy_redirect_cycle(
    tx: &mut PgConnection,
    entity_name: &str,
    field_logicalname: &str,
    new_parent: Uuid,
    redirected_ids: &[Uuid],
) -> Result<(), AppError> {
    if redirected_ids.is_empty() {
        return Ok(());
    }
    if redirected_ids.contains(&new_parent) {
        return Err(AppError::Validation(format!(
            "{field_logicalname}: merge would make a record its own parent"
        )));
    }
    let table = quote_ident(entity_name);
    let field_ident = quote_ident(field_logicalname);
    let (contains_any, max_depth, reached_root): (bool, i32, bool) = sqlx::query_as(&format!(
        "WITH RECURSIVE chain(id, depth) AS ( \
            SELECT {field_ident}, 1::integer FROM {table} WHERE id = $1 \
            UNION ALL \
            SELECT t.{field_ident}, chain.depth + 1 \
            FROM {table} t JOIN chain ON t.id = chain.id \
            WHERE chain.depth < $2 \
         ) \
         SELECT COALESCE(bool_or(id = ANY($3)), false), \
                COALESCE(max(depth), 0), \
                COALESCE(bool_or(id IS NULL), false) \
         FROM chain"
    ))
    .bind(new_parent)
    .bind(MAX_HIERARCHY_DEPTH as i32)
    .bind(redirected_ids.to_vec())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if contains_any {
        return Err(AppError::Validation(format!(
            "{field_logicalname}: merge would create a cycle in the hierarchy"
        )));
    }
    if max_depth >= MAX_HIERARCHY_DEPTH as i32 && !reached_root {
        return Err(AppError::Validation(format!(
            "{field_logicalname}: hierarchy chain exceeds {MAX_HIERARCHY_DEPTH} levels — refusing to guess whether this is a cycle"
        )));
    }
    Ok(())
}

/// B-R6 (D-604): every `formula` field's value, computed from `ctx_source`
/// — `(field, value)` per formula field. A formula is a calculation whose
/// definition lives on the field: it recomputes on every write, whichever
/// fields the writer was allowed to set. Formula fields run in step 3 of the
/// business-rule pipeline (D-789 ruling 5), before `set_value` `always`
/// policies, reading the same snapshot (a policy can never target a
/// formula). A formula over a blank input is blank, not a blocked write: a
/// record may be saved before every input is filled in. Only a failure with
/// every input present (division by zero, a budget) blocks the write.
async fn compute_formula_values(
    state: &EngineState,
    entity_name: &str,
    attrs: &[AttrInfo],
    ctx_source: &serde_json::Map<String, Value>,
) -> Result<Vec<(String, Value)>, AppError> {
    let formulas = crate::rule_engine::formula_rules(entity_name, attrs);
    if formulas.is_empty() {
        return Ok(Vec::new());
    }
    let rules_ctx = crate::rule_engine::context_for_record(chrono::Utc::now(), attrs, ctx_source);
    let mut out = Vec::new();
    for (target, rule) in &formulas {
        let compiled = crate::rule_engine::get_or_compile_formula(state, attrs, rule).await?;
        let value = match crate::rule_engine::evaluate_value(rule, &compiled, &rules_ctx) {
            Ok(value) => value,
            Err(_) if crate::rule_engine::has_blank_input(rule, &rules_ctx) => {
                attome_rules::Value::Null
            }
            Err(e) => return Err(e),
        };
        out.push((
            target.clone(),
            crate::rule_engine::json_from_rules_value(&value),
        ));
    }
    Ok(out)
}

/// `base` with `delta` laid over it, borrowing `base` when there is nothing
/// to add.
fn overlay<'a>(
    base: &'a serde_json::Map<String, Value>,
    delta: &[(String, Value)],
) -> std::borrow::Cow<'a, serde_json::Map<String, Value>> {
    if delta.is_empty() {
        return std::borrow::Cow::Borrowed(base);
    }
    let mut merged = base.clone();
    for (field, value) in delta {
        merged.insert(field.clone(), value.clone());
    }
    std::borrow::Cow::Owned(merged)
}

/// D-789 §3.5: the fields of the caller's own body a business-rule lock is
/// checked against — the body minus the engine's own stamp of a portal
/// write's user field (`access_plan::plan_create`), which no client makes.
fn caller_fields(
    principal: Principal<'_>,
    body: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    body.iter()
        .filter(|(k, v)| match principal {
            Principal::Portal(plan) => !plan.is_own_stamp(k, v),
            Principal::Staff(_) => true,
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// D-789 §3.5: on create, the values the engine itself writes for a field
/// the caller leaves out — engine-managed initial values (D-524) and the
/// state model's initial state (D-406). A caller may send exactly this value
/// for a field a business rule locks.
fn engine_baseline(state: &EngineState, entity_name: &str) -> serde_json::Map<String, Value> {
    let mut baseline = engine_managed_initial_body(
        &state.engine_managed_fields,
        &state.engine_managed_initial_values,
        entity_name,
        &serde_json::Map::new(),
    )
    .ok()
    .flatten()
    .unwrap_or_default();
    let registry = state.state_models.load();
    if let Some(model) = registry
        .get(entity_name)
        .and_then(|entry| entry.model.as_ref())
        .filter(|m| m.is_active)
    {
        baseline.insert(
            model.state_field.clone(),
            Value::String(model.initial_state.clone()),
        );
    }
    baseline
}

/// B-R7 (D-605): every `rich_text` value is sanitized against the
/// allow-list (`attome_html::sanitize_rich_text`) before it is bound — the
/// last transform before the INSERT/UPDATE is built, so it covers what the
/// caller sent *and* anything a default/calculation rule or autovalue put
/// there. Every create/update path (interactive CRUD, bulk, staged import,
/// upsert, merge, bundle record sets, workflow nodes) reaches the database
/// through `create_one_as`/`update_one_as`, which is why this is the one
/// place it runs. Borrows `obj` untouched when there is nothing to change.
fn sanitize_rich_text_fields<'a>(
    attrs: &[AttrInfo],
    obj: &'a serde_json::Map<String, Value>,
) -> std::borrow::Cow<'a, serde_json::Map<String, Value>> {
    let mut out: Option<serde_json::Map<String, Value>> = None;
    for attr in attrs
        .iter()
        .filter(|a| a.field_type() == attome_core::FieldType::RichText)
    {
        let Some(Value::String(raw)) = obj.get(&attr.logicalname) else {
            continue;
        };
        let clean = attome_html::sanitize_rich_text(raw);
        if &clean != raw {
            out.get_or_insert_with(|| obj.clone())
                .insert(attr.logicalname.clone(), Value::String(clean));
        }
    }
    match out {
        Some(map) => std::borrow::Cow::Owned(map),
        None => std::borrow::Cow::Borrowed(obj),
    }
}

/// M45 Phase 3 (REVIEW-2026-09-02 finding #8) — one of the conditions
/// `update_one_as` reads the stored row under ("only pay the extra query if
/// you need it"): a governed entity's guard may reference a field this
/// specific PATCH never touches, so it needs the same effective
/// (patch-over-current) record business rules and formula fields read —
/// this widens when that fetch happens, it does not add a second one.
fn entity_has_active_state_model(state: &EngineState, entity_name: &str) -> bool {
    let registry = state.state_models.load();
    registry
        .get(entity_name)
        .is_some_and(|entry| entry.model.as_ref().is_some_and(|m| m.is_active))
}

/// D-789: the live row `record_id` of `entity_name` (every column, sensitive
/// ones included — it builds evaluation contexts and lock comparisons only,
/// never a response), or `None` when there is no live row.
async fn fetch_stored_record(
    tx: &mut Transaction<'_, Postgres>,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
) -> Result<Option<serde_json::Map<String, Value>>, AppError> {
    let table = quote_ident(entity_name);
    let cols = attome_core::select_columns(attrs, true);
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    );
    let current: Option<Value> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(match current {
        Some(Value::Object(map)) => Some(map),
        _ => None,
    })
}

/// `stored` with the PATCH `obj` laid over it.
fn patched(
    stored: &serde_json::Map<String, Value>,
    obj: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    let mut merged = stored.clone();
    for (k, v) in obj {
        merged.insert(k.clone(), v.clone());
    }
    merged
}

/// D-524 — the create-time half of engine-managed field enforcement
/// ([`validate_engine_managed_fields`] is the update-time half). Runs on
/// **every** [`MutationMode`]: a record may only be born in the initial state
/// its owning engine declared (`EngineModel::engine_managed_initial_values`).
///
/// For each engine-managed field of `entity_name`:
/// - absent or `null` → the declared initial value is written explicitly
///   (nothing is written when the engine declared none);
/// - equal to the declared initial value → accepted;
/// - anything else → `AppError::Validation`.
///
/// Returns `Ok(None)` when the body needs no change, so the common case (an
/// entity with no engine-managed fields) clones nothing. Must run before
/// `validate_body`, because an engine-managed field can be a required
/// attribute (`dashboard_decision.status`) that the caller may omit.
pub(crate) fn apply_engine_managed_initial_values(
    state: &EngineState,
    entity_name: &str,
    obj: &serde_json::Map<String, Value>,
) -> Result<Option<serde_json::Map<String, Value>>, AppError> {
    engine_managed_initial_body(
        &state.engine_managed_fields,
        &state.engine_managed_initial_values,
        entity_name,
        obj,
    )
}

/// The pure core of [`apply_engine_managed_initial_values`], split out so every
/// branch is unit-tested without building an `EngineState`.
fn engine_managed_initial_body(
    managed: &std::collections::HashSet<(String, String)>,
    initial_values: &std::collections::HashMap<(String, String), String>,
    entity_name: &str,
    obj: &serde_json::Map<String, Value>,
) -> Result<Option<serde_json::Map<String, Value>>, AppError> {
    let mut merged: Option<serde_json::Map<String, Value>> = None;
    for (entity, field) in managed {
        if entity != entity_name {
            continue;
        }
        let initial = initial_values.get(&(entity.clone(), field.clone()));
        match (obj.get(field), initial) {
            (None | Some(Value::Null), Some(initial)) => {
                merged
                    .get_or_insert_with(|| obj.clone())
                    .insert(field.clone(), Value::String(initial.clone()));
            }
            (None | Some(Value::Null), None) => {}
            (Some(Value::String(given)), Some(initial)) if given == initial => {}
            (Some(_), Some(initial)) => {
                return Err(AppError::Validation(format!(
                    "'{field}' is managed by the {entity_name} engine; a new record must start \
                     as '{initial}'"
                )));
            }
            (Some(_), None) => {
                return Err(AppError::Validation(format!(
                    "'{field}' is managed by the {entity_name} engine; leave it unset on create"
                )));
            }
        }
    }
    Ok(merged)
}

/// Shared create mutation. Audit is deliberately owned by the caller.
/// One over clippy's default arg-count threshold; every parameter is an
/// independent scalar/borrow the 12 call sites across `entity_crud.rs` and
/// `bulk.rs` already pass distinctly (unlike `bulk.rs`'s `apply_one`/
/// `dry_run_one`/`apply_staged_one`, which share one reusable cluster —
/// see `EntityMutationTarget` there), so a wrapper struct would move the
/// noise to every call site instead of removing it.
#[allow(clippy::too_many_arguments)]
pub async fn create_one(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    user_id: Uuid,
    org_ref: Uuid,
    mode: MutationMode,
) -> Result<MutationResult, AppError> {
    create_one_as(
        tx,
        state,
        Principal::Staff(ctx),
        entity_name,
        attrs,
        obj,
        CreateStamp::staff(user_id, org_ref),
        mode,
    )
    .await
}

/// Whether [`require_metadata_table_unlocked`] has to consult the
/// break-glass window: production profile, an interactive or service writer
/// (a context with `role_ids`; system writers carry none), and a table that
/// carries `owner_layer`.
fn metadata_table_lock_applies(profile: &str, interactive: bool, table: &str) -> bool {
    interactive
        && profile == "production"
        && attome_core::changeset::OWNER_LAYER_TABLES.contains(&table)
}

/// The production authoring lock for metadata tables reached through the
/// generic engine (roles, privileges, workflow definitions and the role join
/// tables: `attome_core::changeset::OWNER_LAYER_TABLES`).
///
/// `attome-server`'s authoring gate locks their admin routes on the production
/// profile by path prefix, but the generic `/api/v1/{entity}` routes, AI
/// actions and MCP tools write the same tables through this engine, so
/// without this check they were a second door past the lock. Same rule as
/// the gate: refused unless an approved break-glass window is open; a failed
/// window lookup refuses (fail closed). System writers (jobs, the changeset
/// applier, workflow nodes: no `role_ids`) are not interactive authoring and
/// keep working. Solution 7 Phase 3 replaces this with the layer rule.
pub async fn require_metadata_table_unlocked(
    state: &EngineState,
    ctx: &SecurityContext,
    table: &str,
) -> Result<(), AppError> {
    if !metadata_table_lock_applies(
        &state.base.config.app.deployment_profile,
        ctx.role_ids.is_some(),
        table,
    ) {
        return Ok(());
    }
    match attome_server::middleware::authoring_gate::break_glass_window_open(&state.base).await {
        Some(true) => {
            tracing::info!(
                table,
                user_id = %ctx.user_id,
                "metadata table written through an open break-glass window"
            );
            Ok(())
        }
        _ => Err(AppError::AuthoringLocked),
    }
}

/// [`create_one`] for any [`Principal`]: the one create pipeline (ledger and
/// engine-owned refusals, body validation, field-write rules, record
/// validators, state initial value, autovalue, the business-rule pipeline —
/// `set_value` defaults, formula fields, `set_value` always, locks and
/// `error` policies on the final record (D-789 ruling 5) — lookup liveness,
/// INSERT, change event), with the
/// principal deciding only what [`Principal`]'s doc lists and `stamp` the
/// system columns.
#[allow(clippy::too_many_arguments)]
pub async fn create_one_as(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    principal: Principal<'_>,
    entity_name: &str,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    stamp: CreateStamp,
    mode: MutationMode,
) -> Result<MutationResult, AppError> {
    // A3-T2: values in the shape they are stored in, before anything judges them.
    let normalized;
    let obj = match normalize_body(attrs, obj) {
        Some(map) => {
            normalized = map;
            &normalized
        }
        None => obj,
    };
    // A28-T1: each empty attribute's declared default, before validation.
    let defaulted;
    let actor = match principal {
        Principal::Staff(ctx) => Some(ctx.user_id),
        Principal::Portal(_) => None,
    };
    let filled = if defaults_skipped() {
        None
    } else {
        apply_defaults(
            attrs,
            obj,
            actor,
            attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref()),
        )
    };
    let obj = match filled {
        Some(map) => {
            defaulted = map;
            &defaulted
        }
        None => obj,
    };
    // D-516 ruling 5 (audit 10/10 plan item 1.1): the audit ledger is written
    // only by `attome_audit`'s own writers, which use
    // `attome_core::crud::append_only_insert`/`append_only_insert_many`.
    // Every other create path in the workspace funnels through this function —
    // the generic entity API (`entity_crud::create_record_for`), bundle record
    // sets (`attome-server::bundle::record_sets`), the workflow Create Record
    // node (`attome-workflow::scheduler`), upsert and bulk — so the refusal lives
    // here rather than being repeated (and eventually forgotten) at each one.
    //
    // Before this, `create_record_for` discarded `resolve_entity`'s
    // `is_append_only` value, unlike update/delete/upsert/bulk, so an admin
    // could POST a forged header, detail or snapshot row through
    // `/api/v1/{entity}`.
    if let Principal::Staff(ctx) = principal {
        require_metadata_table_unlocked(state, ctx, entity_name).await?;
    }
    if crate::entity_crud::LEDGER_ENTITIES.contains(&entity_name) {
        return Err(AppError::Forbidden);
    }

    // D-535: before anything else, whoever the caller is. Independent of the
    // ledger refusal above — that one protects append-only audit rows; this
    // one protects entities an engine owns outright (today `api_key`,
    // minted only through `POST /api/v1/auth/api-keys`, behind D-510's
    // step-up guard).
    validate_engine_owned_entity(state, entity_name)?;

    // D-789 §3.5: a business-rule lock judges what the caller itself sent.
    let caller_body = obj;
    let with_engine_initial;
    let obj = match apply_engine_managed_initial_values(state, entity_name, obj)? {
        None => obj,
        Some(merged) => {
            with_engine_initial = merged;
            &with_engine_initial
        }
    };
    validate_body(attrs, obj, true)?;
    validate_principal_field_writes(principal, entity_name, attrs, obj)?;
    validate_self_addressed(principal, entity_name, obj, true)?;
    validate_model_record_validators(state, entity_name, obj)?;

    // M07 Phase 1 (D-406): if this entity is governed by an attome-state model,
    // the created record must land in the model's initial_state -- either
    // because the caller submitted it explicitly, or because it was left
    // unset and defaults to it here (never an ungoverned/NULL state field).
    // Read-only snapshot (`EngineState::state_models`), no DB round trip -- see
    // `attome_core::state_registry`'s doc comment for why enforcement
    // lives here rather than only in attome-state's own routes.
    let with_initial_state;
    let obj = {
        let registry = state.state_models.load();
        let governed = registry
            .get(entity_name)
            .and_then(|entry| entry.model.as_ref().map(|m| (entry, m)));
        match governed {
            None => obj,
            Some((model_entry, model_def)) => {
                let provided = obj.get(&model_def.state_field).and_then(Value::as_str);
                match attome_core::check_initial_state(model_entry, provided)? {
                    None => obj,
                    Some(initial) => {
                        let mut merged = obj.clone();
                        merged.insert(model_def.state_field.clone(), Value::String(initial));
                        with_initial_state = merged;
                        &with_initial_state
                    }
                }
            }
        }
    };

    // Auto Value (`attome_metadata::autovalue`): fills any field an admin has bound
    // to a format + counter. Hooked into this shared primitive rather than the
    // HTTP handler so interactive create, upsert, and bulk import all allocate
    // through one path, exactly once per record — a second hook anywhere else
    // would burn two numbers for one row.
    //
    // Placed *after* both validations on purpose. `validate_field_write_grants`
    // must judge what the caller submitted, not what the system generated: a
    // field-secured autonumber is precisely the field an ordinary user has no
    // write grant on, and generating before the check would make every such
    // create a 403. `validate_body`'s required check runs on the caller's body
    // for the same reason — see `autovalue::seed`'s note on why a managed
    // attribute is not marked required.
    //
    // Allocation runs on `tx`, so a failure below rolls the numbers back
    // instead of leaving a gap. Nothing is cloned unless a rule actually fired.
    let generated = attome_metadata::autovalue::generate_for_create(
        tx,
        &state.base.db,
        entity_name,
        attrs,
        obj,
        attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref()),
        // A4-T2: only a data migration may bring its own numbers.
        matches!(
            mode,
            MutationMode::ApprovedStagedImport | MutationMode::BundleRecordSet(_)
        ),
    )
    .await?;
    let with_auto_values;
    let obj = if generated.is_empty() {
        obj
    } else {
        let mut merged = obj.clone();
        for (field, value) in generated {
            merged.insert(field, Value::String(value));
        }
        with_auto_values = merged;
        &with_auto_values
    };

    // D-789 ruling 5 — the business-rule pipeline, on M0 = the body plus the
    // engine's initial values, the state initial value and autovalue (a rule
    // only ever fills a gap the structural generators left, never overrides
    // them):
    //   1. conditions on M0 → the `set_value` policies that fire;
    //   2. `set_value` `default` on fields still empty → M1;
    //   3. formula fields (D-604) and `set_value` `always`, both from M1 → M2;
    //   4–6. conditions on M2 → locks on the caller's own body, required-but-
    //        locked, `error` policies (so an error judges the stored record).
    // An entity with no rule binding this writer skips straight to formulas.
    let mut rules =
        crate::business_rules::WritePipeline::new(state, entity_name, attrs, &principal);
    let fired = match rules.as_mut() {
        Some(pipeline) => Some(pipeline.fire_set_values(obj, true).await?),
        None => None,
    };
    let defaults = match (&rules, &fired) {
        (Some(pipeline), Some(fired)) => pipeline.default_values(fired, obj).await,
        _ => Vec::new(),
    };
    let m1 = overlay(obj, &defaults);
    let mut computed = compute_formula_values(state, entity_name, attrs, &m1).await?;
    if let (Some(pipeline), Some(fired)) = (&rules, &fired) {
        computed.extend(pipeline.always_values(fired, &m1).await?);
    }
    let m2 = overlay(&m1, &computed);
    let warnings = match rules.as_mut() {
        Some(pipeline) => {
            let body = caller_fields(principal, caller_body);
            let baseline = engine_baseline(state, entity_name);
            let sides = crate::business_rules::WriteSides {
                body: &body,
                stored: None,
                baseline: &baseline,
                is_create: true,
            };
            pipeline
                .judge(&m2, !defaults.is_empty() || !computed.is_empty(), &sides)
                .await?
        }
        None => Vec::new(),
    };
    let obj: &serde_json::Map<String, Value> = &m2;
    let sanitized = sanitize_rich_text_fields(attrs, obj);
    let obj: &serde_json::Map<String, Value> = &sanitized;

    let (mut cols, mut placeholders, values) = build_insert_binds(attrs, obj, 6);
    if cols.is_empty() {
        return Err(AppError::Validation(
            "no recognised fields in record".into(),
        ));
    }

    if mode.enforce_lookup_liveness() {
        lock_lookup_targets(tx, state, attrs, obj).await?;
    }
    lock_file_fields_for(tx, principal, entity_name, None, attrs, obj, mode).await?;

    // D-137: owner_ref/owner_type are set unconditionally to the creator here
    // (principal_type=0/user, same convention record_share uses) — the
    // one and only other writer is attome_security::admin::reassign_owner. This
    // column is denormalized for query/report/grid/queue purposes only; the
    // actual access grant is still `grant_creator_share`'s record_share
    // row below, which rls_predicate reads exclusively.
    cols.splice(
        0..0,
        [
            "created_by".to_owned(),
            "modified_by".to_owned(),
            "organization_ref".to_owned(),
            "owner_ref".to_owned(),
            "owner_type".to_owned(),
        ],
    );
    placeholders.splice(
        0..0,
        [
            "$1".to_owned(),
            "$2".to_owned(),
            "$3".to_owned(),
            "$4".to_owned(),
            "$5".to_owned(),
        ],
    );
    // Bundle record-set derived id (D-374 amendment): `id` is otherwise
    // never in `cols`/`placeholders` (`is_system_managed_column` excludes it
    // from `build_insert_binds`, on purpose — every other caller relies on
    // the column's `uuidv7()` default). Appended, not spliced in among the
    // audit columns, so its placeholder number is just "one past whatever
    // came before" — no renumbering of the already-built `$6.."` attrs
    // placeholders above.
    let bundle_id = match mode {
        MutationMode::BundleRecordSet(Some(id)) => Some(id),
        _ => None,
    };
    if bundle_id.is_some() {
        let next_param = placeholders.len() + 1;
        cols.push("id".to_owned());
        placeholders.push(format!("${next_param}"));
    }
    // Solution 7 (D-785): a registered entity whose table carries
    // `owner_layer` (roles, privileges, workflow definitions) has no attribute
    // for it, and migration 0525 dropped the column default. Stamp the Phase 1
    // auto layer — the value the default used to supply — as a constant, so a
    // generic create keeps working. A constant literal, not request data.
    if attome_core::changeset::OWNER_LAYER_TABLES.contains(&entity_name) {
        cols.push("owner_layer".to_owned());
        placeholders.push("'project'".to_owned());
    }

    let table = quote_ident(entity_name);
    // Explicit RETURNING projection, not `RETURNING *` (external review,
    // 2026-07-21) â€” always the full column set (`include_sensitive = true`):
    // the caller's audit-event diff needs every field's value regardless of
    // the HTTP caller's own field visibility; `entity_crud::build_response`
    // is the place that later hides a sensitive value from the *response*.
    let returning_cols = attome_core::select_columns(attrs, true);
    let sql = format!(
        "WITH r AS (INSERT INTO {table} ({cols}) VALUES ({phs}) RETURNING {returning_cols}) \
         SELECT row_to_json(r) FROM r",
        cols = cols.join(", "),
        phs = placeholders.join(", "),
    );
    let mut q = sqlx::query_scalar::<_, Value>(&sql)
        .bind(stamp.created_by) // created_by
        .bind(stamp.created_by) // modified_by
        .bind(stamp.org_ref)
        .bind(stamp.owner_ref) // owner_ref: the creator (D-137) or the portal's team (D-579)
        .bind(stamp.owner_type);
    for value in &values {
        q = q.bind(value.clone());
    }
    if let Some(id) = bundle_id {
        q = q.bind(id);
    }
    let row = q.fetch_one(&mut **tx).await.map_err(classify_db_error)?;
    let record_id = row
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::internal("created entity row did not contain a UUID id"))?;

    write_entity_change_event(
        tx,
        entity_name,
        record_id,
        attome_core::ChangeOperation::Create,
    )
    .await?;

    // B4-T3: the tags the rules that hold add or remove.
    if let Some(pipeline) = &rules {
        pipeline.apply_tags(tx, record_id, stamp.created_by).await?;
        pipeline
            .write_overrides(tx, record_id, stamp.created_by)
            .await?;
    }

    // D-787 rule 7: a reference-data create inside a changeset is recorded
    // as `upsert_record` (no-op outside the generic handler's scope).
    record_reference_write(
        tx,
        state,
        entity_name,
        attrs,
        record_id,
        &row,
        &row,
        caller_body,
        mode,
    )
    .await?;

    Ok(MutationResult {
        record_id,
        old_row: None,
        new_row: Some(row),
        cascade_summary: Vec::new(),
        approval: None,
        warnings,
    })
}

/// P-workflow-engine.md / D-267 addendum — durable outbox row for an entity
/// mutation, written in the SAME transaction as the mutation itself
/// (migration `0091_entity_change_event_outbox.sql`'s whole reason for
/// existing: an event can never be recorded for a write that didn't commit,
/// or lost for one that did). Every `create_one`/`update_one` caller gets
/// this for free — interactive CRUD, bulk, staged-import, and
/// `attome-workflow`'s own Create/Update Record nodes alike — so a workflow
/// created by another workflow's node can itself trigger a listening
/// workflow, same as a human-initiated write would.
///
/// D-358 moved the INSERT itself down to `attome_core::change_feed`, so the
/// purge path in `attome-metadata` (which sits below this crate and must emit too)
/// writes the same row through the same function rather than a second copy of
/// this statement. This stays as the crate-local shorthand its call sites read
/// better with.
///
/// `pub` (not module-private) — R-07: `attome-dashboard`'s `layout.rs` writes
/// `attome_dashboard*` rows with bound SQL directly (Tier 2's tree
/// materialization has to stay inside one transaction under the dashboard
/// advisory lock, so it cannot route through `create_one`/`update_one`) but
/// still needs the same outbox row every generic-CRUD write gets, once per
/// written record, inside its own `tx` — see `layout.rs::apply_pages_snapshot`.
pub async fn write_entity_change_event(
    tx: &mut Transaction<'_, Postgres>,
    entity_name: &str,
    record_id: Uuid,
    operation: attome_core::ChangeOperation,
) -> Result<(), AppError> {
    attome_core::change_feed::emit_tx(tx, entity_name, record_id, operation).await
}

/// Solution 7 Phase 2 (D-787 rule 7, design §1 "Write a reference record",
/// §3.8 recorder): a generic create or update of a reference-data entity is
/// recorded as one `upsert_record` when a changeset is in play — the
/// generic handler set the ambient recording
/// (`attome_core::changeset::reference::scope`) and it resolves to an
/// explicit or open changeset (in `auto` mode with nothing open the write is
/// a customer edit and is not recorded; in `required` mode with nothing open
/// the write is refused, `changeset_required`).
///
/// - `target.key`: the declared key's values **before** the write (`key_row`
///   is the pre-write row of an update, the created row of a create), so a
///   key change replays as "find by the old key, set the new one";
/// - snapshot `values`: the post-write attribute values minus system columns
///   and sensitive fields (a changeset file is not a place for them);
///   lookups as `{"key": {…}}` of their target's business key, refused with
///   `lookup_target_has_no_business_key` when it has none;
/// - snapshot `changed`: the fields the caller's write set (design §3.9).
///
/// Bundle record-set writes (the changeset applier) never record. Runs in the
/// write's transaction after the write; nothing else takes the changeset
/// row's lock afterwards, so `seq` order still matches commit order.
#[allow(clippy::too_many_arguments)] // one write's parts, each named at the two call sites
async fn record_reference_write(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    entity_name: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    key_row: &Value,
    new_row: &Value,
    caller: &serde_json::Map<String, Value>,
    mode: MutationMode,
) -> Result<(), AppError> {
    if matches!(mode, MutationMode::BundleRecordSet(_)) {
        return Ok(());
    }
    let Some(recording) = attome_core::changeset::reference::current() else {
        return Ok(());
    };
    let declared: Option<(Option<Vec<String>>, bool)> = sqlx::query_as(
        "SELECT business_key, is_reference_data FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(key_fields), true)) = declared else {
        return Ok(());
    };
    let resolved = recording.preflight(&state.base.db).await?;
    if !attome_core::changeset::reference::changeset_in_play(&resolved) {
        return Ok(());
    }

    let attrs_by_name: HashMap<&str, &AttrInfo> =
        attrs.iter().map(|a| (a.logicalname.as_str(), a)).collect();
    let mut key = serde_json::Map::new();
    for field in &key_fields {
        let value = key_row.get(field).cloned().unwrap_or(Value::Null);
        let value =
            portable_record_value(tx, attrs_by_name.get(field.as_str()).copied(), value).await?;
        key.insert(field.clone(), value);
    }
    let mut values = serde_json::Map::new();
    if let Some(row) = new_row.as_object() {
        for (field, value) in row {
            if attome_core::ALL_SYSTEM_COLS.contains(&field.as_str()) {
                continue;
            }
            let Some(attr) = attrs_by_name.get(field.as_str()).copied() else {
                continue;
            };
            if attr.is_sensitive {
                continue;
            }
            let value = portable_record_value(tx, Some(attr), value.clone()).await?;
            values.insert(field.clone(), value);
        }
    }
    let changed: Vec<&String> = caller
        .keys()
        .filter(|f| values.contains_key(f.as_str()))
        .collect();

    recording
        .record(
            tx,
            attome_core::changeset::RecordedOp {
                op: attome_core::changeset::Op::UpsertRecord,
                object_kind: "record",
                object_ref: Some(record_id),
                target: serde_json::json!({ "entity": entity_name, "key": key }),
                snapshot: serde_json::json!({ "values": values, "changed": changed }),
                changed: Vec::new(),
            },
        )
        .await
}

/// A record value as it travels in a changeset: a lookup becomes the key
/// reference of its target (`attome_metadata::provision::business_key::key_reference_of`);
/// every other value is kept as read.
async fn portable_record_value(
    tx: &mut Transaction<'_, Postgres>,
    attr: Option<&AttrInfo>,
    value: Value,
) -> Result<Value, AppError> {
    let Some(attr) = attr else {
        return Ok(value);
    };
    if !matches!(
        attome_core::FieldType::from_int(attr.field_type_int),
        Some(attome_core::FieldType::Lookup)
    ) {
        return Ok(value);
    }
    let Some(target_entity) = attr.lookup_entity_ref else {
        return Err(AppError::Conflict(
            attome_core::changeset::errors::LOOKUP_TARGET_HAS_NO_BUSINESS_KEY,
        ));
    };
    let Some(target_id) = value.as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
        // Null (or not an id): nothing to translate.
        return Ok(value);
    };
    match attome_metadata::provision::business_key::key_reference_of(tx, target_entity, target_id)
        .await?
    {
        Some(reference) => Ok(reference),
        None => {
            tracing::warn!(
                field = %attr.logicalname,
                "recorded reference write: the lookup's target record is gone; recorded as null"
            );
            Ok(Value::Null)
        }
    }
}

/// P0 0.7 — the name under which a transition `guard_expression` sees the
/// acting principal: a `lookup` holding the staff user's id (the stem of the
/// `@current_user` data-definition builtin), so a guard can require the
/// approver not to be the submitter, e.g. `current_user != submitted_by`. It
/// is `null` for a portal writer, and a guard that names it refuses a portal
/// writer outright (see `enforce_state_transition`). It exists only in
/// transition guards — validation and calculation rules do not see it.
pub const GUARD_CURRENT_USER: &str = "current_user";

/// `Some("state_transition")` when this update moved `entity_name`'s active
/// state model's `state_field` (old and new row disagree), else `None` — the
/// audit marker `MutationRing::commit_mutation` writes on every update path
/// (M07 §4.1; the timeline reads the field change itself, D-601).
pub(crate) fn state_transition_event_name(
    state: &EngineState,
    entity_name: &str,
    old_row: Option<&Value>,
    new_row: Option<&Value>,
) -> Option<String> {
    let registry = state.state_models.load();
    let model = registry.get(entity_name)?.model.as_ref()?;
    if !model.is_active {
        return None;
    }
    let old = old_row?.get(&model.state_field);
    let new = new_row?.get(&model.state_field);
    (old != new).then(|| "state_transition".to_owned())
}

/// M07 Phase 1 (D-406). No-op when `entity_name` has no active state model,
/// or when `obj` doesn't touch that model's `state_field` at all -- the
/// common case, checked with zero extra I/O via the `state.state_models`
/// snapshot. Only when the write actually names the state field does this
/// read the record's *current* value (inside `tx`, so it sees this
/// transaction's own view) and resolve the (current -> new) edge.
///
/// A vanished/soft-deleted record is left for the caller's own subsequent
/// query to report as `NotFound`/`VersionConflict` -- this function only
/// enforces a transition when there is a current value to compare against.
///
/// M45 Phase 3 (REVIEW-2026-09-02 finding #8): after `check_transition`
/// confirms privilege, a non-null `guard_expression` on the matched
/// transition is compiled and evaluated against `guard_ctx_source` (the same
/// effective-record map business rules and formula fields use -- this PATCH layered
/// over the row's current live values, so a guard can reference a field this
/// specific write never touches) via the same `rule_engine` machinery
/// entity-level rules use, including the `(transition.id, transition.
/// row_version)`-keyed `state.rule_compiled` cache. Anything other than a
/// clean `Value::Bool(true)` -- `false`, a non-bool result, or an eval error
/// -- blocks the transition (fail closed, same posture
/// `rule_engine::evaluate_validation` takes for a `severity = "error"` rule).
///
/// P0 0.7: the guard also sees [`GUARD_CURRENT_USER`], the acting principal.
///
/// One over clippy's default arg-count threshold, same call as `create_one`/
/// `update_one` make on themselves (see that comment) -- every parameter is
/// an independent scalar/borrow the one call site already has in hand.
#[allow(clippy::too_many_arguments)]
async fn enforce_state_transition(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    principal: Principal<'_>,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    guard_ctx_source: &serde_json::Map<String, Value>,
    mode: MutationMode,
) -> Result<Option<PendingRedirect>, AppError> {
    let registry = state.state_models.load();
    let Some(entry) = registry.get(entity_name) else {
        return Ok(None);
    };
    let Some(model) = &entry.model else {
        return Ok(None);
    };
    let new_value = obj.get(&model.state_field).and_then(Value::as_str);
    // M07 Phase F: a model with approval transitions needs the current state
    // on every write (the pending lock applies to field edits too); any
    // other model only when the write names the state field — the zero-I/O
    // common case is unchanged.
    let approval_lock = entry.has_approval_transitions();
    if new_value.is_none() && !approval_lock && !matches!(mode, MutationMode::ApprovalFlow(_)) {
        return Ok(None);
    }

    let table = quote_ident(entity_name);
    let field_ident = quote_ident(&model.state_field);
    let current: Option<Option<String>> = sqlx::query_scalar(&format!(
        "SELECT {field_ident} FROM {table} WHERE id = $1 AND is_active = true"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(current) = current else {
        // No live row -- the ordinary update query below reports NotFound/
        // VersionConflict; nothing to enforce against here.
        return Ok(None);
    };

    if let MutationMode::ApprovalFlow(request_id) = mode {
        verify_approval_flow_move(
            tx,
            entity_name,
            record_id,
            &model.state_field,
            current.as_deref(),
            obj,
            request_id,
        )
        .await?;
        return Ok(None);
    }

    // M07 Phase F: while an approval is open the record is locked — no field
    // write and no transition, whoever asks (an admin too: the approval flow
    // is the only way out, so a decision can never be overtaken by a direct
    // edit). This is the minimal `locked_states` behaviour for pending states
    // only; Phase B's general `locked_states` is not built yet.
    if let Some(gated) = entry.approval_pending_in(current.as_deref()) {
        return Err(AppError::TransitionNotAllowed(format!(
            "{entity_name}: the record is in '{}' waiting for the approval of transition '{}'; \
             it cannot be edited or moved until the approval is decided or cancelled \
             (POST /api/v1/{entity_name}/{record_id}/transition/cancel)",
            current.as_deref().unwrap_or(""),
            gated.name
        )));
    }

    let Some(new_value) = new_value else {
        return Ok(None);
    };
    let Some(transition) = attome_core::check_transition_with(
        entry,
        |required| principal.holds(required),
        current.as_deref(),
        new_value,
    )?
    else {
        return Ok(None);
    };

    if let Some(guard_expr) = &transition.guard_expression {
        evaluate_transition_guard(
            tx,
            state,
            principal,
            entity_name,
            record_id,
            attrs,
            obj,
            guard_ctx_source,
            &model.state_field,
            transition,
            guard_expr,
            current.as_deref(),
            new_value,
        )
        .await?;
    }

    // M07 Phase F (D-770): privilege and guard passed exactly as for any
    // transition; a plan-bearing one now parks the record in its pending
    // state and hands the caller what to submit.
    let (Some(plan), Some(pending_state)) = (&transition.approval_plan, &transition.pending_state)
    else {
        return Ok(None);
    };
    let Principal::Staff(ctx) = principal else {
        return Err(AppError::TransitionNotAllowed(format!(
            "{entity_name}: transition '{}' requires an approval, which only a staff user can \
             request",
            transition.name
        )));
    };
    let from = current.unwrap_or_default();
    Ok(Some(PendingRedirect {
        requested_by: ctx.user_id,
        payload: attome_core::TransitionApprovalPayload {
            transition_id: transition.id,
            entity: entity_name.to_owned(),
            state_field: model.state_field.clone(),
            on_reject_state: transition
                .on_reject_state
                .clone()
                .unwrap_or_else(|| from.clone()),
            from,
            to: new_value.to_owned(),
            pending_state: pending_state.clone(),
            requested_by: ctx.user_id,
            // Filled in once the UPDATE has returned the new version.
            row_version: 0,
        },
        plan: plan.clone(),
    }))
}

/// What `enforce_state_transition` hands `update_one_as` for a plan-bearing
/// transition: write `payload.pending_state` instead of the requested state,
/// then submit `plan` regarding the record (M07 Phase F).
struct PendingRedirect {
    requested_by: Uuid,
    payload: attome_core::TransitionApprovalPayload,
    plan: attome_approval::ApprovalPlan,
}

/// The `MutationMode::ApprovalFlow` check (see that variant's doc comment):
/// the move out of a pending state is exactly the one its request allows.
/// Every refusal is `TransitionNotAllowed` naming why, so a stale or forged
/// settle attempt fails loudly and changes nothing.
async fn verify_approval_flow_move(
    tx: &mut Transaction<'_, Postgres>,
    entity_name: &str,
    record_id: Uuid,
    state_field: &str,
    current: Option<&str>,
    obj: &serde_json::Map<String, Value>,
    request_id: Uuid,
) -> Result<(), AppError> {
    let refuse = |why: &str| {
        Err(AppError::TransitionNotAllowed(format!(
            "{entity_name}: approval request {request_id} cannot move record {record_id}: {why}"
        )))
    };
    if obj.len() != 1 || !obj.contains_key(state_field) {
        return refuse("an approval-flow write may change only the state field");
    }
    let Some(new_value) = obj.get(state_field).and_then(Value::as_str) else {
        return refuse("the target state is missing");
    };
    let request = match attome_approval::get_with(&mut **tx, request_id).await {
        Ok(request) => request,
        Err(AppError::NotFound) => return refuse("the request does not exist"),
        Err(e) => return Err(e),
    };
    if request.action_type != attome_core::ACTION_STATE_TRANSITION
        || request.regarding_entity.as_deref() != Some(entity_name)
        || request.regarding_id != Some(record_id)
    {
        return refuse("the request is not a state transition approval for this record");
    }
    let latest = attome_approval::latest_regarding_with(
        &mut **tx,
        attome_core::ACTION_STATE_TRANSITION,
        entity_name,
        record_id,
    )
    .await?;
    if latest.map(|r| r.id) != Some(request_id) {
        return refuse("a newer approval request exists for this record");
    }
    let payload: attome_core::TransitionApprovalPayload =
        serde_json::from_value(request.payload.clone()).map_err(|e| {
            AppError::internal(format!("corrupt state.transition approval payload: {e}"))
        })?;
    if current != Some(payload.pending_state.as_str()) {
        return refuse("the record is no longer in the request's pending state");
    }
    use attome_approval::ApprovalStatus as S;
    let allowed = match request.status {
        S::Executing => payload.to.as_str(),
        S::Rejected => payload.on_reject_state.as_str(),
        S::Cancelled | S::Expired | S::Invalidated => payload.from.as_str(),
        S::Pending | S::Approved | S::Executed => {
            return refuse("the request is not in a status that moves the record");
        }
    };
    if new_value != allowed {
        return refuse(&format!(
            "a {} request moves the record to '{allowed}', not '{new_value}'",
            request.status
        ));
    }
    Ok(())
}

/// M45 Phase 3 / P0 0.7 — evaluates `transition`'s `guard_expression` (see
/// `enforce_state_transition`'s doc comment). Split out unchanged so the
/// approval redirect can follow it.
#[allow(clippy::too_many_arguments)]
async fn evaluate_transition_guard(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    principal: Principal<'_>,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    guard_ctx_source: &serde_json::Map<String, Value>,
    state_field: &str,
    transition: &attome_core::TransitionDef,
    guard_expr: &str,
    current: Option<&str>,
    new_value: &str,
) -> Result<(), AppError> {
    // P0 0.7 (separation of duties): a guard that names `current_user`
    // compares the acting principal against the record. Two extra rules make
    // that comparison trustworthy, both fail closed:
    // - a portal writer has no staff identity to compare, so it is refused;
    // - the fields such a guard compares against may not change in the same
    //   write as the transition — otherwise a submitter could rewrite
    //   `submitted_by` to a colleague and approve in one PATCH, and the guard
    //   would compare against the forged value.
    let guard_refs = attome_rules::parse(guard_expr)
        .map(|expr| crate::rule_engine::referenced_fields(&expr))
        .unwrap_or_default();
    let current_user = match principal {
        Principal::Staff(ctx) => attome_rules::Value::Lookup(ctx.user_id),
        Principal::Portal(_) => attome_rules::Value::Null,
    };
    if guard_refs.contains(GUARD_CURRENT_USER) {
        if matches!(principal, Principal::Portal(_)) {
            return Err(AppError::TransitionNotAllowed(format!(
                "{entity_name}: transition '{}' compares the acting staff user and cannot be \
                 applied by a portal user",
                transition.name
            )));
        }
        let touched: Vec<&AttrInfo> = attrs
            .iter()
            .filter(|a| {
                a.logicalname != state_field
                    && guard_refs.contains(&a.logicalname)
                    && obj.contains_key(&a.logicalname)
            })
            .collect();
        if !touched.is_empty() {
            let stored = fetch_stored_record(tx, entity_name, record_id, attrs)
                .await?
                .unwrap_or_default();
            if let Some(changed) = touched.iter().find(|a| {
                crate::rule_engine::rules_value_of_attr(a, obj.get(&a.logicalname))
                    != crate::rule_engine::rules_value_of_attr(a, stored.get(&a.logicalname))
            }) {
                return Err(AppError::TransitionNotAllowed(format!(
                    "{entity_name}: transition '{}' compares '{}' with the acting user, so that \
                     field cannot change in the same write as the transition",
                    transition.name, changed.logicalname
                )));
            }
        }
    }

    let cache_key = format!(
        "transition-guard:{}:{}",
        transition.id, transition.row_version
    );
    let compiled = match state.rule_compiled.get(&cache_key).await {
        Some(hit) => hit,
        None => {
            let schema = crate::rule_engine::schema_for_entity(attrs)
                .with_field(GUARD_CURRENT_USER, attome_rules::Type::Lookup);
            let compiled = attome_rules::compile(guard_expr, &schema).map_err(|e| {
                AppError::TransitionNotAllowed(format!(
                    "{entity_name}: transition '{}' guard expression failed to compile: {e}",
                    transition.name
                ))
            })?;
            let compiled = std::sync::Arc::new(compiled);
            state
                .rule_compiled
                .insert(cache_key, compiled.clone())
                .await;
            compiled
        }
    };
    // Set after the record's own fields, so an entity attribute that happens
    // to be named `current_user` can never stand in for the principal.
    let rules_ctx =
        crate::rule_engine::context_for_record(chrono::Utc::now(), attrs, guard_ctx_source)
            .with_field(GUARD_CURRENT_USER, current_user);
    match compiled.eval(&rules_ctx) {
        Ok(attome_rules::Value::Bool(true)) => Ok(()),
        Ok(_) => Err(AppError::TransitionNotAllowed(format!(
            "{entity_name}: transition from '{}' to '{new_value}' via '{}' is blocked by its \
             guard condition",
            current.unwrap_or(""),
            transition.name
        ))),
        Err(e) => Err(AppError::TransitionNotAllowed(format!(
            "{entity_name}: transition '{}' guard expression failed to evaluate: {e}",
            transition.name
        ))),
    }
}

/// Submits the approval a [`PendingRedirect`] asks for, inside the record
/// write's transaction, with its `Submitted` security event (D-062/D-545:
/// the request and the event that names who asked commit together, and both
/// commit with the record's move into the pending state or none of them do).
async fn submit_transition_approval(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    record_id: Uuid,
    redirect: PendingRedirect,
    new_row_version: i64,
) -> Result<ApprovalSubmitted, AppError> {
    let PendingRedirect {
        requested_by,
        mut payload,
        plan,
    } = redirect;
    payload.row_version = new_row_version;
    let backstop_ttl = attome_audit::approval::plan_backstop_ttl(&plan);
    let payload_json = serde_json::to_value(&payload).map_err(AppError::internal)?;
    let request = attome_approval::submit_with_plan_regarding_in_tx(
        tx,
        attome_core::ACTION_STATE_TRANSITION,
        payload_json,
        requested_by,
        plan,
        backstop_ttl,
        None,
        Some((payload.entity.as_str(), record_id)),
    )
    .await?;
    attome_audit::security::write_security_event(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Submitted,
            requested_by,
            "approval_request",
            Some(request.id),
        )
        .named(attome_core::ACTION_STATE_TRANSITION)
        .comment(format!(
            "state transition approval {} submitted: {} {record_id} '{}' -> '{}', held in '{}'",
            request.id, payload.entity, payload.from, payload.to, payload.pending_state
        )),
    )
    .await?;
    tracing::info!(
        request_id = %request.id,
        entity = %payload.entity,
        %record_id,
        from = %payload.from,
        to = %payload.to,
        pending_state = %payload.pending_state,
        "state transition parked pending approval"
    );
    Ok(ApprovalSubmitted {
        request_id: request.id,
        from: payload.from,
        requested: payload.to,
        pending_state: payload.pending_state,
    })
}

/// Shared update mutation. `record_id` is a selector, never an entity field.
/// See `create_one`'s comment on why this stays a flat argument list.
#[allow(clippy::too_many_arguments)]
pub async fn update_one(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    entity_id: Uuid,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    user_id: Uuid,
    expected_row_version: i64,
    mode: MutationMode,
) -> Result<MutationResult, AppError> {
    update_one_as(
        tx,
        state,
        Principal::Staff(ctx),
        entity_name,
        entity_id,
        record_id,
        attrs,
        obj,
        Some(user_id),
        expected_row_version,
        mode,
    )
    .await
}

/// [`update_one`] for any [`Principal`]. `modified_by` is the staff user, or
/// `None` for a portal user (D-579: no portal id in a staff column).
#[allow(clippy::too_many_arguments)]
pub async fn update_one_as(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    principal: Principal<'_>,
    entity_name: &str,
    entity_id: Uuid,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    modified_by: Option<Uuid>,
    expected_row_version: i64,
    mode: MutationMode,
) -> Result<MutationResult, AppError> {
    // A3-T2: values in the shape they are stored in, before anything judges them.
    let normalized;
    let obj = match normalize_body(attrs, obj) {
        Some(map) => {
            normalized = map;
            &normalized
        }
        None => obj,
    };
    // D-535: before anything else, in every mode and whoever the caller is.
    validate_engine_owned_entity(state, entity_name)?;
    if let Principal::Staff(ctx) = principal {
        require_metadata_table_unlocked(state, ctx, entity_name).await?;
    }
    validate_body(attrs, obj, false)?;
    validate_principal_field_writes(principal, entity_name, attrs, obj)?;
    validate_self_addressed(principal, entity_name, obj, false)?;
    validate_engine_managed_fields(state, entity_name, obj, mode)?;
    validate_model_record_validators(state, entity_name, obj)?;
    // D-786 follow-up M2: a service principal's email (its marker) is
    // immutable here, in every mode and whoever the caller is.
    if entity_name == "user_account" {
        attome_security::accounts::guard_service_principal_email_change(tx, record_id, obj).await?;
    }

    // D-789 §3.5: a business-rule lock judges what the caller itself sent.
    let caller_body = obj;

    // The business rules binding this writer (D-789, D-791), formula fields
    // (D-604) and a transition guard (M45 Phase 3) all read the record's
    // EFFECTIVE state — the live row with this PATCH laid over it — because
    // `obj` here is a partial patch and any of them may read a field this
    // write never touches. The row is read only when one of them exists, so
    // an entity with none pays no extra query. The effective record builds
    // evaluation contexts only; it is never passed to `build_update_binds`,
    // so the SET clause still names only the caller's fields plus computed
    // ones (partial-update semantics).
    let mut rules =
        crate::business_rules::WritePipeline::new(state, entity_name, attrs, &principal);
    let stored = if rules.is_some()
        || attrs.iter().any(AttrInfo::is_formula)
        || entity_has_active_state_model(state, entity_name)
    {
        fetch_stored_record(tx, entity_name, record_id, attrs).await?
    } else {
        None
    };
    if stored.is_none() {
        // No live row: the UPDATE below answers NotFound / VersionConflict;
        // there is no record to judge.
        rules = None;
    }
    let effective_owned;
    let rule_ctx_source: &serde_json::Map<String, Value> = match &stored {
        Some(stored) => {
            effective_owned = patched(stored, obj);
            &effective_owned
        }
        None => obj,
    };

    // M07 Phase 1 (D-406): if this write touches a state-bound field, resolve
    // the configured model and reject an unconfigured (old -> new) edge
    // before any SQL is built. Interactive CRUD, bulk, and upsert all share
    // this function (guidelines §9), so this is the one place that has to
    // get it right. See `attome_core::state_registry`'s doc comment for
    // why the registry lives there rather than in a sibling engine crate.
    // M45 Phase 3: `rule_ctx_source` is passed a second time here purely as
    // the guard-expression evaluation context (the transition's OWN
    // old/new-value logic still reads `obj`, unchanged) — see this
    // function's doc comment.
    let pending = enforce_state_transition(
        tx,
        state,
        principal,
        entity_name,
        record_id,
        attrs,
        obj,
        rule_ctx_source,
        mode,
    )
    .await?;
    // M07 Phase F (D-770): a plan-bearing transition writes its pending
    // state, not the requested one; the request is submitted below, after
    // the UPDATE, in this same transaction.
    let with_pending_state;
    let obj = match &pending {
        Some(redirect) => {
            let mut redirected = obj.clone();
            redirected.insert(
                redirect.payload.state_field.clone(),
                Value::String(redirect.payload.pending_state.clone()),
            );
            with_pending_state = redirected;
            &with_pending_state
        }
        None => obj,
    };

    // D-789 ruling 5 — the business-rule pipeline on M0 = the live row with
    // this PATCH (after any pending-state redirect) laid over it: conditions
    // on M0 pick the `set_value` policies that fire; formula fields and
    // `set_value` `always` compute from M0 (`default` is create-only); then
    // conditions on the final record decide locks (on the caller's own body,
    // against the stored values), required-but-locked and `error` policies.
    // Computed values join `obj` — only those columns are added to this
    // write's SET clause.
    let m0_owned;
    let m0: &serde_json::Map<String, Value> = match (&stored, &pending) {
        (Some(stored), Some(_)) => {
            m0_owned = patched(stored, obj);
            &m0_owned
        }
        (Some(_), None) => rule_ctx_source,
        (None, _) => obj,
    };
    let fired = match rules.as_mut() {
        Some(pipeline) => Some(pipeline.fire_set_values(m0, false).await?),
        None => None,
    };
    let mut computed = compute_formula_values(state, entity_name, attrs, m0).await?;
    if let (Some(pipeline), Some(fired)) = (&rules, &fired) {
        computed.extend(pipeline.always_values(fired, m0).await?);
    }
    let warnings = match rules.as_mut() {
        Some(pipeline) => {
            let m2 = overlay(m0, &computed);
            let body = caller_fields(principal, caller_body);
            let no_baseline = serde_json::Map::new();
            let sides = crate::business_rules::WriteSides {
                body: &body,
                stored: stored.as_ref(),
                baseline: &no_baseline,
                is_create: false,
            };
            pipeline.judge(&m2, !computed.is_empty(), &sides).await?
        }
        None => Vec::new(),
    };
    let mut with_computed = overlay(obj, &computed);
    // A4-T3: a number its rule held back until a condition is met (status
    // becoming issued) is given by the update that meets it, on this
    // transaction.
    for (field, value) in attome_metadata::autovalue::generate_for_update(
        &mut **tx,
        &state.base.db,
        entity_name,
        record_id,
        attrs,
        &with_computed,
        attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref()),
    )
    .await?
    {
        with_computed.to_mut().insert(field, Value::String(value));
    }
    let sanitized = sanitize_rich_text_fields(attrs, &with_computed);
    let obj: &serde_json::Map<String, Value> = &sanitized;

    let (set_parts, values) = build_update_binds(attrs, obj, 3);
    if set_parts.is_empty() {
        return Err(AppError::Validation(
            "no recognised fields to update".into(),
        ));
    }

    if mode.enforce_lookup_liveness() {
        lock_lookup_targets(tx, state, attrs, obj).await?;
    }
    lock_file_fields_for(
        tx,
        principal,
        entity_name,
        Some(record_id),
        attrs,
        obj,
        mode,
    )
    .await?;
    // Hierarchy locking/cycle guards are never skippable — see MutationMode's
    // doc comment. Unconditional for every mode, unlike the lookup check above.
    // Entity-level lock (P-hierarchy-mutation-locking), not the old per-record
    // lock — see `lock_hierarchy_entity`'s doc comment for why.
    lock_hierarchy_entity(tx, entity_name, entity_id, attrs, obj).await?;
    guard_hierarchy_cycles(tx, entity_name, entity_id, record_id, attrs, obj).await?;

    let version_param = 3 + set_parts.len();
    let table = quote_ident(entity_name);
    // Explicit projection, not `SELECT *`/`RETURNING *` (external review,
    // 2026-07-21) â€” always the full column set (`include_sensitive = true`),
    // same reasoning as `create_one` above: the audit diff needs every
    // field's before/after value regardless of the HTTP caller's own
    // visibility.
    let cols = attome_core::select_columns(attrs, true);
    let sql = format!(
        "WITH old AS ( \
            SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true \
         ), updated AS ( \
            UPDATE {table} \
               SET {sets}, row_version = row_version + 1, modified_at = NOW(), modified_by = $2 \
             WHERE id = $1 AND is_active = true AND row_version = ${version_param} \
            RETURNING {cols} \
         ) \
         SELECT (SELECT row_to_json(old) FROM old) AS old_row, \
                (SELECT row_to_json(updated) FROM updated) AS new_row",
        sets = set_parts.join(", "),
    );
    let mut q = sqlx::query_as::<_, (Option<Value>, Option<Value>)>(&sql)
        .bind(record_id)
        .bind(modified_by);
    for value in &values {
        q = q.bind(value.clone());
    }
    q = q.bind(expected_row_version);
    let (old_row, new_row) = q.fetch_one(&mut **tx).await.map_err(classify_db_error)?;
    let new_row = match new_row {
        Some(row) => row,
        None if old_row.is_some() => return Err(AppError::VersionConflict),
        None => return Err(AppError::NotFound),
    };

    write_entity_change_event(
        tx,
        entity_name,
        record_id,
        attome_core::ChangeOperation::Update,
    )
    .await?;

    let approval = match pending {
        Some(redirect) => {
            let new_version = new_row
                .get("row_version")
                .and_then(Value::as_i64)
                .unwrap_or(expected_row_version + 1);
            Some(submit_transition_approval(tx, state, record_id, redirect, new_version).await?)
        }
        None => None,
    };

    // M55 P2 (file versioning) — only for the writes `lock_file_field_sessions`
    // just validated above (see `create_file_versions_for_update`'s own doc
    // comment for why `MirroredFileWrite`/`BundleRecordSet` are excluded).
    // Deliberately placed after the UPDATE, not before: it needs `old_row`
    // and `new_row`'s actual before/after values to tell "value changed" from
    // "idempotent PATCH of the same key", and runs inside this same `tx` so a
    // version row can never exist for a field write that didn't commit.
    // Staff and portal writes alike (D-774 ruling 1): `record_file_version`
    // takes the owner from the session, so a portal upload's version carries
    // `uploaded_by_portal_user`.
    if mode.enforce_file_session_ownership() {
        create_file_versions_for_update(
            tx,
            entity_name,
            record_id,
            attrs,
            obj,
            old_row.as_ref(),
            &new_row,
        )
        .await?;
    }

    // B4-T3: the tags the rules that hold add or remove.
    if let Some(pipeline) = &rules {
        pipeline.apply_tags(tx, record_id, modified_by).await?;
        pipeline.write_overrides(tx, record_id, modified_by).await?;
    }

    // D-787 rule 7: a reference-data update inside a changeset is recorded
    // as `upsert_record`, keyed by the record's key before this write.
    if let Some(old) = old_row.as_ref() {
        record_reference_write(
            tx,
            state,
            entity_name,
            attrs,
            record_id,
            old,
            &new_row,
            caller_body,
            mode,
        )
        .await?;
    }

    Ok(MutationResult {
        record_id,
        old_row,
        new_row: Some(new_row),
        cascade_summary: Vec::new(),
        approval,
        warnings,
    })
}

/// M55 P2 (file versioning) — for every single-file field (`field_type_int`
/// 12/13, not `options.multi`) this write actually touched, records the
/// newly-referenced object as a new `file_version` row and flips
/// `is_current`, whenever the field's value genuinely changed (including its
/// first-ever value; a no-op re-PATCH of the same key creates nothing).
///
/// Only called when `mode.enforce_file_session_ownership()` — i.e. exactly
/// the writes `lock_file_field_sessions` already validated against a real,
/// clean `upload_session` row moments ago in this same transaction,
/// which is what supplies this version's size/hash/content_type/uploaded_by.
/// `MirroredFileWrite` (the `attome_document` mirror of a source field already
/// versioned once under its own entity/record/field triple) and
/// `BundleRecordSet` (promotion, no interactive session to source metadata
/// from) are deliberately excluded — the same narrow reasoning
/// `MutationMode`'s own doc comment gives for skipping the session-ownership
/// check itself.
///
/// Multi-file fields (`options.multi`) are out of scope for this pass: the
/// version table's key is `(entity, record_id, field, version_no)`, one row
/// per field *value*, which has no way to name which array element changed.
/// Documented follow-up, not attempted here.
async fn create_file_versions_for_update(
    tx: &mut Transaction<'_, Postgres>,
    entity_name: &str,
    record_id: Uuid,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
    old_row: Option<&Value>,
    new_row: &Value,
) -> Result<(), AppError> {
    for attr in attrs
        .iter()
        .filter(|a| a.is_file_backed() && !is_multi_valued(a))
    {
        if !obj.contains_key(&attr.logicalname) {
            continue;
        }
        let Some(new_key) = new_row.get(&attr.logicalname).and_then(Value::as_str) else {
            continue; // cleared to null, or not a string â€” nothing to version
        };
        let old_key = old_row
            .and_then(|r| r.get(&attr.logicalname))
            .and_then(Value::as_str);
        if old_key == Some(new_key) {
            continue; // unchanged value, e.g. an idempotent PATCH
        }
        record_file_version(tx, entity_name, record_id, &attr.logicalname, new_key).await?;
    }
    Ok(())
}

/// Inserts one `file_version` row for `object_key` and flips
/// `is_current` off the field's previous current row (if any) — see
/// `create_file_versions_for_update`'s doc comment for when this runs.
///
/// Metadata (size/hash/content_type/uploaded_by/scan_status) is sourced from
/// the `upload_session` row `object_key` names — a second, narrower
/// SELECT rather than threading `lock_file_field_sessions`' own query result
/// through, since that function loops over every file-typed attribute in one
/// pass and returns nothing per-key today. Finding no such session (it
/// vanished between that check and here, within the same transaction) is
/// treated as "nothing to version" rather than failing the whole write: the
/// field value itself already passed its gate and is already part of this
/// commit.
async fn record_file_version(
    tx: &mut Transaction<'_, Postgres>,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    object_key: &str,
) -> Result<(), AppError> {
    // guidelines §2 â€” serializes concurrent version-creating writes for the
    // same (entity, record, field) so two racing PATCHes can never both read
    // "no current version yet" and both insert version_no = 1, or both flip
    // the same prior row and leave two rows marked current. Same namespace
    // (`xrm-files/`, `attome_server::FILES_ADVISORY_LOCK_NAMESPACE`) `files.rs`'s
    // upload-session-creation lock already uses, just a different key.
    let lock_key = format!("xrm-files/file-version:{entity_name}:{record_id}:{field_name}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::FILES_ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a version is already being recorded for this field, retry shortly",
        ));
    }

    type SessionMeta = (
        i64,
        Option<String>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        String,
    );
    let session: Option<SessionMeta> = sqlx::query_as(
        "SELECT COALESCE(actual_size_bytes, declared_max_size_bytes), actual_checksum_sha256,
                actual_content_type, owner_user_ref, owner_portal_user_ref, status
           FROM upload_session
          WHERE (quarantine_key = $1 OR final_key = $1)
            AND status = 'clean'
            AND entity_logicalname = $2 AND record_id = $3 AND field_logicalname = $4
            AND is_deleted = false",
    )
    .bind(object_key)
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((size, hash, content_type, staff_owner, portal_owner, scan_status)) = session else {
        return Ok(());
    };
    // D-774: the version records whichever owner the session has.
    let (uploaded_by, uploaded_by_portal_user) =
        FileOwner::from_columns(staff_owner, portal_owner)?.columns();

    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version_no), 0) + 1 FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = $3",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "UPDATE file_version SET is_current = false
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND is_current = true",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "INSERT INTO file_version
            (entity, record_id, field, version_no, object_key, size, hash,
             content_type, uploaded_by, uploaded_by_portal_user, scan_status, is_current)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true)",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .bind(next_version)
    .bind(object_key)
    .bind(size)
    .bind(hash)
    .bind(content_type)
    .bind(uploaded_by)
    .bind(uploaded_by_portal_user)
    .bind(scan_status)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(())
}

pub(crate) struct DeletePolicySummary {
    pub(crate) cascade_summary: Vec<String>,
}

/// TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.2 (T2-2) — a CascadeDeactivate
/// dependent group at or below this size still finishes synchronously, inside
/// the deleting request's own transaction, exactly as before this change.
/// Above it, `apply_dependents_on_delete` defers that one dependent group to
/// `EngineJob::CascadeDeactivateDependents` (`run_cascade_deactivate_job`
/// below) instead of building an unbounded `Vec<Uuid>` and holding the
/// request's transaction open for an unbounded `UPDATE ... RETURNING`.
///
/// Deliberately lower than `admin::attribute::ATTRIBUTE_INDEX_INLINE_ROW_LIMIT`/
/// `SCHEMA_CHANGE_INLINE_ROW_LIMIT` (10,000 each): those gate a rare,
/// already-admin-only action; this gates an ordinary interactive `DELETE`,
/// which should stay synchronous for the common case but hand off sooner when
/// it can't.
pub(crate) const CASCADE_INLINE_ROW_LIMIT: i64 = 5_000;

/// Records exactly which dependent rows one cascade batch touched (B16/T2-3),
/// so a later restore of `parent_record_id` can reactivate precisely this set
/// instead of every currently-inactive dependent. Shared by the inline path
/// below and `run_cascade_deactivate_job`'s async batches, so both write to
/// the same durable ledger regardless of which one ran. No-op on an empty
/// batch (the caller's own `RETURNING` already found nothing to cascade).
async fn record_cascade_batch(
    conn: &mut PgConnection,
    parent_entity: &str,
    parent_record_id: Uuid,
    dependent_entity: &str,
    dependent_field: &str,
    dependent_record_ids: &[Uuid],
) -> Result<(), AppError> {
    if dependent_record_ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO cascade_deactivation \
            (parent_entity, parent_record_id, dependent_entity, dependent_field, dependent_record_id) \
         SELECT $1, $2, $3, $4, unnest($5::uuid[])",
    )
    .bind(parent_entity)
    .bind(parent_record_id)
    .bind(dependent_entity)
    .bind(dependent_field)
    .bind(dependent_record_ids)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Locks the target, applies the configured restrict/orphan/cascade policy,
/// and enforces an optional row-version precondition for bulk deletes.
///
/// `tx` widened from `&mut PgConnection` to `&mut Transaction<'_, Postgres>`
/// (finding 3.2/T2-2) so a dependent group over `CASCADE_INLINE_ROW_LIMIT` can
/// enqueue `EngineJob::CascadeDeactivateDependents` in the SAME transaction
/// as the parent's own deactivation via `attome_jobs::enqueue_in_tx_dedup` —
/// `enqueue_in_tx*` needs a concrete `Transaction`, which a bare
/// `PgConnection` cannot provide. `delete_one`, the sole caller, already holds
/// exactly that type.
pub(crate) async fn apply_dependents_on_delete(
    tx: &mut Transaction<'_, Postgres>,
    target_entity_name: &str,
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    modified_by: Option<Uuid>,
    expected_row_version: Option<i64>,
) -> Result<DeletePolicySummary, AppError> {
    // `deactivated_by` on a cascade job is a staff user; a portal delete never
    // has dependents (`access_plan` refuses it), so this is only ever nil
    // when there is nothing to cascade.
    let user_id = modified_by.unwrap_or_else(Uuid::nil);
    let target_table = quote_ident(target_entity_name);
    let current_version: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT row_version FROM {target_table} WHERE id = $1 AND is_active = TRUE FOR UPDATE"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(current_version) = current_version else {
        return Err(AppError::NotFound);
    };
    if let Some(expected) = expected_row_version
        && current_version != expected
    {
        return Err(AppError::VersionConflict);
    }

    let mut dependents = dependents.to_vec();
    dependents.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    for (dep_entity, dep_field, mode) in &dependents {
        if *mode != OnTargetDelete::Restrict {
            continue;
        }
        let dep_table = quote_ident(dep_entity);
        let dep_field_ident = quote_ident(dep_field);
        let has_live_ref: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {dep_table} WHERE {dep_field_ident} = $1 AND is_active = TRUE)"
        ))
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if has_live_ref {
            return Err(AppError::Conflict(
                "cannot delete: a restrict-mode lookup field still references this record",
            ));
        }
    }

    let affected_parent = if expected_row_version.is_some() {
        sqlx::query(&format!(
            "UPDATE {target_table} SET is_active = false, modified_at = NOW(), modified_by = $2, row_version = row_version + 1 WHERE id = $1 AND is_active = TRUE AND row_version = $3"
        ))
        .bind(record_id)
        .bind(modified_by)
        .bind(current_version)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
    } else {
        sqlx::query(&format!(
            "UPDATE {target_table} SET is_active = false, modified_at = NOW(), modified_by = $2, row_version = row_version + 1 WHERE id = $1 AND is_active = TRUE"
        ))
        .bind(record_id)
        .bind(modified_by)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
    };
    if affected_parent == 0 {
        return Err(AppError::NotFound);
    }

    // D-358: the soft delete is a change like any other. Before this, the ONE
    // emit site in this module was reached only by create/update, so a deleted
    // record stayed in every derived copy — a search index would keep
    // returning it, which is a disclosure defect, not just a staleness one.
    attome_core::change_feed::emit_tx(
        tx,
        target_entity_name,
        record_id,
        attome_core::ChangeOperation::Delete,
    )
    .await?;

    let mut cascade_summary = Vec::new();
    for (dep_entity, dep_field, mode) in &dependents {
        if *mode != OnTargetDelete::CascadeDeactivate {
            continue;
        }
        let dep_table = quote_ident(dep_entity);
        let dep_field_ident = quote_ident(dep_field);

        // finding 3.2 — bounded probe, same OFFSET-EXISTS shape as
        // `attome_metadata::provision::table_row_count_exceeds`: classifying a
        // huge fan-out costs no more than reading
        // `CASCADE_INLINE_ROW_LIMIT + 1` rows via the same index the RETURNING
        // update below would use anyway, never a full `COUNT(*)`.
        let exceeds_inline_limit: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {dep_table} WHERE {dep_field_ident} = $1 AND is_active = TRUE OFFSET {CASCADE_INLINE_ROW_LIMIT})"
        ))
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        if exceeds_inline_limit {
            // Defer this dependent group to the durable worker instead of
            // blocking the request's transaction on an unbounded
            // `UPDATE ... RETURNING` (finding 3.2). `enqueue_in_tx_dedup`
            // commits atomically with the parent's own deactivation above, so
            // the job can never be visible for a delete that then rolls back,
            // and the dedup key means a retried/duplicate request enqueues at
            // most one job per parent/dependent-group triple.
            attome_jobs::enqueue_in_tx_dedup(
                tx,
                attome_core::jobs::EngineJob::CascadeDeactivateDependents {
                    target_entity: target_entity_name.to_owned(),
                    target_record_id: record_id,
                    dependent_entity: dep_entity.clone(),
                    dependent_field: dep_field.clone(),
                    deactivated_by: user_id,
                },
                &format!(
                    "attome-server/cascade-deactivate:{target_entity_name}:{record_id}:{dep_entity}:{dep_field}"
                ),
            )
            .await
            .map_err(AppError::internal)?;
            cascade_summary.push(format!(
                "{dep_entity}.{dep_field}: queued for async processing"
            ));
            continue;
        }

        // `RETURNING id` rather than a bare row count (D-358): the cascade
        // deactivates records in OTHER entities, which the deleting caller
        // never names and no consumer can infer from the target's event. Each
        // one needs its own feed row, so the ids have to come back.
        let cascaded: Vec<(Uuid,)> = sqlx::query_as(&format!(
            "UPDATE {dep_table} SET is_active = false, modified_at = NOW(), modified_by = $2, row_version = row_version + 1 WHERE {dep_field_ident} = $1 AND is_active = TRUE RETURNING id"
        ))
        .bind(record_id)
        .bind(user_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        let affected = cascaded.len();
        if affected > 0 {
            let ids: Vec<Uuid> = cascaded.into_iter().map(|(id,)| id).collect();
            attome_core::change_feed::emit_many(
                tx,
                dep_entity,
                &ids,
                attome_core::ChangeOperation::Delete,
            )
            .await?;
            // B16/T2-3 — same ledger `run_cascade_deactivate_job` writes to,
            // so a subsequent restore treats the inline and async cascade
            // paths identically.
            record_cascade_batch(
                tx,
                target_entity_name,
                record_id,
                dep_entity,
                dep_field,
                &ids,
            )
            .await?;
            cascade_summary.push(format!("{dep_entity}.{dep_field}: {affected}"));
        }
    }

    Ok(DeletePolicySummary { cascade_summary })
}

/// Reverses the `CascadeDeactivate` step of `apply_dependents_on_delete` when
/// the target record is restored.
///
/// B16/T2-3 fix: this used to match on current `is_active` state alone
/// (`WHERE {fk} = $1 AND is_active = FALSE`) with no record of which rows the
/// delete actually cascaded — so it reactivated ANY currently-inactive
/// dependent, including one a user had independently deleted *before* the
/// parent was ever deleted. Delete child, delete parent, restore parent
/// wrongly resurrected the child. It now restricts to the ids
/// `apply_dependents_on_delete`/`run_cascade_deactivate_job` recorded in
/// `cascade_deactivation` for this exact parent record and
/// dependent-entity/field pair, then consumes (deletes) that ledger slice —
/// see the migration's doc comment on the table for why `parent_record_id`
/// alone is sufficient to scope the lookup without also passing this
/// function a `parent_entity` argument (`dep_field`'s `lookup_entity_ref` is
/// fixed by metadata to exactly one target entity, so it can never mix a
/// batch cascaded from a different parent entity).
///
/// Consumes (deletes) the ledger slice unconditionally once a dependent
/// group's `mode` is `CascadeDeactivate`, regardless of how many rows were
/// actually still eligible to reactivate: a row that didn't match — already
/// reactivated independently, or deleted again since — is spent either way,
/// and leaving it would let a later delete/restore cycle on the same parent
/// see a stale earlier batch's ids.
pub(crate) async fn reactivate_dependents_on_restore(
    tx: &mut PgConnection,
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    user_id: Uuid,
) -> Result<Vec<String>, AppError> {
    let mut dependents = dependents.to_vec();
    dependents.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut cascade_summary = Vec::new();
    for (dep_entity, dep_field, mode) in &dependents {
        if *mode != OnTargetDelete::CascadeDeactivate {
            continue;
        }
        let dep_table = quote_ident(dep_entity);
        let dep_field_ident = quote_ident(dep_field);
        let reactivated: Vec<(Uuid,)> = sqlx::query_as(&format!(
            "UPDATE {dep_table} SET is_active = true, modified_at = NOW(), modified_by = $2, row_version = row_version + 1 \
             WHERE {dep_field_ident} = $1 AND is_active = FALSE \
               AND id IN ( \
                   SELECT dependent_record_id FROM cascade_deactivation \
                    WHERE parent_record_id = $1 AND dependent_entity = $3 AND dependent_field = $4 \
               ) \
             RETURNING id"
        ))
        .bind(record_id)
        .bind(user_id)
        .bind(dep_entity.as_str())
        .bind(dep_field.as_str())
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let affected = reactivated.len();
        if affected > 0 {
            // Symmetric to the delete cascade (D-358). Without a Restore
            // event, a record that came back stays missing from every derived
            // copy forever — the delete removed it and nothing ever re-adds
            // it.
            let ids: Vec<Uuid> = reactivated.into_iter().map(|(id,)| id).collect();
            attome_core::change_feed::emit_many(
                &mut *tx,
                dep_entity,
                &ids,
                attome_core::ChangeOperation::Restore,
            )
            .await?;
            cascade_summary.push(format!("{dep_entity}.{dep_field}: {affected}"));
        }

        // B16/T2-3 — consume this dependent group's ledger slice regardless
        // of `affected`; see the doc comment above.
        sqlx::query(
            "DELETE FROM cascade_deactivation \
              WHERE parent_record_id = $1 AND dependent_entity = $2 AND dependent_field = $3",
        )
        .bind(record_id)
        .bind(dep_entity.as_str())
        .bind(dep_field.as_str())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    Ok(cascade_summary)
}

/// Worker-side half of the CascadeDeactivate size gate
/// (`EngineJob::CascadeDeactivateDependents`, finding 3.2/T2-2). Re-runs
/// the same `UPDATE ... RETURNING` cascade `apply_dependents_on_delete` runs
/// inline for a small dependent group, but in bounded batches, each in its
/// own short transaction — the guidelines §9 "bounded batch size, resumable
/// progress, idempotent item processing" shape for durable staged work.
///
/// Idempotent and resumable by construction, with no separate cursor to
/// track: every batch's `WHERE` clause is `is_active = TRUE`, so a
/// crash-and-retry (a fresh apalis attempt of the same job row) only ever
/// picks up rows the previous attempt hadn't reached yet — there is nothing
/// left to redo for a row an earlier attempt already deactivated. `FOR UPDATE
/// SKIP LOCKED` inside the batch selection additionally makes this safe to
/// run concurrently with itself, though today's dedup key
/// (`apply_dependents_on_delete`'s `enqueue_in_tx_dedup` call) already keeps
/// at most one such job live per parent/dependent-group triple.
///
/// Not a desired-state snapshot: `target_entity`/`dependent_entity`/
/// `dependent_field` are read straight from the job payload (they came from
/// live metadata at enqueue time and identify fixed physical
/// tables/columns), but every batch re-checks `is_active = TRUE` against the
/// table itself rather than trusting any row count captured at enqueue time.
pub async fn run_cascade_deactivate_job(
    db: &attome_db::DbPool,
    target_entity: &str,
    target_record_id: Uuid,
    dependent_entity: &str,
    dependent_field: &str,
    deactivated_by: Uuid,
) -> Result<(), AppError> {
    /// Rows deactivated per short transaction. Small enough that one batch's
    /// `FOR UPDATE SKIP LOCKED` selection and its `change_feed::emit_many`
    /// stay cheap and the transaction stays short, matching the guidelines §9
    /// "bounded batch sizes" requirement; large enough that a multi-million
    /// row fan-out still finishes in a bounded number of worker attempts.
    const BATCH_SIZE: i64 = 1_000;

    let dep_table = quote_ident(dependent_entity);
    let dep_field_ident = quote_ident(dependent_field);

    loop {
        let mut tx = attome_db::tx::begin(db).await?;
        let batch: Vec<(Uuid,)> = sqlx::query_as(&format!(
            "UPDATE {dep_table} SET is_active = false, modified_at = NOW(), modified_by = $2, row_version = row_version + 1 \
              WHERE id IN ( \
                  SELECT id FROM {dep_table} \
                   WHERE {dep_field_ident} = $1 AND is_active = TRUE \
                   LIMIT {BATCH_SIZE} \
                   FOR UPDATE SKIP LOCKED \
              ) \
             RETURNING id"
        ))
        .bind(target_record_id)
        .bind(deactivated_by)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;

        if batch.is_empty() {
            attome_db::tx::commit(tx).await?;
            break;
        }

        let ids: Vec<Uuid> = batch.into_iter().map(|(id,)| id).collect();
        attome_core::change_feed::emit_many(
            &mut tx,
            dependent_entity,
            &ids,
            attome_core::ChangeOperation::Delete,
        )
        .await?;
        // B16/T2-3 — same ledger the inline path writes to, so a subsequent
        // restore reactivates exactly the rows this job (and/or the inline
        // path, if the same delete's other dependent groups stayed small
        // enough to run synchronously) actually cascaded.
        record_cascade_batch(
            &mut tx,
            target_entity,
            target_record_id,
            dependent_entity,
            dependent_field,
            &ids,
        )
        .await?;
        attome_db::tx::commit(tx).await?;
    }

    Ok(())
}

/// What removed a record (A18-T2): the kind of operation, its id (so a whole
/// action can be restored at once) and the reason given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOrigin {
    pub kind: DeleteKind,
    /// The request, bulk batch, run or merge the delete belonged to; at most
    /// 64 characters.
    pub operation_id: String,
    pub reason: Option<String>,
}

/// `deletion.operation_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteKind {
    Request,
    Agent,
    Flow,
    Bulk,
    Import,
    Merge,
    Portal,
    Migration,
}

impl DeleteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Agent => "agent",
            Self::Flow => "flow",
            Self::Bulk => "bulk",
            Self::Import => "import",
            Self::Merge => "merge",
            Self::Portal => "portal",
            Self::Migration => "migration",
        }
    }
}

/// The longest reason kept.
pub const MAX_DELETE_REASON_CHARS: usize = 500;

impl DeleteOrigin {
    /// A delete of `kind` with a fresh operation id and no reason.
    pub fn new(kind: DeleteKind) -> Self {
        Self::with_id(kind, Uuid::now_v7().to_string())
    }

    /// A delete belonging to an operation the caller names (cut to 64
    /// characters).
    pub fn with_id(kind: DeleteKind, operation_id: impl Into<String>) -> Self {
        let operation_id: String = operation_id.into().trim().chars().take(64).collect();
        Self {
            kind,
            operation_id: if operation_id.is_empty() {
                Uuid::now_v7().to_string()
            } else {
                operation_id
            },
            reason: None,
        }
    }

    /// Adds the reason given (blank means none; cut to
    /// [`MAX_DELETE_REASON_CHARS`]).
    pub fn reason(mut self, reason: Option<&str>) -> Self {
        self.reason = reason
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(|r| r.chars().take(MAX_DELETE_REASON_CHARS).collect());
        self
    }
}

/// A18-T2: refuses a delete without a reason when the entity's bin setting
/// requires one; only people give reasons, so other kinds pass.
async fn require_delete_reason(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    origin: &DeleteOrigin,
) -> Result<(), AppError> {
    if origin.reason.is_some() || origin.kind != DeleteKind::Request {
        return Ok(());
    }
    let required: Option<bool> =
        sqlx::query_scalar("SELECT require_reason FROM bin_setting WHERE entity = $1")
            .bind(entity)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if required == Some(true) {
        return Err(AppError::Validation(
            "delete_reason_required: give a reason to delete this record".into(),
        ));
    }
    Ok(())
}

/// A18-T2: the bin's ledger row for a record this transaction removed.
async fn record_deletion(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    record_id: Uuid,
    deleted_by: Option<Uuid>,
    origin: &DeleteOrigin,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO deletion (id, entity, record_id, deleted_by, reason, operation_kind, operation_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (entity, record_id) WHERE restored_at IS NULL AND purged_at IS NULL DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(entity)
    .bind(record_id)
    .bind(deleted_by)
    .bind(origin.reason.as_deref())
    .bind(origin.kind.as_str())
    .bind(&origin.operation_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

pub async fn delete_one(
    tx: &mut Transaction<'_, Postgres>,
    target_entity_name: &str,
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    user_id: Uuid,
    expected_row_version: Option<i64>,
    origin: &DeleteOrigin,
) -> Result<MutationResult, AppError> {
    delete_one_as(
        tx,
        target_entity_name,
        dependents,
        record_id,
        Some(user_id),
        expected_row_version,
        origin,
    )
    .await
}

/// [`delete_one`] with an optional `modified_by` (`None` for a portal user,
/// D-579). Writes the bin's ledger row in the same transaction (A18-T2).
pub async fn delete_one_as(
    tx: &mut Transaction<'_, Postgres>,
    target_entity_name: &str,
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    modified_by: Option<Uuid>,
    expected_row_version: Option<i64>,
    origin: &DeleteOrigin,
) -> Result<MutationResult, AppError> {
    require_delete_reason(tx, target_entity_name, origin).await?;
    let policy = apply_dependents_on_delete(
        tx,
        target_entity_name,
        dependents,
        record_id,
        modified_by,
        expected_row_version,
    )
    .await?;
    record_deletion(tx, target_entity_name, record_id, modified_by, origin).await?;
    Ok(MutationResult {
        record_id,
        old_row: None,
        new_row: None,
        cascade_summary: policy.cascade_summary,
        approval: None,
        warnings: Vec::new(),
    })
}

/// C-08: restores a soft-deleted record. Same signature family as
/// [`delete_one`] — caller owns the transaction and (post-commit, outside
/// this `tx`) the invalidation hooks `invalidate_audit_user_if_systemuser`/
/// `invalidate_privilege_grant_target` — this owns the version/liveness
/// checks and the cascade reactivation (`reactivate_dependents_on_restore`).
///
/// Before this, restore was handler-local SQL (`entity_crud/mutations.rs`)
/// that only ever read `is_active`/`row_version` before flipping the flag —
/// it never re-checked whether this row's own lookup-typed fields still
/// point at something live. A lookup target can be soft-deleted at any time
/// after the record referencing it was itself deleted, so restoring without
/// re-validating could bring back a row pointing at nothing — the same
/// liveness gate `create_one`/`update_one` already run via
/// [`lock_lookup_targets`] on every other write, just never wired up here.
/// A restore changes no field value itself, so the values to re-validate are
/// exactly what's on the row today: this locks the row (`FOR UPDATE`) once,
/// reads its current column values, and runs `lock_lookup_targets` against
/// that snapshot before allowing the flip. A target that is no longer live
/// surfaces as `AppError::Validation` (422), same as any other write.
///
/// One over clippy's default arg-count threshold, same call `create_one`/
/// `update_one` already make on themselves (see their own doc comments):
/// every parameter here is an independent scalar/borrow the one call site
/// (`entity_crud/mutations.rs::restore_record`) already has in hand.
#[allow(clippy::too_many_arguments)]
pub async fn restore_one(
    tx: &mut Transaction<'_, Postgres>,
    state: &EngineState,
    entity_name: &str,
    attrs: &[AttrInfo],
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    user_id: Uuid,
    expected_row_version: Option<i64>,
) -> Result<MutationResult, AppError> {
    // D-535: a revoked engine-owned record (an API key) is never brought back
    // generically; the holder creates a new one through the owning route.
    validate_engine_owned_entity(state, entity_name)?;
    let table = quote_ident(entity_name);
    // Explicit projection (guidelines §4), not `SELECT *`: the same full
    // column set `create_one`/`update_one` project via `RETURNING`, so the
    // one snapshot below doubles as both the version/liveness check input
    // and the lookup-liveness check input.
    let cols = attome_core::select_columns(attrs, true);
    let snapshot: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 FOR UPDATE) t"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(snapshot) = snapshot else {
        return Err(AppError::NotFound);
    };

    // "already live" is checked first and unconditionally on the version:
    // it's true regardless of what version the caller expected, and it's
    // the more specific answer for a caller that tried to restore a record
    // that was never deleted.
    let old_active = snapshot.get("is_active").and_then(Value::as_bool);
    if old_active == Some(true) {
        return Err(AppError::Conflict("record is not deleted"));
    }
    let old_version = snapshot.get("row_version").and_then(Value::as_i64);
    if let (Some(expected), Some(current)) = (expected_row_version, old_version)
        && expected != current
    {
        return Err(AppError::VersionConflict);
    }

    // C-08's actual fix: re-validate lookup liveness before the row is let
    // back in. The `FOR UPDATE` above already holds this row's own lock;
    // `lock_lookup_targets` additionally takes `FOR KEY SHARE` on every
    // distinct lookup-target table this row's current values reference, so
    // nothing can deactivate a target out from under this restore between
    // the check and the commit below.
    //
    // System columns (`created_by`, `modified_by`, `owner_ref`,
    // `organization_ref`) are skipped: they are server-stamped provenance and
    // ownership, not user lookups, and a record created or owned by a user
    // who has since been deactivated must stay restorable.
    if let Some(obj) = snapshot.as_object() {
        let user_lookups: Vec<AttrInfo> = attrs
            .iter()
            .filter(|a| !attome_core::ALL_SYSTEM_COLS.contains(&a.logicalname.as_str()))
            .cloned()
            .collect();
        lock_lookup_targets(tx, state, &user_lookups, obj).await?;
    }

    // Same `WITH r AS (... RETURNING {cols}) SELECT row_to_json(r)` shape
    // `create_one` uses: `query_scalar::<Value>` decodes column 0 only, and a
    // bare `RETURNING {cols}` puts the `id` uuid there, which sqlx's JSON
    // decoder rejects (masked 500 on every restore).
    let sql = format!(
        "WITH r AS (UPDATE {table} SET is_active = true, row_version = row_version + 1, modified_at = NOW(), modified_by = $2 \
         WHERE id = $1 AND is_active IS NOT TRUE AND ($3::bigint IS NULL OR row_version = $3) \
         RETURNING {cols}) \
         SELECT row_to_json(r) FROM r"
    );
    // A18-T3: a value another live record took while this one was in the
    // bin (a unique field) is a 409 the caller can act on, not a 500.
    let new_row: Option<Value> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .bind(user_id)
        .bind(expected_row_version)
        .fetch_optional(&mut **tx)
        .await
        .map_err(attome_db::classify)?;
    // Defensive, not a race this function actually expects to hit: the `FOR
    // UPDATE` lock taken above is held for the rest of this transaction, and
    // the checks above already proved the predicate matches.
    let Some(new_row) = new_row else {
        return Err(AppError::VersionConflict);
    };
    // A18-T3: the bin's ledger row for this record is closed.
    sqlx::query(
        "UPDATE deletion SET restored_at = NOW(), restored_by = $3 \
         WHERE entity = $1 AND record_id = $2 AND restored_at IS NULL AND purged_at IS NULL",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    // D-358: the restored record's own change-feed row. The cascade's
    // dependents get theirs inside `reactivate_dependents_on_restore` below;
    // without this one the record the caller actually restored is the only
    // one a derived copy never hears about.
    attome_core::change_feed::emit_tx(
        tx,
        entity_name,
        record_id,
        attome_core::ChangeOperation::Restore,
    )
    .await?;

    let cascade_summary =
        reactivate_dependents_on_restore(tx, dependents, record_id, user_id).await?;

    Ok(MutationResult {
        record_id,
        old_row: Some(snapshot),
        new_row: Some(new_row),
        cascade_summary,
        approval: None,
        warnings: Vec::new(),
    })
}

/// C-08: permanently removes a record. Same signature family as
/// [`delete_one`] — caller owns the transaction, the legal-hold gate, and
/// (post-commit) the invalidation hooks; this owns the referential-integrity
/// guard, optimistic concurrency, and the physical `DELETE` + change-feed
/// emission.
///
/// Unlike a soft delete's `apply_dependents_on_delete` (whose referenced-by
/// check only fires for `OnTargetDelete::Restrict`), this refuses ANY
/// reference from `dependents` — active or not — regardless of policy: a
/// physically removed row can never be a valid lookup target again, so
/// leaving even a `CascadeDeactivate`/`SetNull` dependent pointed at it would
/// manufacture a dangling foreign key the metadata says can't exist. Same
/// behavior the handler-local SQL this replaces already had.
///
/// Returns the pre-delete row as `old_row` so the caller (which still owns
/// file-storage cleanup and the audit snapshot — both outside this
/// primitive's concern) doesn't need a second `SELECT` for the same row.
pub async fn hard_delete_one(
    tx: &mut Transaction<'_, Postgres>,
    entity_name: &str,
    dependents: &[(String, String, OnTargetDelete)],
    record_id: Uuid,
    // Unused: a physical DELETE leaves no row to stamp `modified_by` on, and
    // the audit event (the only other place this would matter) is the
    // caller's own concern, same as `delete_one`. Kept, prefixed, only to
    // hold this function's signature in the same family as `delete_one`/
    // `restore_one` (same positional shape a future caller can rely on).
    _user_id: Uuid,
    expected_row_version: Option<i64>,
) -> Result<MutationResult, AppError> {
    let table = quote_ident(entity_name);
    let snapshot: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(target) FROM {table} AS target WHERE id = $1 FOR UPDATE"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(snapshot) = snapshot else {
        return Err(AppError::NotFound);
    };

    let mut dependents = dependents.to_vec();
    dependents.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    for (dep_entity, dep_field, _) in &dependents {
        let dep_table = quote_ident(dep_entity);
        let dep_column = quote_ident(dep_field);
        let referenced: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {dep_table} WHERE {dep_column} = $1)"
        ))
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if referenced {
            return Err(AppError::Conflict(
                "cannot permanently delete: another record still references this record",
            ));
        }
    }

    // DATA-7/CONC-1 — optional `If-Match`. The predicate is a no-op when the
    // caller sent no header ($2 IS NULL), so a header-less hard delete keeps
    // exactly the same behaviour as before this was a primitive, including
    // not treating "no such row" as an error at this step (already handled
    // by the `NotFound` above).
    let deleted = sqlx::query(&format!(
        "DELETE FROM {table} WHERE id = $1 AND ($2::bigint IS NULL OR row_version = $2)"
    ))
    .bind(record_id)
    .bind(expected_row_version)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if expected_row_version.is_some() && deleted.rows_affected() == 0 {
        // The caller's access checks and the snapshot above already proved
        // the record exists and is reachable, so a zero here means the
        // version moved under them.
        return Err(AppError::VersionConflict);
    }

    // Security review follow-up (D-788 §8.2): a hard-deleted record's values
    // archived by a type conversion or a field delete must not outlive the
    // record. Erased in the delete's own transaction, so a rolled-back delete
    // keeps them and a committed one leaves none behind.
    let erased = attome_core::recovery_archive::erase_record(tx, entity_name, record_id).await?;
    if erased > 0 {
        tracing::info!(
            entity = %entity_name,
            record_id = %record_id,
            erased,
            "hard delete: erased the record's recovery-archive values"
        );
    }
    // A18: the record is gone, so its bin entry (if it was in the bin) is
    // closed as purged rather than left restorable.
    sqlx::query(
        "UPDATE deletion SET purged_at = NOW()          WHERE entity = $1 AND record_id = $2 AND restored_at IS NULL AND purged_at IS NULL",
    )
    .bind(entity_name)
    .bind(record_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    attome_core::change_feed::emit_tx(
        tx,
        entity_name,
        record_id,
        attome_core::ChangeOperation::Delete,
    )
    .await?;

    Ok(MutationResult {
        record_id,
        old_row: Some(snapshot),
        new_row: None,
        cascade_summary: Vec::new(),
        approval: None,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod insert_bind_tests {
    use super::*;
    use attome_core::meta_registry::{DataClassification, OnTargetDelete};

    fn attr(logicalname: &str, field_type_int: i32) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
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

    /// A28-T1: declared defaults fill only empty attributes.
    #[test]
    fn defaults_fill_only_empty_attributes() {
        let with_default = |name: &str, ft: i32, default: Value| AttrInfo {
            options: Some(serde_json::json!({ "default": default })),
            ..attr(name, ft)
        };
        let attrs = [
            with_default(
                "status",
                0,
                serde_json::json!({"kind": "fixed", "value": "open"}),
            ),
            with_default("opened_on", 3, serde_json::json!({"kind": "today"})),
            with_default("owner", 11, serde_json::json!({"kind": "current_user"})),
            with_default("count", 2, serde_json::json!({"kind": "fixed", "value": 0})),
        ];
        let actor = uuid::Uuid::now_v7();
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-14T23:30:00+03:00").unwrap();
        let mut obj = serde_json::Map::new();
        obj.insert("status".into(), serde_json::json!(""));
        obj.insert("count".into(), serde_json::json!(7));
        let out = apply_defaults(&attrs, &obj, Some(actor), now).unwrap();
        assert_eq!(out["status"], "open", "an empty string is empty");
        assert_eq!(out["opened_on"], "2026-10-14", "the deployment's local day");
        assert_eq!(out["owner"], actor.to_string());
        assert_eq!(out["count"], 7, "a sent value is never replaced");
        assert!(apply_defaults(&attrs, &out, Some(actor), now).is_none());
    }

    /// `create_one`/`upsert_record` splice `organization_ref` in themselves, so
    /// emitting it from the body too named it twice in the INSERT column list
    /// (Postgres 42701 -> bare 500). `user_account` defines it as a real
    /// metadata attribute, so the metadata-driven user form posted it back on
    /// every create and every create failed.
    #[test]
    fn system_managed_columns_are_never_bound_from_the_body() {
        let attrs = [
            attr("user_name", 0),
            attr("organization_ref", 11),
            attr("owner_ref", 11),
            attr("owner_type", 1),
            attr("created_by", 11),
            attr("modified_by", 11),
        ];
        let obj = serde_json::json!({
            "user_name": "swsws",
            "organization_ref": serde_json::Value::Null,
            "owner_ref": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "owner_type": 0,
            "created_by": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "modified_by": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
        });
        let obj = obj.as_object().expect("test literal is an object");

        let (cols, placeholders, values) = build_insert_binds(&attrs, obj, 6);

        assert_eq!(cols, vec![quote_ident("user_name")]);
        assert_eq!(placeholders.len(), 1);
        assert_eq!(values.len(), 1);
        for reserved in attome_core::ALL_SYSTEM_COLS {
            assert!(
                !cols.contains(&quote_ident(reserved)),
                "{reserved} must come from the caller's context, not the request body"
            );
        }
    }

    /// SEC-1 regression — the update-path mirror of the test above, and the
    /// one that was missing while `build_update_binds` had no filter at all.
    ///
    /// A user holding only ordinary `{entity}.update` privilege plus
    /// record-level Update access on a single record could
    /// `PATCH /api/v1/{entity}/{id}` and move the record across the RLS
    /// boundary (`organization_ref`, read directly by `attome_security::rls`),
    /// reassign ownership around the admin-gated `reassign-owner` endpoint
    /// (`owner_ref`/`owner_type`), forge audit attribution (`created_by`), or
    /// soft-delete without the delete path's audit event and cascade policy
    /// (`is_active`). Neither upstream validator caught it: `validate_body`
    /// rejects only fields *absent* from metadata and these are registered
    /// attributes, and `validate_field_write_grants` gates only
    /// `is_sensitive` fields, which ownership columns are not by default.
    ///
    /// `modified_at`/`modified_by`/`row_version` were safe only by accident —
    /// `update_one`'s SQL appends them to the same `SET` clause, so a
    /// body-supplied value was a duplicate assignment (Postgres 42701 -> bare
    /// 500). They are covered here for the same reason as the rest, which
    /// also turns that 500 into a working full-row PATCH.
    #[test]
    fn system_managed_columns_are_never_bound_from_the_body_on_update() {
        let attrs = [
            attr("user_name", 0),
            attr("id", 11),
            attr("organization_ref", 11),
            attr("owner_ref", 11),
            attr("owner_type", 1),
            attr("created_by", 11),
            attr("created_at", 5),
            attr("modified_by", 11),
            attr("modified_at", 5),
            attr("is_active", 6),
            attr("row_version", 1),
        ];
        let obj = serde_json::json!({
            "user_name": "swsws",
            "id": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "organization_ref": "019fe235-3b81-7d7d-b6a8-7d60c4c57252",
            "owner_ref": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "owner_type": 0,
            "created_by": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "created_at": "2020-01-01T00:00:00Z",
            "modified_by": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "modified_at": "2020-01-01T00:00:00Z",
            "is_active": false,
            "row_version": 99,
        });
        let obj = obj.as_object().expect("test literal is an object");

        let (set_parts, values) = build_update_binds(&attrs, obj, 3);

        assert_eq!(
            set_parts,
            vec![format!("{} = $3", quote_ident("user_name"))],
            "only the ordinary field may reach the SET clause"
        );
        assert_eq!(values.len(), 1);
        for reserved in attome_core::ALL_SYSTEM_COLS {
            assert!(
                !set_parts
                    .iter()
                    .any(|s| s.starts_with(&quote_ident(reserved))),
                "{reserved} must never be writable from an update body"
            );
        }
    }

    /// Both builders drop the same columns, from the same list — the property
    /// SEC-1 is really about. A future mutation path that reuses either
    /// builder inherits it; one that hand-rolls its own SET clause is what
    /// SEC-3's cross-entry-point test is for.
    #[test]
    fn insert_and_update_exclude_the_same_columns() {
        for reserved in attome_core::ALL_SYSTEM_COLS {
            let attrs = [attr("user_name", 0), attr(reserved, 0)];
            let mut obj = serde_json::Map::new();
            obj.insert("user_name".to_owned(), serde_json::json!("x"));
            obj.insert((*reserved).to_owned(), serde_json::json!("x"));

            let (insert_cols, _, insert_values) = build_insert_binds(&attrs, &obj, 1);
            let (set_parts, update_values) = build_update_binds(&attrs, &obj, 3);

            assert_eq!(insert_cols, vec![quote_ident("user_name")], "{reserved}");
            assert_eq!(insert_values.len(), 1, "{reserved}");
            assert_eq!(
                set_parts,
                vec![format!("{} = $3", quote_ident("user_name"))],
                "{reserved}"
            );
            assert_eq!(update_values.len(), 1, "{reserved}");
        }
    }

    /// The update builder's exclusion is name-based, exactly like the insert
    /// builder's, so ordinary fields — including lookups — still bind, and the
    /// placeholder numbering stays contiguous from `start_param`.
    #[test]
    fn ordinary_fields_are_still_bound_on_update() {
        let attrs = [
            attr("user_name", 0),
            attr("organization_ref", 11),
            attr("manager_ref", 11),
        ];
        let obj = serde_json::json!({
            "user_name": "swsws",
            "organization_ref": "019fe235-3b81-7d7d-b6a8-7d60c4c57251",
            "manager_ref": serde_json::Value::Null,
        });
        let obj = obj.as_object().expect("test literal is an object");

        let (set_parts, values) = build_update_binds(&attrs, obj, 3);

        assert_eq!(
            set_parts,
            vec![
                format!("{} = $3", quote_ident("user_name")),
                format!("{} = $4::uuid", quote_ident("manager_ref")),
            ]
        );
        assert_eq!(values.len(), 2);
    }

    /// A client-supplied `is_active` is dropped from the insert entirely, so
    /// the column's `DEFAULT TRUE` decides the new row's lifecycle state.
    ///
    /// The `null` case is the regression this locks down: a JSON `null` binds
    /// as SQL NULL, NULL overrides the column default, and every generic read
    /// filters `is_active = true` — so the record came back 404 from the GET
    /// immediately following its own 201. Any metadata-driven form submits
    /// exactly this for a control the user never touched, and `is_active` is a
    /// registered attribute on `user_account`.
    #[test]
    fn is_active_is_never_bound_from_the_body() {
        let attrs = [attr("user_name", 0), attr("is_active", 6)]; // 6 = bool

        for supplied in [
            serde_json::Value::Null,
            serde_json::Value::Bool(false),
            serde_json::Value::Bool(true),
        ] {
            let obj = serde_json::json!({ "user_name": "ffff", "is_active": supplied });
            let obj = obj.as_object().expect("test literal is an object");

            let (cols, placeholders, values) = build_insert_binds(&attrs, obj, 6);

            assert_eq!(
                cols,
                vec![quote_ident("user_name")],
                "is_active must never reach the INSERT column list"
            );
            assert_eq!(placeholders.len(), 1);
            assert_eq!(values.len(), 1);
        }
    }

    /// The filter keys off the column name only, so an ordinary lookup field is
    /// still bound normally.
    #[test]
    fn ordinary_fields_are_still_bound() {
        let attrs = [attr("user_name", 0), attr("manager_ref", 11)];
        let obj =
            serde_json::json!({ "user_name": "swsws", "manager_ref": serde_json::Value::Null });
        let obj = obj.as_object().expect("test literal is an object");

        let (cols, _, values) = build_insert_binds(&attrs, obj, 6);

        assert_eq!(
            cols,
            vec![quote_ident("user_name"), quote_ident("manager_ref")]
        );
        assert_eq!(values.len(), 2);
    }
}

/// D-524 — every branch of the create-time engine-managed field rule. The rule
/// runs at the top of `create_one` for every `MutationMode`, so these cover
/// POST, bulk, upsert, staged import, S2S and bundle record sets alike.
#[cfg(test)]
mod engine_managed_initial_value_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn managed() -> HashSet<(String, String)> {
        [
            ("attome_dashboard", "lifecycle_status"),
            ("attome_dashboard", "published_version_id"),
            ("dashboard_decision", "status"),
        ]
        .into_iter()
        .map(|(e, f)| (e.to_owned(), f.to_owned()))
        .collect()
    }

    fn initials() -> HashMap<(String, String), String> {
        [
            ("attome_dashboard", "lifecycle_status", "draft"),
            ("dashboard_decision", "status", "proposed"),
        ]
        .into_iter()
        .map(|(e, f, v)| ((e.to_owned(), f.to_owned()), v.to_owned()))
        .collect()
    }

    fn body(v: serde_json::Value) -> serde_json::Map<String, Value> {
        v.as_object().expect("test literal is an object").clone()
    }

    fn run(
        entity: &str,
        v: serde_json::Value,
    ) -> Result<Option<serde_json::Map<String, Value>>, AppError> {
        engine_managed_initial_body(&managed(), &initials(), entity, &body(v))
    }

    #[test]
    fn an_omitted_field_gets_its_initial_value_written() {
        let merged = run("attome_dashboard", serde_json::json!({ "name": "x" }))
            .unwrap()
            .expect("the initial value must be written");
        assert_eq!(merged["lifecycle_status"], "draft");
        assert_eq!(merged["name"], "x");
        assert!(!merged.contains_key("published_version_id"));
    }

    #[test]
    fn a_null_field_gets_its_initial_value_written() {
        let merged = run(
            "attome_dashboard",
            serde_json::json!({ "lifecycle_status": null }),
        )
        .unwrap()
        .expect("the initial value must be written");
        assert_eq!(merged["lifecycle_status"], "draft");
    }

    #[test]
    fn the_declared_initial_value_is_accepted_unchanged() {
        assert!(matches!(
            run(
                "dashboard_decision",
                serde_json::json!({ "status": "proposed" })
            ),
            Ok(None)
        ));
    }

    #[test]
    fn any_other_value_is_rejected() {
        for bad in [
            serde_json::json!({ "lifecycle_status": "published" }),
            serde_json::json!({ "lifecycle_status": "approved" }),
            serde_json::json!({ "lifecycle_status": 1 }),
        ] {
            let err = run("attome_dashboard", bad.clone()).expect_err("must be rejected");
            assert!(
                matches!(&err, AppError::Validation(m) if m.contains("must start as 'draft'")),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn a_managed_field_without_an_initial_value_must_be_left_unset() {
        assert!(matches!(
            run(
                "attome_dashboard",
                serde_json::json!({ "lifecycle_status": "draft", "published_version_id": null })
            ),
            Ok(None)
        ));
        let err = run(
            "attome_dashboard",
            serde_json::json!({
                "lifecycle_status": "draft",
                "published_version_id": "018f1c2e-6b7a-7c3d-8b1a-000000000001",
            }),
        )
        .expect_err("a pointer set on create must be rejected");
        assert!(matches!(&err, AppError::Validation(m) if m.contains("leave it unset on create")));
    }

    #[test]
    fn an_entity_with_no_managed_fields_is_untouched() {
        assert!(matches!(
            run(
                "attome_project",
                serde_json::json!({ "status": "anything" })
            ),
            Ok(None)
        ));
    }
}

#[cfg(test)]
mod metadata_table_lock_tests {
    use super::metadata_table_lock_applies;

    #[test]
    fn production_people_writing_metadata_tables_are_locked() {
        for table in [
            "role",
            "privilege",
            "workflow_definition",
            "role_mm_privilege",
        ] {
            assert!(
                metadata_table_lock_applies("production", true, table),
                "{table}"
            );
        }
    }

    #[test]
    fn system_writers_other_profiles_and_ordinary_tables_are_not() {
        assert!(!metadata_table_lock_applies("production", false, "role"));
        assert!(!metadata_table_lock_applies("development", true, "role"));
        assert!(!metadata_table_lock_applies("test", true, "role"));
        assert!(!metadata_table_lock_applies("production", true, "account"));
        assert!(!metadata_table_lock_applies(
            "production",
            true,
            "user_account_mm_role"
        ));
    }
}
