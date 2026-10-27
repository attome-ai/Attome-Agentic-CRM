//! Enterprise-safe bulk mutations and staged imports.
//!
//! Bulk requests are durable jobs, but each item still uses the same
//! transaction-scoped mutation engine as interactive CRUD.  Lookup liveness,
//! hierarchy-cycle protection, delete policy, and optimistic concurrency are
//! therefore enforced per record.  The item ledger makes retries idempotent:
//! a worker resumes at the first item that has not committed successfully.
//!
//! D-100: staged-import approval (`POST .../staged-import/{id}/approve`) is
//! enqueued the same way, not run inline on the request thread — it has its
//! own `automation_staged_import_item` ledger mirroring `automation_bulk_operation_item`,
//! for the same crash/redelivery-safety reasons. `MutationMode::
//! ApprovedStagedImport` skips lookup-liveness only (the feature's stated
//! purpose is legacy data with dangling references); hierarchy-cycle
//! protection always runs, for every mode.

use attome_server::authz::{Authorized, Privilege, RecordScoped, area};
use attome_server::capability::{Available, BatchJobs};
use std::collections::HashSet;

use attome_audit::{
    Attribution, AuditCategory, AuditEvent, AuditOperation, AuditOutcome, AuditRequestContext,
    AuditService, AuditSource, write_bulk_accepted, write_bulk_completed_once,
};
use attome_auth::SessionClaims;
use attome_core::{AttrInfo, EngineState, OnTargetDelete};
use attome_security::record_action::{Bulk, Read};
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::middleware::idempotency_durable;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{AppError, BatchResult, ItemResult, PageBase, PageWindow, Problem};
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    bulk_graph, entity_crud,
    entity_mutation::{self, MutationMode, MutationResult},
};
use attome_types::ErrorResponse;
use utoipa::{IntoParams, ToSchema};

// D-098's release gate calls for a P50/P99 measurement against a
// production-shaped database before the cap can be 5,000 — that measurement
// has not run (coding-guidelines §14.5). Capped at a value the existing
// audit_throughput_load-style in-process tests have actually exercised
// until that measurement lands; raise it only alongside the measurement,
// not ahead of it.
const MAX_BULK_RECORDS: usize = 500;
const DEFAULT_ITEM_PAGE_SIZE: i64 = 100;

/// The resolved entity a bulk/staged-import item mutates against, grouped so
/// `apply_ledgered_item`/`dry_run_one` take one borrow instead of four
/// separate parameters — both need the identical cluster.
struct EntityMutationTarget<'a> {
    entity_id: Uuid,
    entity_name: &'a str,
    attrs: &'a [AttrInfo],
    dependents: &'a [(String, String, OnTargetDelete)],
}

/// `state`+`ctx` bundled the same way `EntityMutationTarget` bundles the
/// entity cluster — `apply_ledgered_item`/`dry_run_one` need both together
/// for `entity_crud::require_record_access`'s record-level gate
/// (enterprise-audit remediation, Phase 1.6), and threading them as two
/// separate parameters pushes those functions over clippy's
/// `too_many_arguments` limit.
struct RequestContext<'a> {
    state: &'a EngineState,
    ctx: &'a SecurityContext,
}

/// M01-core C-11 — which ledger `apply_ledgered_item`/`process_ledger` are
/// driving. `apply_one`/`apply_staged_one` and `process`/`process_staged_import`
/// used to be near-duplicates of each other, differing only in which
/// table/column pair holds the per-record progress row, the `MutationMode`
/// the mutation itself runs under, and a couple of user-facing message
/// strings — this enum is the one place that difference lives now.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LedgerTable {
    /// `POST /{entity}/bulk` — `automation_bulk_operation`/`..._item`,
    /// keyed by `bulk_operation_id`. Runs under `MutationMode::Strict`: the
    /// ordinary lookup-liveness gate applies.
    BulkItem,
    /// `POST /{entity}/staged-import/{id}/approve` —
    /// `automation_staged_import`/`..._item`, keyed by `staged_import_id`.
    /// Runs under `MutationMode::ApprovedStagedImport` (D-100): lookup-
    /// liveness is skipped, since admitting legacy data with dangling
    /// references is the feature's whole point.
    StagedItem,
}

impl LedgerTable {
    /// The per-item progress table this variant claims/updates rows in.
    fn item_table(self) -> &'static str {
        match self {
            Self::BulkItem => "automation_bulk_operation_item",
            Self::StagedItem => "automation_staged_import_item",
        }
    }

    /// The FK column on `item_table()` naming the parent batch/import row.
    fn id_column(self) -> &'static str {
        match self {
            Self::BulkItem => "bulk_operation_id",
            Self::StagedItem => "staged_import_id",
        }
    }

    /// The parent row's own table — `process_ledger`'s early-failure and
    /// closing writes.
    fn parent_table(self) -> &'static str {
        match self {
            Self::BulkItem => "automation_bulk_operation",
            Self::StagedItem => "automation_staged_import",
        }
    }

    /// `entity_mutation::create_one`/`update_one`'s `MutationMode` for this
    /// ledger.
    fn mutation_mode(self) -> MutationMode {
        match self {
            Self::BulkItem => MutationMode::Strict,
            Self::StagedItem => MutationMode::ApprovedStagedImport,
        }
    }

    /// The parent row's status literal and JSON column an early,
    /// whole-batch failure (`mark_batch_failed`) writes to — bulk closes
    /// early failures to `'failed'`/`errors`, staged import to
    /// `'rejected'`/`validation_report` (its own `'rejected'` is a batch-
    /// level outcome, a different concept from an individual item's
    /// `'rejected'` ledger status — same word, two levels, see
    /// `process_ledger`'s closing `match` for the other one).
    fn early_failure_status_and_column(self) -> (&'static str, &'static str) {
        match self {
            Self::BulkItem => ("failed", "errors"),
            Self::StagedItem => ("rejected", "validation_report"),
        }
    }

    /// Short label for this variant's user-facing early-failure messages.
    fn label(self) -> &'static str {
        match self {
            Self::BulkItem => "bulk",
            Self::StagedItem => "staged-import",
        }
    }

    fn unknown_operation_message(self) -> &'static str {
        match self {
            Self::BulkItem => "unknown bulk operation",
            Self::StagedItem => "unknown staged-import operation",
        }
    }

    fn append_only_message(self) -> &'static str {
        match self {
            Self::BulkItem => "entity is append-only; bulk mutation is not supported",
            Self::StagedItem => "entity is append-only; staged import apply is not supported",
        }
    }
}

/// Bundles `apply_ledgered_item`'s ledger-identity parameters — same "stay
/// under clippy's `too_many_arguments` limit via a struct, not an `#[allow]`"
/// discipline `RequestContext`/`EntityMutationTarget` above already follow,
/// not a semantically meaningful grouping on its own. `migration_run_id` is
/// always `None` for `LedgerTable::BulkItem` (plain bulk mutations have no
/// migration-rollback ledger) — see `apply_ledgered_item`'s own doc comment
/// for the staged-import case.
struct LedgerContext {
    ledger: LedgerTable,
    batch_id: Uuid,
    // M17/D-433 — set only when this staged import is linked to a
    // `migration_run`. See `apply_ledgered_item`'s doc comment.
    migration_run_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
struct BulkRequestBody {
    operation: String,
    #[serde(default)]
    strict: Option<bool>,
    // P-bulk-batch-integrity Gap C: opt-in, defaults to "partial" — every
    // existing caller that doesn't set this field gets byte-identical
    // behavior to before this field existed. Validated ("partial"/"atomic"
    // only) in `validate_request_shape`.
    #[serde(default)]
    batch_mode: Option<String>,
    // M12 (data management) — an `data_mapping` id, applied once at
    // submission time before the preflight/dry-run loop (field rename +
    // lookup resolution; `transform` stays unevaluated, D-408). Only
    // meaningful for `staged_import`; `enqueue` (plain bulk) rejects a
    // non-`None` value rather than silently ignoring it — see `enqueue`'s
    // own check, right after `validate_request_shape`.
    #[serde(default)]
    mapping_ref: Option<Uuid>,
    // M17 (data migration, D-433) — `"stage"` (default, unset) or
    // `"dry_run"`. Only meaningful for `staged_import`, same "enqueue
    // rejects a non-`None` value" contract as `mapping_ref` above. A
    // staged import is already structurally incapable of writing anything
    // before approval; `mode: "dry_run"` additionally marks the row so
    // `POST .../staged-import/{id}/approve` refuses it outright — see that
    // handler's own check.
    #[serde(default)]
    mode: Option<String>,
    /// A28-T3: `false` leaves empty fields empty on create instead of filling
    /// them with their attributes' defaults. Default true.
    #[serde(default)]
    apply_defaults: Option<bool>,
    /// B5-T3: `true` runs the operation without automation: its changes start
    /// no flow (nor an agent a flow runs) and notify no follower. Needs the
    /// `records.bulk_quiet` privilege. Default false.
    #[serde(default)]
    quiet: Option<bool>,
    records: Vec<BulkRecordEnvelope>,
}

impl BulkRequestBody {
    /// Carries `apply_defaults: false` onto every record, so the worker (or a
    /// staged import's approval, much later) sees it with the record.
    fn mark_skip_defaults(&mut self) {
        if self.apply_defaults == Some(false) {
            for record in &mut self.records {
                record.skip_defaults = true;
            }
        }
    }
}

/// `pub(crate)` so `bulk_graph.rs`'s pure preflight functions can operate on
/// the same envelope shape the HTTP layer and the worker already share,
/// instead of introducing a second, parallel record representation.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub(crate) struct BulkRecordEnvelope {
    #[serde(default)]
    pub(crate) id: Option<Uuid>,
    #[serde(default)]
    pub(crate) expected_row_version: Option<i64>,
    pub(crate) data: Value,
    /// A28-T3: create this record without attribute defaults.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) skip_defaults: bool,
}

#[derive(Serialize, ToSchema)]
struct BulkOperationResponse {
    id: Uuid,
    status: String,
    total: i32,
}

#[derive(Serialize, ToSchema)]
struct BulkOperationStatus {
    id: Uuid,
    entity_logicalname: String,
    operation: String,
    status: String,
    total: i32,
    succeeded: i32,
    failed: i32,
    // P-bulk-batch-integrity Gap C: items the batch preflight rejected up
    // front, before any attempt — a subset of `total`, disjoint from
    // `succeeded`/`failed`.
    rejected: i32,
    errors: Value,
    /// With `include_items`: one result per item of this page, by its index
    /// in the request (Z14-T6's `BatchResult`): `ok` when it applied,
    /// `problem` (`version_conflict` with the record's current version in
    /// `detail`, or `item_failed`) when it did not, neither while it has not
    /// run.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    items: Option<BatchResult<BulkItemOk>>,
}

/// An applied bulk item: the record it wrote and how many attempts it took.
#[derive(Serialize, ToSchema)]
struct BulkItemOk {
    record_id: Option<Uuid>,
    attempts: i32,
}

#[derive(sqlx::FromRow)]
struct BulkOperationStatusRow {
    id: Uuid,
    entity_logicalname: String,
    operation: String,
    status: String,
    total: i32,
    succeeded: i32,
    failed: i32,
    rejected: i32,
    errors: Value,
}

#[derive(sqlx::FromRow)]
struct BulkItemStatus {
    item_index: i32,
    record_id: Option<Uuid>,
    status: String,
    /// A16-T6: `ok`, `conflict` (the row's `expected_row_version` was stale;
    /// see `conflict`), `error`, or `pending` while the row has not run.
    outcome: String,
    error: Option<String>,
    /// A16-T6: for a conflict, the record's current version and what changed
    /// since the row's version (`current_version`, `current_state`).
    conflict: Option<Value>,
    attempts: i32,
}

impl BulkItemStatus {
    /// Z14-T6: the ledger row as a standard item result.
    fn into_result(self) -> ItemResult<BulkItemOk> {
        let index = i64::from(self.item_index);
        match self.outcome.as_str() {
            "ok" => ItemResult::ok(
                index,
                BulkItemOk {
                    record_id: self.record_id,
                    attempts: self.attempts,
                },
            ),
            "conflict" => ItemResult::problem(
                index,
                Problem {
                    code: "version_conflict".to_owned(),
                    message: self.error.unwrap_or_else(|| {
                        "the record changed since the version this item named".to_owned()
                    }),
                    detail: self.conflict,
                },
            ),
            "error" => ItemResult::problem(
                index,
                Problem {
                    code: "item_failed".to_owned(),
                    message: self
                        .error
                        .unwrap_or_else(|| format!("item {}", self.status)),
                    detail: Some(serde_json::json!({
                        "status": self.status,
                        "attempts": self.attempts,
                    })),
                },
            ),
            _ => ItemResult::pending(index),
        }
    }
}

/// A16-T6: a ledger row's outcome, from its status and conflict.
const ITEM_OUTCOME_SQL: &str = "CASE WHEN status = 'succeeded' THEN 'ok' \
     WHEN conflict IS NOT NULL THEN 'conflict' \
     WHEN status IN ('failed', 'rejected') THEN 'error' ELSE 'pending' END";

#[derive(Deserialize, Default, IntoParams)]
#[into_params(parameter_in = Query)]
struct BulkStatusQuery {
    /// Include each item's outcome.
    #[serde(default)]
    include_items: Option<bool>,
    /// One-based: page 1 is the first page.
    #[serde(default)]
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Items per page, clamped to `1..=MAX_PAGE_SIZE`; defaults to 100.
    #[serde(default)]
    page_size: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct StagedImportResponse {
    id: Uuid,
    status: String,
    total: i32,
    passed: i32,
    failed: i32,
    // P-bulk-batch-integrity Gap A: batch-level findings (an intra-batch
    // hierarchy cycle or unique-key collision), reported distinctly from a
    // per-record dry-run `failed` so a reviewing admin can tell "this one
    // record's own data is invalid" apart from "this record is fine alone
    // but conflicts with another record in the same batch."
    rejected: i32,
    // M17/D-433 — a bounded sample (see `MAX_SAMPLE_DIFF`) of passed
    // `"update"` records' before/after values, computed for free from the
    // same rolled-back dry-run pass that built `validation_report`. Always
    // empty for `approve_staged_import`'s response (nothing left to preview
    // by then) and for `"create"`/`"delete"` batches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sample_diff: Vec<Value>,
}

#[derive(sqlx::FromRow)]
struct StagedImportRow {
    operation: String,
    raw_records: Value,
    validation_report: Value,
    batch_mode: String,
}

fn valid_bulk_operation(operation: &str) -> bool {
    matches!(operation, "create" | "update" | "delete")
}

/// P-bulk-batch-integrity Gap C: "partial" is the unconditional default,
/// matching every caller's behavior before `batch_mode` existed.
fn effective_batch_mode(body: &BulkRequestBody) -> &str {
    body.batch_mode.as_deref().unwrap_or("partial")
}

/// M17/D-433: `"stage"` is the unconditional default, matching every
/// caller's behavior before `mode` existed.
fn effective_mode(body: &BulkRequestBody) -> &str {
    body.mode.as_deref().unwrap_or("stage")
}

/// Merges same-index preflight findings (a record can be flagged by both the
/// cycle check and the collision check) into one reason string per offending
/// index, sorted by index — the shape both the atomic-mode 422 message and
/// the partial-mode `'rejected'`-seeding UPDATE need.
fn merge_preflight_findings(findings: Vec<bulk_graph::Finding>) -> Vec<(i32, String)> {
    let mut merged: std::collections::BTreeMap<i32, Vec<String>> =
        std::collections::BTreeMap::new();
    for (index, reason) in findings {
        merged.entry(index as i32).or_default().push(reason);
    }
    merged
        .into_iter()
        .map(|(index, reasons)| (index, reasons.join("; ")))
        .collect()
}

/// The atomic-mode 422 rejection message: names every offending item index
/// and its reason so the caller can see exactly what the batch's own payload
/// conflicts with, without needing to inspect any ledger row (none was ever
/// written for this request).
fn atomic_rejection_message(preflight: &[(i32, String)]) -> String {
    let items = preflight
        .iter()
        .map(|(index, reason)| format!("item {index}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ");
    format!("batch rejected (batch_mode=\"atomic\"): {items}")
}

/// AA9-T3: the records one bulk request may carry: the runtime setting
/// `limits.bulk.max_records_per_request` when one is stored, else
/// [`MAX_BULK_RECORDS`].
fn bulk_cap(state: &EngineState) -> usize {
    state
        .runtime_limit("bulk.max_records_per_request")
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_BULK_RECORDS)
}

fn validate_request_shape(body: &BulkRequestBody, max_records: usize) -> Result<(), AppError> {
    if !valid_bulk_operation(&body.operation) {
        return Err(AppError::Validation(format!(
            "operation must be create, update, or delete, got: {}",
            body.operation
        )));
    }
    if body.strict == Some(false) {
        return Err(AppError::Validation(
            "bulk mutation safeguards cannot be disabled".into(),
        ));
    }
    if let Some(mode) = body.batch_mode.as_deref()
        && !matches!(mode, "partial" | "atomic")
    {
        return Err(AppError::Validation(format!(
            "batch_mode must be \"partial\" or \"atomic\", got: {mode}"
        )));
    }
    if let Some(mode) = body.mode.as_deref()
        && !matches!(mode, "stage" | "dry_run")
    {
        return Err(AppError::Validation(format!(
            "mode must be \"stage\" or \"dry_run\", got: {mode}"
        )));
    }
    if body.records.is_empty() {
        return Err(AppError::Validation("records must not be empty".into()));
    }
    if body.records.len() > max_records {
        // AA9-T4: named, with the way forward.
        return Err(AppError::LimitExceeded {
            limit: "bulk.max_records_per_request",
            value: max_records as i64,
            next: attome_types::error::NextStep::Split,
        });
    }
    for (index, record) in body.records.iter().enumerate() {
        validate_record_envelope(&body.operation, record)
            .map_err(|e| AppError::Validation(format!("record {index}: {e}")))?;
    }
    Ok(())
}

fn validate_record_envelope(
    operation: &str,
    record: &BulkRecordEnvelope,
) -> Result<(), &'static str> {
    match operation {
        "create" => {
            if record.id.is_some() || record.expected_row_version.is_some() {
                return Err("create records must not include id or expected_row_version");
            }
        }
        "update" | "delete" => {
            if record.id.is_none() {
                return Err("update and delete records require id");
            }
            if record.expected_row_version.is_none() {
                return Err("update and delete records require expected_row_version");
            }
            if record
                .expected_row_version
                .is_some_and(|version| version < 0)
            {
                return Err("expected_row_version must be non-negative");
            }
        }
        _ => return Err("unknown operation"),
    }
    if !record.data.is_object() {
        return Err("data must be a JSON object");
    }
    Ok(())
}

fn records_as_values(records: &[BulkRecordEnvelope]) -> Result<Vec<Value>, AppError> {
    records
        .iter()
        .map(|record| serde_json::to_value(record).map_err(AppError::internal))
        .collect()
}

/// Decodes one queued job's record back into the envelope the HTTP layer
/// wrote at enqueue time (`records_as_values`'s serialized `BulkRecordEnvelope`).
/// D-099: there is deliberately no legacy-shape fallback here. The
/// pre-D-098 job payload had no `expected_row_version`/ledger contract at
/// all (bare field maps with `id` inline, no envelope) — a decoder that
/// guessed at that older shape would silently apply the *new* strict
/// safety path to a job enqueued under the *old*, unversioned contract,
/// which is worse than refusing it outright. A job already on the queue
/// from before this deploy fails closed here and must be re-submitted
/// through the current HTTP contract, exactly like any other breaking
/// payload-shape change to a durable job type.
fn decode_worker_record(raw: Value) -> Result<BulkRecordEnvelope, AppError> {
    serde_json::from_value(raw).map_err(|error| {
        AppError::Validation(format!(
            "queued record does not match the current bulk envelope \
             (job predates this deployment?): {error}"
        ))
    })
}

/// Start a bulk operation
///
/// Queues many creates, updates or deletes of one entity as a durable job and returns it. Each item runs through the same checks as a single write; a retried job resumes at the first item not yet committed.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/bulk",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = BulkRequestBody,
    responses(
        (status = 201, description = "Success", body = BulkOperationResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::BulkAccepted)])))),
)]
async fn enqueue(
    State(state): State<EngineState>,
    // The extractor enforces the static half, `{entity}.bulk`. The other half
    // is `body.operation` — unknowable before the body is read, so it stays
    // below.
    ctx: Authorized<RecordScoped<Bulk>>,
    // D-344: this route's entire contract is "durably accepted, will be
    // applied later" — it returns 201 and an operation id, and the work
    // happens on the batch worker (`EngineJob::is_batch`). With no live
    // batch worker the row is written, the 201 is honest about acceptance
    // and silently wrong about completion, and the caller polls
    // `/bulk/{id}` forever. Refusing the enqueue is the only answer that
    // does not manufacture a lie.
    _jobs: Available<BatchJobs>,
    Extension(claims): Extension<SessionClaims>,
    // P-idempotency-hardening §4.4/§5 step 10 — present only when this route
    // is listed in `idempotency.mandatory_operations` (the gate inserts it
    // before calling this handler). `Option` because the default config
    // leaves that list empty, in which case this route is protected by the
    // ordinary Redis-only tier instead and this is always `None`.
    idempotency_handle: Option<Extension<idempotency_durable::DurableIdempotencyHandle>>,
    Path(entity_input): Path<String>,
    Json(body): Json<BulkRequestBody>,
) -> Result<(StatusCode, Json<BulkOperationResponse>), AppError> {
    let response = enqueue_inner(
        &state,
        &ctx,
        claims.sub,
        &entity_input,
        body,
        idempotency_handle.map(|Extension(handle)| handle),
    )
    .await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// One record of a bulk submission made in code ([`submit_bulk`]): the
/// record's id (for update and delete), the row version it was read at
/// (optional), and its values (for create and update).
#[derive(Debug, Clone)]
pub struct BulkItem {
    pub id: Option<Uuid>,
    pub expected_row_version: Option<i64>,
    pub data: Value,
}

/// What [`submit_bulk`] accepted: the operation to follow with
/// [`bulk_status`].
#[derive(Debug, Clone, Serialize)]
pub struct BulkSubmitted {
    pub id: Uuid,
    pub total: i32,
}

/// `POST /api/v1/{entity}/bulk` without the transport (roadmap N6-T3): the
/// same shape checks, preflight, item ledger, durable job and audit event,
/// for a caller in code such as an agent action. Checks `{entity}.bulk` and
/// the operation's own privilege, and refuses (503) while no batch worker
/// can run the job, as the route's extractors do.
pub async fn submit_bulk(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    operation: &str,
    items: Vec<BulkItem>,
    atomic: bool,
    quiet: bool,
) -> Result<BulkSubmitted, AppError> {
    state
        .base
        .capabilities
        .ensure_available(attome_server::capability::Capability::BatchJobs)?;
    let body = BulkRequestBody {
        operation: operation.to_owned(),
        strict: None,
        batch_mode: Some(if atomic { "atomic" } else { "partial" }.to_owned()),
        mapping_ref: None,
        mode: None,
        apply_defaults: None,
        quiet: Some(quiet),
        records: items
            .into_iter()
            .map(|item| BulkRecordEnvelope {
                id: item.id,
                expected_row_version: item.expected_row_version,
                data: item.data,
                skip_defaults: false,
            })
            .collect(),
    };
    let response = enqueue_inner(state, ctx, ctx.user_id, entity_input, body, None).await?;
    Ok(BulkSubmitted {
        id: response.id,
        total: response.total,
    })
}

async fn enqueue_inner(
    state: &EngineState,
    ctx: &SecurityContext,
    user_id: Uuid,
    entity_input: &str,
    mut body: BulkRequestBody,
    idempotency_handle: Option<idempotency_durable::DurableIdempotencyHandle>,
) -> Result<BulkOperationResponse, AppError> {
    body.mark_skip_defaults();
    let state = state.clone();
    let (entity_id, entity_name, attrs, is_append_only) =
        entity_crud::resolve_entity(&state, entity_input).await?;
    // The route's extractor checks this too; a caller in code has none.
    ctx.require(&entity_name, "bulk")?;
    validate_request_shape(&body, bulk_cap(&state))?;
    if body.mapping_ref.is_some() {
        return Err(AppError::Validation(
            "mapping_ref is only supported on staged-import".into(),
        ));
    }
    if body.mode.is_some() {
        return Err(AppError::Validation(
            "mode is only supported on staged-import".into(),
        ));
    }
    ctx.require(&entity_name, &body.operation)?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    // B5-T3: running without automation is its own privilege.
    let quiet = body.quiet == Some(true);
    if quiet {
        ctx.require_key(attome_core::quiet_scope::QUIET_PRIVILEGE)?;
    }

    let bulk_op_id = Uuid::now_v7();
    let total = body.records.len() as i32;
    let records_json = Value::Array(records_as_values(&body.records)?);
    let batch_mode = effective_batch_mode(&body).to_owned();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // P-bulk-batch-integrity Gaps A/C: whole-batch preflight runs inside this
    // same transaction, before any row is written — an "atomic" rejection
    // must leave nothing behind (D-090's "enqueue and tracking are atomic"
    // guarantee, extended to the preflight's own verdict).
    let preflight = merge_preflight_findings(
        bulk_graph::run_preflight(
            &mut tx,
            &entity_name,
            entity_id,
            &attrs,
            &body.operation,
            &body.records,
        )
        .await?,
    );
    if !preflight.is_empty() && batch_mode == "atomic" {
        return Err(AppError::Validation(atomic_rejection_message(&preflight)));
    }

    sqlx::query(
        "INSERT INTO automation_bulk_operation (id, entity_logicalname, operation, status, total, created_by, batch_mode, quiet)
         VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7)",
    )
    .bind(bulk_op_id)
    .bind(&entity_name)
    .bind(&body.operation)
    .bind(total)
    .bind(user_id)
    .bind(&batch_mode)
    .bind(quiet)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "INSERT INTO automation_bulk_operation_item
            (bulk_operation_id, item_index, record_id, payload, status)
         SELECT $1, (item.ordinality - 1)::integer,
                CASE WHEN item.value->>'id' IS NULL THEN NULL
                     ELSE (item.value->>'id')::uuid END,
                item.value, 'pending'
         FROM jsonb_array_elements($2::jsonb) WITH ORDINALITY AS item(value, ordinality)",
    )
    .bind(bulk_op_id)
    .bind(records_json)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // "partial" (the default): the preflight's own findings, if any, are
    // seeded straight to the new terminal 'rejected' status instead of
    // 'pending' — never attempted, never retried — so a preflight-caught
    // problem can't be silently re-created by the ordinary per-item worker
    // loop re-processing what it thinks is just a 'failed' item.
    if !preflight.is_empty() {
        let (indices, reasons): (Vec<i32>, Vec<String>) = preflight.into_iter().unzip();
        sqlx::query(
            "UPDATE automation_bulk_operation_item AS t
             SET status = 'rejected', error = r.reason, updated_at = NOW(), row_version = row_version + 1
             FROM (SELECT unnest($2::int[]) AS item_index, unnest($3::text[]) AS reason) AS r
             WHERE t.bulk_operation_id = $1 AND t.item_index = r.item_index",
        )
        .bind(bulk_op_id)
        .bind(&indices)
        .bind(&reasons)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // D-193 Release B (BJB-10b): the item ledger above holds every record,
    // written in this transaction, so the job carries a pointer only. Every
    // worker must be at or after Release A (ledger fallback), or an older one
    // would process zero records.
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::BulkEntityOperation(
            attome_core::jobs::BulkEntityOperationPayload {
                bulk_op_id,
                entity_logicalname: entity_name.clone(),
                operation: body.operation.clone(),
                records: Vec::new(),
                user_id,
            },
        ),
    )
    .await
    .map_err(AppError::internal)?;

    let response_body = BulkOperationResponse {
        id: bulk_op_id,
        status: "pending".into(),
        total,
    };

    // Plan item 3.10 / D-541 rule 5 — the `BulkAccepted` parent event, in the
    // same transaction as the job enqueue above: if this transaction rolls
    // back, no parent event and no operation exists. Category/entity match
    // the per-record events this batch will write (`apply_ledgered_item`).
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, user_id).await;
    let accepted_event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.clone()),
        record_id: None,
        operation: AuditOperation::BulkAccepted,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(bulk_op_id),
        event_name: None,
        event_comment: Some(format!("bulk {} accepted", body.operation)),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    write_bulk_accepted(
        &audit_service,
        &mut tx,
        accepted_event,
        Attribution::user(user_id),
        total,
    )
    .await?;

    // P-idempotency-hardening §4.4/§5 step 10 — the transactional-linkage
    // step: completes the durable idempotency record in the SAME commit as
    // the mutation above, so "bulk operation enqueued" and "idempotency
    // record marked completed" cannot be torn apart by a crash between two
    // separate writes. A no-op (via `Option`) when this route isn't in
    // `idempotency.mandatory_operations`.
    if let Some(handle) = idempotency_handle {
        let response_bytes = serde_json::to_vec(&response_body).map_err(AppError::internal)?;
        idempotency_durable::complete_in_tx(
            &mut tx,
            handle.record_id,
            Some(bulk_op_id),
            StatusCode::ACCEPTED.as_u16(),
            &[("content-type".to_string(), "application/json".to_string())],
            &response_bytes,
        )
        .await
        .map_err(AppError::internal)?;
    }

    attome_db::tx::commit(tx).await?;

    Ok(response_body)
}

/// A bulk operation's progress
///
/// The status and item counts of a bulk operation the caller started.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/bulk/{id}",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The bulk operation"),
        BulkStatusQuery,
    ),
    responses(
        (status = 200, description = "Success", body = BulkOperationStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_status(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, bulk_op_id)): Path<(String, Uuid)>,
    Query(query): Query<BulkStatusQuery>,
) -> Result<Json<BulkOperationStatus>, AppError> {
    status_inner(
        &state,
        claims.sub,
        ctx.is_admin,
        &entity_input,
        bulk_op_id,
        &query,
    )
    .await
    .map(Json)
}

/// A bulk operation's progress and, with `include_items`, its per-record
/// results (the first `page_size` items, up to 100 by default), for a caller
/// in code (roadmap N6-T3). Visible to its creator and to administrators,
/// as on `GET /api/v1/{entity}/bulk/{id}`.
pub async fn bulk_status(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    bulk_op_id: Uuid,
    include_items: bool,
) -> Result<Value, AppError> {
    ctx.require(
        &entity_crud::resolve_entity(state, entity_input).await?.1,
        "read",
    )?;
    let status = status_inner(
        state,
        ctx.user_id,
        ctx.is_admin,
        entity_input,
        bulk_op_id,
        &BulkStatusQuery {
            include_items: Some(include_items),
            ..BulkStatusQuery::default()
        },
    )
    .await?;
    serde_json::to_value(status).map_err(AppError::internal)
}

async fn status_inner(
    state: &EngineState,
    user_id: Uuid,
    is_admin: bool,
    entity_input: &str,
    bulk_op_id: Uuid,
    query: &BulkStatusQuery,
) -> Result<BulkOperationStatus, AppError> {
    let (_, entity_name, _, _) = entity_crud::resolve_entity(state, entity_input).await?;
    let row: Option<BulkOperationStatusRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, operation, status, total, succeeded, failed, rejected, errors
         FROM automation_bulk_operation
         WHERE id = $1 AND entity_logicalname = $2 AND is_deleted = false
           AND (created_by = $3 OR $4)",
    )
    .bind(bulk_op_id)
    .bind(&entity_name)
    .bind(user_id)
    .bind(is_admin)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    let mut status = BulkOperationStatus {
        id: row.id,
        entity_logicalname: row.entity_logicalname,
        operation: row.operation,
        status: row.status,
        total: row.total,
        succeeded: row.succeeded,
        failed: row.failed,
        rejected: row.rejected,
        errors: row.errors,
        items: None,
    };

    if query.include_items == Some(true) {
        let window = PageWindow::resolve(
            query.page,
            query.page_size,
            PageBase::One,
            DEFAULT_ITEM_PAGE_SIZE,
        );
        let items: Vec<BulkItemStatus> = sqlx::query_as(&format!(
            "SELECT item_index, record_id, status, {ITEM_OUTCOME_SQL} AS outcome, error, conflict,
                    attempts
             FROM automation_bulk_operation_item
             WHERE bulk_operation_id = $1 AND is_deleted = false
             ORDER BY item_index
             LIMIT $2 OFFSET $3"
        ))
        .bind(bulk_op_id)
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        status.items = Some(BatchResult {
            items: items.into_iter().map(BulkItemStatus::into_result).collect(),
        });
    }
    Ok(status)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/{entity}/bulk", post(enqueue))
        .merge(crate::bulk_edit::routes())
        .merge(crate::mass::routes())
        .route("/api/v1/{entity}/bulk/{id}", get(get_status))
        .route("/api/v1/{entity}/staged-import", post(staged_import))
        .route(
            "/api/v1/{entity}/staged-import/{id}/approve",
            post(approve_staged_import),
        )
}

/// Operation-name strings (`"{METHOD} {route}"`, matching
/// `attome_server::middleware::idempotency::operation_name`'s format) this
/// crate registers that are eligible to be named in
/// `idempotency.mandatory_operations` (P-idempotency-hardening §4.5).
/// `attome-config` cannot validate that list itself (guidelines §1 — base-*
/// has zero xrm-* route knowledge), so `server::boot::init` checks every
/// configured entry against this list at boot and fails closed on an
/// unrecognized one. Kept next to `routes()` so the two can't drift apart —
/// `POST /api/v1/{entity}` (plain entity create) is deliberately NOT listed
/// here: P-idempotency-hardening §4.5 named it only as a deferred candidate
/// (no per-entity "financial" metadata flag exists today to gate a blanket
/// mandatory policy on), not a committed mandatory-tier route.
pub const MANDATORY_TIER_OPERATIONS: &[&str] = &[
    "POST /api/v1/{entity}/bulk",
    "POST /api/v1/{entity}/staged-import/{id}/approve",
];

/// M01-core C-11 — merged `mark_failed`/`mark_staged_import_failed`: same
/// "whole batch/import can't even start" early-failure write, differing only
/// in `ledger`'s parent table/status/column (see
/// `LedgerTable::early_failure_status_and_column`).
async fn mark_batch_failed(
    state: &EngineState,
    ledger: LedgerTable,
    batch_id: Uuid,
    entity_logicalname: &str,
    user_id: Uuid,
    message: &str,
) -> Result<(), AppError> {
    let parent_table = ledger.parent_table();
    let (status, column) = ledger.early_failure_status_and_column();
    sqlx::query(&format!(
        "UPDATE {parent_table}
         SET status = '{status}', {column} = $2, updated_at = NOW(), row_version = row_version + 1
         WHERE id = $1"
    ))
    .bind(batch_id)
    .bind(json!([{ "error": message }]))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // Plan item 3.10 rule 4 — the whole batch/import never started (no items
    // were attempted), so this is the "all-or-nothing" shape: a `Failed`,
    // affected-0 `BulkCompleted` event, in its own transaction after this
    // early-bail write (there is nothing left to attach it to).
    write_bulk_completed(state, ledger, batch_id, entity_logicalname, user_id, 0, 0).await
}

/// Plan item 3.10 / D-541 rule 5 — writes the `BulkCompleted` parent event
/// for `batch_id` in its own transaction (never the caller's — every call
/// site here is either past its own transaction already, or, for
/// `mark_batch_failed`, deliberately writing after an early-bail commit).
/// `succeeded` becomes `affected_count` (I13: it must equal the number of
/// per-record events sharing this `batch_id`, which per plan rule 2 is
/// exactly the succeeded items); `other` (failed + rejected) becomes
/// `failed_count`. Idempotent via [`write_bulk_completed_once`] — safe to
/// call from a resumed/retried terminal-state write.
async fn write_bulk_completed(
    state: &EngineState,
    ledger: LedgerTable,
    batch_id: Uuid,
    entity_name: &str,
    user_id: Uuid,
    succeeded: i32,
    other: i32,
) -> Result<(), AppError> {
    let outcome = if other == 0 {
        if succeeded == 0 {
            AuditOutcome::Failed
        } else {
            AuditOutcome::Succeeded
        }
    } else if succeeded == 0 {
        AuditOutcome::Failed
    } else {
        AuditOutcome::PartiallyFailed
    };
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: None,
        operation: AuditOperation::BulkCompleted,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(batch_id),
        event_name: None,
        event_comment: Some(format!("{} completed", ledger.label())),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_bulk_completed_once(
        &audit_service,
        &mut tx,
        event,
        Attribution::user(user_id),
        outcome,
        succeeded,
        other,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// M01-core C-11 — merged `mark_item_failed`/`mark_staged_item_failed`:
/// identical aside from `ledger`'s item table/id column.
async fn mark_item_failed(
    state: &EngineState,
    ledger: LedgerTable,
    batch_id: Uuid,
    item_index: i32,
    error: &str,
    conflict: Option<&Value>,
) -> Result<(), AppError> {
    let item_table = ledger.item_table();
    let id_column = ledger.id_column();
    sqlx::query(&format!(
        "UPDATE {item_table}
         SET status = 'failed', error = $3, conflict = $4, attempts = attempts + 1,
             updated_at = NOW(), row_version = row_version + 1
         WHERE {id_column} = $1 AND item_index = $2
           AND status <> 'succeeded' AND is_deleted = false"
    ))
    .bind(batch_id)
    .bind(item_index)
    .bind(error)
    .bind(conflict)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// M01-core C-11 — the merged `apply_one`/`apply_staged_one`: identical
/// aside from which ledger table/column pair `lctx.ledger` names, the
/// `MutationMode` it runs the mutation under, and staged import's extra
/// `migration_run_item` rollback-ledger row (written only when
/// `lctx.migration_run_id` is `Some`, which is only ever true for
/// `LedgerTable::StagedItem` — see `LedgerContext`'s doc comment).
///
/// Also closes the actual C-11 defect: neither predecessor ever called
/// `sync_file_field_documents`, so a bulk/staged-import write of a
/// file-typed field never mirrored into `attome_document` (D-36x) the way the
/// interactive `PATCH .../{entity}/{id}` path always has.
/// `create_record_for`/`update_record_for` get that mirror step (plus the
/// creator-share grant, the `AuditService` construction, and the post-commit
/// invalidation this function also does by hand below) via
/// `MutationRing::commit_mutation` (C-10) — this calls the same shared
/// `sync_file_field_documents` helper directly rather than through the ring,
/// because the ring's `AuditEvent` construction has no way to carry this
/// call's own `batch_id` correlation (`Some(lctx.batch_id)` here, hardcoded
/// to `None` in `MutationRing::commit_mutation`) or its bulk/staged-specific
/// `event_comment`. Routing through the ring as it stands today would
/// silently drop that `batch_id` from every bulk/staged-import audit event —
/// a real regression, since `attome-audit`'s admin listing/export and the
/// registered "Batch ID" field both read it — so this stays on the
/// direct-call shape until the ring grows a way to carry a caller-supplied
/// `batch_id`/`event_comment` (a `MutationAudit` field, outside this file's
/// scope to add).
/// C-13: `(entity_id, action)` derives entirely from `entity_id`/`operation`
/// — parameters fixed for an entire bulk/staged-import batch, never from any
/// individual item — so resolving `(access_level, owner_visible)` once here
/// and reusing it for every row (via `entity_crud::require_record_access_with`)
/// is exactly as correct as the old per-row `require_record_access`, at a
/// fraction of the query cost. `None` for "create", which never calls a
/// record-level access check. Shared by `process_ledger`'s worker loop and
/// `staged_import`'s dry-run loop, the batch's only two per-item callers of
/// that check.
async fn resolve_batch_record_access(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity_name: &str,
    operation: &str,
) -> Result<Option<(AccessLevel, bool)>, AppError> {
    let action = match operation {
        "delete" => RecordAction::Delete,
        "update" => RecordAction::Update,
        _ => return Ok(None),
    };
    entity_crud::resolve_record_access_inputs(state, ctx, entity_id, entity_name, action)
        .await
        .map(Some)
}

#[allow(clippy::too_many_arguments)]
async fn apply_ledgered_item(
    rctx: RequestContext<'_>,
    lctx: LedgerContext,
    item_index: i32,
    target: &EntityMutationTarget<'_>,
    operation: &str,
    record: &BulkRecordEnvelope,
    user_id: Uuid,
    record_access: Option<(AccessLevel, bool)>,
) -> Result<(), AppError> {
    let RequestContext { state, ctx } = rctx;
    let LedgerContext {
        ledger,
        batch_id,
        migration_run_id,
    } = lctx;
    let EntityMutationTarget {
        entity_id,
        entity_name,
        attrs,
        dependents,
    } = *target;
    validate_record_envelope(operation, record)
        .map_err(|error| AppError::Validation(error.into()))?;
    let obj = record
        .data
        .as_object()
        .ok_or_else(|| AppError::Validation("record data must be a JSON object".into()))?;
    if matches!(operation, "update" | "delete") {
        let record_id = record
            .id
            .ok_or_else(|| AppError::Validation("record requires id".into()))?;
        // update and delete resolve independent depths (a role's Team-Update
        // scope says nothing about its Delete scope for the same entity) —
        // see RecordAction::share_capability's doc comment.
        let action = if operation == "delete" {
            RecordAction::Delete
        } else {
            RecordAction::Update
        };
        // C-13: use the batch-resolved (access_level, owner_visible) when the
        // caller has one (process_ledger always does, for "update"/"delete");
        // fall back to a fresh per-row resolve rather than skip the check if
        // it somehow doesn't, so a missing batch resolve can never turn into
        // a missing access check.
        match record_access {
            Some((access_level, owner_visible)) => {
                entity_crud::require_record_access_with(
                    state,
                    ctx,
                    entity_id,
                    entity_name,
                    record_id,
                    action,
                    access_level,
                    owner_visible,
                )
                .await?;
            }
            None => {
                entity_crud::require_record_access(
                    state,
                    ctx,
                    entity_id,
                    entity_name,
                    record_id,
                    action,
                )
                .await?;
            }
        }
    }
    // U1 (basic-units plan B-R1): a note/communication/tag/follow is gated by
    // the record it is attached to, in bulk exactly as in single-record CRUD.
    let existing_id = record
        .id
        .filter(|_| matches!(operation, "update" | "delete"));
    if let Some(record_id) = existing_id {
        entity_crud::require_child_parent_access(state, ctx, entity_name, record_id).await?;
    }
    if matches!(operation, "create" | "update") {
        entity_crud::require_child_parent_access_for_write(
            state,
            ctx,
            entity_name,
            existing_id,
            obj,
        )
        .await?;
    }
    // M01 Core C-12: resolved here, on the pool, before the transaction below
    // opens — see `entity_crud::resolve_cascade_dependent_access`'s doc
    // comment. Only the "delete" branch below actually consults this.
    let cascade_access = if operation == "delete" {
        Some(entity_crud::resolve_cascade_dependent_access(state, ctx, dependents).await?)
    } else {
        None
    };
    // A15-T11: a bulk or imported row meets the same duplicate rules as a
    // save through the API, before the transaction opens.
    if matches!(operation, "create" | "update") {
        crate::duplicate_check::guard(state, ctx, entity_id, entity_name, existing_id, obj).await?;
    }
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let item_table = ledger.item_table();
    let id_column = ledger.id_column();

    // D-099/D-100: lock the item row first so two concurrent `process_ledger`
    // attempts (Apalis redelivery while a prior attempt is still executing,
    // not just a later retry after that attempt finished) serialize on this
    // row instead of racing to claim it. The loser blocks here until the
    // winner's transaction commits or rolls back, then re-evaluates status
    // with fresh data — never a blind unconditional UPDATE.
    let claimed: Option<String> = sqlx::query_scalar(&format!(
        "SELECT status FROM {item_table}
         WHERE {id_column} = $1 AND item_index = $2 AND is_deleted = false
         FOR UPDATE"
    ))
    .bind(batch_id)
    .bind(item_index)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(status) = claimed else {
        return Err(AppError::Internal("bulk item ledger row is missing".into()));
    };
    // P-bulk-batch-integrity Gap D: a durably *committed* 'running' row can
    // never be observed here to begin with — this function claims, mutates,
    // and finalizes inside one transaction (commit at the very end), so a
    // crash before commit rolls the claim back too via Postgres MVCC plus
    // this SELECT's own `FOR UPDATE` row lock: a concurrent attempt either
    // blocks until the prior transaction commits/rolls back, or sees the
    // pre-attempt 'pending' state. There is nothing to reclaim from a stale
    // claim, so a formerly-conditional (timeout-based) reclaim branch has
    // been removed in favor of simply never reprocessing a 'running' item —
    // that branch could not fire under this design and was unverified by any
    // test (P-bulk-batch-integrity Gap D). `'rejected'` (a batch-preflight
    // rejection, seeded before any attempt) is also terminal, like
    // `'succeeded'`.
    let claimable = match status.as_str() {
        "succeeded" | "running" | "rejected" => false,
        _ => true, // pending, failed
    };
    if !claimable {
        // Another attempt already holds (or just finished) this item; skip
        // it rather than reprocess in parallel. The owning attempt's own
        // commit — success or failure — is authoritative for this item.
        return Ok(());
    }

    let attempts = sqlx::query(&format!(
        "UPDATE {item_table}
         SET status = 'running', attempts = attempts + 1, error = NULL,
             claimed_at = NOW(), updated_at = NOW(), row_version = row_version + 1
         WHERE {id_column} = $1 AND item_index = $2 AND is_deleted = false"
    ))
    .bind(batch_id)
    .bind(item_index)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if attempts.rows_affected() != 1 {
        return Err(AppError::Internal("bulk item ledger row is missing".into()));
    }

    let mutation_mode = ledger.mutation_mode();
    let mutation = match operation {
        "create" => {
            let created = entity_mutation::with_defaults(
                !record.skip_defaults,
                entity_mutation::create_one(
                    &mut tx,
                    state,
                    ctx,
                    entity_name,
                    attrs,
                    obj,
                    user_id,
                    org_ref,
                    mutation_mode,
                ),
            )
            .await?;
            // D-133 (2): bulk/staged create bypasses `create_record`'s own
            // INSERT path entirely, so it must grant the same implicit
            // creator share itself — otherwise a Team/BusinessUnit-scoped
            // caller's own bulk-created records are invisible to them.
            entity_crud::grant_creator_share(&mut tx, entity_id, created.record_id, user_id)
                .await?;
            created
        }
        "update" => {
            entity_mutation::update_one(
                &mut tx,
                state,
                ctx,
                entity_name,
                entity_id,
                record
                    .id
                    .ok_or_else(|| AppError::Validation("record requires id".into()))?,
                attrs,
                obj,
                user_id,
                record.expected_row_version.ok_or_else(|| {
                    AppError::Validation("record requires expected_row_version".into())
                })?,
                mutation_mode,
            )
            .await?
        }
        "delete" => {
            let record_id = record
                .id
                .ok_or_else(|| AppError::Validation("record requires id".into()))?;
            entity_crud::guard_cascade_dependent_access(
                &mut tx,
                state,
                ctx,
                dependents,
                record_id,
                cascade_access.as_deref().unwrap_or(&[]),
            )
            .await?;
            entity_mutation::delete_one(
                &mut tx,
                entity_name,
                dependents,
                record_id,
                user_id,
                record.expected_row_version,
                &match migration_run_id {
                    Some(run) => entity_mutation::DeleteOrigin::with_id(
                        entity_mutation::DeleteKind::Import,
                        run.to_string(),
                    ),
                    None => entity_mutation::DeleteOrigin::with_id(
                        entity_mutation::DeleteKind::Bulk,
                        batch_id.to_string(),
                    ),
                },
            )
            .await?
        }
        _ => {
            return Err(AppError::Validation(
                ledger.unknown_operation_message().into(),
            ));
        }
    };

    // C-11: the actual defect this item closes — see this function's own
    // doc comment for why this calls the shared helper directly instead of
    // through `MutationRing::commit_mutation`. Delete has no `new_row` to
    // mirror (`entity_mutation::delete_one` returns `new_row: None`), so the
    // `matches!` guard is defense-in-depth, not the thing actually skipping
    // it.
    if matches!(operation, "create" | "update")
        && let Some(row) = mutation.new_row.as_ref()
    {
        entity_crud::sync_file_field_documents(
            &mut tx,
            state,
            ctx,
            user_id,
            org_ref,
            entity_name,
            mutation.record_id,
            attrs,
            row,
        )
        .await?;
    }

    let audit_operation = match operation {
        "create" => AuditOperation::Create,
        "update" => AuditOperation::Update,
        "delete" => AuditOperation::SoftDelete,
        _ => unreachable!(),
    };
    let changed_fields = if operation == "delete" {
        Vec::new()
    } else {
        entity_crud::field_changes_from_obj(&mut tx, state, attrs, obj, mutation.old_row.as_ref())
            .await
    };
    let event_comment = match ledger {
        LedgerTable::BulkItem => Some(if mutation.cascade_summary.is_empty() {
            format!("bulk {operation}")
        } else {
            format!(
                "bulk {operation}; cascade-deactivated dependents: {}",
                mutation.cascade_summary.join(", ")
            )
        }),
        LedgerTable::StagedItem => Some("approved staged import".to_owned()),
    };
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(mutation.record_id),
        operation: audit_operation,
        version_before: record.expected_row_version,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(batch_id),
        event_name: None,
        event_comment,
        changed_fields,
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    audit_service.write_in_tx(&mut tx, event).await?;

    // M17/D-433 — same transaction as the mutation and the item-ledger
    // update below, so the rollback ledger can never record an item that
    // didn't actually commit (or vice versa). Only ever `Some` for
    // `LedgerTable::StagedItem` (see `LedgerContext`'s doc comment); "delete"
    // items are never tracked — migration rollback is scoped to
    // create/update only (D-433).
    if let Some(migration_run_id) = migration_run_id
        && matches!(operation, "create" | "update")
    {
        let applied_row_version =
            extract_row_version(mutation.new_row.as_ref()).ok_or_else(|| {
                AppError::internal("mutation result missing row_version for migration ledger")
            })?;
        let prior_row_version = if operation == "update" {
            record.expected_row_version
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO migration_run_item
                (migration_run_id, item_index, entity_logicalname, record_id, operation,
                 prior_row_version, applied_row_version, prior_data)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (migration_run_id, item_index) DO NOTHING",
        )
        .bind(migration_run_id)
        .bind(item_index)
        .bind(entity_name)
        .bind(mutation.record_id)
        .bind(operation)
        .bind(prior_row_version)
        .bind(applied_row_version)
        .bind(&mutation.old_row)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    sqlx::query(&format!(
        "UPDATE {item_table}
         SET status = 'succeeded', record_id = $3, error = NULL,
             updated_at = NOW(), row_version = row_version + 1
         WHERE {id_column} = $1 AND item_index = $2 AND is_deleted = false"
    ))
    .bind(batch_id)
    .bind(item_index)
    .bind(mutation.record_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    entity_crud::invalidate_audit_user_if_systemuser(state, entity_name, mutation.record_id).await;
    entity_crud::invalidate_privilege_grant_target(
        state,
        entity_name,
        mutation.record_id,
        mutation.new_row.as_ref(),
    )
    .await;
    Ok(())
}

/// D-193 — closes ENTERPRISE-AUDIT-2026-07-24.md finding #19/#39's "large
/// records should not be embedded indefinitely in queue rows" concern for
/// `BulkEntityOperation`. `enqueue`'s own transaction (above) already writes
/// every record into `automation_bulk_operation_item.payload` durably, in the same
/// commit as the job row — that ledger is not just a progress tracker, it is
/// already a complete, transactionally-consistent copy of the records. The
/// worker can therefore treat an empty `raw_records` job payload as "read
/// from the ledger instead" rather than "nothing to process": `enqueue`'s own
/// `validate_request_shape` already rejects a genuinely empty record set, so
/// `[]` can never mean that here. This supersedes
/// `document/detailed-plans/P-job-envelope-versioning.md` §4.2's
/// object-storage-reference design for these two variants — see D-193 for why
/// (no new dependency/threshold/failure-mode needed once the ledger is
/// already the durable copy).
/// M01-core C-11 — merged `fetch_ledger_records`/`fetch_staged_ledger_records`:
/// identical aside from `ledger`'s item table/id column.
async fn fetch_ledger_records(
    db: &attome_db::DbPool,
    ledger: LedgerTable,
    batch_id: Uuid,
) -> Result<Vec<Value>, AppError> {
    let item_table = ledger.item_table();
    let id_column = ledger.id_column();
    sqlx::query_scalar::<_, Value>(&format!(
        "SELECT payload FROM {item_table}
         WHERE {id_column} = $1 AND is_deleted = false
         ORDER BY item_index"
    ))
    .bind(batch_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// M01-core C-11 — the merged `process`/`process_staged_import`: both walk
/// the same claim/mutate/finalize-item shape (`apply_ledgered_item`) over
/// their own ledger table, and differ only in a handful of table/column
/// names (`LedgerTable`), whether a migration-run link needs fetching
/// (staged import only), and the parent row's own closing update — which
/// genuinely differs in shape (bulk closes to `'completed'` with
/// succeeded/failed/rejected counts and a per-failed-item `errors` array;
/// staged import closes to `'approved'`/`'rejected'` with a full per-item
/// `validation_report` and `approved_by`), so that step stays a `match` on
/// `ledger` rather than being forced into one shared SQL statement.
///
/// Authorization is deliberately resolved directly from PostgreSQL before
/// the loop, so a revoked grant cannot remain usable because an app node
/// still has a warm security cache.
async fn process_ledger(
    state: &EngineState,
    ledger: LedgerTable,
    batch_id: Uuid,
    entity_logicalname: &str,
    operation: &str,
    raw_records: Vec<Value>,
    user_id: Uuid,
) -> Result<(), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        match entity_crud::resolve_entity(state, entity_logicalname).await {
            Ok(value) => value,
            Err(error) => {
                mark_batch_failed(
                    state,
                    ledger,
                    batch_id,
                    entity_logicalname,
                    user_id,
                    &format!("entity resolution failed: {error}"),
                )
                .await?;
                return Ok(());
            }
        };
    if !valid_bulk_operation(operation) || is_append_only {
        mark_batch_failed(
            state,
            ledger,
            batch_id,
            entity_logicalname,
            user_id,
            if is_append_only {
                ledger.append_only_message()
            } else {
                ledger.unknown_operation_message()
            },
        )
        .await?;
        return Ok(());
    }

    let security = match attome_security::resolve_uncached(&state.base.db, user_id).await {
        Ok(context) => context,
        Err(error) => return Err(error),
    };
    if security.require(&entity_name, operation).is_err()
        || security.require(&entity_name, "bulk").is_err()
    {
        mark_batch_failed(
            state,
            ledger,
            batch_id,
            entity_logicalname,
            user_id,
            &format!(
                "{} authorization was revoked before processing",
                ledger.label()
            ),
        )
        .await?;
        return Ok(());
    }

    // M17/D-433 — this staged import's linked migration run, if any. Only
    // meaningful for `LedgerTable::StagedItem`; a plain bulk operation has
    // no such link. Read fresh here rather than threaded through the job
    // payload: the link is set once (`POST .../migration-projects/{id}/runs`,
    // before approval) and never changes, so re-reading it costs one query
    // and keeps the job payload shape unchanged for every other caller.
    let migration_run_id: Option<Uuid> = match ledger {
        LedgerTable::StagedItem => sqlx::query_scalar(
            "SELECT migration_run_id FROM automation_staged_import WHERE id = $1",
        )
        .bind(batch_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        LedgerTable::BulkItem => None,
    };

    // D-193: `[]` means "the enqueue/approve side omitted the records, read
    // the ledger instead" — see `fetch_ledger_records`'s doc comment. A job
    // enqueued before that change (or a direct worker invocation that still
    // passes real records) takes the `raw_records` it was given, unchanged.
    let raw_records = if raw_records.is_empty() {
        fetch_ledger_records(&state.base.db, ledger, batch_id).await?
    } else {
        raw_records
    };

    let mut records = Vec::with_capacity(raw_records.len());
    for raw in raw_records {
        match decode_worker_record(raw) {
            Ok(record) => records.push(record),
            Err(error) => {
                mark_batch_failed(
                    state,
                    ledger,
                    batch_id,
                    entity_logicalname,
                    user_id,
                    &format!("invalid queued record: {error}"),
                )
                .await?;
                return Ok(());
            }
        }
    }

    let item_table = ledger.item_table();
    let id_column = ledger.id_column();

    // Normal production enqueue/approve already created these rows.  The
    // idempotent insert also lets a worker safely resume jobs created by an
    // older build (and makes direct worker invocation in operational
    // tooling durable).
    let normalized_records = Value::Array(records_as_values(&records)?);
    sqlx::query(&format!(
        "INSERT INTO {item_table}
            ({id_column}, item_index, record_id, payload, status)
         SELECT $1, (item.ordinality - 1)::integer,
                CASE WHEN item.value->>'id' IS NULL THEN NULL
                     ELSE (item.value->>'id')::uuid END,
                item.value, 'pending'
         FROM jsonb_array_elements($2::jsonb) WITH ORDINALITY AS item(value, ordinality)
         ON CONFLICT ({id_column}, item_index) DO NOTHING"
    ))
    .bind(batch_id)
    .bind(normalized_records)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // Bulk-only status transition ('pending' -> 'running'); a staged
    // import's row is already 'approving' by the time this runs (set at
    // approval time) and has no equivalent intermediate step here.
    if ledger == LedgerTable::BulkItem {
        sqlx::query(
            "UPDATE automation_bulk_operation
             SET status = 'running', updated_at = NOW(), row_version = row_version + 1
             WHERE id = $1",
        )
        .bind(batch_id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }

    let succeeded_indices: HashSet<i32> = sqlx::query_scalar(&format!(
        "SELECT item_index FROM {item_table}
         WHERE {id_column} = $1 AND status = 'succeeded' AND is_deleted = false"
    ))
    .bind(batch_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let dependents = state.entities.load().dependents_of(entity_id);
    let target = EntityMutationTarget {
        entity_id,
        entity_name: &entity_name,
        attrs: &attrs,
        dependents: &dependents,
    };
    // C-13: resolved once for the whole batch — see
    // `resolve_batch_record_access`'s doc comment.
    let record_access =
        resolve_batch_record_access(state, &security, entity_id, &entity_name, operation).await?;

    for (index, record) in records.iter().enumerate() {
        let item_index = index as i32;
        if succeeded_indices.contains(&item_index) {
            continue;
        }
        if let Err(error) = apply_ledgered_item(
            RequestContext {
                state,
                ctx: &security,
            },
            LedgerContext {
                ledger,
                batch_id,
                migration_run_id,
            },
            item_index,
            &target,
            operation,
            record,
            user_id,
            record_access,
        )
        .await
        {
            if matches!(&error, AppError::Internal(_)) {
                // Leave the item pending/running and let Apalis retry the
                // job. Previously committed item rows are skipped on retry;
                // a transient database failure must not be converted into a
                // permanent business-level failure.
                return Err(error);
            }
            // A16-T6: a stale row is a conflict with what changed since its
            // version; the other rows still apply.
            let conflict = match (&error, record.id, record.expected_row_version) {
                (AppError::VersionConflict, Some(record_id), Some(expected)) => {
                    Some(conflict_body(
                        crate::entity_crud::history::version_conflict(
                            state,
                            &security,
                            &entity_name,
                            record_id,
                            expected,
                            match ledger {
                                LedgerTable::BulkItem => "bulk",
                                LedgerTable::StagedItem => "import",
                            },
                        )
                        .await,
                    ))
                }
                _ => None,
            };
            mark_item_failed(
                state,
                ledger,
                batch_id,
                item_index,
                &error.to_string(),
                conflict.as_ref(),
            )
            .await?;
        }
    }

    match ledger {
        LedgerTable::BulkItem => {
            let (succeeded, failed, rejected): (i64, i64, i64) = sqlx::query_as(&format!(
                "SELECT
                     COUNT(*) FILTER (WHERE status = 'succeeded'),
                     COUNT(*) FILTER (WHERE status = 'failed'),
                     COUNT(*) FILTER (WHERE status = 'rejected')
                 FROM {item_table} WHERE {id_column} = $1 AND is_deleted = false"
            ))
            .bind(batch_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let errors: Vec<(i32, Option<String>, Option<Value>)> = sqlx::query_as(&format!(
                "SELECT item_index, error, conflict FROM {item_table}
                 WHERE {id_column} = $1 AND status = 'failed' AND is_deleted = false
                 ORDER BY item_index"
            ))
            .bind(batch_id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let errors = Value::Array(
                errors
                    .into_iter()
                    .map(|(index, error, conflict)| match conflict {
                        Some(conflict) => json!({
                            "index": index, "status": "conflict", "error": error, "conflict": conflict,
                        }),
                        None => json!({ "index": index, "status": "error", "error": error }),
                    })
                    .collect(),
            );
            sqlx::query(
                "UPDATE automation_bulk_operation
                 SET status = 'completed', succeeded = $2, failed = $3, rejected = $4, errors = $5,
                     updated_at = NOW(), row_version = row_version + 1
                 WHERE id = $1",
            )
            .bind(batch_id)
            .bind(succeeded as i32)
            .bind(failed as i32)
            .bind(rejected as i32)
            .bind(errors)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            write_bulk_completed(
                state,
                ledger,
                batch_id,
                &entity_name,
                user_id,
                succeeded as i32,
                (failed + rejected) as i32,
            )
            .await?;
        }
        LedgerTable::StagedItem => {
            let (succeeded, failed, rejected): (i64, i64, i64) = sqlx::query_as(&format!(
                "SELECT
                     COUNT(*) FILTER (WHERE status = 'succeeded'),
                     COUNT(*) FILTER (WHERE status = 'failed'),
                     COUNT(*) FILTER (WHERE status = 'rejected')
                 FROM {item_table} WHERE {id_column} = $1 AND is_deleted = false"
            ))
            .bind(batch_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            #[allow(clippy::type_complexity)]
            let items: Vec<(
                i32,
                String,
                String,
                Option<Uuid>,
                Option<String>,
                Option<Value>,
            )> = sqlx::query_as(&format!(
                "SELECT item_index, status, {ITEM_OUTCOME_SQL}, record_id, error, conflict
                     FROM {item_table}
                     WHERE {id_column} = $1 AND is_deleted = false
                     ORDER BY item_index"
            ))
            .bind(batch_id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let report = Value::Array(
                items
                    .into_iter()
                    .map(|(index, status, outcome, record_id, error, conflict)| {
                        json!({
                            "index": index, "status": status, "outcome": outcome,
                            "record_id": record_id, "error": error, "conflict": conflict,
                        })
                    })
                    .collect(),
            );
            // A preflight-rejected item (caught at approve time, e.g.
            // metadata that drifted since submission) means this run is not
            // a clean approval either, same as a genuine per-item `failed`
            // — both make the overall `automation_staged_import.status`
            // land on 'rejected', not 'approved'. This `status = 'rejected'`
            // is the staged import's own overall outcome, a different
            // concept from an individual item's `'rejected'` ledger status
            // above (one row's preflight verdict) — same word, two levels.
            let final_status = if failed == 0 && rejected == 0 {
                "approved"
            } else {
                "rejected"
            };
            sqlx::query(
                "UPDATE automation_staged_import
                 SET status = $2, validation_report = $3, approved_by = $4, rejected = $5,
                     approved_at = NOW(), updated_at = NOW(), row_version = row_version + 1
                 WHERE id = $1",
            )
            .bind(batch_id)
            .bind(final_status)
            .bind(report)
            .bind(user_id)
            .bind(rejected as i32)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            write_bulk_completed(
                state,
                ledger,
                batch_id,
                &entity_name,
                user_id,
                succeeded as i32,
                (failed + rejected) as i32,
            )
            .await?;
        }
    }

    Ok(())
}

/// A16-T6: the stored form of a row's version conflict: the body a single
/// PATCH answers with (`current_version`, `current_state`), or only a null
/// version when the record's details could not be read.
fn conflict_body(error: AppError) -> Value {
    match error {
        AppError::VersionConflictAt {
            current_version,
            current_state,
        } => json!({ "current_version": current_version, "current_state": current_state }),
        _ => json!({ "current_version": null }),
    }
}

/// Worker-side processing for `EngineJob::BulkEntityOperation`.
pub async fn process(
    state: &EngineState,
    bulk_op_id: Uuid,
    entity_logicalname: &str,
    operation: &str,
    raw_records: Vec<Value>,
    user_id: Uuid,
) -> Result<(), AppError> {
    // B5-T3: an operation submitted without automation writes its items'
    // change events quiet.
    let quiet: bool =
        sqlx::query_scalar("SELECT quiet FROM automation_bulk_operation WHERE id = $1")
            .bind(bulk_op_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .unwrap_or(false);
    let work = process_ledger(
        state,
        LedgerTable::BulkItem,
        bulk_op_id,
        entity_logicalname,
        operation,
        raw_records,
        user_id,
    );
    // L7-T2: a bulk job's change events carry the `job` channel.
    let provenance = attome_core::provenance_scope::Provenance {
        channel: attome_core::provenance_scope::JOB_CHANNEL,
        run_id: None,
    };
    if quiet {
        attome_core::provenance_scope::scope(provenance, attome_core::quiet_scope::quiet(work))
            .await
    } else {
        attome_core::provenance_scope::scope(provenance, work).await
    }
}

/// Returns the underlying [`MutationResult`] (never persisted — the
/// transaction is always rolled back below) so `staged_import`'s
/// `mode: "dry_run"` path can build a sample diff from the same old/new row
/// values this validation already computed, at zero extra cost.
#[allow(clippy::too_many_arguments)]
async fn dry_run_one(
    state: &EngineState,
    ctx: &SecurityContext,
    target: &EntityMutationTarget<'_>,
    operation: &str,
    record: &BulkRecordEnvelope,
    user_id: Uuid,
    mode: MutationMode,
    record_access: Option<(AccessLevel, bool)>,
) -> Result<MutationResult, AppError> {
    let EntityMutationTarget {
        entity_id,
        entity_name,
        attrs,
        dependents,
    } = *target;
    validate_record_envelope(operation, record)
        .map_err(|error| AppError::Validation(error.into()))?;
    let obj = record
        .data
        .as_object()
        .ok_or_else(|| AppError::Validation("record data must be a JSON object".into()))?;
    if matches!(operation, "update" | "delete") {
        let record_id = record
            .id
            .ok_or_else(|| AppError::Validation("record requires id".into()))?;
        // update and delete resolve independent depths (a role's Team-Update
        // scope says nothing about its Delete scope for the same entity) —
        // see RecordAction::share_capability's doc comment.
        let action = if operation == "delete" {
            RecordAction::Delete
        } else {
            RecordAction::Update
        };
        // C-13: see `apply_ledgered_item`'s identical fallback comment.
        match record_access {
            Some((access_level, owner_visible)) => {
                entity_crud::require_record_access_with(
                    state,
                    ctx,
                    entity_id,
                    entity_name,
                    record_id,
                    action,
                    access_level,
                    owner_visible,
                )
                .await?;
            }
            None => {
                entity_crud::require_record_access(
                    state,
                    ctx,
                    entity_id,
                    entity_name,
                    record_id,
                    action,
                )
                .await?;
            }
        }
    }
    // U1 (basic-units plan B-R1): a note/communication/tag/follow is gated by
    // the record it is attached to, in bulk exactly as in single-record CRUD.
    let existing_id = record
        .id
        .filter(|_| matches!(operation, "update" | "delete"));
    if let Some(record_id) = existing_id {
        entity_crud::require_child_parent_access(state, ctx, entity_name, record_id).await?;
    }
    if matches!(operation, "create" | "update") {
        entity_crud::require_child_parent_access_for_write(
            state,
            ctx,
            entity_name,
            existing_id,
            obj,
        )
        .await?;
    }
    // M01 Core C-12: resolved here, on the pool, before the transaction below
    // opens — see `entity_crud::resolve_cascade_dependent_access`'s doc
    // comment. Only the "delete" branch below actually consults this.
    let cascade_access = if operation == "delete" {
        Some(entity_crud::resolve_cascade_dependent_access(state, ctx, dependents).await?)
    } else {
        None
    };
    let (_, org_ref) = entity_crud::fetch_audit_ctx(state, user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = match operation {
        "create" => {
            entity_mutation::with_defaults(
                !record.skip_defaults,
                entity_mutation::create_one(
                    &mut tx,
                    state,
                    ctx,
                    entity_name,
                    attrs,
                    obj,
                    user_id,
                    org_ref,
                    mode,
                ),
            )
            .await
        }
        "update" => match (record.id, record.expected_row_version) {
            (Some(record_id), Some(row_version)) => {
                entity_mutation::update_one(
                    &mut tx,
                    state,
                    ctx,
                    entity_name,
                    entity_id,
                    record_id,
                    attrs,
                    obj,
                    user_id,
                    row_version,
                    mode,
                )
                .await
            }
            // Unreachable in practice: validate_record_envelope already
            // guaranteed both fields are present for "update". Kept as a
            // graceful error instead of unwrap() so a future refactor that
            // loosens that guard fails loudly, not with a panic.
            _ => Err(AppError::internal(
                "staged-import record missing id/expected_row_version after validation",
            )),
        },
        "delete" => match record.id {
            Some(record_id) => {
                match entity_crud::guard_cascade_dependent_access(
                    &mut tx,
                    state,
                    ctx,
                    dependents,
                    record_id,
                    cascade_access.as_deref().unwrap_or(&[]),
                )
                .await
                {
                    Ok(()) => {
                        // A dry run rolls back; the origin is never stored.
                        let origin =
                            entity_mutation::DeleteOrigin::new(entity_mutation::DeleteKind::Bulk);
                        entity_mutation::delete_one(
                            &mut tx,
                            entity_name,
                            dependents,
                            record_id,
                            user_id,
                            record.expected_row_version,
                            &origin,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
            // Unreachable in practice: see the "update" arm's comment above.
            None => Err(AppError::internal(
                "staged-import record missing id after validation",
            )),
        },
        _ => Err(AppError::Validation(
            "unknown staged-import operation".into(),
        )),
    };
    // Dry run: never persist, regardless of outcome. An explicit, checked
    // rollback (rather than letting `tx` merely drop) so a rollback failure
    // itself surfaces as an error instead of being silently swallowed — this
    // function's entire contract is "guaranteed zero effect," so a failed
    // rollback must not be indistinguishable from a successful one.
    tx.rollback().await.map_err(AppError::internal)?;
    result
}

/// Stage an import
///
/// Stores rows to import into an entity for review; nothing is written to the entity until the import is approved.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/staged-import",
    tag = "entity",
    params(("entity" = String, Path, description = "The entity's logical name")),
    request_body = BulkRequestBody,
    responses(
        (status = 201, description = "Success", body = StagedImportResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::BulkAccepted)])))),
)]
async fn staged_import(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Bulk>>,
    // See `enqueue`'s identical parameter. Staging is the same
    // accept-now/apply-later contract, one approval step longer.
    _jobs: Available<BatchJobs>,
    Extension(claims): Extension<SessionClaims>,
    Path(entity_input): Path<String>,
    Json(mut body): Json<BulkRequestBody>,
) -> Result<(StatusCode, Json<StagedImportResponse>), AppError> {
    // D-766: staged rows resolve lookups against other entities in the
    // worker, outside the S2S entity ceiling — refuse a capped caller.
    ctx.refuse_if_capped()?;
    body.mark_skip_defaults();
    let (entity_id, entity_name, attrs, is_append_only) =
        entity_crud::resolve_entity(&state, &entity_input).await?;
    validate_request_shape(&body, bulk_cap(&state))?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }
    let dependents = state.entities.load().dependents_of(entity_id);
    let target = EntityMutationTarget {
        entity_id,
        entity_name: &entity_name,
        attrs: &attrs,
        dependents: &dependents,
    };

    // M12 (data management) — applied once here, before the preflight/
    // dry-run loop below, so both operate on the already-mapped field names
    // (field rename + lookup resolution; `transform` stays unevaluated,
    // D-408). A resolution failure becomes a per-record finding merged into
    // `mapping_errors` below — the same "rejected, not a whole-batch 422"
    // treatment `bulk_graph::run_preflight`'s findings already get, not a
    // second failure mode.
    let mut mapping_errors: Vec<(i32, String)> = Vec::new();
    if let Some(mapping_id) = body.mapping_ref {
        let (mapping_target_entity, mapping_fields) =
            crate::data_mapping::load_mapping(&state.base.db, mapping_id)
                .await?
                .ok_or_else(|| AppError::Validation("unknown mapping_ref".into()))?;
        if mapping_target_entity != entity_name {
            return Err(AppError::Validation(format!(
                "mapping_ref targets entity '{mapping_target_entity}', not '{entity_name}'"
            )));
        }
        let choice_matchers = crate::data_mapping::load_choice_matchers(
            &state.base.db,
            &entity_name,
            &attrs,
            &mapping_fields,
        )
        .await?;
        for (index, record) in body.records.iter_mut().enumerate() {
            if let Err(error) = crate::data_mapping::apply_mapping_to_record(
                &state.base.db,
                &attrs,
                &mapping_fields,
                &choice_matchers,
                record,
            )
            .await
            {
                mapping_errors.push((index as i32, error.to_string()));
            }
        }
    }

    // P-bulk-batch-integrity Gap A.1: run the whole-batch preflight before
    // the per-record dry-run loop, in its own short-lived transaction (the
    // loop below already runs one full transaction per record via
    // `dry_run_one`; holding a second, outer transaction open across that
    // whole loop would violate guidelines §4's "keep transactions short," and
    // buys nothing here — unlike `enqueue`/`approve_staged_import`, nothing
    // durable is written until after the loop finishes, so there is no
    // atomicity to protect between the preflight and this handler's own
    // final INSERT). This closes the dry-run's own structural blind spot:
    // `dry_run_one` unconditionally rolls back, so today two mutually-cyclic
    // records both report "passed" here with zero cross-record signal.
    let batch_mode = effective_batch_mode(&body).to_owned();
    let preflight = {
        let mut preflight_tx = attome_db::tx::begin(&state.base.db).await?;
        let findings = bulk_graph::run_preflight(
            &mut preflight_tx,
            &entity_name,
            entity_id,
            &attrs,
            &body.operation,
            &body.records,
        )
        .await?;
        attome_db::tx::commit(preflight_tx).await?;
        // Merge by index (not a plain `.extend` + collect into a map, which
        // would silently drop one reason on the rare index that carries
        // both a mapping-resolution error and a preflight finding).
        let mut merged: std::collections::BTreeMap<i32, Vec<String>> =
            std::collections::BTreeMap::new();
        for (index, reason) in merge_preflight_findings(findings)
            .into_iter()
            .chain(mapping_errors)
        {
            merged.entry(index).or_default().push(reason);
        }
        merged
            .into_iter()
            .map(|(index, reasons)| (index, reasons.join("; ")))
            .collect::<Vec<(i32, String)>>()
    };
    if !preflight.is_empty() && batch_mode == "atomic" {
        return Err(AppError::Validation(atomic_rejection_message(&preflight)));
    }
    let rejected_indices: std::collections::BTreeMap<i32, String> = preflight.into_iter().collect();

    // dry_run_one runs one full transaction per record (validation only,
    // rolled back), same per-record cost as a real mutation — apply the same
    // MAX_BULK_RECORDS cap `validate_request_shape` already enforces here, so
    // a submission can never exceed what the enqueue path would ever allow it
    // to become on approval. A preflight-rejected index is reported directly
    // without running `dry_run_one` for it — the batch-level finding is the
    // more informative reason, and dry_run_one's per-record check has
    // nothing to add for a record already reported as conflicting with
    // another record in the same batch.
    let import_mode = effective_mode(&body).to_owned();
    let mut report = Vec::with_capacity(body.records.len());
    let mut passed = 0i32;
    let mut failed = 0i32;
    let mut rejected = 0i32;
    // M17/D-433 — "validate + count + sample diff without writing": the
    // dry-run loop below already computes each passed update's before/after
    // row via `dry_run_one`'s (rolled-back) `MutationResult`; capture a
    // bounded sample of it here rather than doing a second, separate read
    // pass. Capped independent of `mode` — cheap either way, and a caller
    // that never asked for `mode: "dry_run"` still benefits from seeing what
    // an update would change before approving it.
    const MAX_SAMPLE_DIFF: usize = 10;
    let mut sample_diff: Vec<Value> = Vec::new();
    // C-13: resolved once for the whole batch — see
    // `resolve_batch_record_access`'s doc comment.
    let record_access =
        resolve_batch_record_access(&state, &ctx, entity_id, &entity_name, &body.operation).await?;
    for (index, record) in body.records.iter().enumerate() {
        if let Some(reason) = rejected_indices.get(&(index as i32)) {
            rejected += 1;
            report.push(json!({ "index": index, "status": "rejected", "error": reason }));
            continue;
        }
        let result = dry_run_one(
            &state,
            &ctx,
            &target,
            &body.operation,
            record,
            claims.sub,
            MutationMode::Strict,
            record_access,
        )
        .await;
        match result {
            Ok(mutation) => {
                passed += 1;
                report.push(json!({ "index": index, "status": "passed" }));
                if body.operation == "update" && sample_diff.len() < MAX_SAMPLE_DIFF {
                    sample_diff.push(json!({
                        "index": index,
                        "record_id": mutation.record_id,
                        "before": mutation.old_row,
                        "after": mutation.new_row,
                    }));
                }
            }
            Err(error) => {
                failed += 1;
                report.push(json!({
                    "index": index,
                    "status": "failed",
                    "error": error.to_string()
                }));
            }
        }
    }
    let import_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO automation_staged_import
            (id, entity_logicalname, operation, raw_records, validation_report, status, created_by, batch_mode, rejected, mapping_ref, mode)
         VALUES ($1, $2, $3, $4, $5, 'pending_review', $6, $7, $8, $9, $10)",
    )
    .bind(import_id)
    .bind(&entity_name)
    .bind(&body.operation)
    .bind(Value::Array(records_as_values(&body.records)?))
    .bind(Value::Array(report))
    .bind(claims.sub)
    .bind(&batch_mode)
    .bind(rejected)
    .bind(body.mapping_ref)
    .bind(&import_mode)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(StagedImportResponse {
            id: import_id,
            status: "pending_review".into(),
            total: body.records.len() as i32,
            passed,
            failed,
            rejected,
            sample_diff,
        }),
    ))
}

/// D-100: mirrors `apply_ledgered_item`'s D-099 row-claiming so a
/// redelivered/retried `ApplyStagedImport` job resumes safely instead of
/// double-applying an already-succeeded item. See `apply_ledgered_item` for
/// the full rationale. Extracts `row_version` from a mutation's
/// `row_to_json` result — every
/// entity table carries the column (F027), so its absence means the caller
/// passed something other than a real mutation outcome.
fn extract_row_version(row: Option<&Value>) -> Option<i64> {
    row.and_then(|r| r.get("row_version"))
        .and_then(Value::as_i64)
}

/// Approve a staged import
///
/// D-100: approving a staged import is enqueued, not run on the request
/// thread. The original synchronous handler ran one full transaction per
/// record inline in the HTTP response path with no size bound beyond the
/// original submission's `MAX_BULK_RECORDS` cap — a large approved import
/// could exceed `config.request_timeout` mid-loop, leaving the row stuck at
/// `status = 'approving'` forever (the `WHERE status = 'pending_review'`
/// guard on this same query meant a stuck row could never be re-approved or
/// retried). This handler now only validates, transitions the row, seeds the
/// item ledger, and enqueues — mirroring `enqueue`'s shape for regular bulk.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/staged-import/{id}/approve",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The staged import"),
    ),
    responses(
        (status = 201, description = "Success", body = StagedImportResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::ApplyStagedImport (process_ledger's LedgerTable::StagedItem arm)"),
        "the route only flips status to approving, seeds the item ledger and enqueues the job; \
         the job writes the parent BulkCompleted event in the same transaction as the \
         approved/rejected terminal-state update",
    )))),
)]
async fn approve_staged_import(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    // D-344: approval is the moment the staged rows actually become work —
    // it flips `pending_review` to `approving` and enqueues
    // `ApplyStagedImport` (a batch job). Approving into a dead worker leaves
    // the import parked in `approving` with no one to move it, which is
    // strictly worse than the `pending_review` state it came from, because
    // the `WHERE status = 'pending_review'` guard means it cannot be
    // approved again.
    _jobs: Available<BatchJobs>,
    Extension(claims): Extension<SessionClaims>,
    // See `enqueue`'s identical parameter for why this is `Option`.
    idempotency_handle: Option<Extension<idempotency_durable::DurableIdempotencyHandle>>,
    Path((entity_input, import_id)): Path<(String, Uuid)>,
) -> Result<(StatusCode, Json<StagedImportResponse>), AppError> {
    let (entity_id, entity_name, attrs, is_append_only) =
        entity_crud::resolve_entity(&state, &entity_input).await?;
    if is_append_only {
        return Err(AppError::Forbidden);
    }

    // M17/D-433: a `mode: "dry_run"` staged import must never be approved —
    // checked before the claiming UPDATE below (rather than folded into its
    // WHERE clause) so a caller gets a clear 422 explaining why, instead of
    // an indistinguishable 404.
    let existing_mode: Option<String> = sqlx::query_scalar(
        "SELECT mode FROM automation_staged_import
         WHERE id = $1 AND entity_logicalname = $2 AND is_deleted = false",
    )
    .bind(import_id)
    .bind(&entity_name)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if existing_mode.as_deref() == Some("dry_run") {
        return Err(AppError::Validation(
            "a dry-run staged import cannot be approved; resubmit without mode: \"dry_run\" \
             to stage it for approval"
                .into(),
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<StagedImportRow> = sqlx::query_as(
        "UPDATE automation_staged_import
         SET status = 'approving', updated_at = NOW(), row_version = row_version + 1
         WHERE id = $1 AND entity_logicalname = $2 AND status = 'pending_review'
         RETURNING operation, raw_records, validation_report, batch_mode",
    )
    .bind(import_id)
    .bind(&entity_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    let records_json = row.raw_records.clone();
    let records: Vec<BulkRecordEnvelope> =
        serde_json::from_value(row.raw_records).map_err(AppError::internal)?;
    let report_len = row
        .validation_report
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| AppError::internal("staged import report is not an array"))?;
    if report_len != records.len() {
        return Err(AppError::internal(
            "staged import report does not match raw record count",
        ));
    }
    let total = records.len() as i32;

    // P-bulk-batch-integrity Gaps A/C: re-run the same preflight as
    // defense-in-depth against metadata drift between submission and
    // approval (e.g. a unique index added to the entity in the interim), in
    // the SAME transaction as the item-ledger seed + enqueue below — an
    // "atomic" rejection here rolls the `status = 'approving'` transition
    // back too, via this transaction's own drop-rollback, leaving the row
    // exactly as it was at `pending_review`.
    let preflight = merge_preflight_findings(
        bulk_graph::run_preflight(
            &mut tx,
            &entity_name,
            entity_id,
            &attrs,
            &row.operation,
            &records,
        )
        .await?,
    );
    if !preflight.is_empty() && row.batch_mode == "atomic" {
        return Err(AppError::Validation(atomic_rejection_message(&preflight)));
    }

    sqlx::query(
        "INSERT INTO automation_staged_import_item
            (staged_import_id, item_index, record_id, payload, status)
         SELECT $1, (item.ordinality - 1)::integer,
                CASE WHEN item.value->>'id' IS NULL THEN NULL
                     ELSE (item.value->>'id')::uuid END,
                item.value, 'pending'
         FROM jsonb_array_elements($2::jsonb) WITH ORDINALITY AS item(value, ordinality)",
    )
    .bind(import_id)
    .bind(&records_json)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if !preflight.is_empty() {
        let (indices, reasons): (Vec<i32>, Vec<String>) = preflight.into_iter().unzip();
        sqlx::query(
            "UPDATE automation_staged_import_item AS t
             SET status = 'rejected', error = r.reason, updated_at = NOW(), row_version = row_version + 1
             FROM (SELECT unnest($2::int[]) AS item_index, unnest($3::text[]) AS reason) AS r
             WHERE t.staged_import_id = $1 AND t.item_index = r.item_index",
        )
        .bind(import_id)
        .bind(&indices)
        .bind(&reasons)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // D-193 Release B (BJB-10b): the staged-item ledger above holds every
    // record; see `enqueue`.
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::ApplyStagedImport(
            attome_core::jobs::ApplyStagedImportPayload {
                import_id,
                entity_logicalname: entity_name.clone(),
                operation: row.operation.clone(),
                records: Vec::new(),
                user_id: claims.sub,
            },
        ),
    )
    .await
    .map_err(AppError::internal)?;

    let response_body = StagedImportResponse {
        id: import_id,
        status: "approving".into(),
        total,
        passed: 0,
        failed: 0,
        rejected: 0,
        sample_diff: Vec::new(),
    };

    // Plan item 3.10 / D-541 rule 5 — same `BulkAccepted` event as `enqueue`,
    // in the same transaction as the approval claim + job enqueue above.
    // Approval, not staging, is "accepted" in the plan's sense: staging alone
    // creates no durable job and does no work.
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(&state, claims.sub).await;
    let accepted_event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.clone()),
        record_id: None,
        operation: AuditOperation::BulkAccepted,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(import_id),
        event_name: None,
        event_comment: Some(format!("staged import {} approved", row.operation)),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    write_bulk_accepted(
        &audit_service,
        &mut tx,
        accepted_event,
        Attribution::user(claims.sub),
        total,
    )
    .await?;

    // See `enqueue`'s identical step — completes the durable idempotency
    // record in the same commit as the approval claim + item-ledger insert
    // above, not a separate write.
    if let Some(Extension(handle)) = idempotency_handle {
        let response_bytes = serde_json::to_vec(&response_body).map_err(AppError::internal)?;
        idempotency_durable::complete_in_tx(
            &mut tx,
            handle.record_id,
            Some(import_id),
            StatusCode::ACCEPTED.as_u16(),
            &[("content-type".to_string(), "application/json".to_string())],
            &response_bytes,
        )
        .await
        .map_err(AppError::internal)?;
    }

    attome_db::tx::commit(tx).await?;

    Ok((StatusCode::ACCEPTED, Json(response_body)))
}

/// Worker-side processing for `EngineJob::ApplyStagedImport`, mirroring
/// `process`'s shape (crash/redelivery-safe via the item ledger, resumes at
/// whatever hasn't already committed as `succeeded`).
pub async fn process_staged_import(
    state: &EngineState,
    import_id: Uuid,
    entity_logicalname: &str,
    operation: &str,
    raw_records: Vec<Value>,
    user_id: Uuid,
) -> Result<(), AppError> {
    process_ledger(
        state,
        LedgerTable::StagedItem,
        import_id,
        entity_logicalname,
        operation,
        raw_records,
        user_id,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{BulkRecordEnvelope, validate_record_envelope};
    use serde_json::json;
    use uuid::Uuid;

    /// AA9-T3: the cap is the one passed in (the runtime setting's value).
    #[test]
    fn bulk_cap_follows_setting() {
        let body: super::BulkRequestBody = serde_json::from_value(json!({
            "operation": "create",
            "records": [{ "data": {} }, { "data": {} }, { "data": {} }, { "data": {} }],
        }))
        .expect("a bulk body");
        match super::validate_request_shape(&body, 3) {
            Err(attome_types::AppError::LimitExceeded { value, .. }) => assert_eq!(value, 3),
            other => panic!("4 records over a cap of 3: {other:?}"),
        }
        assert!(super::validate_request_shape(&body, 4).is_ok());
    }

    #[test]
    fn create_envelope_rejects_selector_and_version() {
        let record = BulkRecordEnvelope {
            id: Some(Uuid::now_v7()),
            expected_row_version: Some(0),
            data: json!({}),
            skip_defaults: false,
        };
        assert!(validate_record_envelope("create", &record).is_err());
    }

    #[test]
    fn update_and_delete_require_id_and_expected_version() {
        let record = BulkRecordEnvelope {
            id: None,
            expected_row_version: None,
            data: json!({}),
            skip_defaults: false,
        };
        assert!(validate_record_envelope("update", &record).is_err());
        assert!(validate_record_envelope("delete", &record).is_err());
    }
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(enqueue, get_status, staged_import, approve_staged_import))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
