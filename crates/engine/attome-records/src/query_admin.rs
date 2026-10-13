use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, audit_service};
use attome_core::changeset::{Layer, Op, RecordedOp, Recording, RecordingCtx};
use attome_core::{EngineState, quote_ident};
use attome_db::DbPool;
use attome_metadata::provision::{
    ReconcileOutcome, ReconcilePolicy, reject_unsafe_default_query_sql,
};
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Column, Executor, TypeInfo};
use std::collections::HashSet;
use utoipa::ToSchema;
use uuid::Uuid;

/// A minimal runtime-shape twin of `attome_server::bundle::model::QueryDef` —
/// D-477 (T3-2): `attome-server`'s `bundle/apply.rs` (the sole caller of
/// [`reconcile_query`]) translates its own bundle-wire-shape `QueryDef` into
/// this one at the call site, the same "wire shape in the bundle model,
/// runtime shape in the crate that consumes it" pattern
/// `attome_core::state_registry::StateModelDef` already establishes for
/// M07's `StateModelDef`. Only the fields `reconcile_query` actually reads.
#[derive(Clone, Debug)]
pub struct QueryDef {
    pub entity: Option<String>,
    pub name: String,
    pub sql: String,
    pub table_definition: Option<String>,
    pub required_privilege: Option<String>,
    pub is_report: bool,
    pub entity_mappings: Vec<QueryEntityMapping>,
}

impl QueryDef {
    /// Human display form, `entity.name` or `*.name` for a multi-entity
    /// query — same shape `attome_server::bundle::model::QueryRef::display`
    /// produces, inlined here rather than pulling that type in too.
    fn display_key(&self) -> String {
        match &self.entity {
            Some(e) => format!("{e}.{}", self.name),
            None => format!("*.{}", self.name),
        }
    }
}

#[derive(Clone, Debug)]
pub struct QueryEntityMapping {
    pub entity: String,
    pub id_column: String,
}

/// P-stored-query-containment addendum §11(d): `create_query`/`update_query`/
/// `delete_query` previously wrote no audit trail at all — confirmed by grep,
/// zero references to `query_admin`/`query_exec`/`sql_query` anywhere
/// under `attome-audit` before this fix. Builds the event only — each call site
/// writes it with `AuditService::write_in_tx` inside the same transaction as
/// the `sql_query` mutation (see `do_create_query`/`do_update_query`/
/// `delete_query` below), so a failed audit write now rolls the mutation
/// back too, same atomicity guarantee `entity_crud.rs` gives ordinary entity
/// CRUD — not the best-effort/logged-only posture `approval_admin::gate`'s
/// `Submitted` event has to settle for (that one genuinely can't share a
/// transaction across the base/xrm layer boundary; this one has no such
/// constraint, both writes are already on `state.base.db`).
async fn query_audit_event(
    state: &EngineState,
    actor_id: Uuid,
    operation: AuditOperation,
    query_id: Uuid,
    event_name: &str,
    comment: String,
) -> AuditEvent {
    let (user_ctx, organization_ref) = crate::entity_crud::fetch_audit_ctx(state, actor_id).await;
    AuditEvent {
        organization_ref,
        // D-541 rule 7: stored queries are Configuration (mandatory, rule 4).
        category: AuditCategory::Configuration,
        entity_name: Some("sql_query".to_string()),
        record_id: Some(query_id),
        operation,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event_name.to_string()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    }
}

// ── Reconcile support (shared by query_admin / view_admin / sidebar) ──────────
//
// P-environment-promotion §5 step 13: the attome-server half of the service
// reconcile API. C-19: this used to restate `attome_metadata::provision::
// reconcile`'s private decision matrix a third time (a `WriteStep`/
// `RowStatus`/`decide_step` copy under different names) — now a thin
// re-export/wrapper over the one shared implementation in
// `attome_core::reconcile`. `ReconcileStep` stays a type alias rather
// than a fresh enum, and `reconcile_step`/`customized_marker` stay free
// functions under their original names/signatures, so nothing external has
// to change its import: `app_admin.rs`, `calendar_admin.rs`,
// `rule_admin.rs`, `sidebar.rs`, and `view_admin.rs` all still write `use
// attome_records::query_admin::{ReconcileStep, customized_marker,
// map_unique_violation, reconcile_step, ...}` unchanged, and `ReconcileStep::
// outcome()` keeps working because it is `WriteStep`'s own inherent method,
// which a type alias inherits.
pub type ReconcileStep = attome_core::reconcile::WriteStep;

/// The `is_customized` value a policy writes, or `None` when it leaves the
/// column alone (`Seed`). Thin wrapper over `ReconcilePolicy::
/// customized_marker` (C-19); kept as a free function since several
/// `attome-server` files import it by this name.
pub fn customized_marker(policy: ReconcilePolicy) -> Option<bool> {
    policy.customized_marker()
}

/// `current` is `Some((is_customized, is_live))` for an existing row — this
/// file's tuple shape predates `attome_core::reconcile::RowStatus` (a
/// named struct); this wrapper adapts one to the other so no caller has to
/// change its call shape.
pub fn reconcile_step(
    policy: ReconcilePolicy,
    current: Option<(bool, bool)>,
    state_differs: bool,
) -> ReconcileStep {
    let row = current.map(
        |(is_customized, is_live)| attome_core::reconcile::RowStatus {
            is_customized,
            is_live,
        },
    );
    attome_core::reconcile::decide_step(policy, row, state_differs)
}

/// A unique-key violation (SQLSTATE 23505) on a metadata INSERT/UPDATE — the
/// natural-key indexes migration 0133 added (`uq_core_sql_query_entity_name`,
/// `uq_xrm_sidebar_parent_name`) and `uq_core_view_name` — is a
/// client-actionable 409 ("that name is taken"), or a lost race against a
/// concurrent writer of the same key that a retry resolves; never a masked
/// 500. Same classification `entity_mutation::classify_db_error` gives the
/// generic CRUD path.
///
/// M01 Core C-23: everything else now falls through to `attome_db::classify`
/// (instead of a blanket `AppError::internal`), so a foreign-key violation
/// or a serialization/deadlock conflict on the same INSERT/UPDATE also
/// resolves to a 409/422 rather than a masked 500 — this function's own
/// 23505 message stays exactly as it was.
pub fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("an active object with this name already exists")
    } else {
        attome_db::classify(error)
    }
}

/// Resolves an entity logicalname to its live `entity_info.id`.
pub async fn resolve_live_entity_id(db: &DbPool, logicalname: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{logicalname}'"
        ))
    })
}

// ── DB rows ───────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct QueryRow {
    id: Uuid,
    record_no: Option<String>,
    entity_logical_name: Option<Uuid>,
    is_active: Option<bool>,
    sql_preview: Option<String>,
    owner_layer: String,
}

#[derive(sqlx::FromRow)]
struct QueryDetailRow {
    id: Uuid,
    sql_query: Option<String>,
    table_definition: Option<String>,
    record_no: Option<String>,
    entity_logical_name: Option<Uuid>,
    is_active: Option<bool>,
    required_privilege: Option<String>,
    is_report: Option<bool>,
    /// C-19: `sql_query.row_version` (migration 0443) — the
    /// concurrency token `update_query`'s optional `If-Match` checks.
    row_version: i64,
    owner_layer: String,
}

// ── Changeset recording (Solution 7 Phase 1, D-785, design §1.1) ─────────────
//
// `create_query`/`update_query`/`delete_query` record one `upsert_query` /
// `retire_query` operation, target `{ entity, query }` (the bundle's `QueryDef`
// key: entity logicalname + `record_no`), as the last statement before the
// publish transaction commits. A new row is stamped with the recording
// changeset's layer; a republish or retire is refused with 409
// `layer_mismatch` unless the row's `owner_layer` is that layer. The bundle
// reconcile path and the approval-executed path (`do_create_query` /
// `do_update_query`, called by `attome-server::approval_admin`) pass no
// recording: they stamp `project` (`platform` for a seed reconcile,
// `policy_layer`) and record nothing —
// design §4.5's approval-deferred recording is lane L6's.

/// `target.entity` of a multi-entity query (`entity_logical_name IS NULL`,
/// the bundle's `QueryDef { entity: None }`). The changeset target must be a
/// logical name (`^[a-z][a-z0-9_]*$`), and there is no entity to name, so
/// this sentinel stands in for "none". It is longer than
/// `attome_metadata::provision::MAX_IDENTIFIER_LEN` (48), so no real entity can
/// ever carry it; close-time translation maps it back to `entity: None`.
pub const MULTI_ENTITY_QUERY_TARGET: &str =
    "multi_entity_stored_query_with_no_primary_entity_bound";

/// The layer a row a recorded write inserts gets; `unrecorded` when nothing
/// records the write (`project` on the admin and approval paths, the
/// policy's layer on the reconcile path).
fn stamp_layer(recording: Option<&Recording>, unrecorded: Layer) -> Result<Layer, AppError> {
    recording.map_or(Ok(unrecorded), Recording::stamp)
}

/// The layer `reconcile_query` stamps on a row it inserts (design §1.4): a
/// boot seed writes the platform's own definitions, a bundle apply or an
/// admin reconcile writes `project`.
fn policy_layer(policy: ReconcilePolicy) -> Layer {
    match policy {
        ReconcilePolicy::Seed => Layer::Platform,
        ReconcilePolicy::Admin | ReconcilePolicy::Bundle { .. } => Layer::Project,
    }
}

/// A stored `owner_layer`, parsed. The column's CHECK admits only the four
/// layers, so an unknown value is a defect, not client input.
fn parse_owner_layer(value: &str) -> Result<Layer, AppError> {
    Layer::parse(value).ok_or_else(|| AppError::internal(format!("unknown owner_layer {value:?}")))
}

/// The changeset operation for a stored query just written. `entity` is the
/// bound entity's logicalname (`None` for a multi-entity query), `name` its
/// `record_no`.
///
/// `None` for a nameless query: a changeset names objects by logical key and
/// a stored query's key is its name, so a nameless (ad-hoc) query has no
/// identity another deployment could apply it under — the same reason
/// `bundle/export.rs` never exports one. Its write succeeds unrecorded, as
/// before D-785 (wire behaviour unchanged); name a query to promote it.
fn query_op(
    op: Op,
    id: Uuid,
    entity: Option<&str>,
    name: Option<&str>,
    snapshot: Value,
) -> Option<RecordedOp> {
    let name = name.filter(|n| !n.trim().is_empty())?;
    Some(RecordedOp {
        op,
        object_kind: "query",
        object_ref: Some(id),
        target: serde_json::json!({
            "entity": entity.unwrap_or(MULTI_ENTITY_QUERY_TARGET),
            "query": name,
        }),
        snapshot,
        changed: Vec::new(),
    })
}

/// Reads the post-write row inside the write's transaction and builds its
/// operation: enumerated columns plus the bound entity's logicalname, and the
/// current version's entity mappings when the caller has them. `None` for a
/// nameless query (see [`query_op`]).
async fn recorded_query_op(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    op: Op,
    id: Uuid,
    entity_mappings: Option<&[EntityMappingInfo]>,
) -> Result<Option<RecordedOp>, AppError> {
    let row: Option<(Option<String>, Option<String>, Value)> = sqlx::query_as(
        "SELECT q.record_no, e.logicalname, jsonb_build_object( \
             'id', q.id, 'name', q.record_no, \
             'entity_logical_name', q.entity_logical_name, 'entity', e.logicalname, \
             'sql_query', q.sql_query, 'table_definition', q.table_definition, \
             'required_privilege', q.required_privilege, 'is_report', q.is_report, \
             'is_active', q.is_active, 'is_customized', q.is_customized, \
             'row_version', q.row_version, 'owner_layer', q.owner_layer) \
         FROM sql_query q \
         LEFT JOIN entity_info e ON e.id = q.entity_logical_name \
         WHERE q.id = $1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (name, entity, mut snapshot) = row.ok_or(AppError::NotFound)?;
    if let (Some(mappings), Some(map)) = (entity_mappings, snapshot.as_object_mut()) {
        map.insert(
            "entity_mappings".into(),
            serde_json::to_value(mappings).map_err(AppError::internal)?,
        );
    }
    let recorded = query_op(op, id, entity.as_deref(), name.as_deref(), snapshot);
    if recorded.is_none() {
        tracing::info!(
            query_id = %id,
            op = op.as_str(),
            "changeset recording: a nameless stored query is not recorded (it has no logical key)"
        );
    }
    Ok(recorded)
}

/// Checks the row's owner layer against the recording (409
/// `layer_mismatch`); `NotFound` when the row does not exist. Takes the row
/// lock the write that follows would take anyway.
async fn check_query_owner(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    recording: &Recording,
    id: Uuid,
) -> Result<(), AppError> {
    let layer: Option<String> =
        sqlx::query_scalar("SELECT owner_layer FROM sql_query WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    let layer = layer.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&layer)?)
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct QueryMeta {
    id: Uuid,
    name: String,
    sql_preview: String,
    entity_logical_name: Option<Uuid>,
    is_active: bool,
    /// Solution 7 (D-785): the layer that owns this query — `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer may
    /// change or retire it.
    owner_layer: String,
}

impl std::fmt::Debug for QueryMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryMeta").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct QueryDetail {
    id: Uuid,
    name: String,
    sql_query: String,
    table_definition: String,
    entity_logical_name: Option<Uuid>,
    is_active: bool,
    /// P1.1e: when set, `query/execute` requires this exact privilege key
    /// instead of the coarse admin-only default.
    required_privilege: Option<String>,
    /// P1.1e: raises the read-only transaction's statement_timeout to 5s.
    is_report: bool,
    /// P-stored-query-containment Phase 3 (D-146): the current published
    /// version's admin-declared entity/id-column mappings — what
    /// `query_exec.rs` splices a per-record RLS predicate against for a
    /// custom/multi-entity query. Empty for a single-entity query (which
    /// doesn't need one — see `entity_logical_name`) or a multi-entity query
    /// that hasn't declared any mapping yet (still gated by the prior
    /// all-or-nothing Global-scope-required check).
    entity_mappings: Vec<EntityMappingInfo>,
    /// C-19: `sql_query.row_version` (migration 0443) — send back as
    /// `If-Match` on the next `PATCH` to guard against a lost update. Additive:
    /// a caller that ignores this keeps behaving exactly as it did before this
    /// column existed (`update_query`'s `If-Match` stays optional).
    row_version: i64,
    /// Solution 7 (D-785): the layer that owns this query.
    owner_layer: String,
}

impl std::fmt::Debug for QueryDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryDetail").finish_non_exhaustive()
    }
}

/// One admin-declared entity/id-column mapping, as accepted on
/// create/update. `entity` is a logicalname (matches the rest of this file's
/// convention — `sql_query.entity_logical_name` is the one place a raw
/// UUID is used instead, for historical reasons this plan doesn't touch).
#[derive(Deserialize, Clone)]
struct EntityMappingInput {
    entity: String,
    id_column: String,
}

/// Response shape for [`QueryDetail::entity_mappings`] — echoes the input
/// shape plus the resolved `entity_ref` for a caller that wants to cross-
/// reference `entity_info` without a second lookup.
#[derive(Serialize, Clone, ToSchema)]
struct EntityMappingInfo {
    entity: String,
    entity_ref: Uuid,
    id_column: String,
}

#[derive(Deserialize, ToSchema)]
struct DescribeQueryBody {
    sql_query: String,
}

#[derive(Serialize, ToSchema)]
struct DescribedColumn {
    name: String,
    data_type: &'static str,
}

fn editor_data_type(pg_type: &str) -> &'static str {
    match pg_type {
        "BOOL" => "boolean",
        "INT2" | "INT4" | "INT8" | "FLOAT4" | "FLOAT8" | "NUMERIC" | "MONEY" => "number",
        "DATE" | "TIME" | "TIMETZ" | "TIMESTAMP" | "TIMESTAMPTZ" | "INTERVAL" => "date",
        "UUID" => "uuid",
        _ => "string",
    }
}

// ── Request types ─────────────────────────────────────────────────────────────

/// D-195/P-four-eyes-approval §5 step 9 — the `action_type` for both
/// creating and re-publishing a stored query (`do_create_query`/
/// `do_update_query` below share this one action_type; the approval
/// payload's `"op"` discriminator tells `execute_approved` which to
/// dispatch to). `attome_approval` treats it as an opaque string either way.
pub const ACTION_QUERY_PUBLISH: &str = "query.publish";

#[derive(Deserialize)]
pub struct CreateQueryBody {
    name: Option<String>,
    sql_query: String,
    table_definition: Option<String>,
    entity_logical_name: Option<Uuid>,
    #[serde(default)]
    required_privilege: Option<String>,
    #[serde(default)]
    is_report: bool,
    /// P-stored-query-containment Phase 3 (D-146). `None`/omitted means no
    /// mappings — a multi-entity query with none declared keeps today's
    /// all-or-nothing Global-scope-required gate at execute time.
    #[serde(default)]
    entity_mappings: Option<Vec<EntityMappingInput>>,
}

impl std::fmt::Debug for CreateQueryBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateQueryBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
pub struct UpdateQueryBody {
    name: Option<String>,
    sql_query: Option<String>,
    table_definition: Option<String>,
    entity_logical_name: Option<Uuid>,
    #[serde(default)]
    required_privilege: Option<String>,
    #[serde(default)]
    is_report: Option<bool>,
    /// P-stored-query-containment Phase 3 (D-146). `None`/omitted carries
    /// forward the previous version's mappings unchanged (same convention
    /// as every other field in this body); `Some(vec![])` explicitly clears
    /// them; `Some(vec![...])` replaces them.
    #[serde(default)]
    entity_mappings: Option<Vec<EntityMappingInput>>,
}

impl std::fmt::Debug for UpdateQueryBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateQueryBody").finish_non_exhaustive()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn meta_from_row(r: QueryRow) -> QueryMeta {
    QueryMeta {
        id: r.id,
        name: r
            .record_no
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unnamed Query".into()),
        sql_preview: r.sql_preview.unwrap_or_default(),
        entity_logical_name: r.entity_logical_name,
        is_active: r.is_active.unwrap_or(true),
        owner_layer: r.owner_layer,
    }
}

fn detail_from_row(r: QueryDetailRow, entity_mappings: Vec<EntityMappingInfo>) -> QueryDetail {
    QueryDetail {
        id: r.id,
        name: r
            .record_no
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Unnamed Query".into()),
        sql_query: r.sql_query.unwrap_or_default(),
        table_definition: r.table_definition.unwrap_or_else(|| "[]".into()),
        entity_logical_name: r.entity_logical_name,
        is_active: r.is_active.unwrap_or(true),
        required_privilege: r.required_privilege,
        is_report: r.is_report.unwrap_or(false),
        entity_mappings,
        row_version: r.row_version,
        owner_layer: r.owner_layer,
    }
}

/// Fetches the entity/id-column mappings for the *current* (latest)
/// published version of `query_id` — `None` when the query has never been
/// published (pre-containment row) or has no mappings declared.
async fn fetch_current_entity_mappings(
    db: &DbPool,
    query_id: Uuid,
) -> Result<Vec<EntityMappingInfo>, AppError> {
    sqlx::query_as::<_, (String, Uuid, String)>(
        "SELECT ei.logicalname, m.entity_ref, m.id_column
         FROM sql_query_entity_mapping m
         JOIN entity_info ei ON ei.id = m.entity_ref
         WHERE m.query_version_id = (
             SELECT id FROM sql_query_version
             WHERE query_id = $1 ORDER BY id DESC LIMIT 1
         )
         ORDER BY ei.logicalname, m.id_column",
    )
    .bind(query_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
    .map(|rows| {
        rows.into_iter()
            .map(|(entity, entity_ref, id_column)| EntityMappingInfo {
                entity,
                entity_ref,
                id_column,
            })
            .collect()
    })
}

// ── Publish-time relation lint + version capture (P-stored-query-containment,
// phases 1(b)/2, D-126) ─────────────────────────────────────────────────────

/// Plans the candidate SQL on the **readonly** pool — the same identity
/// `query/execute` runs stored queries under — so phase 1(a)'s per-table
/// grants (migration 0046, `attome_metadata::provision::grant_readonly_select`)
/// are themselves the enforcement: this lint is the friendly 422 at publish
/// time, the missing grant is the actual guarantee at execute time. Returns
/// the plan's total cost (cached into `sql_query_version` so
/// `query/execute` doesn't have to re-plan on every request, phase 2) and
/// every relation the plan touches. Rejects, naming the relation, if any
/// touched relation is not a live `entity_info` entity table.
/// Publish-time relation check for one query, routed by `skip`
/// (`PublishParams::skip_containment_lint`): `false` runs the full
/// `EXPLAIN`-based [`lint_and_plan`] every admin/API-authored query gets;
/// `true` runs `attome_metadata::provision::reject_unsafe_default_query_sql`'s
/// structural-only check instead — same trust boundary as that function's
/// own seed callers, see [`reconcile_query`]'s doc comment. The skip path
/// returns `(0.0, vec![])`: no `EXPLAIN` runs, so there is no measured cost
/// or touched-relation list to cache — `sql_query_version.relations`
/// simply stays empty for a platform-bundle-published query, the same gap
/// `ensure_default_query` already accepts (it writes no version row at all).
async fn plan_or_trust(
    db_readonly: &DbPool,
    sql_query: &str,
    skip: bool,
) -> Result<(f64, Vec<String>), AppError> {
    if skip {
        reject_unsafe_default_query_sql(sql_query)?;
        return Ok((0.0, Vec::new()));
    }
    lint_and_plan(db_readonly, sql_query).await
}

/// C-25 (query-execution RLS gap): `query_exec`'s single-entity branch
/// (`qrow.entity_logical_name.is_some()`) always calls
/// `attome_security::rls_predicate(ctx, entity_id, "t", ...)` — hardcoded to
/// table alias `t`, because a single-entity query's RLS filter has nowhere
/// else to attach it. That is correct only when the published SQL is truly
/// `FROM {table} t` with no join: the moment it touches a second relation
/// (an admin-authored `JOIN`), rows from that second relation reach the
/// caller with no RLS predicate ever applied to them, since nothing filters
/// anything but `t`. A multi-entity query is meant to declare each joined
/// relation through `entity_mappings` instead (see `query_exec.rs`'s
/// multi-entity branch, which applies `rls_predicate_by_column` per
/// declared mapping) — so this rejects the unsafe combination at publish
/// time rather than leaving it to leak silently at execute time. Only
/// meaningful when the lint actually ran (`relations` is always empty under
/// `skip_containment_lint`, the platform-bundle trust boundary
/// `plan_or_trust` documents), which is exactly right: a bundle-authored
/// query is vetted before export, never through this admin path.
fn reject_unsafe_single_entity_join(
    entity_logical_name: Option<Uuid>,
    relations: &[String],
) -> Result<(), AppError> {
    if entity_logical_name.is_some() && relations.len() > 1 {
        return Err(AppError::Validation(
            "a single-entity query (entity_logical_name set) may not join additional \
             relations — its RLS filter only scopes the query's own table (alias `t`), so a \
             join would expose rows from the joined relation with no row-level-security \
             predicate ever applied to them. Publish it as a multi-entity query instead, with \
             an explicit entity_mapping per joined relation."
                .into(),
        ));
    }
    Ok(())
}

async fn lint_and_plan(
    db_readonly: &DbPool,
    sql_query: &str,
) -> Result<(f64, Vec<String>), AppError> {
    let explain_sql = format!("EXPLAIN (FORMAT JSON) SELECT * FROM ({sql_query}) AS t LIMIT 0");
    let plan: Value = sqlx::query_scalar(&explain_sql)
        .fetch_one(db_readonly)
        .await
        .map_err(|e| AppError::Validation(format!("sql_query failed to plan: {e}")))?;

    let total_cost = plan
        .pointer("/0/Plan/Total Cost")
        .and_then(Value::as_f64)
        .ok_or_else(|| AppError::internal("PostgreSQL returned an invalid query plan"))?;

    // P-stored-query-containment addendum §11(b): `collect_relation_names`
    // only sees `Relation Name` nodes — Postgres's planner never descends
    // into a called function's body, so `SELECT * FROM some_function()`
    // would otherwise publish clean even if that function internally reads
    // a forbidden table. Reject any `Function Scan` node outright at
    // publish time rather than relying solely on the readonly role's
    // (migration 0060) revoked EXECUTE privilege to fail it at execute
    // time — same "friendly 422 now, the missing grant is the actual
    // guarantee" split this function already uses for relations.
    if let Some(function_name) = find_function_scan(&plan) {
        return Err(AppError::Validation(format!(
            "sql_query calls a function ({function_name}), which stored queries are not \
             permitted to do — function bodies are opaque to the publish-time relation lint \
             and could read a table this query isn't otherwise granted to see"
        )));
    }

    let mut relations = HashSet::new();
    collect_relation_names(&plan, &mut relations);

    if !relations.is_empty() {
        let names: Vec<String> = relations.iter().cloned().collect();
        let known: Vec<String> = sqlx::query_scalar(
            "SELECT logicalname FROM entity_info \
             WHERE (is_active IS NULL OR is_active = true) AND logicalname = ANY($1)",
        )
        .bind(names.as_slice())
        .fetch_all(db_readonly)
        .await
        .map_err(AppError::internal)?;
        let known: HashSet<&str> = known.iter().map(String::as_str).collect();

        for relation in &relations {
            if !known.contains(relation.as_str()) {
                return Err(AppError::Validation(format!(
                    "sql_query references a relation that is not a registered entity table: {relation}"
                )));
            }
        }
    }

    let mut relations: Vec<String> = relations.into_iter().collect();
    relations.sort();
    Ok((total_cost, relations))
}

/// Recursively collects every `"Relation Name"` value from an `EXPLAIN
/// (FORMAT JSON)` plan — plan nodes nest under `"Plan"`/`"Plans"` keys, and
/// the document's top level is itself a one-element array.
fn collect_relation_names(node: &Value, out: &mut HashSet<String>) {
    if let Some(name) = node.get("Relation Name").and_then(Value::as_str) {
        out.insert(name.to_owned());
    }
    if let Some(plan) = node.get("Plan") {
        collect_relation_names(plan, out);
    }
    if let Some(plans) = node.get("Plans").and_then(Value::as_array) {
        for p in plans {
            collect_relation_names(p, out);
        }
    }
    if let Some(arr) = node.as_array() {
        for item in arr {
            collect_relation_names(item, out);
        }
    }
}

/// Walks an `EXPLAIN (FORMAT JSON)` plan for any `"Node Type": "Function
/// Scan"` node — same recursion shape as `collect_relation_names`, but
/// returns the first offending function name (if `EXPLAIN` reported one)
/// instead of collecting everything, since one is enough to reject the
/// publish. `Function Scan` covers `FROM some_function(...)`,
/// `LATERAL some_function(...)`, and a function used as a row source inside
/// a join — anywhere Postgres's planner would otherwise hide table access
/// this lint can't see into.
fn find_function_scan(node: &Value) -> Option<String> {
    if node.get("Node Type").and_then(Value::as_str) == Some("Function Scan") {
        return Some(
            node.get("Function Name")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>")
                .to_owned(),
        );
    }
    if let Some(plan) = node.get("Plan")
        && let Some(found) = find_function_scan(plan)
    {
        return Some(found);
    }
    if let Some(plans) = node.get("Plans").and_then(Value::as_array) {
        for p in plans {
            if let Some(found) = find_function_scan(p) {
                return Some(found);
            }
        }
    }
    if let Some(arr) = node.as_array() {
        for item in arr {
            if let Some(found) = find_function_scan(item) {
                return Some(found);
            }
        }
    }
    None
}

/// Writes the immutable version row `query_exec.rs` reads at execute time
/// (phase 2 / audit finding #25 — skips re-planning on every request).
/// Append-only (D-005): never updated, only ever inserted; "current" is
/// whichever row for this `query_id` sorts last by id (uuidv7 is
/// time-ordered, D-017/D-018).
///
/// `created_by` is `None` for `revalidate_all`'s background-job-triggered
/// version rows (addendum §11(c)) — no admin acted, so there is no user to
/// attribute the row to; `create_query`/`update_query` always pass
/// `Some(ctx.user_id)`.
///
/// Generic over the executor (same `E: sqlx::PgExecutor<'e>` shape
/// `query_exec.rs`'s `run_live_explain` already uses) so `revalidate_all`
/// can keep calling this with a bare pool reference while `do_create_query`/
/// `do_update_query` (§11(d)) pass `&mut *tx` and get this insert folded into
/// their own transaction instead of auto-committing on its own.
async fn write_version<'e, E>(
    db: E,
    query_id: Uuid,
    sql_query: &str,
    cost_estimate: f64,
    relations: &[String],
    created_by: Option<Uuid>,
) -> Result<Uuid, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let version_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query_version \
         (id, query_id, sql_query, relations, cost_estimate, created_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, NOW(), $6)",
    )
    .bind(version_id)
    .bind(query_id)
    .bind(sql_query)
    .bind(relations)
    .bind(cost_estimate)
    .bind(created_by)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(version_id)
}

// ── Background plan revalidation (P-stored-query-containment addendum
// §11(c), `EngineJob::RevalidateQueryPlans`) ─────────────────────────────

/// Counts from one `revalidate_all` run — the job handler logs this rather
/// than returning it to any caller, since nothing currently consumes it
/// beyond an operator reading the log line.
pub struct RevalidationSummary {
    /// A fresh `sql_query_version` row was written because the plan's
    /// cost estimate or relation set had drifted since the last version.
    pub revalidated: usize,
    /// Re-planned successfully but nothing had drifted past
    /// `RECOST_DRIFT_RATIO` — no new version row written.
    pub unchanged: usize,
    /// The query no longer passes `lint_and_plan` (its entity was retired,
    /// a column disappeared, etc.) — skipped, not failed: the row's last
    /// good version keeps serving `query/execute` regardless.
    pub failed: usize,
}

impl std::fmt::Debug for RevalidationSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevalidationSummary")
            .finish_non_exhaustive()
    }
}

/// A cached `cost_estimate` is allowed to move by up to this fraction before
/// `revalidate_all` bothers writing a new version row for it. Keeps a nightly
/// revalidation pass from appending a `sql_query_version` row (D-005
/// append-only — rows are never pruned) for every published query on every
/// run regardless of whether anything meaningful changed; a query whose plan
/// genuinely drifted (table grew/shrank, a new index appeared) still gets a
/// fresh row promptly. Chosen as a round, conservative number — no
/// production cost-drift data exists yet to tune it against (same
/// unmeasured-threshold caveat the plan's own clock-rollback forgiveness
/// window and cursor-default flip already carry elsewhere in this repo).
const RECOST_DRIFT_RATIO: f64 = 0.2;

/// `true` if `current` has moved far enough from `previous` (by
/// `RECOST_DRIFT_RATIO`) to be worth a fresh version row. A previous
/// estimate of exactly `0.0` (a `LIMIT 0`-cost trivial query) is treated as
/// "any positive cost is drift" rather than dividing by zero.
fn cost_has_drifted(previous: f64, current: f64) -> bool {
    if previous <= 0.0 {
        return current > 0.0;
    }
    ((current - previous).abs() / previous) > RECOST_DRIFT_RATIO
}

/// Re-runs the publish-time relation lint (`lint_and_plan`) for every
/// currently active `sql_query` row, on the same readonly pool/identity
/// `query/execute` itself runs under — so a revalidation that passes is a
/// genuine guarantee, not just a self-report. Appends a fresh
/// `sql_query_version` row only when the newly measured cost or
/// relation set has actually drifted from the current version
/// (`cost_has_drifted`); otherwise this run is a no-op for that query beyond
/// the `EXPLAIN` itself.
///
/// A single query failing to (re-)plan is logged and skipped, never
/// propagated — one broken query (its entity retired, a column dropped)
/// must not block every other query's revalidation, and skipping never
/// deletes or weakens that query's last good version.
pub async fn revalidate_all(
    db_readonly: &DbPool,
    db: &DbPool,
) -> Result<RevalidationSummary, AppError> {
    let queries: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, sql_query FROM sql_query \
         WHERE (is_active IS NULL OR is_active = true) AND sql_query IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut summary = RevalidationSummary {
        revalidated: 0,
        unchanged: 0,
        failed: 0,
    };

    for (query_id, sql_query) in queries {
        let (cost_estimate, relations) = match lint_and_plan(db_readonly, &sql_query).await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(
                    query_id = %query_id,
                    error = %e,
                    "query plan revalidation: skipping — no longer passes the publish-time lint"
                );
                summary.failed += 1;
                continue;
            }
        };

        let previous: Option<(f64, Vec<String>)> = sqlx::query_as(
            "SELECT cost_estimate, relations FROM sql_query_version \
             WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(query_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;

        let drifted = match &previous {
            Some((prev_cost, prev_relations)) => {
                cost_has_drifted(*prev_cost, cost_estimate) || prev_relations != &relations
            }
            None => true,
        };

        if !drifted {
            summary.unchanged += 1;
            continue;
        }

        write_version(db, query_id, &sql_query, cost_estimate, &relations, None).await?;
        summary.revalidated += 1;
    }

    Ok(summary)
}

/// P-stored-query-containment Phase 3 (D-146): validates and persists this
/// publish's entity/id-column mappings — the trust anchor
/// `apply_multi_entity_record_scope` (`query_exec.rs`) reads at execute time
/// to splice a per-record RLS predicate for a custom/multi-entity query.
/// Runs on the readonly pool for the same reason `lint_and_plan` does (same
/// identity `query/execute` runs under, so a mapping that validates here is
/// guaranteed to actually resolve at execute time too).
///
/// Every declared mapping is checked two ways, both fail-closed (422, never
/// a silent skip):
/// - the entity must be one of the relations `lint_and_plan` already found
///   this SQL actually touches (never let an admin declare a mapping for a
///   table the query doesn't reference — meaningless, and would silently
///   never apply);
/// - `id_column` must be a real output column of the query and cast
///   cleanly to `uuid` (`quote_ident`-guarded — guidelines §4, dynamic
///   identifiers only from a validated-then-quoted source).
///
/// M01 Core C-12: split into this validation half (pure readonly-pool
/// probes, no transaction at all) and [`write_entity_mappings`] (pure
/// `INSERT`s against the caller's write transaction, no pool probe of any
/// kind) — the combined function used to run both halves with the write
/// transaction already open, so each mapping's two readonly-pool round trips
/// acquired a second pool connection while the first was still checked out
/// for that transaction, which self-deadlocks under pool saturation. Callers
/// (`publish_new_query`/`republish_query`) now call this BEFORE opening their
/// write transaction, then [`write_entity_mappings`] once it is open.
///
/// Every declared mapping is checked two ways, both fail-closed (422, never
/// a silent skip):
/// - the entity must be one of the relations `lint_and_plan` already found
///   this SQL actually touches (never let an admin declare a mapping for a
///   table the query doesn't reference — meaningless, and would silently
///   never apply);
/// - `id_column` must be a real output column of the query and cast
///   cleanly to `uuid` (`quote_ident`-guarded — guidelines §4, dynamic
///   identifiers only from a validated-then-quoted source).
///
/// Runs on the readonly pool for the same reason `lint_and_plan` does (same
/// identity `query/execute` runs under, so a mapping that validates here is
/// guaranteed to actually resolve at execute time too).
async fn validate_entity_mappings(
    db_readonly: &DbPool,
    sql_query: &str,
    relations: &[String],
    mappings: &[EntityMappingInput],
) -> Result<Vec<EntityMappingInfo>, AppError> {
    let mut out = Vec::with_capacity(mappings.len());
    for m in mappings {
        if !relations.iter().any(|r| r == &m.entity) {
            return Err(AppError::Validation(format!(
                "entity_mappings: '{}' is declared as a mapping but not referenced by this query",
                m.entity
            )));
        }

        let entity_ref: Uuid = sqlx::query_scalar(
            "SELECT id FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&m.entity)
        .fetch_optional(db_readonly)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::Validation(format!("entity_mappings: unknown entity '{}'", m.entity))
        })?;

        let quoted_col = quote_ident(&m.id_column);
        let probe = format!("SELECT {quoted_col}::uuid FROM ({sql_query}) AS t LIMIT 0");
        sqlx::query(&probe)
            .execute(db_readonly)
            .await
            .map_err(|e| {
                AppError::Validation(format!(
                    "entity_mappings: id_column '{}' for entity '{}' is not a uuid-castable \
                 output column of this query: {e}",
                    m.id_column, m.entity
                ))
            })?;

        out.push(EntityMappingInfo {
            entity: m.entity.clone(),
            entity_ref,
            id_column: m.id_column.clone(),
        });
    }
    Ok(out)
}

/// M01 Core C-12 — the write half of the old combined function: pure
/// `INSERT`s against the caller's already-open write transaction, no pool
/// probe of any kind. `mappings` must already be validated
/// ([`validate_entity_mappings`]). Same `&mut **tx` idiom
/// `entity_crud::grant_creator_share` already uses for a helper called with a
/// transaction reference.
async fn write_entity_mappings(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    query_version_id: Uuid,
    mappings: &[EntityMappingInfo],
) -> Result<(), AppError> {
    for m in mappings {
        sqlx::query(
            "INSERT INTO sql_query_entity_mapping \
             (id, query_version_id, entity_ref, id_column) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::now_v7())
        .bind(query_version_id)
        .bind(m.entity_ref)
        .bind(&m.id_column)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/queries",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QueryMeta>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_queries(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<QueryMeta>>, AppError> {
    let window = query.window();

    let rows: Vec<QueryRow> = sqlx::query_as(
        r#"SELECT id, record_no, entity_logical_name, is_active,
                  LEFT(sql_query, 120) AS sql_preview, owner_layer
           FROM sql_query
           WHERE is_active IS NULL OR is_active = true
           ORDER BY created_at ASC NULLS LAST
           LIMIT $1 OFFSET $2"#,
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sql_query WHERE is_active IS NULL OR is_active = true",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows.into_iter().map(meta_from_row).collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Serialize, ToSchema)]
struct QueryDependency {
    id: Uuid,
    name: String,
    is_active: bool,
}

/// `GET /api/v1/admin/queries/dependencies/{relation}` — `system.admin` only.
///
/// Item 14 ("query dependency tracking") from the 2026-07-31 backlog review of
/// `P-stored-query-containment.md`: answers "which stored queries would break
/// if I altered/dropped `relation`" — the reverse of the publish-time relation
/// lint (`lint_and_plan` records the *forward* direction, one query → its
/// relations, into `sql_query_version.relations`; this walks the same
/// column the other way, no new table or migration needed since the data was
/// already being captured for phase 2's cost-cache purpose). Only ever reads
/// `sql_query_version.relations`, which `lint_and_plan` already
/// guarantees contains only registered entity logicalnames (never a
/// credential/security table, per phase 1(b)'s publish-time rejection) — so
/// this endpoint needs no additional access check beyond `require_admin`.
///
/// "Current" version per query is the same `(query_id, id DESC) LIMIT 1`
/// pattern `fetch_current_entity_mappings` already uses — a query whose
/// *current* published version no longer references `relation` (it was
/// edited to remove that join) correctly stops appearing here, even though an
/// older, superseded version once did; that's the right answer for "would
/// altering `relation` break something live today," not an audit-history
/// question.
///
/// Returns an empty list for an unknown or never-referenced relation — not a
/// 404 — since "nothing depends on this" is a legitimate, common answer, not
/// an error.
#[utoipa::path(
    get,
    path = "/api/v1/admin/queries/dependencies/{relation}",
    tag = "admin",
    params(
        ("relation" = String, Path),
        OnePageQuery,
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<QueryDependency>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_query_dependencies(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(relation): Path<String>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<QueryDependency>>, AppError> {
    let window = query.window();

    let rows: Vec<(Uuid, Option<String>, Option<bool>)> = sqlx::query_as(
        r#"SELECT q.id, q.record_no, q.is_active
           FROM sql_query q
           JOIN LATERAL (
               SELECT relations FROM sql_query_version v
               WHERE v.query_id = q.id
               ORDER BY v.id DESC LIMIT 1
           ) cur ON true
           WHERE $1 = ANY(cur.relations)
           ORDER BY q.created_at ASC NULLS LAST
           LIMIT $2 OFFSET $3"#,
    )
    .bind(&relation)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM sql_query q
           JOIN LATERAL (
               SELECT relations FROM sql_query_version v
               WHERE v.query_id = q.id
               ORDER BY v.id DESC LIMIT 1
           ) cur ON true
           WHERE $1 = ANY(cur.relations)"#,
    )
    .bind(&relation)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|(id, record_no, is_active)| QueryDependency {
            id,
            name: record_no
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "Unnamed Query".into()),
            is_active: is_active.unwrap_or(true),
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Serialize)]
struct QueryPublishPending {
    approval_pending: bool,
    approval_request_id: Uuid,
}

/// Describes the output shape of an unsaved SELECT without fetching rows.
/// The same readonly identity and publish-time lint used for stored queries
/// keep this preview from becoming a bypass around query containment.
#[utoipa::path(
    post,
    path = "/api/v1/admin/queries/describe",
    tag = "admin",
    request_body = DescribeQueryBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "describes an unsaved SELECT's output columns on the read-only pool; persists nothing",
    )))),
    responses(
        (status = 200, description = "Success", body = Vec<DescribedColumn>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn describe_query(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<DescribeQueryBody>,
) -> Result<Json<Vec<DescribedColumn>>, AppError> {
    let sql_query = body.sql_query.trim().trim_end_matches(';').trim();
    if sql_query.is_empty() {
        return Ok(Json(Vec::new()));
    }

    // D-384 amendment / DATA-9 — `readonly_query_pool`, not the bare
    // `db_readonly` handle. Both run under the SELECT-only `attome_readonly`
    // role, so this is not a privilege change; what it adds is the
    // sticky-primary pin and the replica-lag breaker. This is the sharpest of
    // the six sites: `body.sql_query` is caller-supplied and reaches the
    // planner immediately, with no publish step in between, so an admin who
    // just provisioned an entity can otherwise `EXPLAIN` against a replica
    // that has not replayed the DDL yet and get a spurious "relation does not
    // exist" back.
    let pool = state.base.readonly_query_pool(ctx.user_id).await;
    lint_and_plan(pool, sql_query).await?;
    let discovery_sql = format!("SELECT * FROM ({sql_query}) AS query_output LIMIT 0");
    let description = pool
        .describe(&discovery_sql)
        .await
        .map_err(|e| AppError::Validation(format!("cannot describe query output: {e}")))?;

    Ok(Json(
        description
            .columns()
            .iter()
            .map(|column| DescribedColumn {
                name: column.name().to_owned(),
                data_type: editor_data_type(column.type_info().name()),
            })
            .collect(),
    ))
}

/// C-25: `query_exec::build_columns` reads a column definition under either
/// of two wire dialects — snake_case (`display_name`, `data_type`,
/// `is_visible`, `is_sortable`, `is_searchable`, `is_clickable`,
/// `route_template`) or camelCase (`displayName`, `dataType`, …) — because
/// both have shipped from different admin UI iterations over time and old
/// rows still carry whichever their author's client sent. That tolerance
/// stays on the read side (existing rows must keep working), but every
/// *write* through this admin surface now normalises to the one canonical
/// (snake_case) dialect before the value ever reaches the database, so a
/// query published or edited from here on has exactly one shape stored,
/// never a mix. `name`/`logicalName` is deliberately left alone (not
/// renamed to `name` if it arrived as `logicalName`) because `build_columns`
/// itself only reads `name`, never `logicalName`, for this key — so
/// dropping that alias here would be a silent behavior change. Malformed
/// JSON, or a definition holding a shape `build_columns` doesn't recognise
/// (not an array, no `columns` array), is passed through unchanged: this is
/// a normalisation, not a validator, and `build_columns`'s existing fallback
/// to `infer_columns` already handles anything it can't parse.
fn normalize_table_definition(raw: &str) -> String {
    /// `(camelCase key, canonical snake_case key)` — mirrors exactly the
    /// `.or_else` pairs `query_exec::build_columns` reads.
    const CAMEL_TO_SNAKE: &[(&str, &str)] = &[
        ("displayName", "display_name"),
        ("dataType", "data_type"),
        ("isVisible", "is_visible"),
        ("isSortable", "is_sortable"),
        ("isSearchable", "is_searchable"),
        ("isClickable", "is_clickable"),
        ("routeTemplate", "route_template"),
    ];

    let Ok(mut value) = serde_json::from_str::<Value>(raw) else {
        return raw.to_owned();
    };

    let normalize_columns = |cols: &mut Vec<Value>| {
        for col in cols.iter_mut() {
            let Some(obj) = col.as_object_mut() else {
                continue;
            };
            for (camel, snake) in CAMEL_TO_SNAKE {
                if obj.contains_key(*snake) {
                    continue;
                }
                if let Some(v) = obj.remove(*camel) {
                    obj.insert((*snake).to_owned(), v);
                }
            }
        }
    };

    if let Some(arr) = value.as_array_mut() {
        normalize_columns(arr);
    } else if let Some(arr) = value
        .as_object_mut()
        .and_then(|obj| obj.get_mut("columns"))
        .and_then(|c| c.as_array_mut())
    {
        normalize_columns(arr);
    } else {
        // Not a shape `build_columns` recognises — leave it exactly as sent
        // rather than guessing.
        return raw.to_owned();
    }

    serde_json::to_string(&value).unwrap_or_else(|_| raw.to_owned())
}

/// `POST /api/v1/admin/queries` — `system.admin` only.
///
/// D-195: gated behind `approval.required_actions` (empty/off by default,
/// same opt-in shape as every other wired action). When gated, submits an
/// approval request carrying the raw request body instead of publishing
/// anything and returns `202` with `approval_pending: true` — the lint,
/// plan capture, and entity-mapping validation all only run once a
/// different `system.admin` approves it (`do_create_query` via
/// `execute_approved`), same as the direct path always ran them.
#[utoipa::path(
    post,
    path = "/api/v1/admin/queries",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or a live query with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_query(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(raw_body): Json<Value>,
) -> Result<Response, AppError> {
    // Refuse before the approval gate: a write that cannot be recorded must
    // not be queued for approval either.
    recording.preflight(&state.base.db).await?;
    if let Some(request) = attome_audit::approval::gate(
        &state,
        ACTION_QUERY_PUBLISH,
        serde_json::json!({ "op": "create", "body": raw_body }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(QueryPublishPending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let body: CreateQueryBody = serde_json::from_value(raw_body)
        .map_err(|e| AppError::Validation(format!("invalid request body: {e}")))?;
    let (status, detail) =
        do_create_query_recorded(&state, ctx.user_id, body, Some(&*recording)).await?;
    Ok((status, Json(detail)).into_response())
}

/// The approval-executed create (`attome-server::approval_admin`): records
/// nothing (design §4.5 is lane L6's).
pub async fn do_create_query(
    state: &EngineState,
    user_id: Uuid,
    body: CreateQueryBody,
) -> Result<(StatusCode, QueryDetail), AppError> {
    do_create_query_recorded(state, user_id, body, None).await
}

/// [`do_create_query`], recording the publish into `recording`'s changeset
/// when one is given (the direct admin path).
async fn do_create_query_recorded(
    state: &EngineState,
    user_id: Uuid,
    body: CreateQueryBody,
    recording: Option<&Recording>,
) -> Result<(StatusCode, QueryDetail), AppError> {
    if body.sql_query.trim().is_empty() {
        return Err(AppError::Validation("sql_query is required".into()));
    }
    let sql_query = body.sql_query.trim();
    let name = body
        .name
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let owner_layer = stamp_layer(recording, Layer::Project)?;
    let td = normalize_table_definition(body.table_definition.as_deref().unwrap_or("[]"));

    // P-stored-query-containment Phase 3 (D-146): a fresh query has no prior
    // version to carry forward, so `entity_mappings.unwrap_or_default()` is
    // simply "no mappings declared yet."
    let mappings = body.entity_mappings.unwrap_or_default();
    let (id, entity_mappings) = publish_new_query(
        state,
        &PublishParams {
            sql_query,
            table_definition: &td,
            name: name.as_deref(),
            entity_logical_name: body.entity_logical_name,
            required_privilege: body.required_privilege.as_deref(),
            is_report: body.is_report,
            entity_mappings: &mappings,
            // P-environment-promotion §5 step 5: an admin publish marks the
            // row so boot seeds leave it alone and bundles carry the marker.
            is_customized: Some(true),
            actor: Some(user_id),
            // Admin-authored input — always the full EXPLAIN containment
            // lint, never the platform-bundle bypass.
            skip_containment_lint: false,
            // A fresh row has no prior version to conflict against.
            expected_row_version: None,
            // Admin-authored create — always a random id, never derived.
            desired_id: None,
            recording,
            unrecorded_layer: Layer::Project,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        QueryDetail {
            id,
            name: name.unwrap_or_else(|| "Unnamed Query".into()),
            sql_query: body.sql_query,
            table_definition: td,
            entity_logical_name: body.entity_logical_name,
            is_active: true,
            required_privilege: body.required_privilege,
            is_report: body.is_report,
            entity_mappings,
            // Fresh row — the column default (migration 0443).
            row_version: 0,
            owner_layer: owner_layer.as_str().to_owned(),
        },
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/queries/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = QueryDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_query(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(query_id): Path<Uuid>,
) -> Result<Json<QueryDetail>, AppError> {
    let row: Option<QueryDetailRow> = sqlx::query_as(
        "SELECT id, sql_query, table_definition, record_no, entity_logical_name, is_active,
                required_privilege, is_report, row_version, owner_layer
         FROM sql_query WHERE id = $1",
    )
    .bind(query_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    let entity_mappings = fetch_current_entity_mappings(&state.base.db, query_id).await?;
    Ok(Json(detail_from_row(row, entity_mappings)))
}

/// `PATCH /api/v1/admin/queries/{id}` — `system.admin` only.
///
/// D-195: gated behind `approval.required_actions`, same as `create_query`
/// above — an update re-publishes the query, so it goes through the same
/// `ACTION_QUERY_PUBLISH` gate.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/queries/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "row_version mismatch, no open changeset to record into, or the query is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_query(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(query_id): Path<Uuid>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> Result<Response, AppError> {
    // C-19: additive optimistic-concurrency guard — absent header means no
    // check, exactly today's behavior; present-but-malformed is a 422, never
    // a silent fall-through to the unguarded path.
    let expected_row_version = optional_expected_row_version(&headers)?;
    recording.preflight(&state.base.db).await?;

    if let Some(request) = attome_audit::approval::gate(
        &state,
        ACTION_QUERY_PUBLISH,
        serde_json::json!({ "op": "update", "query_id": query_id, "body": raw_body }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(QueryPublishPending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let body: UpdateQueryBody = serde_json::from_value(raw_body)
        .map_err(|e| AppError::Validation(format!("invalid request body: {e}")))?;
    let detail = do_update_query_recorded(
        &state,
        query_id,
        ctx.user_id,
        body,
        expected_row_version,
        Some(&*recording),
    )
    .await?;
    Ok(Json(detail).into_response())
}

/// Parses `If-Match` into an expected `row_version`, when present (C-19).
/// Additive, unlike `entity_crud`'s mandatory `expected_row_version` (D-079
/// is scoped to the generic entity PATCH path, not this table): a caller
/// that never sends the header keeps behaving exactly as it did before this
/// column existed. A malformed header is still a 422 — garbage must never
/// silently degrade into the unguarded last-write-wins path.
fn optional_expected_row_version(headers: &HeaderMap) -> Result<Option<i64>, AppError> {
    let Some(raw) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map(Some).map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// The approval-executed republish (`attome-server::approval_admin`): records
/// nothing (design §4.5 is lane L6's).
pub async fn do_update_query(
    state: &EngineState,
    query_id: Uuid,
    user_id: Uuid,
    body: UpdateQueryBody,
    expected_row_version: Option<i64>,
) -> Result<QueryDetail, AppError> {
    do_update_query_recorded(state, query_id, user_id, body, expected_row_version, None).await
}

/// [`do_update_query`], checking the row's owner layer and recording the
/// republish into `recording`'s changeset when one is given.
async fn do_update_query_recorded(
    state: &EngineState,
    query_id: Uuid,
    user_id: Uuid,
    body: UpdateQueryBody,
    expected_row_version: Option<i64>,
    recording: Option<&Recording>,
) -> Result<QueryDetail, AppError> {
    let cur: Option<QueryDetailRow> = sqlx::query_as(
        "SELECT id, sql_query, table_definition, record_no, entity_logical_name, is_active,
                required_privilege, is_report, row_version, owner_layer
         FROM sql_query WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(query_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let cur = cur.ok_or(AppError::NotFound)?;

    let new_sql = body
        .sql_query
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| cur.sql_query.unwrap_or_default());

    let new_td = normalize_table_definition(
        &body
            .table_definition
            .or(cur.table_definition)
            .unwrap_or_else(|| "[]".into()),
    );

    let new_name = body
        .name
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| cur.record_no.filter(|s| !s.is_empty()));

    let new_entity = body.entity_logical_name.or(cur.entity_logical_name);
    let new_required_privilege = body.required_privilege.or(cur.required_privilege);
    let new_is_report = body
        .is_report
        .unwrap_or_else(|| cur.is_report.unwrap_or(false));

    // P-stored-query-containment Phase 3 (D-146): `None`/omitted carries the
    // previous version's mappings forward (same convention as every other
    // field above) — re-validated against the new SQL/relations below, not
    // blindly copied, so a mapping that no longer makes sense after a SQL
    // edit is caught rather than silently carried into an invalid state.
    let new_entity_mappings: Vec<EntityMappingInput> = match body.entity_mappings {
        Some(explicit) => explicit,
        None => fetch_current_entity_mappings(&state.base.db, query_id)
            .await?
            .into_iter()
            .map(|m| EntityMappingInput {
                entity: m.entity,
                id_column: m.id_column,
            })
            .collect(),
    };

    let (new_row_version, entity_mappings) = republish_query(
        state,
        query_id,
        &PublishParams {
            sql_query: &new_sql,
            table_definition: &new_td,
            name: new_name.as_deref(),
            entity_logical_name: new_entity,
            required_privilege: new_required_privilege.as_deref(),
            is_report: new_is_report,
            entity_mappings: &new_entity_mappings,
            is_customized: Some(true),
            actor: Some(user_id),
            // Admin-authored input — always the full EXPLAIN containment
            // lint, never the platform-bundle bypass.
            skip_containment_lint: false,
            expected_row_version,
            // Update path — `desired_id` is never read by `republish_query`.
            desired_id: None,
            recording,
            unrecorded_layer: Layer::Project,
        },
    )
    .await?;

    Ok(QueryDetail {
        id: query_id,
        name: new_name.unwrap_or_else(|| "Unnamed Query".into()),
        sql_query: new_sql,
        table_definition: new_td,
        entity_logical_name: new_entity,
        is_active: cur.is_active.unwrap_or(true),
        required_privilege: new_required_privilege,
        is_report: new_is_report,
        entity_mappings,
        row_version: new_row_version,
        // A republish never changes the owner (the layer rule refused one
        // that would).
        owner_layer: cur.owner_layer,
    })
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/queries/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the query is owned by another layer", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_query(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(query_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    // §11(d): same transactional wrap as create/update — the deactivation
    // and its audit event either both land or neither does.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Solution 7: the layer rule. A missing or already inactive row stays
    // the 404 below.
    let live: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM sql_query \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(query_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(owner_layer) = live else {
        return Err(AppError::NotFound);
    };
    recording.check_owner(parse_owner_layer(&owner_layer)?)?;

    // `is_customized = true` on retire too (P-environment-promotion §5 step
    // 5, "any admin write that touches the row"): an admin who deliberately
    // deactivated a seeded query must not have it re-activated by the next
    // boot's `ensure_default_query` reconcile — the seed skips customized
    // rows, retired or not.
    let n = sqlx::query(
        "UPDATE sql_query SET is_active = false, is_customized = true
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(query_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if n == 0 {
        return Err(AppError::NotFound);
    }

    let event = query_audit_event(
        &state,
        ctx.user_id,
        AuditOperation::SoftDelete,
        query_id,
        "query.delete",
        format!("stored query {query_id} deactivated"),
    )
    .await;
    audit_service(&state).write_in_tx(&mut tx, event).await?;

    if let Some(op) = recorded_query_op(&mut tx, Op::RetireQuery, query_id, None).await? {
        recording.record(&mut tx, op).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Publish pipeline (one implementation for the admin create/update paths and
// `reconcile_query`) ─────────────────────────────────────────────────────────

/// Everything a (re-)publish needs — the admin bodies and a bundle `QueryDef`
/// both reduce to this.
struct PublishParams<'a> {
    sql_query: &'a str,
    table_definition: &'a str,
    /// `record_no` — the query's name.
    name: Option<&'a str>,
    entity_logical_name: Option<Uuid>,
    required_privilege: Option<&'a str>,
    is_report: bool,
    entity_mappings: &'a [EntityMappingInput],
    /// `Some(v)` writes `is_customized = v`; `None` leaves the column alone
    /// (`Seed` policy; `false` on a fresh row).
    is_customized: Option<bool>,
    /// Who publishes — the version row's `created_by` and the audit actor.
    /// `None` for a publish no user triggered (a bundle apply job with no
    /// requester); the audit row then carries a nil user context, as
    /// `revalidate_all`'s background versions already do.
    actor: Option<Uuid>,
    /// See [`reconcile_query`]'s own doc comment. `true` only for a platform
    /// bundle's query steps.
    skip_containment_lint: bool,
    /// C-19: an optimistic-concurrency guard `republish_query` enforces at the
    /// DB layer (`WHERE ... AND row_version = $expected`), never consulted by
    /// `publish_new_query` (a fresh row has no prior version to conflict
    /// against). `None` for every caller but `do_update_query`'s admin
    /// `PATCH` path — a bundle apply/reconcile publish never carries a
    /// client's `If-Match`.
    expected_row_version: Option<i64>,
    /// Bundle-derived deterministic id (D-374 amendment) for a brand-new
    /// row — `publish_new_query` only, ignored by `republish_query` (an
    /// existing row's id never changes). `None` reproduces the previous
    /// random-`Uuid::now_v7()` behavior exactly; set only by
    /// `reconcile_query`'s `Create` path.
    desired_id: Option<Uuid>,
    /// Solution 7 (D-785): the admin request's changeset recording — `Some`
    /// only on the direct admin create/update path. A new row is stamped with
    /// its layer, a republish checks the row's owner layer, and one operation
    /// is recorded before commit. `None` stamps `project` and records nothing.
    recording: Option<&'a Recording>,
    /// The layer a new row gets when `recording` is `None`.
    unrecorded_layer: Layer,
}

/// Publishes a brand-new stored query: lint + plan on the readonly pool, the
/// `sql_query` row, its first immutable version row, the entity
/// mappings and the audit event, in one transaction (§11(d)). Returns
/// `(query_id, mappings)`.
async fn publish_new_query(
    state: &EngineState,
    p: &PublishParams<'_>,
) -> Result<(Uuid, Vec<EntityMappingInfo>), AppError> {
    // Publish-time relation lint (phase 1(b)) — runs on the readonly pool,
    // so a query that would blow up at execute time (or, before phase 1(a)'s
    // containment, quietly read a credential table) is rejected here with a
    // 422 naming the relation instead of at first execution.
    //
    // D-384 amendment / DATA-9 — via `readonly_query_pool` rather than the
    // bare `db_readonly` handle, so the lint gets the same sticky-primary pin
    // and lag breaker `query_exec.rs` already uses. Same restricted role
    // either way; the difference is which host answers. Publishing a query
    // that references a just-provisioned entity would otherwise `EXPLAIN`
    // against a replica that may not have the table yet.
    let readonly = state
        .base
        .readonly_query_pool(p.actor.unwrap_or(Uuid::nil()))
        .await;
    let (cost_estimate, relations) =
        plan_or_trust(readonly, p.sql_query, p.skip_containment_lint).await?;
    reject_unsafe_single_entity_join(p.entity_logical_name, &relations)?;

    // M01 Core C-12: validated here, on the readonly pool, before the write
    // transaction below opens — see `validate_entity_mappings`'s doc comment.
    let entity_mappings =
        validate_entity_mappings(readonly, p.sql_query, &relations, p.entity_mappings).await?;

    // §11(d): the row insert, the version row, the entity-mapping rows, and
    // the audit event all land in one transaction — a failure at any step
    // rolls back the whole publish instead of leaving a half-written query.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // sql_query.id has no column default (legacy table) — must be bound explicitly.
    let id = p.desired_id.unwrap_or_else(Uuid::now_v7);
    let owner_layer = stamp_layer(p.recording, p.unrecorded_layer)?;
    sqlx::query(
        r#"INSERT INTO sql_query
               (id, sql_query, table_definition, record_no, entity_logical_name,
                required_privilege, is_report, is_active, is_customized, created_at,
                owner_layer)
           VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, NOW(), $9)"#,
    )
    .bind(id)
    .bind(p.sql_query)
    .bind(p.table_definition)
    .bind(p.name)
    .bind(p.entity_logical_name)
    .bind(p.required_privilege)
    .bind(p.is_report)
    .bind(p.is_customized.unwrap_or(false))
    .bind(owner_layer.as_str())
    .execute(&mut *tx)
    .await
    // `uq_core_sql_query_entity_name` (0133): a live named query per entity.
    .map_err(map_unique_violation)?;

    // Phase 2: immutable version row capturing the SQL that just passed the
    // lint, its measured cost, and the relations it touches — query_exec.rs
    // reads this instead of re-planning on every execute call.
    let version_id = write_version(
        &mut *tx,
        id,
        p.sql_query,
        cost_estimate,
        &relations,
        p.actor,
    )
    .await?;

    write_entity_mappings(&mut tx, version_id, &entity_mappings).await?;

    // M18 Data Catalog Phase 1 (D-466): the generalized lineage table,
    // keyed by the STABLE query id (not `version_id`) so a later republish
    // replaces this same object's reference set rather than leaving the
    // prior version's rows orphaned — see 0356's header.
    write_catalog_lineage(&mut tx, id, p.name.unwrap_or(""), &relations).await?;

    let event = query_audit_event(
        state,
        p.actor.unwrap_or(Uuid::nil()),
        AuditOperation::Create,
        id,
        "query.create",
        format!("stored query {id} published"),
    )
    .await;
    audit_service(state).write_in_tx(&mut tx, event).await?;

    if let Some(recording) = p.recording
        && let Some(op) =
            recorded_query_op(&mut tx, Op::UpsertQuery, id, Some(&entity_mappings)).await?
    {
        recording.record(&mut tx, op).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok((id, entity_mappings))
}

/// M18 Data Catalog Phase 1 (D-466): records this query's current entity
/// references into `metadata_reference`. `relations` (from
/// `lint_and_plan`) is the full set of registered-entity tables this SQL
/// touches — a superset of the id-mapped subset
/// `validate_entity_mappings`/`write_entity_mappings` write for RLS purposes, and the
/// right set for "what does this query reference" lineage. Entity-level
/// only (no attribute-level lineage for queries in Phase 1): a query's
/// output columns are not reliably traceable back to source attributes
/// without a full SQL-column-lineage pass, which is out of scope here.
async fn write_catalog_lineage(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    query_id: Uuid,
    name: &str,
    relations: &[String],
) -> Result<(), AppError> {
    let refs: Vec<attome_core::MetadataReferenceInput> = relations
        .iter()
        .map(attome_core::MetadataReferenceInput::entity)
        .collect();
    attome_core::replace_references(tx, "query", query_id, name, &refs).await
}

/// M18 Data Catalog Phase 1 (D-466) — `EngineJob::CatalogLineageBackfill`'s
/// 'query' half: populates `metadata_reference` for every stored
/// query published BEFORE this release's `write_catalog_lineage` writer
/// existed. Reuses `sql_query_version.relations` — the same
/// relation list `lint_and_plan` computed and cached at that query's own
/// publish time — rather than re-running `EXPLAIN` against possibly-drifted
/// current schema for historical SQL; correctness here means "what the
/// query was granted to reach when it published", the same meaning the live
/// writer gives it. Bounded, resumable, idempotent to reprocess (0357's
/// header) — one bounded batch per call, safe to call again after any
/// failure. Returns the number of queries processed this call (0 once the
/// 'query' kind's cursor is marked complete).
pub async fn backfill_catalog_lineage(db: &DbPool, batch_limit: i64) -> Result<usize, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let progress = attome_core::backfill_progress(&mut conn, "query").await?;
    if progress.completed {
        return Ok(0);
    }
    let cursor = progress.last_ref.unwrap_or(Uuid::nil());

    let rows: Vec<(Uuid, Option<String>, Vec<String>)> = sqlx::query_as(
        "SELECT q.id, q.record_no, v.relations \
         FROM sql_query q \
         JOIN LATERAL ( \
             SELECT relations FROM sql_query_version \
             WHERE query_id = q.id ORDER BY id DESC LIMIT 1 \
         ) v ON true \
         WHERE q.id > $1 AND q.is_active = true \
         ORDER BY q.id \
         LIMIT $2",
    )
    .bind(cursor)
    .bind(batch_limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    if rows.is_empty() {
        attome_core::advance_backfill_progress(&mut conn, "query", cursor, 0, true).await?;
        return Ok(0);
    }
    // Release the plain connection before opening a separate transaction —
    // no reason to hold two pool connections for the rest of this call.
    drop(conn);

    let mut tx = attome_db::tx::begin(db).await?;
    let mut last = cursor;
    let processed = rows.len();
    for (id, name, relations) in &rows {
        let refs: Vec<attome_core::MetadataReferenceInput> = relations
            .iter()
            .map(attome_core::MetadataReferenceInput::entity)
            .collect();
        attome_core::replace_references(
            &mut tx,
            "query",
            *id,
            name.as_deref().unwrap_or(""),
            &refs,
        )
        .await?;
        last = *id;
    }
    let completed = (processed as i64) < batch_limit;
    attome_core::advance_backfill_progress(&mut tx, "query", last, processed as i64, completed)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(processed)
}

/// Re-publishes an existing stored query (`query_id`): the same lint, a
/// fresh version row, replaced entity mappings and an audit event, plus the
/// row UPDATE — which also sets `is_active = true`, so re-publishing a
/// retired row reactivates it (reconcile's reactivate-over-insert). Returns
/// `(new_row_version, mappings)`.
///
/// C-19: `p.expected_row_version` — set only by `do_update_query`'s admin
/// `PATCH` path — turns the UPDATE below into a real optimistic-concurrency
/// guard (`WHERE ... AND row_version = $expected`), not a check-then-write:
/// two concurrent requests each reading the same prior `row_version` can
/// still only have one of them win, because the second's UPDATE now matches
/// zero rows once the first has committed its `+ 1`. `None` (every other
/// caller — `reconcile_query`, `publish_new_query`'s sibling) skips the
/// guard entirely, same as today.
async fn republish_query(
    state: &EngineState,
    query_id: Uuid,
    p: &PublishParams<'_>,
) -> Result<(i64, Vec<EntityMappingInfo>), AppError> {
    // Publish-time relation lint (phase 1(b)) — an update re-publishes the
    // query, whether or not sql_query itself changed in this request, so it
    // gets the same lint + a fresh version row every time.
    //
    // D-384 amendment / DATA-9 — same reasoning as `publish_new_query` above:
    // `readonly_query_pool` for the pin and lag breaker, same restricted role.
    let readonly = state
        .base
        .readonly_query_pool(p.actor.unwrap_or(Uuid::nil()))
        .await;
    let (cost_estimate, relations) =
        plan_or_trust(readonly, p.sql_query, p.skip_containment_lint).await?;
    reject_unsafe_single_entity_join(p.entity_logical_name, &relations)?;

    // M01 Core C-12: validated here, on the readonly pool, before the write
    // transaction below opens — see `validate_entity_mappings`'s doc comment.
    let entity_mappings =
        validate_entity_mappings(readonly, p.sql_query, &relations, p.entity_mappings).await?;

    // §11(d): same transactional wrap as publish_new_query — the UPDATE, the
    // version row, the entity-mapping rows, and the audit event either all
    // land or none do.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if let Some(recording) = p.recording {
        check_query_owner(&mut tx, recording, query_id).await?;
    }

    let new_row_version: Option<i64> = sqlx::query_scalar(
        "UPDATE sql_query
         SET sql_query = $2, table_definition = $3, record_no = $4, entity_logical_name = $5,
             required_privilege = $6, is_report = $7, is_active = true,
             is_customized = COALESCE($8, is_customized),
             row_version = row_version + 1
         WHERE id = $1 AND ($9::bigint IS NULL OR row_version = $9)
         RETURNING row_version",
    )
    .bind(query_id)
    .bind(p.sql_query)
    .bind(p.table_definition)
    .bind(p.name)
    .bind(p.entity_logical_name)
    .bind(p.required_privilege)
    .bind(p.is_report)
    .bind(p.is_customized)
    .bind(p.expected_row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(map_unique_violation)?;
    let new_row_version = match new_row_version {
        Some(v) => v,
        // Either the row doesn't exist (or was deactivated/deleted between
        // the caller's fetch and here — vanishingly rare, since this table
        // has no hard delete) or `expected_row_version` was `Some` and no
        // longer matches. Every caller that passes `Some` has already
        // confirmed the row's existence moments earlier (`do_update_query`'s
        // own fetch), so treating a guarded miss as a stale-If-Match
        // conflict rather than a not-found is the more accurate answer for
        // that caller, and `reconcile_query`'s ungated path never hits this
        // branch (it never sets `expected_row_version`).
        None if p.expected_row_version.is_some() => {
            return Err(AppError::VersionConflict);
        }
        None => return Err(AppError::NotFound),
    };

    // Phase 2: immutable version row for this (re-)publish.
    let version_id = write_version(
        &mut *tx,
        query_id,
        p.sql_query,
        cost_estimate,
        &relations,
        p.actor,
    )
    .await?;

    write_entity_mappings(&mut tx, version_id, &entity_mappings).await?;

    // M18 Data Catalog Phase 1 (D-466): replaces this query's reference set
    // — see `write_catalog_lineage`'s doc comment.
    write_catalog_lineage(&mut tx, query_id, p.name.unwrap_or(""), &relations).await?;

    let event = query_audit_event(
        state,
        p.actor.unwrap_or(Uuid::nil()),
        AuditOperation::Update,
        query_id,
        "query.update",
        format!("stored query {query_id} republished"),
    )
    .await;
    audit_service(state).write_in_tx(&mut tx, event).await?;

    if let Some(recording) = p.recording
        && let Some(op) =
            recorded_query_op(&mut tx, Op::UpsertQuery, query_id, Some(&entity_mappings)).await?
    {
        recording.record(&mut tx, op).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok((new_row_version, entity_mappings))
}

// ── Service reconcile API (P-environment-promotion §5 step 13) ────────────────

/// The current row a `reconcile_query` probe finds for a `(entity, name)` key
/// — the live one if there is one, else the most recently created retired one.
#[derive(sqlx::FromRow)]
struct QueryProbeRow {
    id: Uuid,
    sql_query: Option<String>,
    table_definition: Option<String>,
    required_privilege: Option<String>,
    is_report: Option<bool>,
    is_customized: bool,
    is_live: bool,
}

async fn fetch_query_by_key(
    db: &DbPool,
    entity_id: Option<Uuid>,
    name: &str,
) -> Result<Option<QueryProbeRow>, AppError> {
    sqlx::query_as(
        "SELECT id, sql_query, table_definition, required_privilege, is_report, is_customized, \
                (is_active IS NULL OR is_active = true) AS is_live \
         FROM sql_query \
         WHERE record_no = $1 AND entity_logical_name IS NOT DISTINCT FROM $2 \
         ORDER BY (is_active IS NULL OR is_active = true) DESC, created_at DESC NULLS LAST, id DESC \
         LIMIT 1",
    )
    .bind(name)
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Create-or-update one stored query to match `desc`, keyed by
/// `(entity, name)` (`sql_query.record_no`). A thin orchestrator over
/// the publish pipeline above — never a raw row write: every create goes
/// through `lint_and_plan` (unless `skip_containment_lint`, see below), a
/// version row and the entity-mapping validation exactly as the admin
/// POST/PATCH do. Compare-first (`Unchanged` writes nothing, not even a
/// version row); `Seed` skips an `is_customized` row; `Admin` marks it;
/// `Bundle` carries the marker; a retired row with the same key is
/// re-published (reactivated) rather than duplicated. Returns `(query_id,
/// outcome)`. Nothing here notifies — queries are not in the entity metadata
/// registry, and today's admin handlers do not notify either.
///
/// `skip_containment_lint`: `true` only for a platform bundle
/// (`attome-server/src/bundle/apply.rs`'s `Step::Query` passes its
/// `ApplyContext::additive_only`, itself `PlanOptions::additive_only`
/// carried through the ledger — see that field's own doc comment). Platform
/// bundles are compiled-in, developer-authored content (`platform.rs`: "the
/// same trust level as the binary itself"), so this reuses the exact trust
/// argument `attome_metadata::provision::ensure_default_query`'s doc comment
/// already makes for its own seven boot-seed call sites, one of which is
/// `attome-audit` itself: skip the EXPLAIN-based relation lint, run
/// `attome_metadata::provision::reject_unsafe_default_query_sql`'s structural-only
/// check instead. Needed in practice, not just in principle: `audit_detail`
/// is a genuinely partitioned table, and `EXPLAIN`ing a plain `SELECT * FROM
/// audit_detail` surfaces its partition-child relation (e.g.
/// `audit_detail_pre_partition`) in the plan — which the lint's
/// `entity_info` containment check rejects, since only the parent
/// table is a registered entity. A pulled/admin-uploaded bundle (`bundle::
/// pull::sync`, the admin apply/rollback routes) always passes `false` here
/// and keeps the full lint — this bypass is scoped to code-shipped platform
/// content only, never to a human-authored or remote artifact.
pub async fn reconcile_query(
    state: &EngineState,
    desc: &QueryDef,
    policy: ReconcilePolicy,
    actor: Option<Uuid>,
    skip_containment_lint: bool,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("query name is required".into()));
    }
    let sql_query = desc.sql.trim();
    if sql_query.is_empty() {
        return Err(AppError::Validation("sql_query is required".into()));
    }
    let table_definition = desc.table_definition.as_deref().unwrap_or("[]");
    let entity_id = match desc
        .entity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(entity) => Some(resolve_live_entity_id(&state.base.db, entity).await?),
        None => None,
    };
    let mappings: Vec<EntityMappingInput> = desc
        .entity_mappings
        .iter()
        .map(|m| EntityMappingInput {
            entity: m.entity.clone(),
            id_column: m.id_column.clone(),
        })
        .collect();

    let current = fetch_query_by_key(&state.base.db, entity_id, name).await?;
    let state_differs = match current.as_ref() {
        Some(row) => {
            let mut cur_mappings: Vec<(String, String)> =
                fetch_current_entity_mappings(&state.base.db, row.id)
                    .await?
                    .into_iter()
                    .map(|m| (m.entity, m.id_column))
                    .collect();
            cur_mappings.sort();
            let mut wanted_mappings: Vec<(String, String)> = mappings
                .iter()
                .map(|m| (m.entity.clone(), m.id_column.clone()))
                .collect();
            wanted_mappings.sort();
            row.sql_query.as_deref().map(str::trim) != Some(sql_query)
                || row.table_definition.as_deref().unwrap_or("[]") != table_definition
                || row.required_privilege.as_deref() != desc.required_privilege.as_deref()
                || row.is_report.unwrap_or(false) != desc.is_report
                || cur_mappings != wanted_mappings
        }
        None => false,
    };
    let status = current.as_ref().map(|r| (r.is_customized, r.is_live));
    let step = reconcile_step(policy, status, state_differs);
    let params = PublishParams {
        sql_query,
        table_definition,
        name: Some(name),
        entity_logical_name: entity_id,
        required_privilege: desc.required_privilege.as_deref(),
        is_report: desc.is_report,
        entity_mappings: &mappings,
        is_customized: customized_marker(policy),
        actor,
        skip_containment_lint,
        // A service reconcile call never carries a client's `If-Match`.
        expected_row_version: None,
        desired_id,
        // The bundle apply path records nothing (design §1.4).
        recording: None,
        unrecorded_layer: policy_layer(policy),
    };
    let key = desc.display_key();
    match step {
        ReconcileStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        ReconcileStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(query = %key, "query reconcile: seed skipped a customized query (is_customized = true)");
            Ok((id, ReconcileOutcome::SkippedCustomized))
        }
        ReconcileStep::Create => {
            let (id, _) = publish_new_query(state, &params).await?;
            tracing::info!(query = %key, ?policy, "query reconcile: created");
            Ok((id, ReconcileOutcome::Created))
        }
        ReconcileStep::Update => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            republish_query(state, id, &params).await?;
            tracing::info!(query = %key, ?policy, "query reconcile: updated");
            Ok((id, ReconcileOutcome::Updated))
        }
    }
}

/// Flips `is_active` on the query keyed by `(entity, name)`. Idempotent:
/// `Unchanged` when no row is in the opposite state (including a key that
/// does not exist). Shared by [`retire_query`] / [`reactivate_query`].
async fn set_query_active(
    state: &EngineState,
    entity: Option<&str>,
    name: &str,
    live: bool,
) -> Result<ReconcileOutcome, AppError> {
    let entity_id = match entity.map(str::trim).filter(|s| !s.is_empty()) {
        Some(entity) => Some(resolve_live_entity_id(&state.base.db, entity).await?),
        None => None,
    };
    let candidate: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sql_query \
         WHERE record_no = $1 AND entity_logical_name IS NOT DISTINCT FROM $2 \
           AND (is_active IS NULL OR is_active = true) = $3 \
         ORDER BY created_at DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(name)
    .bind(entity_id)
    .bind(!live)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(query_id) = candidate else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    let n = sqlx::query(
        "UPDATE sql_query SET is_active = $2 \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) = $3",
    )
    .bind(query_id)
    .bind(live)
    .bind(!live)
    .execute(&state.base.db)
    .await
    .map_err(map_unique_violation)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    tracing::info!(query = %name, entity = ?entity, live, "query reconcile: active flag changed");
    Ok(ReconcileOutcome::Updated)
}

/// Soft-retire (`is_active = false`) the stored query keyed by
/// `(entity, name)`. Idempotent. Never drops; the version rows stay.
pub async fn retire_query(
    state: &EngineState,
    entity: Option<&str>,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_query_active(state, entity, name, false).await
}

/// Reactivate a previously retired stored query. Idempotent.
pub async fn reactivate_query(
    state: &EngineState,
    entity: Option<&str>,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_query_active(state, entity, name, true).await
}

// ── Routes ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/queries",
            get(list_queries).post(create_query),
        )
        .route(
            "/api/v1/admin/queries/dependencies/{relation}",
            get(list_query_dependencies),
        )
        .route(
            "/api/v1/admin/queries/describe",
            axum::routing::post(describe_query),
        )
        .route(
            "/api/v1/admin/queries/{id}",
            get(get_query).patch(update_query).delete(delete_query),
        )
}

// ── Tests (pure functions only — everything else in this module needs a
// live readonly Postgres pool; see attome-server/tests/query_exec.rs) ─────────
#[cfg(test)]
mod tests {
    use super::{
        RECOST_DRIFT_RATIO, cost_has_drifted, normalize_table_definition,
        reject_unsafe_single_entity_join,
    };
    use uuid::Uuid;

    #[test]
    fn normalize_table_definition_rewrites_camel_case_keys_to_snake_case() {
        let raw = r#"[{"name":"amount","displayName":"Amount","dataType":"currency","isVisible":true,"isSortable":false,"isSearchable":true,"isClickable":false,"routeTemplate":"/x"}]"#;
        let normalized = normalize_table_definition(raw);
        let value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        let col = &value[0];
        assert_eq!(col["display_name"], "Amount");
        assert_eq!(col["data_type"], "currency");
        assert_eq!(col["is_visible"], true);
        assert_eq!(col["is_sortable"], false);
        assert_eq!(col["is_searchable"], true);
        assert_eq!(col["is_clickable"], false);
        assert_eq!(col["route_template"], "/x");
        // The camelCase originals must not survive alongside the renamed keys.
        assert!(col.get("displayName").is_none());
        assert!(col.get("dataType").is_none());
    }

    #[test]
    fn normalize_table_definition_leaves_snake_case_input_unchanged_in_shape() {
        let raw = r#"[{"name":"amount","display_name":"Amount","data_type":"currency"}]"#;
        let normalized = normalize_table_definition(raw);
        let value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(value[0]["display_name"], "Amount");
        assert_eq!(value[0]["data_type"], "currency");
    }

    #[test]
    fn normalize_table_definition_prefers_an_existing_snake_case_key_over_the_camel_alias() {
        // A row that (incorrectly) carries both — the snake_case value wins,
        // never silently overwritten by the camelCase alias.
        let raw = r#"[{"name":"amount","display_name":"Canonical","displayName":"Stale"}]"#;
        let normalized = normalize_table_definition(raw);
        let value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(value[0]["display_name"], "Canonical");
    }

    #[test]
    fn normalize_table_definition_handles_the_columns_wrapper_shape() {
        let raw = r#"{"columns":[{"name":"amount","dataType":"currency"}]}"#;
        let normalized = normalize_table_definition(raw);
        let value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
        assert_eq!(value["columns"][0]["data_type"], "currency");
    }

    #[test]
    fn normalize_table_definition_passes_through_malformed_json_unchanged() {
        let raw = "not json";
        assert_eq!(normalize_table_definition(raw), raw);
    }

    #[test]
    fn normalize_table_definition_passes_through_an_unrecognised_shape_unchanged() {
        let raw = r#"{"not_columns": []}"#;
        assert_eq!(normalize_table_definition(raw), raw);
    }

    #[test]
    fn single_entity_query_with_one_relation_is_accepted() {
        assert!(reject_unsafe_single_entity_join(Some(Uuid::now_v7()), &["lead".into()]).is_ok());
    }

    #[test]
    fn single_entity_query_with_a_join_is_rejected() {
        let err = reject_unsafe_single_entity_join(
            Some(Uuid::now_v7()),
            &["lead".into(), "organization".into()],
        )
        .unwrap_err();
        assert!(matches!(err, attome_types::AppError::Validation(_)));
    }

    #[test]
    fn multi_entity_query_with_no_entity_logical_name_is_accepted_regardless_of_relation_count() {
        assert!(
            reject_unsafe_single_entity_join(None, &["lead".into(), "organization".into()]).is_ok()
        );
    }

    #[test]
    fn single_entity_query_with_zero_relations_is_accepted() {
        // The platform-bundle skip-lint path reports no relations at all —
        // this must never be misread as "one relation, safe."
        assert!(reject_unsafe_single_entity_join(Some(Uuid::now_v7()), &[]).is_ok());
    }

    #[test]
    fn cost_has_drifted_false_for_identical_cost() {
        assert!(!cost_has_drifted(100.0, 100.0));
    }

    #[test]
    fn cost_has_drifted_false_within_the_drift_ratio() {
        // 100 -> 115 is a 15% move, under the 20% threshold.
        assert!(!cost_has_drifted(100.0, 115.0));
        assert!(!cost_has_drifted(100.0, 85.0));
    }

    #[test]
    fn cost_has_drifted_true_beyond_the_drift_ratio() {
        // 100 -> 130 is a 30% move, over the 20% threshold, either direction.
        assert!(cost_has_drifted(100.0, 130.0));
        assert!(cost_has_drifted(100.0, 70.0));
    }

    #[test]
    fn cost_has_drifted_true_exactly_at_the_boundary_is_not_drift() {
        let boundary = 100.0 * (1.0 + RECOST_DRIFT_RATIO);
        assert!(!cost_has_drifted(100.0, boundary));
        assert!(cost_has_drifted(100.0, boundary + 0.01));
    }

    #[test]
    fn cost_has_drifted_handles_a_zero_previous_cost_without_dividing_by_zero() {
        assert!(!cost_has_drifted(0.0, 0.0));
        assert!(cost_has_drifted(0.0, 0.01));
    }

    // ── Solution 7 changeset ops (D-785) ──────────────────────────────────

    use super::{
        MULTI_ENTITY_QUERY_TARGET, Op, ReconcilePolicy, parse_owner_layer, policy_layer, query_op,
        stamp_layer,
    };
    use attome_core::changeset::Layer;

    #[test]
    fn query_ops_are_keyed_by_entity_and_name_and_pass_the_recorder_check() {
        for op in [Op::UpsertQuery, Op::RetireQuery] {
            let recorded = query_op(
                op,
                Uuid::now_v7(),
                Some("account"),
                Some("active_accounts"),
                serde_json::json!({ "name": "active_accounts" }),
            )
            .expect("op");
            recorded.check().expect("well-formed op");
            assert_eq!(
                recorded.target,
                serde_json::json!({ "entity": "account", "query": "active_accounts" })
            );
        }
    }

    #[test]
    fn a_multi_entity_query_uses_a_sentinel_no_entity_can_carry() {
        let recorded = query_op(
            Op::UpsertQuery,
            Uuid::now_v7(),
            None,
            Some("pipeline_report"),
            serde_json::json!({}),
        )
        .expect("op");
        recorded.check().expect("well-formed op");
        assert_eq!(recorded.target["entity"], MULTI_ENTITY_QUERY_TARGET);
        // Longer than MAX_IDENTIFIER_LEN, so never a real entity's name, and
        // still a logical name the changeset validator accepts.
        assert!(MULTI_ENTITY_QUERY_TARGET.len() > attome_metadata::provision::MAX_IDENTIFIER_LEN);
        let mut chars = MULTI_ENTITY_QUERY_TARGET.chars();
        assert!(chars.next().is_some_and(|c| c.is_ascii_lowercase()));
        assert!(chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
    }

    #[test]
    fn a_nameless_query_has_no_op() {
        for name in [None, Some(""), Some("  ")] {
            let op = query_op(
                Op::UpsertQuery,
                Uuid::now_v7(),
                Some("account"),
                name,
                serde_json::json!({}),
            );
            assert!(op.is_none());
        }
    }

    #[test]
    fn an_unrecorded_publish_stamps_project_and_unknown_layers_are_internal() {
        assert_eq!(stamp_layer(None, Layer::Project).ok(), Some(Layer::Project));
        assert_eq!(policy_layer(ReconcilePolicy::Seed), Layer::Platform);
        assert_eq!(
            policy_layer(ReconcilePolicy::Bundle {
                is_customized: false
            }),
            Layer::Project
        );
        assert_eq!(parse_owner_layer("platform").ok(), Some(Layer::Platform));
        assert!(parse_owner_layer("tenant").is_err());
    }
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_queries,
    list_query_dependencies,
    describe_query,
    create_query,
    get_query,
    update_query,
    delete_query
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
