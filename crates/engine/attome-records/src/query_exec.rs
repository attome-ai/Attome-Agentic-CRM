/// Single execute endpoint mirroring attome-root's POST /api/query/execute.
///
/// Returns both column definitions (from sql_query.table_definition)
/// and row data in one response — no separate schema call needed.
use attome_server::authz::{Authorized, RecordScoped};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Column, Executor};
use utoipa::ToSchema;
use uuid::Uuid;

use attome_core::filter::{FieldCastError, FilterSchema};
use attome_core::{EngineState, Filter, parameter_cast, quote_ident};
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;

// ── Request ───────────────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, ToSchema)]
pub struct ExecuteQueryRequest {
    /// Direct: specific query UUID
    query_id: Option<Uuid>,
    /// Direct list/view selection. The view resolves to its referenced SQL query.
    view_id: Option<Uuid>,
    /// Entity UUID (from entity_info) — backend looks up default view
    entity_logical_name: Option<Uuid>,
    /// Fallback: entity name string — backend derives UUID via entity_info
    entity: Option<String>,

    /// One-based — the first page is `page=1` (D-347). Unlike the platform's
    /// `GET` list endpoints, which clamp an out-of-range page, this one rejects
    /// `page < 1` with 422; `page > 10000` is likewise rejected rather than
    /// clamped, to push large scans onto `after_id` (D-031).
    #[serde(default = "one")]
    #[schema(minimum = 1, maximum = 10000, default = 1)]
    page: i64,
    #[serde(default = "fifty")]
    #[schema(minimum = 1, maximum = 200, default = 50)]
    page_size: i64,
    #[serde(default)]
    search: String,
    #[serde(default)]
    order_by: String,
    /// `"asc"` or `"desc"` — see `Filter::op`'s doc comment for why this
    /// isn't expressed as a JSON-schema `enum` constraint (P-api-contract
    /// Phase 0 disclosure: same reason applies here).
    #[serde(default = "asc")]
    #[schema(default = "asc", example = "asc")]
    order_dir: String,
    #[serde(default)]
    filters: Vec<Filter>,
    /// P-stored-query-containment phase 2 / D-126: `true` is the only way to
    /// get an exact `COUNT(*) OVER()` total — the full-set window scan is
    /// expensive enough (audit finding #25) that it is opt-in, not the
    /// default, now that cursor mode (below) is the default execution mode.
    /// Defaulting this to `false` (was `true` pre-phase-2) is the one
    /// behavioral flip this plan makes to the wire contract.
    #[serde(default)]
    #[schema(default = false)]
    include_total: bool,
    /// P1.11(g)/P-stored-query-containment phase 2: the id of the last row
    /// the caller already has. `Some` continues an existing keyset/cursor
    /// page; `None` with `include_total: false` (the default) still runs in
    /// cursor mode, starting from the beginning of the set — see
    /// `config.query.cursor_default`. `page`/`page_size` (offset math) are
    /// ignored whenever cursor mode is in effect.
    #[serde(default)]
    after_id: Option<Uuid>,
    /// AA4-T4: start a keyset page at this sort value ("jump to M", "jump
    /// to March"): the first page holds the rows whose `order_by` value is
    /// at or after it (at or before it for `desc`), with a `next_cursor` as
    /// usual. Coerced and bound like a filter value on the sort column, so a
    /// value of the wrong type is a 422; no rows are counted to find the
    /// place. Not with `after_id` (422).
    #[serde(default)]
    seek: Option<Value>,
    /// M01 Core P3 gap (D-455) — narrows a single-entity query to rows
    /// linked, through a named M:M relationship, to one anchor record on
    /// the relationship's other side. `AppError::Validation` (422) for a
    /// multi-entity/custom-SQL query (`entity_logical_name.is_some()` is
    /// false — there is no single attribute set / entity for a relationship
    /// to resolve against, the same D-057 boundary record-level RLS
    /// scoping already draws in this file) or for a relationship that
    /// exists but does not connect this query's entity.
    #[serde(default)]
    related_to: Option<RelatedToFilter>,
    /// D-521 — pinned execution: run this exact immutable
    /// `sql_query_version` instead of the query's current SQL. The
    /// version must belong to the resolved query and the query must still be
    /// active. Only the SQL text, relation inventory and cost estimate come
    /// from the pinned version; `required_privilege`, record-level scope and
    /// the cost ceiling are evaluated at run time exactly as for an unpinned
    /// call (pinned SQL, live security). A published dashboard records the
    /// version each widget was published with and executes it through this.
    #[serde(default)]
    query_version_id: Option<Uuid>,
}

impl std::fmt::Debug for ExecuteQueryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecuteQueryRequest")
            .finish_non_exhaustive()
    }
}

impl ExecuteQueryRequest {
    /// D-543 — a server-side caller (a published dashboard widget) building a
    /// request for one stored query at one pinned version. Deliberately narrow:
    /// no `view_id` (a published widget resolves its query at publish time),
    /// and the definition travels separately as a [`PublishedDefinition`].
    pub fn for_published_widget(
        query_id: Uuid,
        query_version_id: Option<Uuid>,
        page_size: i64,
        filters: Vec<Filter>,
    ) -> Self {
        Self {
            query_id: Some(query_id),
            view_id: None,
            entity_logical_name: None,
            entity: None,
            page: 1,
            page_size,
            search: String::new(),
            order_by: String::new(),
            order_dir: "asc".to_string(),
            filters,
            include_total: false,
            after_id: None,
            seek: None,
            related_to: None,
            query_version_id,
        }
    }

    /// Dashboard 10/10 Phase 2.3 — an editor's draft preview of a widget: its
    /// live view (preferred, as the viewer always rendered it) or query, never
    /// pinned. `None` when the widget names neither.
    pub fn for_draft_widget(
        view_id: Option<Uuid>,
        query_id: Option<Uuid>,
        page_size: i64,
        filters: Vec<Filter>,
    ) -> Option<Self> {
        if view_id.is_none() && query_id.is_none() {
            return None;
        }
        let mut request = Self::for_published_widget(Uuid::nil(), None, page_size, filters);
        request.query_id = if view_id.is_some() { None } else { query_id };
        request.view_id = view_id;
        Some(request)
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct RelatedToFilter {
    /// `relationship_info.name`.
    relationship: String,
    /// The anchor record's id, on the relationship's side OTHER than this
    /// query's own entity.
    id: Uuid,
}

impl std::fmt::Debug for RelatedToFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelatedToFilter").finish_non_exhaustive()
    }
}

fn one() -> i64 {
    1
}
fn fifty() -> i64 {
    50
}
fn asc() -> String {
    "asc".to_owned()
}

// `Filter` (and its scalar/array value validators below) lives in
// `attome_core::filter` now — promoted once `attome-search`'s aggregation
// endpoint needed the exact same grammar (coding-guidelines.md §1: shared
// XRM primitives belong in attome-core once more than one engine owns
// the concept). Imported above; this file's own WHERE-loop below is
// unchanged, since it stays entangled with this file's `ColumnDef`/
// `table_definition`-derived whitelist.

// ── DB lookup ─────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct SqlQueryRow {
    id: Uuid,
    view_id: Option<Uuid>,
    sql_query: String,
    table_definition: Option<String>, // varchar in DB — parse as JSON manually
    record_no: Option<String>,
    /// P1.1e: if set, `execute` requires this exact privilege key instead of
    /// the coarse admin-only default — checked via `SecurityContext`.
    required_privilege: Option<String>,
    /// P1.1e: raises the read-only transaction's `statement_timeout` from
    /// the 500ms fast-read default to 5s.
    is_report: bool,
    /// P1.11(h): which entity (if any) this query is over — lets the
    /// unindexed-sort/filter warning below look up `attribute_info`
    /// flags via the cached registry. `None` for a custom multi-entity/
    /// join query, which has no single attribute set to check against.
    entity_logical_name: Option<Uuid>,
    /// D-429's view `kind`/`view_metadata` (chart follow-up, migration 0447)
    /// — `None` when this execution has no bound view (the bare `query_id`
    /// branch below). Threaded into `ExecMeta` so a non-admin dashboard
    /// widget viewer can render a `kind = chart` view's settings without a
    /// second, admin-gated `GET /api/v1/admin/views/{id}` call — same "no new
    /// endpoint, reuse the feed already trusted" posture D-429 established
    /// for kanban/calendar.
    view_kind: Option<String>,
    view_metadata: Option<Value>,
}

async fn lookup(db: &DbPool, body: &ExecuteQueryRequest) -> Result<SqlQueryRow, AppError> {
    // 1. Direct: caller knows the exact query UUID
    if let Some(qid) = body.query_id {
        return sqlx::query_as(
            "SELECT id, NULL::uuid AS view_id, sql_query, table_definition, record_no, required_privilege, is_report,
                    entity_logical_name, NULL::varchar AS view_kind, NULL::jsonb AS view_metadata
             FROM sql_query WHERE id = $1 AND is_active = true LIMIT 1",
        )
        .bind(qid)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound);
    }

    // 2. A view is list/presentation metadata and references executable SQL.
    if let Some(view_id) = body.view_id {
        return sqlx::query_as(
            "SELECT q.id, v.id AS view_id, q.sql_query, v.table_definition::text, v.name AS record_no,
                    q.required_privilege, q.is_report, v.entity_logical_name,
                    v.kind AS view_kind, v.view_metadata AS view_metadata
             FROM view v
             JOIN sql_query q ON q.id = v.sql_query_ref
             WHERE v.id = $1 AND v.is_active = true AND q.is_active = true
             LIMIT 1",
        )
        .bind(view_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound);
    }

    // 3. Lists resolve the entity's explicit default view; they never infer a
    // view from an arbitrary SQL query or query insertion order.
    if let Some(eln) = body.entity_logical_name {
        return sqlx::query_as(
            "SELECT q.id, v.id AS view_id, q.sql_query, v.table_definition::text, v.name AS record_no,
                    q.required_privilege, q.is_report, v.entity_logical_name,
                    v.kind AS view_kind, v.view_metadata AS view_metadata
             FROM view v
             JOIN sql_query q ON q.id = v.sql_query_ref
             WHERE v.entity_logical_name = $1
               AND v.is_default = true AND v.is_active = true
               AND q.is_active = true
             LIMIT 1",
        )
        .bind(eln)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound);
    }

    // 4. Resolve the entity's explicit default view by logical name.
    if let Some(ref entity) = body.entity {
        return sqlx::query_as(
            "SELECT csq.id, v.id AS view_id, csq.sql_query, v.table_definition::text, v.name AS record_no,
                    csq.required_privilege, csq.is_report, v.entity_logical_name,
                    v.kind AS view_kind, v.view_metadata AS view_metadata
             FROM view v
             JOIN sql_query csq ON csq.id = v.sql_query_ref
             JOIN entity_info ei ON ei.id = v.entity_logical_name
             WHERE ei.logicalname = $1
               AND v.is_default = true AND v.is_active = true
               AND csq.is_active = true
             LIMIT 1",
        )
        .bind(entity)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound);
    }

    Err(AppError::internal(
        "query_id, view_id, entity_logical_name, or entity required",
    ))
}

/// D-521 — one immutable published version of a stored query.
struct PinnedVersion {
    id: Uuid,
    sql_query: String,
    relations: Vec<String>,
    cost_estimate: f64,
}

/// Loads `version_id`, refusing a version that belongs to a different query.
/// The query itself was already resolved (and required to be active) by
/// [`lookup`], so a deactivated query never reaches this and its pinned SQL
/// never runs.
async fn load_pinned_version(
    db: &DbPool,
    query_id: Uuid,
    version_id: Uuid,
) -> Result<PinnedVersion, AppError> {
    let row: Option<(Uuid, String, Vec<String>, f64)> = sqlx::query_as(
        "SELECT id, sql_query, relations, cost_estimate FROM sql_query_version \
         WHERE id = $1 AND query_id = $2",
    )
    .bind(version_id)
    .bind(query_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (id, sql_query, relations, cost_estimate) = row.ok_or_else(|| {
        AppError::Validation("query_version_id does not belong to this query".into())
    })?;
    Ok(PinnedVersion {
        id,
        sql_query,
        relations,
        cost_estimate,
    })
}

/// P-stored-query-containment Phase 3 (D-146). A single-entity query can have
/// the shared record predicate spliced into its generated outer SQL because
/// the outer wrapper's own output happens to expose that entity's `id`/
/// `organization_ref` columns directly (see the single-entity branch below).
/// Arbitrary admin-authored multi-entity SQL has no such implicit column —
/// parsing it into a real SQL AST to find one for every relation, in every
/// join shape, was considered and rejected as its own XL effort (see D-146).
///
/// Instead, this generalizes the exact same "filter the outer wrapper"
/// mechanism using an **admin-declared** column instead of an implicit one:
/// `sql_query_entity_mapping` records, per relation the admin has opted
/// to row-filter, which output column carries that relation's row id. For a
/// relation with a declared mapping, this splices one
/// `attome_security::rls_predicate_by_column` fragment per mapping (more than
/// one for a self-join) into `conds`/`params` — the exact same convention the
/// single-entity branch below already uses. For a relation with **no**
/// mapping, the original all-or-nothing gate still applies: a non-admin must
/// hold read privilege on every relation *and* every unmapped relation must
/// resolve to Global scope, or the whole query is rejected. This is strictly
/// additive over the prior behavior — an unmapped relation is exactly as
/// restrictive as before this plan; a mapped one gets real per-record
/// filtering instead of an outright block.
async fn apply_multi_entity_record_scope(
    state: &EngineState,
    ctx: &SecurityContext,
    query_id: Uuid,
    pinned: Option<(Uuid, &[String])>,
    conds: &mut Vec<String>,
    params: &mut Vec<String>,
) -> Result<(), AppError> {
    if ctx.is_admin {
        return Ok(());
    }

    // D-521: a pinned execution is scoped by the relation inventory of the
    // version whose SQL actually runs, never the latest one.
    let version: Option<(Uuid, Vec<String>)> = match pinned {
        Some((version_id, relations)) => Some((version_id, relations.to_vec())),
        None => sqlx::query_as(
            "SELECT id, relations FROM sql_query_version \
             WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(query_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?,
    };
    // Queries created before the publish/version containment path have no
    // authoritative relation inventory. They must be re-published by an
    // administrator before a non-admin can execute them.
    let Some((version_id, relations)) = version else {
        return Err(AppError::Forbidden);
    };

    if relations.is_empty() {
        // A published literal/constant-only query reads no entity rows, so
        // record-level scope cannot be bypassed.
        return Ok(());
    }

    let entities: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, logicalname FROM entity_info \
         WHERE (is_active IS NULL OR is_active = true) AND logicalname = ANY($1)",
    )
    .bind(&relations)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if entities.len() != relations.len() {
        // The relation list is emitted by the readonly publish-time lint;
        // a missing/deactivated entity is never a reason to fall back to
        // executing unscoped SQL.
        return Err(AppError::Forbidden);
    }

    let mappings: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT entity_ref, id_column FROM sql_query_entity_mapping \
         WHERE query_version_id = $1",
    )
    .bind(version_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    // C-13: one query for every relation's read-access depth instead of one
    // per relation — `resolve_all_entity_access_levels` already exists for
    // exactly this (D-140's polymorphic-audit follow-up uses it the same
    // way below), it just wasn't reused here yet. An entity absent from the
    // map means no matching grant (direct or role) was found for it — same
    // fail-safe default `resolve_entity_access_level` itself returns in that
    // case (`AccessLevel::None`), not an error; `ctx.require` above already
    // rejects a caller with no privilege at all, so this only ever narrows
    // an already-permitted caller's depth, never widens it.
    let access_by_entity = attome_security::resolve_all_entity_access_levels(
        &state.base.db,
        ctx.user_id,
        attome_security::RecordAction::Read,
    )
    .await?;

    for (entity_id, logicalname) in entities {
        ctx.require(&logicalname, "read")?;
        let access_level = access_by_entity
            .get(&logicalname)
            .map(|(_, level)| *level)
            .unwrap_or(AccessLevel::None);
        if access_level == AccessLevel::Global {
            continue;
        }

        // Audit-family carve-out — still fail-closed here, unlike the
        // single-entity branch below (which now applies a real per-row
        // predicate, `attome_security::polymorphic_audit_predicate`, D-140's
        // follow-up). That fix leans on the row's own `entity_name`/
        // `record_id` columns (or, for `audit_detail`, a correlated
        // subquery to `audit_header` via `audit_ref`) being reachable
        // by a fixed expression relative to table alias `t` — true for a
        // bare `FROM {table} t` single-entity list, not true here: this
        // branch scopes an *admin-authored* custom/multi-entity query
        // wrapped as `FROM ({base_sql}) AS t`, whose output columns are
        // whatever the admin's SQL happens to select, named however the
        // admin named them. `sql_query_entity_mapping` (this
        // function's `mappings`) only declares an `id_column` per relation
        // today — extending it to also declare which output column(s)
        // carry a mapped entity's polymorphic `entity_name`/`record_id`
        // (when the relation is one of the three audit entities) is real,
        // separate follow-up work, not a copy-paste of the single-entity
        // fix.
        // U1 (basic-units plan B-R1): a polymorphic child (note, communication,
        // tag, follow) needs the same referenced-record predicate, and for the
        // same reason cannot get it here — refused like the audit family.
        if crate::entity_crud::POLYMORPHIC_AUDIT_ENTITIES.contains(&logicalname.as_str())
            || crate::entity_crud::POLYMORPHIC_CHILD_ENTITIES.contains(&logicalname.as_str())
        {
            return Err(AppError::Forbidden);
        }

        let id_columns: Vec<&str> = mappings
            .iter()
            .filter(|(entity_ref, _)| *entity_ref == entity_id)
            .map(|(_, id_column)| id_column.as_str())
            .collect();
        if id_columns.is_empty() {
            // No admin-declared mapping for this relation — the original
            // fail-closed gate, now scoped to just this relation instead of
            // the whole query.
            return Err(AppError::Forbidden);
        }
        for id_column in id_columns {
            if let Some(pred) = attome_security::rls_predicate_by_column(
                ctx,
                entity_id,
                "t",
                id_column,
                access_level,
                attome_security::RecordAction::Read.share_capability(),
                params.len() + 1,
            ) {
                conds.push(pred.sql.trim_start_matches("AND ").to_owned());
                params.extend(pred.binds.to_text_params());
            }
        }
    }
    Ok(())
}

// ── Column building ───────────────────────────────────────────────────────────

#[derive(Serialize, Clone, ToSchema)]
pub struct ColumnDef {
    pub name: String,
    pub display_name: String,
    pub data_type: String,
    pub is_visible: bool,
    pub is_sortable: bool,
    pub is_searchable: bool,
    pub is_clickable: bool,
    pub route_template: String,
    /// Logical name of the entity a `data_type: "lookup"` column points to —
    /// `None` for every other column. Metadata-derived (never from
    /// `table_definition`), set alongside `data_type` in the enrichment loop
    /// below. The frontend turns this into a route
    /// (`logicalToUrlPath`) to make an unconfigured lookup cell clickable by
    /// default — a plain logical name, not a route, so this crate stays free
    /// of Angular's routing scheme.
    pub lookup_target_entity: Option<String>,
    /// Per-value color/icon presentation hints for a `data_type: "choice"`
    /// column — the raw `choice_styles` map from `attome_field::ChoiceOptions`,
    /// keyed by choice value. `None` for every other column, and for a
    /// choice column with no configured styles. Metadata-derived, set
    /// alongside `data_type` in the enrichment loop below.
    pub choice_styles: Option<Value>,
}

impl std::fmt::Debug for ColumnDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColumnDef").finish_non_exhaustive()
    }
}

fn build_columns(td: Option<&Value>, sql_cols: &[String]) -> Vec<ColumnDef> {
    let arr_opt = td.and_then(|v| {
        v.as_array()
            .or_else(|| v.get("columns").and_then(|c| c.as_array()))
    });

    let Some(arr) = arr_opt else {
        return infer_columns(sql_cols);
    };

    let mut cols: Vec<ColumnDef> = arr
        .iter()
        .filter_map(|c| {
            let name = c
                .get("name")
                .or_else(|| c.get("logicalName"))
                .and_then(|v| v.as_str())?;
            Some(ColumnDef {
                name: name.to_owned(),
                display_name: c
                    .get("display_name")
                    .or_else(|| c.get("displayName"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(name)
                    .to_owned(),
                data_type: c
                    .get("data_type")
                    .or_else(|| c.get("dataType"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("text")
                    .to_owned(),
                is_visible: c
                    .get("is_visible")
                    .or_else(|| c.get("isVisible"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
                is_sortable: c
                    .get("is_sortable")
                    .or_else(|| c.get("isSortable"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
                is_searchable: c
                    .get("is_searchable")
                    .or_else(|| c.get("isSearchable"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                is_clickable: c
                    .get("is_clickable")
                    .or_else(|| c.get("isClickable"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                route_template: c
                    .get("route_template")
                    .or_else(|| c.get("routeTemplate"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                lookup_target_entity: None,
                choice_styles: None,
            })
        })
        .collect();

    // Append any SQL output columns not present in table_definition
    let defined: std::collections::HashSet<String> = cols.iter().map(|c| c.name.clone()).collect();
    for col in sql_cols {
        if col == "id" || defined.contains(col) {
            continue;
        }
        cols.push(ColumnDef {
            name: col.clone(),
            display_name: col.replace('_', " "),
            data_type: "text".to_owned(),
            is_visible: true,
            is_sortable: true,
            is_searchable: false,
            is_clickable: false,
            route_template: String::new(),
            lookup_target_entity: None,
            choice_styles: None,
        });
    }

    cols
}

fn infer_columns(sql_cols: &[String]) -> Vec<ColumnDef> {
    sql_cols
        .iter()
        .filter(|c| c.as_str() != "id")
        .map(|c| ColumnDef {
            name: c.clone(),
            display_name: c.replace('_', " "),
            data_type: "text".to_owned(),
            is_visible: true,
            is_sortable: true,
            is_searchable: false,
            is_clickable: false,
            route_template: String::new(),
            lookup_target_entity: None,
            choice_styles: None,
        })
        .collect()
}

/// `data_type` for a physical system column, which
/// [`enrich_columns_from_entity`] cannot learn from `entity.attrs` — the
/// system columns are provisioned by `attome_metadata::provision::table`'s
/// `CREATE TABLE` (D-005) and deliberately carry no `attribute_info`
/// row of their own.
///
/// Without this the enrichment loop left every one of them at
/// `build_columns`' `"text"` default, and `parameter_cast` then emitted
/// `"owner_ref" = $1::text` against a `UUID` column — PostgreSQL answers
/// `operator does not exist: uuid = text` (SQLSTATE 42883) and the whole grid
/// 500s. Same breakage for `created_at`/`modified_at` (`timestamptz > text`),
/// `is_active` (`boolean = text`), and `row_version`/`owner_type`
/// (`bigint`/`smallint` vs `text`), so the map covers all of
/// `ALL_SYSTEM_COLS`, not just the UUID ones.
///
/// The UUID columns map to `"uuid"` rather than `"lookup"`: both cast
/// identically (`parameter_cast`), but `"lookup"` additionally promises the
/// client a resolvable `lookup_target_entity` and a display-name join, which
/// these denormalized pointers do not have.
fn system_column_data_type(name: &str) -> Option<&'static str> {
    match name {
        "id" | "created_by" | "modified_by" | "organization_ref" | "owner_ref" => Some("uuid"),
        "created_at" | "modified_at" => Some("date"),
        "is_active" => Some("bool"),
        "row_version" | "owner_type" => Some("number"),
        _ => None,
    }
}

/// Applies metadata-derived `data_type`/`lookup_target_entity`/multi-choice
/// enrichment to a columns list. Pulled out into its own function because it
/// used to run only over `validation_columns` (internal filter/search
/// type-casting) and never over the `columns` actually returned to the
/// caller — a default seeded query (no admin `table_definition`) therefore
/// always reported `data_type: "text"` for every column, lookups included,
/// to the client. Both passes now call this. `resolve_target_logicalname` is
/// a closure rather than a registry reference so this function doesn't need
/// to know the arc-swap guard's concrete type.
fn enrich_columns_from_entity(
    columns: &mut [ColumnDef],
    entity: &attome_core::EntityMeta,
    resolve_target_logicalname: impl Fn(Uuid) -> Option<String>,
) -> std::collections::HashSet<String> {
    let mut multi_choice_fields = std::collections::HashSet::new();
    for column in columns.iter_mut() {
        let Some(attr) = entity
            .attrs
            .iter()
            .find(|attr| attr.logicalname == column.name)
        else {
            // Not an attribute — but it may still be a system column whose
            // physical type we know statically. An attribute always wins:
            // an entity that declares its own `is_active`/`owner_ref`
            // attribute keeps the metadata-derived type.
            if let Some(data_type) = system_column_data_type(&column.name) {
                column.data_type = data_type.to_owned();
                column.lookup_target_entity = None;
            }
            continue;
        };
        // C-16 / U9 checklist item 5: this was a second hand-copied
        // int -> string map; it is `FieldType`'s own codec now. The
        // *presentation* type: a formula column reads as its result type
        // (`number`, `date`, ...), while `rich_text`/`image` keep their own
        // name so the grid can render them (`parameter_cast` maps both to
        // `text` for filtering and search).
        column.data_type = attr.presentation_type().as_str().to_owned();
        column.lookup_target_entity = if attr.field_type_int == 11 {
            attr.lookup_entity_ref.and_then(&resolve_target_logicalname)
        } else {
            None
        };
        column.choice_styles = if matches!(attr.field_type_int, 7 | 8) {
            attr.options
                .as_ref()
                .and_then(|options| options.get("choice_styles"))
                .cloned()
        } else {
            None
        };
        if matches!(attr.field_type_int, 7 | 8)
            && attr
                .options
                .as_ref()
                .and_then(|options| options.get("multi"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            multi_choice_fields.insert(column.name.clone());
        }
    }
    multi_choice_fields
}

/// Grid/list counterpart of `entity_crud::response::resolve_lookup_meta`
/// (D-077): that function batches by distinct target entity for *one* row's
/// several lookup fields; this one batches by distinct target entity across
/// an entire *page* of rows — one `WHERE id = ANY($1)` per (field, target)
/// pair covering every row on the page, never one query per row. Merges a
/// `__lookups: {field: {exists, is_active, name}}` object into each row that
/// carries at least one populated lookup field, mirroring the single-record
/// wire shape rather than overwriting `data`'s stored UUID — D-077 made that
/// raw-UUID-in-`data` contract deliberate, and this stays additive to it.
///
/// Only called when `qrow.entity_logical_name` is `Some` — the same D-133
/// boundary this file already draws for RLS scoping ("no single attribute
/// set to resolve lookup targets against" for a multi-entity/custom query).
/// M01-core C-05: resolution goes through
/// `entity_crud::resolve_visible`, which splices the target entity's own
/// `rls_predicate` in, so a target row this caller can't read is excluded
/// from the map — rendered `{exists: false, is_active: false, name: null}`
/// below, the same as a target that doesn't exist. Best-effort like its
/// single-record sibling (`entity_crud::response::resolve_lookup_meta`): a
/// target query failure is logged and that target's fields are simply left
/// as the raw UUID (no `__lookups` entry at all for that field).
#[expect(
    clippy::expect_used,
    reason = "__lookups is inserted as a JSON object just above"
)]
async fn attach_lookup_display_names(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    records: &mut [Value],
) {
    if records.is_empty() {
        return;
    }
    let lookup_attrs: Vec<(String, Uuid)> = {
        let registry = state.entities.load();
        let Some(meta) = registry.get_by_id(entity_id) else {
            return;
        };
        meta.attrs
            .iter()
            .filter(|a| a.field_type_int == 11)
            .filter_map(|a| {
                a.lookup_entity_ref
                    .map(|target| (a.logicalname.clone(), target))
            })
            .collect()
    };

    for (field, target_id) in lookup_attrs {
        let ids: Vec<Uuid> = records
            .iter()
            .filter_map(|r| {
                r.get(&field)
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
            })
            .collect();
        if ids.is_empty() {
            continue;
        }

        let found = crate::entity_crud::resolve_visible(state, ctx, target_id, &ids).await;

        for record in records.iter_mut() {
            let Some(id) = record
                .get(&field)
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            let (exists, is_active, name) = match found.get(&id) {
                Some(r) => (r.exists, r.is_active, r.name.clone()),
                None => (false, false, None),
            };
            if let Some(obj) = record.as_object_mut() {
                obj.entry("__lookups")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .expect("__lookups is always inserted as a JSON object literal above")
                    .insert(
                        field.clone(),
                        json!({ "exists": exists, "is_active": is_active, "name": name }),
                    );
            }
        }
    }
}

/// Declared `logicalName`s from `table_definition` — used as the identifier
/// whitelist for filters/search/order_by *before* the main query runs, so a
/// single query can do column-discovery, filtering, and counting together
/// (P1.11b). `table_definition` is admin-authored metadata (guidelines §4:
/// identifiers only from validated metadata), not a live sample of the SQL
/// output — a declared column that isn't actually present in `base_sql`'s
/// output will surface as a SQL error if search/filter/order_by touches it,
/// rather than being silently skipped the way a live-sample check would.
/// Returns `None` when `table_definition` is absent/unparseable/empty.
fn table_definition_names(td: &Value) -> Option<Vec<String>> {
    let arr = td
        .as_array()
        .or_else(|| td.get("columns").and_then(|c| c.as_array()))?;

    let names: Vec<String> = arr
        .iter()
        .filter_map(|c| {
            c.get("name")
                .or_else(|| c.get("logicalName"))
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .collect();

    if names.is_empty() { None } else { Some(names) }
}

/// [`FilterSchema`] over this endpoint's own `ColumnDef`/
/// `table_definition`-derived whitelist — C-15 (M01 §7): the filter -> WHERE
/// fragment itself is the shared `attome_core::filter::compile` writer
/// now; only this whitelist stays entangled with this file's own
/// column-resolution machinery (this module's original filter-grammar doc
/// comment, now on `attome_core::filter` itself).
struct QueryExecFilterSchema<'a> {
    columns: &'a [ColumnDef],
    multi_choice: &'a std::collections::HashSet<String>,
    /// A17-T2: the tree each lookup column points into, when its target has
    /// exactly one self-referencing lookup.
    hierarchies: std::collections::HashMap<String, attome_core::filter::Hierarchy>,
    /// B4-T4: the base entity and caller, for `tagged`.
    tag_scope: Option<attome_core::filter::TagScope>,
}

/// A17-T2: for each lookup column, the target entity's tree, when it has one
/// self-referencing parent lookup.
fn lookup_hierarchies(
    columns: &[ColumnDef],
    registry: &attome_core::EntityMetaRegistry,
) -> std::collections::HashMap<String, attome_core::filter::Hierarchy> {
    let mut out = std::collections::HashMap::new();
    for column in columns {
        let Some(target) = column.lookup_target_entity.as_deref() else {
            continue;
        };
        let Some(meta) = registry.get(target) else {
            continue;
        };
        let mut parents = meta
            .attrs
            .iter()
            .filter(|a| a.field_type_int == 11 && a.lookup_entity_ref == Some(meta.entity_id));
        if let (Some(parent), None) = (parents.next(), parents.next()) {
            out.insert(
                column.name.clone(),
                attome_core::filter::Hierarchy {
                    table: meta.logicalname.clone(),
                    parent: parent.logicalname.clone(),
                },
            );
        }
    }
    out
}

impl FilterSchema for QueryExecFilterSchema<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        let column = self
            .columns
            .iter()
            .find(|column| column.name == field)
            .ok_or(FieldCastError::Unknown)?;
        parameter_cast(&column.data_type).ok_or(FieldCastError::UnsupportedType)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.multi_choice.contains(field)
    }

    fn hierarchy(&self, field: &str) -> Option<attome_core::filter::Hierarchy> {
        self.hierarchies.get(field).cloned()
    }

    fn tag_scope(&self) -> Option<attome_core::filter::TagScope> {
        self.tag_scope.clone()
    }
}

/// PostgreSQL `undefined_function`. Also what it raises for a missing
/// *operator* — `operator does not exist: uuid = text` is a 42883.
const SQLSTATE_UNDEFINED_FUNCTION: &str = "42883";

/// `query_canceled`: what PostgreSQL raises when `statement_timeout` fires.
const SQLSTATE_QUERY_CANCELED: &str = "57014";

/// Maps a stored-query execution failure to an `AppError`, attaching the
/// operator-facing context that a bare [`AppError::internal`] call cannot:
/// that one logs only the driver's message, so a failed grid recorded
/// `internal error: error returned from database: operator does not exist:
/// uuid = text` with nothing saying which query, entity, or filter produced
/// it. The request id in the span was the only handle, and it does not
/// survive into anything the caller can act on.
///
/// Identifiers only — never a filter *value*. The whole point of masking
/// `AppError::Internal` at the transport boundary (guidelines §7) is that
/// request data must not leak, and a log line is not exempt from that.
///
/// A 42883 means a comparison's operand types don't line up. Every cast this
/// module synthesizes for a *filter* comes from the column's declared
/// `data_type` (`parameter_cast`), so when the request carried filters that
/// is the caller's input being untypeable against the physical column — a
/// 422 naming the fields, not a masked 500 (guidelines §6: "Do not convert
/// every failure to `Internal`"). A filterless query hitting 42883 is an
/// admin-authored SQL bug instead, and stays a 500.
fn query_exec_error(
    e: sqlx::Error,
    query_id: Uuid,
    entity: Option<&str>,
    filters: &[Filter],
) -> AppError {
    let filter_fields: Vec<&str> = filters.iter().map(|f| f.field.as_str()).collect();
    let entity = entity.unwrap_or("(no single entity scope)");

    // AA4-T7: the statement time limit cancelled the query.
    if e.as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code.as_ref() == SQLSTATE_QUERY_CANCELED)
    {
        tracing::info!(query_id = %query_id, entity, "query/execute ran past its time limit");
        return AppError::QueryTimeout;
    }
    let operand_type_mismatch = e
        .as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code.as_ref() == SQLSTATE_UNDEFINED_FUNCTION);
    if operand_type_mismatch && !filter_fields.is_empty() {
        tracing::warn!(
            error = %e,
            query_id = %query_id,
            entity,
            filter_fields = ?filter_fields,
            "query/execute filter does not type against its column"
        );
        return AppError::Validation(format!(
            "this query cannot be filtered on: {}",
            filter_fields.join(", ")
        ));
    }

    // The context rides in the masked detail: `AppError::Internal`'s one
    // response-boundary `error!` logs it (BTY-5), so logging here too would
    // split one failure across two lines.
    AppError::Internal(format!(
        "query/execute failed (query_id={query_id}, entity={entity}, filter_fields={filter_fields:?}): {e}"
    ))
}

#[cfg(test)]
mod query_exec_error_tests {
    use super::*;

    #[test]
    fn a_masked_failure_carries_its_identifiers_in_the_logged_detail() {
        let id = Uuid::nil();
        match query_exec_error(sqlx::Error::RowNotFound, id, Some("account"), &[]) {
            AppError::Internal(detail) => {
                assert!(detail.contains(&id.to_string()), "{detail}");
                assert!(detail.contains("entity=account"), "{detail}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}

// ── Response ──────────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ExecMeta {
    query_id: Uuid,
    /// Presentation view used for this execution. Raw query executions have no view.
    view_id: Option<Uuid>,
    record_no: Option<String>,
    /// Logical name resolved from the query's entity UUID link. Clients use
    /// this to derive generic list/form routes without hardcoded entity URLs.
    entity_logical_name: Option<String>,
    /// The caller may open the admin query editor for this exact query.
    /// Query mutations are currently system.admin-only, so derive this from
    /// the same authoritative SecurityContext that authorized execution.
    can_edit_query: bool,
    /// D-429's view `kind` (chart follow-up, migration 0447) — `None` when
    /// this execution has no bound view. Lets a non-admin client (e.g. the
    /// dashboard widget viewer) render `kind`-specific settings without a
    /// second, admin-gated call — see `SqlQueryRow::view_kind`'s doc comment.
    view_kind: Option<String>,
    view_metadata: Option<Value>,
}

impl std::fmt::Debug for ExecMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecMeta").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ExecData {
    columns: Vec<ColumnDef>,
    records: Vec<Value>,
    /// `None` in keyset/cursor mode (P1.11(g)) — `COUNT(*) OVER()` scans the
    /// full matching set regardless of OFFSET vs keyset, a cost independent
    /// of (and additional to) the O(offset) problem keyset fixes, so cursor
    /// requests skip it rather than pay for a total the typical cursor
    /// caller (export/infinite-scroll/API integration) doesn't need.
    total: Option<i64>,
    /// A13-T2: `true` when `total` is the planner's estimate rather than a
    /// count: a matching set of [`EXACT_TOTAL_LIMIT`] rows or more is not
    /// counted, as counting it would scan it all.
    total_estimated: bool,
    page: i64,
    page_size: i64,
    total_pages: Option<i64>,
    /// Present only in cursor mode: the `after_id` value the caller passes
    /// back to fetch the next page. `None` means either OFFSET mode, or
    /// cursor mode with no further rows (the page came back short).
    next_cursor: Option<Uuid>,
}

impl std::fmt::Debug for ExecData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecData").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ExecResponse {
    metadata: ExecMeta,
    data: ExecData,
}

impl std::fmt::Debug for ExecResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecResponse").finish_non_exhaustive()
    }
}

/// Plans `base_sql` (with its WHERE/ORDER BY applied) live and returns its
/// total cost — the pre-phase-2 per-execute behavior, kept as the
/// `query.validate_on_execute` rollback path and as the fallback for any
/// `sql_query` row with no `sql_query_version` entry.
async fn run_live_explain<'e, E>(
    executor: E,
    base_sql: &str,
    where_sql: &str,
    order_sql: &str,
    params: &[String],
) -> Result<f64, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let explain_sql = format!(
        "EXPLAIN (FORMAT JSON) SELECT 1 FROM ({base_sql}) AS t {where_sql} {order_sql} LIMIT 1"
    );
    let mut explain = sqlx::query_scalar::<_, Value>(&explain_sql);
    for param in params {
        explain = explain.bind(param.clone());
    }
    let plan = explain
        .fetch_one(executor)
        .await
        .map_err(AppError::internal)?;
    plan.pointer("/0/Plan/Total Cost")
        .and_then(Value::as_f64)
        .ok_or_else(|| AppError::internal("PostgreSQL returned an invalid query plan"))
}

/// A13-T2: the size from which a total is the planner's estimate, not a count.
pub const EXACT_TOTAL_LIMIT: i64 = 100_000;

/// The planner's estimate of how many rows `base_sql` (with its WHERE)
/// matches; nothing is read.
async fn estimate_rows<'e, E>(
    executor: E,
    base_sql: &str,
    where_sql: &str,
    params: &[String],
) -> Result<i64, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let explain_sql = format!("EXPLAIN (FORMAT JSON) SELECT 1 FROM ({base_sql}) AS t {where_sql}");
    let mut explain = sqlx::query_scalar::<_, Value>(&explain_sql);
    for param in params {
        explain = explain.bind(param.clone());
    }
    let plan = explain
        .fetch_one(executor)
        .await
        .map_err(AppError::internal)?;
    Ok(plan_rows(&plan))
}

/// The top plan node's row estimate in `EXPLAIN (FORMAT JSON)` output, `0`
/// when absent.
fn plan_rows(plan: &Value) -> i64 {
    plan.pointer("/0/Plan/Plan Rows")
        .and_then(Value::as_f64)
        .map_or(0, |rows| rows.round() as i64)
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// P-api-contract Phase 0: like-for-like migration of the retired
/// `openapi/query-v1.json` hand file onto generated utoipa annotations — see
/// `openapi_contract_keeps_query_v1_compatibility_points` below for the
/// compatibility points this reproduces, and `Filter`'s doc comment for the
/// one disclosed fidelity gap (`op`'s `enum` constraint).
#[utoipa::path(
    post,
    path = "/api/v1/query/execute",
    tag = "query",
    request_body = ExecuteQueryRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "executes a stored query against the read-only pool; persists nothing",
    )))),
    responses(
        (status = 200, description = "A bounded query page", body = ExecResponse),
        (status = 422, description = "Invalid filter, ordering, or pagination contract"),
    ),
)]
/// RecordScoped, not Admin: the gate in [`execute_stored_query`] is
/// per-stored-query — a query carrying a `required_privilege` is reachable by
/// any caller holding that key, and only a query with none falls back to
/// requiring admin. Typing this handler `Admin` would collapse both arms into
/// admin-only.
async fn execute(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Json(body): Json<ExecuteQueryRequest>,
) -> Result<Json<ExecResponse>, AppError> {
    execute_stored_query(&state, &ctx, body).await.map(Json)
}

/// Running a stored query, with every transport concern removed.
///
/// Extracted from the handler above so `attome-ai`'s `query.execute` reuses
/// THIS — including the per-query privilege gate, the record-level scoping,
/// the read-only pinned-aware pool, the statement timeout, and the pagination
/// contract. An action that rebuilt any of that would be a second way to run
/// admin-authored SQL, which is precisely what invariant I-9 and guidelines §4
/// exist to prevent.
///
/// The model's role at the layer above is to CHOOSE a stored query and bind
/// its parameters. It never authors SQL, and nothing here would let it: the
/// `name` selects a row from `sql_query`, and everything else is a
/// bound value.
pub async fn execute_stored_query(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    body: ExecuteQueryRequest,
) -> Result<ExecResponse, AppError> {
    execute_stored_query_with_definition(state, ctx, body, None).await
}

/// D-543 — the definition a published dashboard captured at publish, replacing
/// the parts of a query/view that execution would otherwise read live. Built
/// server-side from a published snapshot; never accepted from a client
/// (D-522 decision 7), which is why it is a separate argument rather than a
/// field on [`ExecuteQueryRequest`].
///
/// It overrides the executable *definition* only: the column metadata (which
/// decides the identifier whitelist and the returned columns) and the view's
/// presentation semantics. It never touches `required_privilege`, the query's
/// `is_active`, record-level scope, the pinned SQL or the cost ceiling — those
/// stay live (D-521 rule 3).
#[derive(Debug, Default, Clone)]
pub struct PublishedDefinition {
    /// The captured `table_definition`, already parsed. `None` leaves the live
    /// one in place (a format-2 snapshot, or a widget with no captured
    /// metadata).
    pub column_definition: Option<Value>,
    /// The captured view `kind`, echoed in the response metadata.
    pub view_kind: Option<String>,
    /// The captured `view_metadata`, echoed in the response metadata — this is
    /// what chart settings ride on.
    pub view_metadata: Option<Value>,
}

/// [`execute_stored_query`] with an optional published definition. The
/// ordering is deliberate and must not change: `lookup` resolves the query,
/// the pinned version is loaded, the per-query privilege gate and record
/// scoping run against live security, and only the definition-shaped reads are
/// replaced.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub async fn execute_stored_query_with_definition(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    body: ExecuteQueryRequest,
    definition: Option<PublishedDefinition>,
) -> Result<ExecResponse, AppError> {
    // P-api-consistency-hardening (a): route through the pinned-aware pool so
    // a caller who just published (query_admin.rs) or wrote through this same
    // execute path doesn't see a stale replica for either the metadata lookup
    // below or the data-fetching transaction further down — see
    // `AppState::readonly_query_pool`'s doc comment for why this can't just
    // reuse `read_pool` (that one may fall through to the full-privilege `db`
    // pool, reopening P1.1e's SELECT-only isolation for stored SQL).
    let db = state.base.readonly_query_pool(ctx.user_id).await;
    let qrow = lookup(db, &body).await?;
    // D-521 — pinned SQL, live security: resolved before the privilege gate
    // below so a wrong version is refused the same way for every caller, but
    // it changes nothing about which privilege or record scope applies.
    let pinned = match body.query_version_id {
        Some(version_id) => Some(load_pinned_version(db, qrow.id, version_id).await?),
        None => None,
    };
    let linked_entity_logical_name = {
        let registry = state.entities.load();
        qrow.entity_logical_name
            .and_then(|id| registry.get_by_id(id))
            .map(|entity| entity.logicalname.clone())
    };

    // Per-query gating: a query opting in via required_privilege is reachable
    // by any caller holding that exact key (admin always short-circuits);
    // queries that don't opt in keep the coarse admin-only default.
    match &qrow.required_privilege {
        Some(key) => ctx.require_key(key)?,
        None => ctx.require_admin()?,
    }

    // M01 Core C-12: this record-level scoping used to run after the readonly
    // transaction below opened, calling attome_security's resolve_* helpers and
    // apply_multi_entity_record_scope against `state.base.db` while a second
    // connection was already checked out for `tx` on the same pool (`db` can be
    // the very same pool as `state.base.db` -- see readonly_query_pool's own doc
    // comment) -- N such requests self-deadlock under pool saturation waiting on
    // a second connection each never frees (M01-core C-12). None of it needs the
    // transaction's own connection -- only `qrow`/`ctx`/`state` -- so it now runs
    // here, before `db.begin()`, on the pool alone.
    let mut conds: Vec<String> = vec![];
    let mut params: Vec<String> = vec![];

    // D-133: record-level scoping for single-entity stored queries only —
    // the exact D-057 boundary this codebase already established
    // ("List-path filtering is skipped entirely for admin-authored custom/
    // multi-entity stored queries... since there's no single attribute set
    // to resolve lookup targets against"). A multi-entity/custom query is
    // admin-authored and already privilege-gated by `required_privilege`
    // (D-036) — RLS does not wrap it, same trust boundary this file already
    // uses for the `entity_logical_name.is_some()` branch above.
    //
    // `rls_predicate`'s generated SQL casts every placeholder explicitly
    // (`$N::uuid` etc.), so it binds correctly through this file's existing
    // `Vec<String>` param convention (`to_text_params()`) even though every
    // other caller of this function (`entity_crud.rs`) binds typed values —
    // see `RlsBinds::to_text_params`'s doc comment.
    // Row-scoping depth is resolved from the entity's own "{entity}.read"
    // grant (`resolve_entity_access_level`), independent of whatever custom
    // `required_privilege` gated running this query at all (D-036) — same
    // separation `entity_crud.rs` already keeps between the boolean
    // `ctx.require(entity, "read")` gate and the record-level scope.
    if let Some(entity_id) = qrow.entity_logical_name {
        let cached_logicalname = state
            .entities
            .load()
            .get_by_id(entity_id)
            .map(|meta| meta.logicalname.clone());
        // A just-provisioned entity can briefly predate the async registry
        // refresh. Skipping RLS during that window would fail open, so fall
        // back to authoritative metadata and fail closed if the entity has
        // disappeared.
        let entity_logicalname = match cached_logicalname {
            Some(logicalname) => logicalname,
            None => sqlx::query_scalar(
                "SELECT logicalname FROM entity_info \
                 WHERE id = $1 AND is_active = true LIMIT 1",
            )
            .bind(entity_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?,
        };
        let access_level = attome_security::resolve_entity_access_level(
            &state.base.db,
            ctx.user_id,
            entity_id,
            &entity_logicalname,
            attome_security::RecordAction::Read,
        )
        .await?;
        if crate::entity_crud::POLYMORPHIC_AUDIT_ENTITIES.contains(&entity_logicalname.as_str()) {
            // `audit_header`/`audit_detail`/`audit_snapshot`
            // rows have no meaningful row-level RLS of their own — nobody
            // shares an individual audit-log entry via `record_share`
            // keyed to the audit row's own id, so ANDing `rls_predicate`
            // (audit entity's own scope) with `polymorphic_audit_predicate`
            // (referenced-record scope) unconditionally would make a
            // target-bearing row's referenced-record share unsatisfiable for
            // a narrowed-tier caller (D-147's bug, fixed by 9ec8c7a). But a
            // *target-less* row (e.g. a login/logout audit entry —
            // `polymorphic_audit_predicate` deliberately evaluates `false`
            // for these, see its own doc comment) has no referenced record
            // to check at all, so it must fall back to the caller's own
            // audit-entity scope instead of being left unfiltered — mirrors
            // `entity_crud.rs::get_record`'s `None` arm falling back to
            // `require_record_access` when `polymorphic_audit_target`
            // resolves no target. The two predicates are therefore OR'd
            // per-row, gated by which case applies, not ANDed globally.
            if !ctx.is_admin && access_level != AccessLevel::Global {
                // `audit_detail` has no `entity_name`/`record_id` of its
                // own — they live on the `audit_header` row it points at
                // via `audit_ref` (`polymorphic_audit_target`'s two shapes).
                // A correlated scalar subquery keeps this inside the
                // existing WHERE-splice convention without touching the
                // FROM clause (which is a bare `FROM {table} t`, no join,
                // for every entity this function handles).
                let (entity_name_col, record_id_col) = if entity_logicalname == "audit_detail" {
                    (
                        "(SELECT h.entity_name FROM audit_header h WHERE h.id = t.audit_ref)"
                            .to_string(),
                        "(SELECT h.record_id FROM audit_header h WHERE h.id = t.audit_ref)"
                            .to_string(),
                    )
                } else {
                    // `::uuid` — redundant for the audit entities' native
                    // `uuid` column, load-bearing for `attome_document`'s plain
                    // `text` column (see `access.rs::polymorphic_audit_target`'s
                    // comment on why it can't be a `lookup`-typed column
                    // instead). `polymorphic_audit_predicate` compares this
                    // expression against `record_share.record_id`,
                    // a native `uuid` column — a bare `text` column here
                    // would fail that comparison at the SQL level, not just
                    // read wrong.
                    ("t.entity_name".to_string(), "t.record_id::uuid".to_string())
                };

                // `access_level != Global` was just checked above, so this is
                // always `Some` — the audit entity's own narrowed scope,
                // applied only to target-less rows below.
                let own_scope_pred = attome_security::rls_predicate(
                    ctx,
                    entity_id,
                    "t",
                    access_level,
                    attome_security::RecordAction::Read.share_capability(),
                    params.len() + 1,
                )
                .expect("access_level != Global was just checked above");
                let own_scope_sql = own_scope_pred.sql.trim_start_matches("AND ").to_owned();
                params.extend(own_scope_pred.binds.to_text_params());

                let access_by_entity = attome_security::resolve_all_entity_access_levels(
                    &state.base.db,
                    ctx.user_id,
                    attome_security::RecordAction::Read,
                )
                .await?;
                // Entity-default shares carry no `record_id`, so they resolve
                // once per request here rather than as a correlated subquery
                // re-evaluated per candidate audit row (D-357).
                let default_share_entities = attome_security::resolve_default_share_entities(
                    &state.base.db,
                    ctx.user_id,
                    &ctx.team_ids,
                    attome_security::RecordAction::Read
                        .share_capability()
                        .as_i16(),
                )
                .await?;
                let poly_pred = attome_security::polymorphic_audit_predicate(
                    ctx,
                    &access_by_entity,
                    &default_share_entities,
                    // No fast tier here: the audit rows carry no
                    // organization_ref of their own, which is D-146's original
                    // structural reason and is unchanged. `None` generates
                    // byte-identical SQL to before TODO-003.
                    None,
                    &entity_name_col,
                    &record_id_col,
                    params.len() + 1,
                );
                let poly_sql = poly_pred.sql.trim_start_matches("AND ").to_owned();
                params.extend(poly_pred.binds.to_text_params());

                // Outer parens are load-bearing: `conds` are ANDed together
                // below (`conds.join(" AND ")`), and SQL's `AND` binds
                // tighter than `OR` — without wrapping the whole per-row
                // disjunction, a sibling `cond` would attach to only one
                // side of the `OR`.
                conds.push(format!(
                    "((({record_id_col} IS NULL OR {entity_name_col} IS NULL) \
                      AND {own_scope_sql}) OR {poly_sql})"
                ));
            }
        } else if let Some(pred) = attome_security::rls_predicate(
            ctx,
            entity_id,
            "t",
            access_level,
            attome_security::RecordAction::Read.share_capability(),
            params.len() + 1,
        ) {
            conds.push(pred.sql.trim_start_matches("AND ").to_owned());
            params.extend(pred.binds.to_text_params());
        }

        // U1 (basic-units plan B-R1): a polymorphic child row (note,
        // communication, tag, follow) is additionally gated by the record it is
        // attached to. ANDed with the row's own scope above, never substituted
        // for it (unlike the audit family: these rows have real row-level
        // security of their own), and applied at every access level short of
        // admin, so a caller with Global read on `note` still cannot list
        // the notes of a record hidden from them.
        if !ctx.is_admin
            && crate::entity_crud::POLYMORPHIC_CHILD_ENTITIES.contains(&entity_logicalname.as_str())
        {
            // `record_id` is a plain `text` column on these entities. A value
            // that is not a UUID becomes NULL instead of raising a cast error
            // for the whole page. `polymorphic_audit_predicate` then hides the
            // row unless the caller reads the named parent entity at Global
            // scope (every record of it visible anyway), and a NULL or unknown
            // `entity_name` hides it outright: fail closed. No own-scope
            // fallback is OR'd in for target-less rows, deliberately.
            let record_id_col = concat!(
                "(CASE WHEN t.record_id ~* ",
                "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' ",
                "THEN t.record_id::uuid END)"
            );
            let access_by_entity = attome_security::resolve_all_entity_access_levels(
                &state.base.db,
                ctx.user_id,
                attome_security::RecordAction::Read,
            )
            .await?;
            let default_share_entities = attome_security::resolve_default_share_entities(
                &state.base.db,
                ctx.user_id,
                &ctx.team_ids,
                attome_security::RecordAction::Read
                    .share_capability()
                    .as_i16(),
            )
            .await?;
            let parent_pred = attome_security::polymorphic_audit_predicate(
                ctx,
                &access_by_entity,
                &default_share_entities,
                None,
                "t.entity_name",
                record_id_col,
                params.len() + 1,
            );
            conds.push(parent_pred.sql.trim_start_matches("AND ").to_owned());
            params.extend(parent_pred.binds.to_text_params());
        }

        // M01 Core P3 gap (D-455) — `related_to`: narrow to rows joined,
        // through a named M:M relationship, to one anchor record on the
        // other side. Spliced as one more `t.id IN (...)` condition into
        // the same `conds`/`params` convention every filter/RLS fragment
        // above already uses — an ordinary correlated subquery against the
        // relationship's join table, never a join added to the base query's
        // own `FROM` clause (which stays a bare `FROM {table} t` for every
        // entity this branch handles, same invariant the audit-entity
        // scalar-subquery comment above already documents).
        if let Some(related) = &body.related_to {
            let registry = state.relationships.load();
            let def = registry
                .get(&related.relationship)
                .filter(|d| d.is_active)
                .ok_or(AppError::NotFound)?;
            let side = def.other_side(&entity_logicalname).ok_or_else(|| {
                AppError::Validation(format!(
                    "relationship '{}' does not connect entity '{entity_logicalname}'",
                    related.relationship
                ))
            })?;
            let join_table = quote_ident(&def.join_table);
            let this_col = side.this_column;
            let other_col = side.other_column;
            let n = params.len() + 1;
            params.push(related.id.to_string());
            conds.push(format!(
                "t.id IN (SELECT {this_col} FROM {join_table} \
                          WHERE {other_col} = ${n}::uuid AND is_active = true)"
            ));
        }
    } else if body.related_to.is_some() {
        return Err(AppError::Validation(
            "related_to is only supported for single-entity queries".into(),
        ));
    } else {
        apply_multi_entity_record_scope(
            state,
            ctx,
            qrow.id,
            pinned.as_ref().map(|p| (p.id, p.relations.as_slice())),
            &mut conds,
            &mut params,
        )
        .await?;
    }

    let base_sql: &str = pinned
        .as_ref()
        .map(|p| p.sql_query.as_str())
        .unwrap_or(qrow.sql_query.as_str());
    if body.page < 1 {
        return Err(AppError::Validation("page must be at least 1".into()));
    }
    if !(1..=attome_types::MAX_PAGE_SIZE).contains(&body.page_size) {
        return Err(AppError::Validation(format!(
            "page_size must be between 1 and {}",
            attome_types::MAX_PAGE_SIZE
        )));
    }
    if body.page > 10_000 {
        return Err(AppError::Validation(
            "page exceeds the offset-pagination limit; use after_id".into(),
        ));
    }
    if !matches!(body.order_dir.to_ascii_lowercase().as_str(), "asc" | "desc") {
        return Err(AppError::Validation("order_dir must be asc or desc".into()));
    }
    let page = body.page;
    // Guidelines §12: max page size is the platform-wide constant (was a
    // hardcoded 1000, ex-audit-finding #44).
    let page_size = body.page_size;
    let offset = (page - 1)
        .checked_mul(page_size)
        .ok_or_else(|| AppError::Validation("pagination offset is too large".into()))?;

    // The stored SQL actually runs inside a transaction on the same
    // pinned-aware pool `db` resolved to above, so we can bound it with SET
    // LOCAL statement_timeout — a fast-read 500ms default, 5s for queries
    // flagged is_report (guidelines §14.1).
    let mut tx = attome_db::tx::begin(db).await?;
    // AA4-T7: the deployment's limits, by kind of request.
    let limits = state.base.config.query.timeouts_ms;
    let timeout_ms = if qrow.is_report {
        limits.report
    } else {
        limits.interactive
    }
    .max(1);
    sqlx::query(&format!("SET LOCAL statement_timeout = {timeout_ms}"))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // Parse table_definition varchar → JSON up front — it's the preferred
    // (trusted, pre-query) source for the column whitelist below. D-543: a
    // published widget uses the metadata captured at publish instead, so an
    // edit to the view or query after publication cannot change the columns
    // or the whitelist a viewer sees.
    let td_json: Option<Value> = match definition
        .as_ref()
        .and_then(|d| d.column_definition.clone())
    {
        Some(captured) => Some(captured),
        None => qrow
            .table_definition
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok()),
    };
    let td_names: Option<Vec<String>> = td_json.as_ref().and_then(table_definition_names);

    let needs_validation =
        !body.search.is_empty() || !body.filters.is_empty() || !body.order_by.is_empty();

    // Identifier whitelist for anything interpolated into SQL below. Prefer
    // table_definition (validated metadata, no query needed). Default entity
    // queries have no table_definition, so ask PostgreSQL to describe a
    // zero-row wrapper. This works even when the entity has no records.
    let mut whitelist: Vec<String> = match &td_names {
        Some(names) => names.clone(),
        None => {
            let discovery_sql = format!("SELECT * FROM ({base_sql}) AS t LIMIT 0");
            (&mut *tx)
                .describe(&discovery_sql)
                .await
                .map_err(AppError::internal)?
                .columns()
                .iter()
                .map(|column| column.name().to_owned())
                .collect()
        }
    };

    // Columns as known from the whitelist — used only to check is_searchable
    // for the search condition below, not returned to the caller.
    let mut validation_columns = build_columns(td_json.as_ref(), &whitelist);
    // The database storage kind is metadata-owned: never trust a request
    // field to claim that an arbitrary output column is a `TEXT[]` Choice.
    let mut multi_choice_fields = std::collections::HashSet::new();
    if let Some(entity_id) = qrow.entity_logical_name {
        let registry = state.entities.load();
        if let Some(entity) = registry.get_by_id(entity_id) {
            multi_choice_fields =
                enrich_columns_from_entity(&mut validation_columns, entity, |target_id| {
                    registry.get_by_id(target_id).map(|m| m.logicalname.clone())
                });
        }
    }
    // Prefer per-entity, per-caller masking (matches entity_crud.rs's
    // `is_sensitive && !has_field_read_grant` gate) when this query has a
    // single known entity scope — the registry-wide `sensitive_field_names`
    // union over-masks every other entity's unrelated same-named columns,
    // including for a caller who does hold the grant. Fall back to the
    // conservative registry-wide set only for a custom stored query with no
    // single entity scope to derive per-field grants from.
    let sensitive: std::collections::HashSet<String> = {
        let registry = state.entities.load();
        match qrow
            .entity_logical_name
            .and_then(|id| registry.get_by_id(id))
        {
            // D-589: query/execute is a bulk surface. Hidden = every attribute
            // the gate refuses, not only the sensitive ones.
            Some(entity) => entity
                .attrs
                .iter()
                .filter(|attr| {
                    !attome_security::field_gate::readable(
                        ctx,
                        &entity.logicalname,
                        attr,
                        entity.primary_name_attribute.as_deref(),
                        attome_security::field_gate::Surface::Bulk,
                    )
                })
                .map(|attr| attr.logicalname.clone())
                .collect(),
            // A custom stored query with no single entity scope: the
            // conservative registry-wide set, and for a D-589 `listed` caller
            // also every attribute name that none of the caller's roles lists
            // on any entity. A column the query's author renamed with an alias
            // isn't an attribute name and so isn't caught here: publishing an
            // unscoped query is an admin act (`required_privilege`), and the
            // author owns what its aliases expose.
            None => {
                let mut hidden: std::collections::HashSet<String> = registry
                    .sensitive_field_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                if let attome_server::security::BulkFields::Listed(listed) = &ctx.bulk_fields
                    && !ctx.is_admin
                {
                    let listed_names: std::collections::HashSet<&str> = listed
                        .iter()
                        .filter_map(|pair| pair.split_once('.').map(|(_, f)| f))
                        .collect();
                    for meta in registry.iter() {
                        for attr in &meta.attrs {
                            let primary =
                                meta.primary_name_attribute.as_deref() == Some(&attr.logicalname);
                            if !primary && !listed_names.contains(attr.logicalname.as_str()) {
                                hidden.insert(attr.logicalname.clone());
                            }
                        }
                    }
                }
                hidden
            }
        }
    };
    whitelist.retain(|field| !sensitive.contains(field));
    validation_columns.retain(|column| !sensitive.contains(&column.name));
    if needs_validation && whitelist.is_empty() {
        return Err(AppError::Validation(
            "filters, search, and ordering require declared query columns".into(),
        ));
    }

    // ── WHERE conditions ──────────────────────────────────────────────────────

    // Global search across isSearchable columns
    if !body.search.is_empty() {
        let searchable: Vec<String> = validation_columns
            .iter()
            .filter(|c| c.is_searchable && parameter_cast(&c.data_type) == Some("text"))
            .map(|c| format!("{} ILIKE ${}", quote_ident(&c.name), params.len() + 1))
            .collect();
        if searchable.is_empty() {
            return Err(AppError::Validation(
                "search requested but the query has no searchable text columns".into(),
            ));
        }
        params.push(format!("%{}%", body.search));
        conds.push(format!("({})", searchable.join(" OR ")));
    }

    // Column-level filters (field must be in the whitelist) — C-15 (M01 §7):
    // the actual WHERE-fragment rendering is `attome_core::filter::compile`
    // now, shared with `attome-search::aggregate`, `data_export.rs`, and
    // `legal_matter_admin.rs`; this loop keeps only the whitelist membership
    // check and this endpoint's own `ColumnDef` adapter.
    let filter_schema = QueryExecFilterSchema {
        columns: &validation_columns,
        multi_choice: &multi_choice_fields,
        hierarchies: lookup_hierarchies(&validation_columns, &state.entities.load()),
        tag_scope: qrow.entity_logical_name.and_then(|id| {
            state
                .entities
                .load()
                .get_by_id(id)
                .map(|e| attome_core::filter::TagScope {
                    entity: e.logicalname.clone(),
                    user_id: ctx.user_id,
                })
        }),
    };
    // A13-T1: `@me`, `@my_team`, `@this_month` and the like, for this caller
    // today.
    let dynamic = attome_core::filter::DynamicValues {
        user_id: ctx.user_id,
        team_ids: ctx.team_ids.clone(),
        unit_ids: ctx.accessible_org_ids.clone(),
        today: chrono::Utc::now().date_naive(),
    };
    for f in &body.filters {
        if !whitelist.contains(&f.field) {
            return Err(AppError::Validation(format!(
                "unknown filter field: {}",
                f.field
            )));
        }
        for f in attome_core::filter::expand_dynamic(f, &dynamic)? {
            let (cond, binds) = attome_core::filter::compile(&f, &filter_schema, params.len() + 1)?;
            conds.push(cond);
            params.extend(binds);
        }
    }
    // AA4-T4: a seek is a bound comparison on the sort column, compiled like
    // a filter so it is coerced and cast the same way.
    if let Some(seek) = &body.seek {
        if body.after_id.is_some() {
            return Err(AppError::Validation(
                "seek_and_after_id: give seek or after_id, not both".into(),
            ));
        }
        let sort_field = if body.order_by.is_empty() {
            "id"
        } else {
            body.order_by.as_str()
        };
        if !whitelist.iter().any(|w| w == sort_field) {
            return Err(AppError::Validation(format!(
                "unknown order_by field: {sort_field}"
            )));
        }
        let value = match seek {
            Value::String(_) => seek.clone(),
            Value::Number(_) | Value::Bool(_) => Value::String(seek.to_string()),
            _ => {
                return Err(AppError::Validation(
                    "seek: a string, number or boolean".into(),
                ));
            }
        };
        let descending = body.order_dir.eq_ignore_ascii_case("desc");
        let seek_filter = attome_core::filter::Filter {
            field: sort_field.to_owned(),
            op: if descending { "lte" } else { "gte" }.to_owned(),
            value: Some(value),
        };
        let (cond, binds) =
            attome_core::filter::compile(&seek_filter, &filter_schema, params.len() + 1)?;
        conds.push(cond);
        params.extend(binds);
    }

    let where_sql = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };

    // ── ORDER BY (validated against the whitelist) ────────────────────────────

    let dir = if body.order_dir.to_lowercase() == "desc" {
        "DESC"
    } else {
        "ASC"
    };
    // B21-T3: an Arabic reader's text column sorts by the ICU Arabic
    // collation. Not with a seek, whose bound compares in the column's own
    // collation and would then disagree with the order.
    let sorts_text = !body.order_by.is_empty()
        && FilterSchema::cast(&filter_schema, &body.order_by) == Ok("text")
        && !filter_schema.is_multi_choice(&body.order_by);
    let collate = if sorts_text
        && body.seek.is_none()
        && is_arabic_locale(&state.user_locale(ctx.user_id))
        && arabic_collation_available(&state.base.db).await
    {
        Some(ARABIC_COLLATION)
    } else {
        None
    };
    let order_sql = if body.order_by.is_empty() {
        String::new()
    } else if whitelist.contains(&body.order_by) {
        format!(
            "ORDER BY {} {}",
            sort_expr(&quote_ident(&body.order_by), collate),
            dir
        )
    } else {
        return Err(AppError::Validation(format!(
            "unknown order_by field: {}",
            body.order_by
        )));
    };

    // Reject plans that are predictably too expensive before they consume
    // the execution-time budget. Reports get a larger, still finite ceiling.
    //
    // P-stored-query-containment phase 2 / D-126 (audit finding #25): by
    // default, skip re-planning on every request and trust the cost captured
    // once in sql_query_version when this query was published
    // (query_admin.rs's publish-time lint). `query.validate_on_execute`
    // (default false) is the rollback switch back to a live EXPLAIN on every
    // call. A query with no version row — the seeded per-entity default view
    // (`attome_metadata::provision::ensure_default_query`) writes `sql_query`
    // directly and never goes through query_admin.rs's publish path — always
    // falls back to a live EXPLAIN rather than skipping the cost ceiling.
    let total_cost = if state.base.config.query.validate_on_execute {
        run_live_explain(&mut *tx, base_sql, &where_sql, &order_sql, &params).await?
    } else {
        let cached: Option<f64> = match &pinned {
            Some(p) => Some(p.cost_estimate),
            None => sqlx::query_scalar(
                "SELECT cost_estimate FROM sql_query_version \
                 WHERE query_id = $1 ORDER BY id DESC LIMIT 1",
            )
            .bind(qrow.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?,
        };

        match cached {
            Some(cost) => cost,
            None => run_live_explain(&mut *tx, base_sql, &where_sql, &order_sql, &params).await?,
        }
    };
    let max_cost = if qrow.is_report {
        1_000_000.0
    } else {
        100_000.0
    };
    if total_cost > max_cost {
        return Err(AppError::Validation(format!(
            "query plan cost {total_cost:.2} exceeds the allowed limit {max_cost:.0}"
        )));
    }

    // P1.11(h): debug-visibility only, never blocks the request — warns when
    // a sort/filter targets an attribute that exists on this query's entity
    // but isn't flagged sortable/filterable (so no provision-time index is
    // expected for it). Only checkable when the stored query is scoped to a
    // single known entity; a custom multi-entity/join query has no single
    // attribute set to check against, so it's skipped rather than guessed at.
    if let Some(entity_id) = qrow.entity_logical_name {
        let registry = state.entities.load();
        if let Some(meta) = registry.get_by_id(entity_id) {
            let find = |name: &str| meta.attrs.iter().find(|a| a.logicalname == name);
            if !body.order_by.is_empty()
                && let Some(a) = find(&body.order_by).filter(|a| !a.is_sortable)
            {
                tracing::warn!(
                    entity = %meta.logicalname, field = %a.logicalname,
                    "query/execute sorts on an attribute not flagged is_sortable — no provision-time index expected"
                );
            }
            for f in &body.filters {
                if let Some(a) = find(&f.field).filter(|a| !a.is_filterable) {
                    tracing::warn!(
                        entity = %meta.logicalname, field = %a.logicalname,
                        "query/execute filters on an attribute not flagged is_filterable — no provision-time index expected"
                    );
                }
            }
        }
    }

    // ── DATA, one query per mode ───────────────────────────────────────────────
    // P1.11(g) / P-stored-query-containment phase 2 (D-126): `after_id`
    // continues an existing keyset/cursor page — O(page_size) regardless of
    // depth instead of OFFSET's scan-and-discard. `config.query.cursor_default`
    // (default true) additionally makes a request with NO `after_id` and
    // `include_total: false` (now also the default, see `ExecuteQueryRequest::include_total`)
    // start a *fresh* cursor page from the beginning of the set instead of
    // falling back to plain OFFSET — cursor mode is the default execution mode
    // now, not an opt-in one. `include_total: true` always forces the OFFSET +
    // `COUNT(*) OVER()` branch regardless of this flag, since that's the only
    // way to get an exact total. Setting `cursor_default: false` restores the
    // pre-phase-2 default (plain OFFSET, no total, no cursor) for one release
    // as a rollback switch.
    let cursor_default = state.base.config.query.cursor_default;
    // A report may be an aggregate with no `id` column to page by, so it never
    // starts a fresh cursor page; it runs in offset mode unless the caller
    // continues a cursor.
    let use_cursor = body.after_id.is_some()
        || body.seek.is_some()
        || (!body.include_total && cursor_default && !qrow.is_report);
    // AA4-T3: an offset page reads and discards every row before it; past the
    // configured depth, keyset paging is the only answer.
    let max_offset = state.base.config.query.max_offset_rows.max(0);
    if !use_cursor && offset > max_offset {
        return Err(AppError::Validation(format!(
            "offset paging stops at row {max_offset}; page with after_id (the last id you have) instead"
        )));
    }

    // A13-T2: a large matching set gets the planner's estimate, not a count.
    let estimated_total = if body.include_total && !use_cursor {
        let estimate = estimate_rows(&mut *tx, base_sql, &where_sql, &params).await?;
        (estimate >= EXACT_TOTAL_LIMIT).then_some(estimate)
    } else {
        None
    };
    let total_estimated = estimated_total.is_some();
    let (mut records, total, total_pages, next_cursor): (
        Vec<Value>,
        Option<i64>,
        Option<i64>,
        Option<Uuid>,
    ) = if use_cursor {
        let sort_col = if !body.order_by.is_empty() && whitelist.contains(&body.order_by) {
            body.order_by.as_str()
        } else {
            "id"
        };
        let sort_col = quote_ident(sort_col);
        let cursor_op = if dir == "DESC" { "<" } else { ">" };
        // B21-T3: the keyset bound compares in the same collation it sorts by.
        let sort_by = sort_expr(&format!("t.{sort_col}"), collate);

        // `after_id` present: continue an existing page, anchored via a
        // subquery that looks the cursor's sort value up from the DB by id rather
        // than accepting it from the client — this predicate then compares
        // against `sort_col`'s own native type, the same basis `ORDER BY`
        // itself uses, without this endpoint needing to know base_sql's
        // arbitrary output types up front. A stale/deleted after_id (the
        // referenced row no longer matches base_sql) makes that value NULL,
        // which makes the whole page empty too, rather than an explicit
        // error — acceptable for this mode's scope.
        //
        // `after_id` absent (cursor_default's fresh-start case): the same
        // shape with no anchor predicate at all — just the first
        // page in sort order.
        let main_sql = if let Some(cursor_param) = body.after_id.is_some().then(|| params.len() + 1)
        {
            // AA4-T1: the cursor's sort value is one scalar subquery, not a
            // CTE cross-joined to every candidate row, so the planner can
            // walk the sort index from the cursor and stop after the page. A
            // cursor row that no longer matches makes the bound NULL and the
            // page empty, as before.
            let mut cursor_conds = conds.clone();
            cursor_conds.push(format!(
                "({sort_by}, t.id) {cursor_op} (                    (SELECT c.{sort_col} FROM ({base_sql}) AS c WHERE c.id = ${cursor_param}),                    ${cursor_param}::uuid)"
            ));
            let cursor_where = format!("WHERE {}", cursor_conds.join(" AND "));
            let limit_param = cursor_param + 1;
            format!(
                "SELECT row_to_json(t.*) AS __row
                     FROM ({base_sql}) AS t
                     {cursor_where}
                     ORDER BY {sort_by} {dir}, t.id {dir}
                     LIMIT ${limit_param}"
            )
        } else {
            let limit_param = params.len() + 1;
            format!(
                "SELECT row_to_json(t.*) AS __row
                 FROM ({base_sql}) AS t
                 {where_sql}
                 ORDER BY {sort_by} {dir}, t.id {dir}
                 LIMIT ${limit_param}"
            )
        };
        let mut main_q = sqlx::query_as::<_, (Value,)>(&main_sql);
        for p in &params {
            main_q = main_q.bind(p.clone());
        }
        if let Some(after_id) = body.after_id {
            main_q = main_q.bind(after_id);
        }
        main_q = main_q.bind(page_size);
        let rows: Vec<(Value,)> = main_q.fetch_all(&mut *tx).await.map_err(|e| {
            query_exec_error(
                e,
                qrow.id,
                linked_entity_logical_name.as_deref(),
                &body.filters,
            )
        })?;

        tx.commit().await.map_err(AppError::internal)?;

        let records: Vec<Value> = rows.into_iter().map(|(row,)| row).collect();
        // A short page (fewer rows than requested) means there is
        // nothing further — only offer a cursor when the page is full,
        // matching the usual "keep paging until short" client contract.
        let next_cursor = (records.len() as i64 == page_size)
            .then(|| records.last())
            .flatten()
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());

        (records, None, None, next_cursor)
    } else if body.include_total && estimated_total.is_none() {
        // ── DATA + COUNT, one query (P1.11b) ──────────────────────────────
        // COUNT(*) OVER() is a window aggregate computed over the whole
        // matching set before LIMIT/OFFSET apply, so every returned row
        // carries the same total — read it off the first row instead of a
        // separate COUNT query.
        let lp = params.len() + 1;
        let op = params.len() + 2;
        let main_sql = format!(
            "SELECT row_to_json(t.*) AS __row, COUNT(*) OVER() AS __total_count
                 FROM ({base_sql}) AS t {where_sql} {order_sql} LIMIT ${lp} OFFSET ${op}"
        );
        let mut main_q = sqlx::query_as::<_, (Value, i64)>(&main_sql);
        for p in &params {
            main_q = main_q.bind(p.clone());
        }
        main_q = main_q.bind(page_size).bind(offset);
        let rows: Vec<(Value, i64)> = main_q.fetch_all(&mut *tx).await.map_err(|e| {
            query_exec_error(
                e,
                qrow.id,
                linked_entity_logical_name.as_deref(),
                &body.filters,
            )
        })?;

        tx.commit().await.map_err(AppError::internal)?;

        // Zero rows means zero total too (COUNT(*) OVER() would've been on
        // the same row set) — handled explicitly rather than assuming row
        // 0 exists.
        let total: i64 = rows.first().map(|(_, c)| *c).unwrap_or(0);
        let records: Vec<Value> = rows.into_iter().map(|(row, _)| row).collect();
        let total_pages = (total + page_size - 1).max(0) / page_size.max(1);

        (records, Some(total), Some(total_pages), None)
    } else {
        // Only reachable when `cursor_default` is false (the rollback
        // switch) — the pre-phase-2 plain-OFFSET-no-total default.
        let lp = params.len() + 1;
        let op = params.len() + 2;
        let main_sql = format!(
            "SELECT row_to_json(t.*) AS __row
             FROM ({base_sql}) AS t {where_sql} {order_sql} LIMIT ${lp} OFFSET ${op}"
        );
        let mut main_q = sqlx::query_as::<_, (Value,)>(&main_sql);
        for p in &params {
            main_q = main_q.bind(p.clone());
        }
        main_q = main_q.bind(page_size).bind(offset);
        let records = main_q
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                query_exec_error(
                    e,
                    qrow.id,
                    linked_entity_logical_name.as_deref(),
                    &body.filters,
                )
            })?
            .into_iter()
            .map(|(row,)| row)
            .collect();
        tx.commit().await.map_err(AppError::internal)?;
        // A13-T2: the estimate stands in for the count it would cost.
        let total_pages =
            estimated_total.map(|total| (total + page_size - 1).max(0) / page_size.max(1));
        (records, estimated_total, total_pages, None)
    };

    // P-entity-contract-hardening item (a): list responses return the raw
    // stored UUID for every lookup field, same as `entity_crud.rs`'s
    // single-record paths now do — the D-057 orphan-nulling block that used
    // to live here is gone (superseded; see DECISIONS.md). This removes the
    // asymmetry the plan documented rather than adding one: custom/
    // multi-entity queries always returned the raw UUID, and now every path
    // agrees.

    // Final column list for the response: prefer actual output columns (to
    // catch any SQL column not declared in table_definition, same as the old
    // live-sample behavior) — read off the first returned row instead of a
    // separate discovery query. Falls back to the whitelist when there are
    // no rows to read columns from.
    for record in &mut records {
        if let Some(object) = record.as_object_mut() {
            object.retain(|name, _| !sensitive.contains(name.as_str()));
        }
    }

    // Order from `whitelist` (read straight off the driver's column-position
    // metadata via `describe()`, or off `table_definition`'s own order — both
    // genuine SELECT-list order), not from the row object's own key order:
    // `serde_json::Map` is BTreeMap-backed in this workspace (no
    // `preserve_order` feature), so iterating a row's keys silently
    // alphabetizes every column — which is what made the first visible
    // column, and therefore `EntityListComponent`'s record-link column,
    // effectively random with respect to the SQL that produced it. Any
    // output column absent from `whitelist` (a custom query's column
    // `table_definition` never learned about) is still appended, preserving
    // the "catch any undeclared column" behavior above.
    let sql_cols: Vec<String> = records
        .first()
        .and_then(|r| r.as_object())
        .map(|o| {
            let mut ordered: Vec<String> = whitelist
                .iter()
                .filter(|name| o.contains_key(name.as_str()))
                .cloned()
                .collect();
            ordered.extend(o.keys().filter(|name| !whitelist.contains(name)).cloned());
            ordered
        })
        .unwrap_or_else(|| whitelist.clone());
    let mut columns = build_columns(td_json.as_ref(), &sql_cols);
    // Same enrichment as `validation_columns` above, applied here too: a
    // default seeded query has no `table_definition`, so without this every
    // column — lookups included — would reach the client as plain
    // `data_type: "text"` regardless of what the entity's metadata says.
    if let Some(entity_id) = qrow.entity_logical_name {
        let registry = state.entities.load();
        if let Some(entity) = registry.get_by_id(entity_id) {
            enrich_columns_from_entity(&mut columns, entity, |target_id| {
                registry.get_by_id(target_id).map(|m| m.logicalname.clone())
            });
        }
    }
    let columns: Vec<ColumnDef> = columns
        .into_iter()
        .filter(|column| !sensitive.contains(column.name.as_str()))
        .collect();

    // Grid/list name resolution: additive `__lookups` sidecar per row, same
    // wire pattern D-077 gave single-record reads — computed after `columns`
    // so the synthetic key never leaks into the column list. Single-entity
    // queries only (see `attach_lookup_display_names`'s doc comment).
    if let Some(entity_id) = qrow.entity_logical_name {
        attach_lookup_display_names(state, ctx, entity_id, &mut records).await;
    }

    // P-stored-query-containment addendum §11(d): a lightweight execution
    // record, not a durable AuditService event — this is the platform's
    // designated hot list-serving path (D-036), and a per-request audit
    // write would undo Phase 2's whole point of removing per-execute
    // overhead. Durable audit coverage lives on the publish/update/delete
    // side (query_admin.rs); this is the execute-side complement so an
    // operator can still correlate "who ran query X, how many rows, which
    // pagination mode" from the trace log.
    tracing::info!(
        query_id = %qrow.id,
        caller_id = %ctx.user_id,
        row_count = records.len(),
        cursor_mode = use_cursor,
        "query/execute served"
    );

    Ok(ExecResponse {
        metadata: ExecMeta {
            query_id: qrow.id,
            view_id: qrow.view_id,
            record_no: qrow.record_no,
            entity_logical_name: linked_entity_logical_name,
            can_edit_query: ctx.is_admin,
            // D-543: the published view semantics, when this ran from a
            // snapshot.
            view_kind: definition
                .as_ref()
                .and_then(|d| d.view_kind.clone())
                .or(qrow.view_kind),
            view_metadata: definition
                .as_ref()
                .and_then(|d| d.view_metadata.clone())
                .or(qrow.view_metadata),
        },
        data: ExecData {
            columns,
            records,
            total,
            total_estimated,
            page,
            page_size,
            total_pages,
            next_cursor,
        },
    })
}

// ── Router ────────────────────────────────────────────────────────────────────

/// P-api-contract Phase 0 — retired `openapi/query-v1.json` (was
/// hand-maintained, served via `include_str!`): `execute`'s `#[utoipa::path]`
/// plus the `ToSchema` derives on `ExecuteQueryRequest`/`Filter`/`ExecResponse`/
/// `ExecMeta`/`ExecData`/`ColumnDef` are the source of truth for this
/// endpoint's contract.
///
/// Phase 1 turned this from "the whole document" into one fragment among ~56:
/// every handler-owning file now carries its own `ApiDocFragment`, and
/// `crate::openapi::openapi_document()` merges them. The explicit
/// `components(schemas(...))` list stays because these six types are the ones
/// the retired hand file named — keeping them listed pins them into the
/// document even if a future refactor stops referencing one from a response.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(execute),
    components(schemas(
        ExecuteQueryRequest,
        Filter,
        ExecResponse,
        ExecMeta,
        ExecData,
        ColumnDef
    ))
)]
pub(crate) struct QueryApiDoc;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <QueryApiDoc as utoipa::OpenApi>::openapi()
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/query/execute", post(execute))
}

#[cfg(test)]
mod contract_tests {

    #[test]
    fn a_plan_s_row_estimate_is_read_from_its_top_node() {
        let plan =
            serde_json::json!([{ "Plan": { "Node Type": "Seq Scan", "Plan Rows": 250000.0 } }]);
        assert_eq!(super::plan_rows(&plan), 250_000);
        assert_eq!(super::plan_rows(&serde_json::json!([])), 0);
        assert!(super::plan_rows(&plan) >= super::EXACT_TOTAL_LIMIT);
    }

    use super::*;

    #[test]
    fn openapi_contract_keeps_query_v1_compatibility_points() {
        // P-api-contract Phase 0: re-expressed against the utoipa-generated
        // document instead of the retired hand-written `openapi/query-v1.json`
        // — same compatibility points the old golden test asserted, with one
        // disclosed, deliberate fidelity gap (see below) rather than a silent
        // drop.
        //
        // Phase 1 pointed this at this file's own fragment rather than the
        // whole-workspace document: these assertions are about the
        // `query/execute` contract specifically, and running them against the
        // merged document would make an unrelated crate's annotation able to
        // fail this test.
        let document: Value = serde_json::to_value(openapi_fragment())
            .expect("utoipa::openapi::OpenApi must serialize to JSON");
        assert_eq!(document["openapi"], "3.1.0");
        let request = &document["components"]["schemas"]["ExecuteQueryRequest"];
        assert_eq!(request["properties"]["page_size"]["maximum"], 200);
        // P-stored-query-containment phase 2 (D-126): flipped false -> cursor
        // mode is the default execution mode now; include_total: true is the
        // only way to get an exact COUNT(*) OVER() total.
        assert_eq!(request["properties"]["include_total"]["default"], false);
        assert!(document["paths"]["/api/v1/query/execute"]["post"]["responses"]["422"].is_object());
        // Disclosed Phase 0 gap (see `Filter`'s doc comment): the retired
        // hand file declared `op` as a JSON-schema `enum` of these 8
        // operators; this session did not reproduce that constraint via
        // utoipa's `schema_with` escape hatch (unverifiable builder-API call
        // without a compiler). Asserting the field exists and is a string
        // schema instead of asserting an `enum` array that isn't there yet —
        // tighten this back up once `schema_with` is added and compile-checked.
        let op_schema = &document["components"]["schemas"]["Filter"]["properties"]["op"];
        assert_eq!(op_schema["type"], "string");
        assert!(
            op_schema.get("enum").is_none(),
            "op enum constraint not yet reproduced (Phase 0 disclosed gap) — \
             update this assertion (and add schema_with) once it is, rather \
             than leaving a stale comment"
        );
    }

    // `parameter_cast`'s own coverage moved to `attome_core::filter`
    // (C-15, M01 §7) — it's tested there now, next to the function itself.

    /// Every physical system column must have a `data_type`, or the
    /// enrichment loop leaves it at `build_columns`' `"text"` default and a
    /// filter on it emits e.g. `"owner_ref" = $1::text` against a `UUID`
    /// column — `operator does not exist: uuid = text`, a 500 on the grid.
    /// Keyed off `ALL_SYSTEM_COLS` rather than a copy of the list so a
    /// column added to `provision::table`'s `CREATE TABLE` fails here instead
    /// of silently reintroducing the bug.
    #[test]
    fn every_system_column_has_a_filterable_data_type() {
        for name in attome_core::ALL_SYSTEM_COLS {
            let data_type = system_column_data_type(name)
                .unwrap_or_else(|| panic!("system column {name} has no data_type mapping"));
            assert!(
                parameter_cast(data_type).is_some(),
                "system column {name} maps to {data_type}, which parameter_cast rejects"
            );
        }
    }

    /// The UUID system columns must not claim to be `lookup`s: both cast to
    /// `::uuid`, but `lookup` additionally promises the client a resolvable
    /// `lookup_target_entity` and a display-name join these denormalized
    /// pointers have no target for.
    #[test]
    fn uuid_system_columns_cast_to_uuid_without_claiming_to_be_lookups() {
        for name in [
            "id",
            "created_by",
            "modified_by",
            "organization_ref",
            "owner_ref",
        ] {
            assert_eq!(system_column_data_type(name), Some("uuid"), "{name}");
            assert_eq!(parameter_cast("uuid"), Some("uuid"));
        }
    }

    fn attr(logicalname: &str, field_type_int: i32) -> attome_core::AttrInfo {
        attome_core::AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            options: None,
        }
    }

    fn entity_meta(
        logicalname: &str,
        attrs: Vec<attome_core::AttrInfo>,
    ) -> attome_core::EntityMeta {
        attome_core::EntityMeta {
            entity_id: Uuid::nil(),
            logicalname: logicalname.to_owned(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    /// The regression: a seeded query has no `table_definition`, so every
    /// output column arrives as `"text"` and only the ones backed by an
    /// `attribute_info` row get corrected. The system columns have
    /// no such row by design, and used to stay `"text"` — this asserts the
    /// enrichment pass now types them from their physical shape.
    #[test]
    fn enrichment_types_system_columns_that_have_no_attribute_row() {
        let entity = entity_meta("note", vec![attr("title", 3)]);
        let mut columns = infer_columns(&[
            "title".to_owned(),
            "owner_ref".to_owned(),
            "organization_ref".to_owned(),
            "created_at".to_owned(),
            "is_active".to_owned(),
            "row_version".to_owned(),
        ]);

        enrich_columns_from_entity(&mut columns, &entity, |_| None);

        let of = |name: &str| {
            columns
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("{name} missing"))
                .data_type
                .clone()
        };
        assert_eq!(of("title"), "text");
        assert_eq!(of("owner_ref"), "uuid");
        assert_eq!(of("organization_ref"), "uuid");
        assert_eq!(of("created_at"), "date");
        assert_eq!(of("is_active"), "bool");
        assert_eq!(of("row_version"), "number");
    }

    /// An entity that declares its own attribute named like a system column
    /// keeps the metadata-derived type — the fallback only fills a gap, it
    /// never overrides metadata.
    #[test]
    fn an_entity_attribute_still_wins_over_the_system_column_fallback() {
        let entity = entity_meta("custom", vec![attr("is_active", 3)]);
        let mut columns = infer_columns(&["is_active".to_owned()]);

        enrich_columns_from_entity(&mut columns, &entity, |_| None);

        assert_eq!(columns[0].data_type, "text");
    }

    #[test]
    fn build_columns_reads_editor_snake_case_routing_definition() {
        let definition = serde_json::json!([{
            "name": "customer_name",
            "display_name": "Customer",
            "data_type": "string",
            "is_visible": true,
            "is_sortable": false,
            "is_searchable": true,
            "is_clickable": true,
            "route_template": "/customers/{{customer_id}}"
        }]);

        let columns = build_columns(Some(&definition), &["customer_name".to_owned()]);
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].name, "customer_name");
        assert_eq!(columns[0].display_name, "Customer");
        assert!(columns[0].is_clickable);
        assert_eq!(columns[0].route_template, "/customers/{{customer_id}}");
        assert_eq!(
            table_definition_names(&definition),
            Some(vec!["customer_name".to_owned()])
        );
    }

    // `text_array_literal`'s own coverage moved to `attome_core::filter`
    // too, same reason.

    // ── QueryExecFilterSchema (C-15's per-caller adapter) ─────────────────

    fn column_def(name: &str, data_type: &str) -> ColumnDef {
        ColumnDef {
            name: name.to_owned(),
            display_name: name.to_owned(),
            data_type: data_type.to_owned(),
            is_visible: true,
            is_sortable: true,
            is_searchable: false,
            is_clickable: false,
            route_template: String::new(),
            lookup_target_entity: None,
            choice_styles: None,
        }
    }

    #[test]
    fn query_exec_filter_schema_cast_agrees_with_parameter_cast() {
        let columns = vec![column_def("amount", "number"), column_def("name", "text")];
        let multi_choice = std::collections::HashSet::new();
        let schema = QueryExecFilterSchema {
            columns: &columns,
            multi_choice: &multi_choice,
            hierarchies: std::collections::HashMap::new(),
            tag_scope: None,
        };
        assert_eq!(FilterSchema::cast(&schema, "amount"), Ok("numeric"));
        assert_eq!(FilterSchema::cast(&schema, "name"), Ok("text"));
    }

    #[test]
    fn query_exec_filter_schema_rejects_a_field_not_in_the_column_list() {
        let columns = vec![column_def("amount", "number")];
        let multi_choice = std::collections::HashSet::new();
        let schema = QueryExecFilterSchema {
            columns: &columns,
            multi_choice: &multi_choice,
            hierarchies: std::collections::HashMap::new(),
            tag_scope: None,
        };
        assert_eq!(
            FilterSchema::cast(&schema, "ssn"),
            Err(FieldCastError::Unknown)
        );
    }

    #[test]
    fn query_exec_filter_schema_reports_multi_choice_from_its_own_set() {
        let columns = vec![column_def("tags", "choice")];
        let multi_choice = std::collections::HashSet::from(["tags".to_owned()]);
        let schema = QueryExecFilterSchema {
            columns: &columns,
            multi_choice: &multi_choice,
            hierarchies: std::collections::HashMap::new(),
            tag_scope: None,
        };
        assert!(FilterSchema::is_multi_choice(&schema, "tags"));
        assert!(!FilterSchema::is_multi_choice(&schema, "amount"));
    }
}

/// Property-based coverage for this file's pure filter/SQL-builder functions —
/// `P-verification-depth-hardening` (splits `P-enterprise-maturity-backlog`
/// item 1, triggered 2026-07-30), explicitly named by that item as one of the
/// two "query/policy compiler" surfaces to generalize (the other is
/// `attome-security`'s `rls_property.rs`, whose style this file follows). Kept
/// in-crate rather than an external `tests/*.rs` file because every function
/// under test here (`build_columns`, `table_definition_names`,
/// `QueryExecFilterSchema`) is module-private, per `testing`'s own
/// "pure logic → unit tests in-crate" rule.
///
/// C-15 (M01 §7) moved the proptests that were really about the *generic*
/// `Filter` grammar (`text_array_literal`'s round-trip, `filter_type`'s
/// cast-agreement/whitelist-rejection, `scalar_filter_value`/
/// `multi_choice_filter_values`) to `attome_core::filter::proptests`,
/// since the functions they exercise live there now — what's left here is
/// specific to this file's own `ColumnDef`/`table_definition` machinery.
///
/// Deliberately pure: zero I/O, no `DATABASE_URL`, no Redis, no running
/// server. **Verified 2026-08-24 (MAINT-10): 7 passed, 0 failed.** This
/// previously read "NOT verified against a real `cargo test` run in the
/// session that authored this file — no Rust toolchain available"
/// (`document/detailed-plans/P-verification-depth-hardening.md` §10 TODO 1);
/// the toolchain exists now and the proptests pass as written. Run with:
///
/// ```powershell
/// cargo test -p attome-records --lib query_exec::proptests
/// ```
/// B21-T3: the ICU collation Arabic text sorts by (alif before ba, hamza
/// forms and tatweel handled), present when PostgreSQL was built with ICU.
const ARABIC_COLLATION: &str = "ar-x-icu";

/// Whether this server's PostgreSQL has [`ARABIC_COLLATION`]; asked once and
/// kept for the process (a catalog fact that does not change while it runs).
/// A failed probe is not kept, so the next sort asks again; two first sorts
/// at once may both ask, which is harmless.
static ARABIC_COLLATION_AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

async fn arabic_collation_available(db: &DbPool) -> bool {
    if let Some(available) = ARABIC_COLLATION_AVAILABLE.get() {
        return *available;
    }
    let probe = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_collation WHERE collname = $1)",
    )
    .bind(ARABIC_COLLATION)
    .fetch_one(db)
    .await;
    match probe {
        Ok(available) => {
            if !available {
                tracing::debug!("no ICU Arabic collation; Arabic text sorts by the default one");
            }
            *ARABIC_COLLATION_AVAILABLE.get_or_init(|| available)
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not look up the ICU Arabic collation");
            false
        }
    }
}

/// B21-T3: whether a BCP-47 tag is Arabic (`ar`, `ar-SA`, `ar_EG`).
fn is_arabic_locale(tag: &str) -> bool {
    let tag = tag.trim().to_ascii_lowercase();
    tag == "ar" || tag.starts_with("ar-") || tag.starts_with("ar_")
}

/// B21-T3: a sort key, under `collation` when one is given.
fn sort_expr(column_sql: &str, collation: Option<&str>) -> String {
    match collation {
        Some(collation) => format!("{column_sql} COLLATE \"{collation}\""),
        None => column_sql.to_owned(),
    }
}

#[cfg(test)]
mod arabic_collation_tests {
    use super::*;

    #[test]
    fn arabic_collation_applies_to_arabic_locales_only() {
        for tag in ["ar", "ar-SA", "AR-eg", "ar_EG"] {
            assert!(is_arabic_locale(tag), "{tag}");
        }
        for tag in ["en-US", "fr", "arn", "", "a"] {
            assert!(!is_arabic_locale(tag), "{tag}");
        }
    }

    #[test]
    fn arabic_collation_sort_expression() {
        assert_eq!(
            sort_expr("\"name\"", Some(ARABIC_COLLATION)),
            "\"name\" COLLATE \"ar-x-icu\""
        );
        assert_eq!(sort_expr("t.\"name\"", None), "t.\"name\"");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// `QueryExecFilterSchema::cast` succeeds if and only if
        /// `parameter_cast` recognizes the column's `data_type` — for any
        /// data-type string (known or unknown) and any field name.
        /// Generalizes the hand-picked unit test's cases; the operator/
        /// multi-choice semantics downstream of a resolved cast are
        /// `attome_core::filter::compile`'s own property coverage now,
        /// not this file's.
        #[test]
        fn query_exec_filter_schema_cast_agrees_with_parameter_cast_for_any_data_type(
            data_type in prop_oneof![
                Just("number".to_owned()), Just("numeric".to_owned()), Just("decimal".to_owned()),
                Just("integer".to_owned()), Just("date".to_owned()), Just("datetime".to_owned()),
                Just("timestamp".to_owned()), Just("bool".to_owned()), Just("boolean".to_owned()),
                Just("choice".to_owned()), Just("lookup".to_owned()), Just("uuid".to_owned()),
                Just("text".to_owned()), Just("file".to_owned()), Just("string".to_owned()),
                "[a-z]{1,10}", // plausible-but-unrecognized data types too
            ],
            field in "[a-z_]{1,8}",
        ) {
            let columns = vec![ColumnDef {
                name: field.clone(),
                display_name: field.clone(),
                data_type: data_type.clone(),
                is_visible: true,
                is_sortable: true,
                is_searchable: false,
                is_clickable: false,
                route_template: String::new(),
                lookup_target_entity: None,
                choice_styles: None,
            }];
            let multi_choice = std::collections::HashSet::new();
            let schema = QueryExecFilterSchema { columns: &columns, multi_choice: &multi_choice, hierarchies: Default::default(), tag_scope: None };
            prop_assert_eq!(
                FilterSchema::cast(&schema, &field).is_ok(),
                parameter_cast(&data_type).is_some()
            );
        }

        /// A field name absent from the column list is always rejected,
        /// regardless of what other columns are declared — the whitelist
        /// half of this adapter's contract (guidelines §4: identifiers only
        /// from validated metadata).
        #[test]
        fn query_exec_filter_schema_rejects_any_field_not_in_the_column_list(
            known_fields in prop::collection::vec("[a-z_]{1,8}", 0..4),
            probe in "[a-z_]{1,8}",
        ) {
            prop_assume!(!known_fields.contains(&probe));
            let columns: Vec<ColumnDef> = known_fields
                .into_iter()
                .map(|name| ColumnDef {
                    name,
                    display_name: String::new(),
                    data_type: "text".to_owned(),
                    is_visible: true,
                    is_sortable: true,
                    is_searchable: false,
                    is_clickable: false,
                    route_template: String::new(),
                    lookup_target_entity: None,
                    choice_styles: None,
                })
                .collect();
            let multi_choice = std::collections::HashSet::new();
            let schema = QueryExecFilterSchema { columns: &columns, multi_choice: &multi_choice, hierarchies: Default::default(), tag_scope: None };
            prop_assert!(FilterSchema::cast(&schema, &probe).is_err());
        }

        /// `infer_columns` never surfaces the implicit `id` column and always
        /// surfaces every other distinct SQL output column, for any list of
        /// column names.
        #[test]
        fn infer_columns_excludes_id_and_includes_everything_else(
            cols in prop::collection::vec(prop_oneof![Just("id".to_owned()), "[a-z_]{1,8}"], 0..6),
        ) {
            let result = infer_columns(&cols);
            prop_assert!(result.iter().all(|c| c.name != "id"));
            for col in cols.iter().filter(|c| c.as_str() != "id") {
                prop_assert!(result.iter().any(|c| &c.name == col));
            }
        }

        /// `build_columns`/`table_definition_names` must never panic on an
        /// arbitrary JSON shape for `table_definition` — admin-authored
        /// metadata (guidelines §4) is validated before it reaches this path
        /// in production, but this function itself must degrade to its
        /// documented no-op/inferred-columns fallback rather than panic on a
        /// malformed or unexpected shape.
        #[test]
        fn build_columns_never_panics_on_arbitrary_table_definition_shape(
            td in prop_oneof![
                Just(serde_json::Value::Null),
                any::<bool>().prop_map(serde_json::Value::Bool),
                any::<i32>().prop_map(|n| serde_json::json!(n)),
                "[a-z]{0,8}".prop_map(serde_json::Value::String),
                Just(serde_json::json!([])),
                Just(serde_json::json!([{ "logicalName": "x" }])),
                Just(serde_json::json!({ "columns": [{ "logicalName": "y" }] })),
                Just(serde_json::json!({ "unrelated": true })),
            ],
            sql_cols in prop::collection::vec("[a-z_]{1,6}", 0..4),
        ) {
            let _ = table_definition_names(&td);
            let _ = build_columns(Some(&td), &sql_cols);
            let _ = build_columns(None, &sql_cols);
        }
    }
}
