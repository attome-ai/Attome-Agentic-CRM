use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::changeset::{Op, RecordedOp, Recording, RecordingCtx};
use attome_core::filter::{FieldCastError, FilterSchema};
use attome_core::{EngineState, Filter};
use attome_metadata::provision::{ReconcileOutcome, ReconcilePolicy};
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_server::security::SecurityContext;
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::admin_hooks as hooks;

use crate::bundle::model::ViewDef;
use attome_records::query_admin::{
    ReconcileStep, customized_marker, map_unique_violation, reconcile_step, resolve_live_entity_id,
};

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct ViewDetail {
    id: Uuid,
    name: String,
    icon: String,
    entity_logical_name: Uuid,
    entity_name: String,
    sql_query_ref: Uuid,
    query_name: String,
    table_definition: Value,
    is_default: bool,
    is_active: bool,
    /// D-429 (+ chart, migration 0447) — how this view renders: `list`
    /// (default), `kanban`, `calendar`, `timeline`, `chart`. Kind-specific
    /// settings live in `view_metadata`.
    kind: String,
    /// D-429 — kind-specific settings, advisory only. Never a source of
    /// server-side enforcement: a kanban `state_field`/`wip_limits` never
    /// substitutes for `attome-state`'s own transition checks, a
    /// calendar/timeline `start_field`/`end_field` never substitutes for the
    /// view's own privilege/record-security gate, and a chart's
    /// `x_field`/`y_fields`/aggregation never substitutes for `query/execute`
    /// actually returning that column (see `chart_view_metadata`'s doc
    /// comment).
    view_metadata: Value,
    /// D-429 — always `system` through this admin surface; `personal`/
    /// `shared` views are created and promoted only through the self-service
    /// `/api/v1/views` routes below.
    scope: String,
    owner_ref: Option<Uuid>,
    /// Solution 7 (D-785) — the layer that owns this view: `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer
    /// may update or retire a system view (409 `layer_mismatch` otherwise).
    /// Personal and shared views are user data and always `project`.
    owner_layer: String,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct ViewBody {
    name: String,
    #[serde(default = "default_view_icon")]
    icon: String,
    entity_logical_name: Uuid,
    sql_query_ref: Uuid,
    #[serde(default)]
    table_definition: Value,
    #[serde(default)]
    is_default: bool,
    #[serde(default = "default_view_kind")]
    kind: String,
    #[serde(default)]
    view_metadata: Value,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct AvailableViewsQuery {
    /// Only this entity (its logical name).
    entity: String,
}

#[derive(sqlx::FromRow)]
struct AvailableViewRow {
    id: Uuid,
    name: String,
    icon: String,
    is_default: bool,
    kind: String,
    view_metadata: Value,
    scope: String,
    owner_ref: Option<Uuid>,
    required_privilege: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct AvailableView {
    id: Uuid,
    name: String,
    icon: String,
    is_default: bool,
    /// D-429 — `list` | `kanban` | `calendar` | `timeline`.
    kind: String,
    view_metadata: Value,
    /// D-429 — `system` | `personal` | `shared`. Drives whether the Angular
    /// list toolbar offers "edit"/"delete"/"share" for this row (only ever
    /// the caller's own `personal` rows).
    scope: String,
    /// `true` for a `personal`/`shared` view the caller themselves owns —
    /// the client-side signal for showing owner-only actions. Never used for
    /// enforcement; the mutating routes re-check ownership server-side.
    is_mine: bool,
}

fn default_view_icon() -> String {
    "las la-table".into()
}

fn default_view_kind() -> String {
    "list".into()
}

/// D-429 — the one place `kind`/`view_metadata` combinations are validated,
/// shared by the admin CRUD below and the self-service personal-view CRUD.
/// Deliberately permissive about *unknown* extra keys in `view_metadata`
/// (forward compatible with a future kind-specific addition) and strict only
/// about the keys a kind actually declares it needs to render.
///
/// `chart` (migration 0447) delegates entirely to
/// `chart_view_metadata::validate`, which is stricter than the other three
/// kinds here (deny-unknown-fields, closed enums) — see that module's own
/// doc comment for why a chart's settings warrant it.
/// B17-T6: the swipe actions a phone list offers.
pub const MOBILE_ACTIONS: &[&str] = &["call", "complete", "assign", "open"];

/// B17-T6: `view_metadata.mobile`, a phone list's cards and swipes, when
/// present: `card_title` a field name, `card_lines` up to three, and
/// `swipe_start` / `swipe_end` one of [`MOBILE_ACTIONS`]. Pure.
pub fn validate_mobile_options(metadata: &Value) -> Result<(), AppError> {
    let Some(mobile) = metadata.get("mobile").filter(|m| !m.is_null()) else {
        return Ok(());
    };
    let mobile = mobile
        .as_object()
        .ok_or_else(|| AppError::Validation("view_metadata.mobile must be an object".into()))?;
    let field = |v: &Value| v.as_str().is_some_and(|s| !s.trim().is_empty());
    for (key, value) in mobile {
        match key.as_str() {
            "card_title" if value.is_null() || field(value) => {}
            "card_lines" => {
                let lines = value.as_array().ok_or_else(|| {
                    AppError::Validation("view_metadata.mobile.card_lines must be a list".into())
                })?;
                if lines.len() > 3 || !lines.iter().all(field) {
                    return Err(AppError::Validation(
                        "view_metadata.mobile.card_lines: up to three field names".into(),
                    ));
                }
            }
            "swipe_start" | "swipe_end"
                if value.is_null()
                    || value.as_str().is_some_and(|a| MOBILE_ACTIONS.contains(&a)) => {}
            "swipe_start" | "swipe_end" => {
                return Err(AppError::Validation(format!(
                    "view_metadata.mobile.{key} is one of {}",
                    MOBILE_ACTIONS.join(", ")
                )));
            }
            other => {
                return Err(AppError::Validation(format!(
                    "view_metadata.mobile.{other} is not a phone list setting"
                )));
            }
        }
    }
    Ok(())
}

fn validate_view_kind_metadata(kind: &str, metadata: &Value) -> Result<(), AppError> {
    if kind != "chart" {
        validate_mobile_options(metadata)?;
    }
    if kind == "chart" {
        return crate::chart_view_metadata::validate(metadata)
            .map(|_| ())
            .map_err(|errors| AppError::Validation(errors.join("; ")));
    }
    let obj = match kind {
        "list" => return Ok(()),
        "kanban" | "calendar" | "timeline" | "map" => metadata.as_object().ok_or_else(|| {
            AppError::Validation(format!("{kind} view_metadata must be a JSON object"))
        })?,
        other => {
            return Err(AppError::Validation(format!("unknown view kind '{other}'")));
        }
    };
    let non_empty_string = |key: &str| -> Result<(), AppError> {
        match obj.get(key).and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => Ok(()),
            _ => Err(AppError::Validation(format!(
                "{kind} view_metadata.{key} is required"
            ))),
        }
    };
    match kind {
        "kanban" => {
            non_empty_string("state_field")?;
            // `wip_limits` (advisory only, never enforced server-side — see
            // the M64 plan) is optional but must be an object of
            // state -> integer|null when present.
            if let Some(limits) = obj.get("wip_limits") {
                let limits_obj = limits.as_object().ok_or_else(|| {
                    AppError::Validation("kanban view_metadata.wip_limits must be an object".into())
                })?;
                for (state, limit) in limits_obj {
                    if !limit.is_null() && !limit.is_u64() {
                        return Err(AppError::Validation(format!(
                            "kanban view_metadata.wip_limits.{state} must be a non-negative integer or null"
                        )));
                    }
                }
            }
            // D5-T2: optional board totals, stalled markers and a flag; each
            // names a field (a string) or is null.
            for key in [
                "sum_field",
                "weighted_field",
                "state_entered_field",
                "flag_field",
            ] {
                if let Some(field) = obj.get(key)
                    && !field.is_null()
                    && !field.as_str().is_some_and(|s| !s.trim().is_empty())
                {
                    return Err(AppError::Validation(format!(
                        "kanban view_metadata.{key} must be a field name or null"
                    )));
                }
            }
            if let Some(days) = obj.get("stalled_after_days") {
                let days = days.as_object().ok_or_else(|| {
                    AppError::Validation(
                        "kanban view_metadata.stalled_after_days must be an object".into(),
                    )
                })?;
                for (state, limit) in days {
                    if !limit.is_null() && !limit.is_u64() {
                        return Err(AppError::Validation(format!(
                            "kanban view_metadata.stalled_after_days.{state} must be a non-negative integer or null"
                        )));
                    }
                }
            }
        }
        // B15-T2: a map places each record at its geolocation field.
        "map" => {
            non_empty_string("location_field")?;
            for key in ["label_field", "color_field"] {
                if let Some(field) = obj.get(key)
                    && !field.is_null()
                    && !field.as_str().is_some_and(|s| !s.trim().is_empty())
                {
                    return Err(AppError::Validation(format!(
                        "map view_metadata.{key} must be a field name or null"
                    )));
                }
            }
        }
        "calendar" | "timeline" => {
            non_empty_string("start_field")?;
            non_empty_string("end_field")?;
            if let Some(color) = obj.get("color_field")
                && !color.is_null()
                && !color.as_str().is_some_and(|s| !s.trim().is_empty())
            {
                return Err(AppError::Validation(format!(
                    "{kind} view_metadata.color_field must be a non-empty string when present"
                )));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// D-607 (B-R10 Phase A) — the most conditions `view_metadata.filters` may
/// carry. The same bound Phase B will put on nested groups (§5.4).
pub(crate) const MAX_VIEW_FILTERS: usize = 50;

/// `view_metadata.filters`'s whitelist: the view entity's own attributes,
/// cast exactly as [`attome_core::filter::cast_for_attr`] casts them for
/// every other `AttrInfo`-keyed caller. A field the saver cannot read is left
/// out of the whitelist, so it is refused as "unknown" — the same masked
/// answer `query/execute` gives, never a "forbidden" that would confirm it
/// exists.
struct ViewFilterSchema<'a> {
    attrs: Vec<&'a attome_core::AttrInfo>,
}

impl ViewFilterSchema<'_> {
    fn attr(&self, field: &str) -> Option<&attome_core::AttrInfo> {
        self.attrs
            .iter()
            .copied()
            .find(|attr| attr.logicalname == field)
    }
}

impl FilterSchema for ViewFilterSchema<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        self.attr(field)
            .ok_or(FieldCastError::Unknown)
            .and_then(attome_core::filter::cast_for_attr)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.attr(field)
            .is_some_and(attome_core::filter::is_multi_choice_attr)
    }

    fn is_geolocation(&self, field: &str) -> bool {
        self.attr(field)
            .is_some_and(attome_core::filter::is_geolocation_attr)
    }
}

/// D-607 (B-R10 Phase A) — validates `view_metadata.filters`, the advanced
/// find conditions a view saves: a JSON array of at most
/// [`MAX_VIEW_FILTERS`] `{field, op, value}` objects in the one flat AND
/// grammar (`attome_core::Filter`), each naming an attribute of the view's
/// own entity and using an operator valid for that attribute's type. The
/// operator/type/value check is `attome_core::filter::compile` itself
/// (its SQL is discarded), so a filter a view saves is exactly a filter
/// `query/execute` accepts. When `caller` is set (the admin and self-service
/// routes; bundle reconcile has no caller), an attribute the caller cannot
/// read on a bulk surface is refused as unknown.
///
/// Per D-429 this is metadata only: the list sends the saved filters to
/// `query/execute`, which re-checks every one against the caller who runs
/// the view and enforces row security as always. Absent or `null` `filters`
/// is valid for every kind; `chart` never reaches here with one because its
/// own validator denies unknown keys.
fn validate_view_filters(
    state: &EngineState,
    caller: Option<&SecurityContext>,
    entity_id: Uuid,
    metadata: &Value,
) -> Result<(), AppError> {
    let Some(raw) = metadata.get("filters").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let items = raw.as_array().ok_or_else(|| {
        AppError::Validation("view_metadata.filters must be an array of filters".into())
    })?;
    if items.len() > MAX_VIEW_FILTERS {
        return Err(AppError::Validation(format!(
            "view_metadata.filters may hold at most {MAX_VIEW_FILTERS} conditions, got {}",
            items.len()
        )));
    }
    if items.is_empty() {
        return Ok(());
    }
    let registry = state.entities.load();
    let entity = registry.get_by_id(entity_id).ok_or_else(|| {
        AppError::Validation("view_metadata.filters needs an entity with attribute metadata".into())
    })?;
    let schema = ViewFilterSchema {
        attrs: entity
            .attrs
            .iter()
            .filter(|attr| {
                caller.is_none_or(|ctx| {
                    attome_security::field_gate::readable(
                        ctx,
                        &entity.logicalname,
                        attr,
                        entity.primary_name_attribute.as_deref(),
                        attome_security::field_gate::Surface::Bulk,
                    )
                })
            })
            .collect(),
    };
    for (index, item) in items.iter().enumerate() {
        let filter: Filter = serde_json::from_value(item.clone()).map_err(|_| {
            AppError::Validation(format!(
                "view_metadata.filters[{index}] must be an object with field, op and value"
            ))
        })?;
        attome_core::filter::compile(&filter, &schema, 1).map_err(|err| match err {
            AppError::Validation(message) => {
                AppError::Validation(format!("view_metadata.filters[{index}]: {message}"))
            }
            other => other,
        })?;
    }
    Ok(())
}

const VIEW_SELECT: &str = "SELECT v.id, v.name, v.icon, v.entity_logical_name, e.logicalname AS entity_name, \
            v.sql_query_ref, COALESCE(NULLIF(q.record_no, ''), 'Unnamed Query') AS query_name, \
            v.table_definition, v.is_default, v.is_active, v.kind, v.view_metadata, v.scope, v.owner_ref, \
            v.owner_layer \
     FROM view v \
     JOIN entity_info e ON e.id = v.entity_logical_name \
     JOIN sql_query q ON q.id = v.sql_query_ref";

/// List views
///
/// List views. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/views",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ViewDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_views(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ViewDetail>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    // Admin studio manages system metadata only — personal/shared rows
    // belong to their owner and are never listed or editable here.
    let sql = format!(
        "{VIEW_SELECT} WHERE v.is_active = true AND v.scope = 'system' \
         ORDER BY e.logicalname, v.name LIMIT $1 OFFSET $2"
    );
    let rows = sqlx::query_as(&sql)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM view v WHERE v.is_active = true AND v.scope = 'system'",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

/// My views of an entity
///
/// Views the current caller can actually see for one entity list — system
/// views gated by the linked query's `required_privilege` (unchanged),
/// personal views the caller owns (bypasses that gate entirely, D-429), and
/// shared views (re-enters the same privilege gate a system view uses — see
/// `view.scope`'s migration comment for why "shared" is the inverse
/// of the personal bypass rather than a distinct grant mechanism).
///
/// Authenticated-only by design, like `sidebar::get_sidebar`: the route is not
/// gated, each row is filtered below against the caller's own privileges
/// (`required_privilege`) or ownership, so an unprivileged caller gets an
/// empty list rather than a 403. The sibling CRUD handlers on `view`
/// take `Authorized<Admin>` (system scope) or `Authorized<SelfService>`
/// (personal scope, below).
#[utoipa::path(
    get,
    path = "/api/v1/views",
    tag = "query",
    params(AvailableViewsQuery),
    responses(
        (status = 200, description = "Success", body = Vec<AvailableView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_available_views(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(params): Query<AvailableViewsQuery>,
) -> Result<Json<Vec<AvailableView>>, AppError> {
    let rows: Vec<AvailableViewRow> = sqlx::query_as(
        "SELECT v.id, v.name, v.icon, v.is_default, v.kind, v.view_metadata, v.scope, v.owner_ref, \
                q.required_privilege \
         FROM view v \
         JOIN entity_info e ON e.id = v.entity_logical_name \
         JOIN sql_query q ON q.id = v.sql_query_ref \
         WHERE e.logicalname = $1 AND v.is_active = true \
           AND (q.is_active IS NULL OR q.is_active = true) \
           AND (v.scope <> 'personal' OR v.owner_ref = $2) \
           AND (v.organization_ref IS NULL \
                OR v.organization_ref IN (SELECT organization_ref FROM user_account WHERE id = $2) \
                OR v.organization_ref IN (SELECT organization_ref FROM user_account_mm_organization \
                                          WHERE user_ref = $2 AND (is_deleted IS NULL OR is_deleted = false))) \
         ORDER BY v.is_default DESC, v.name ASC",
    )
    .bind(params.entity.trim())
    .bind(ctx.user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(
        rows.into_iter()
            .filter_map(|row| {
                let is_mine = row.owner_ref == Some(ctx.user_id);
                let allowed = match row.scope.as_str() {
                    // Owner-only, no privilege check at all (D-429).
                    "personal" => is_mine,
                    // Re-enters the same gate a system view uses.
                    "shared" | "system" => match row.required_privilege.as_deref() {
                        Some(key) => ctx.is_admin || ctx.privileges.contains(key),
                        None => ctx.is_admin,
                    },
                    _ => false,
                };
                allowed.then_some(AvailableView {
                    id: row.id,
                    name: row.name,
                    icon: row.icon,
                    is_default: row.is_default,
                    kind: row.kind,
                    view_metadata: row.view_metadata,
                    scope: row.scope,
                    is_mine,
                })
            })
            .collect(),
    ))
}

/// One view
///
/// One view. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/views/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The view")),
    responses(
        (status = 200, description = "Success", body = ViewDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_view(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ViewDetail>, AppError> {
    let sql =
        format!("{VIEW_SELECT} WHERE v.id = $1 AND v.is_active = true AND v.scope = 'system'");
    let row = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// Create a view
///
/// Create a view. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/views",
    tag = "admin",
    request_body = ViewBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ViewDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_view(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    recording: RecordingCtx,
    Json(body): Json<ViewBody>,
) -> Result<(StatusCode, Json<ViewDetail>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("view name is required".into()));
    }
    validate_view_kind_metadata(&body.kind, &body.view_metadata)?;
    validate_view_filters(
        &state,
        Some(&ctx),
        body.entity_logical_name,
        &body.view_metadata,
    )?;
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;
    let id = Uuid::now_v7();
    // D-541 rule 4: a system view is shared configuration; its event commits
    // with the insert (D-062).
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "view",
            Some(id),
        )
        .named("view.create")
        .comment(format!("system view '{}' created", body.name.trim())),
    )
    .await?;
    let row = create_view_in_tx(tx.tx(), &recording, id, ctx.user_id, &body).await?;
    // Last before commit (the security event is written by `commit` itself,
    // a plain insert that takes no lock after the changeset row's).
    recording
        .record(tx.tx(), view_op(Op::UpsertView, &row)?)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Reads one view row (any state) inside `tx` — the post-write snapshot a
/// recorded op carries and the handler returns.
async fn read_view_in_tx(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<ViewDetail, AppError> {
    let sql = format!("{VIEW_SELECT} WHERE v.id = $1");
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// Locks the active system view `id` and applies the owner-layer rule
/// (D-785 §1): `NotFound` when there is no such view, 409 `layer_mismatch`
/// when another layer owns it.
async fn lock_view_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
) -> Result<(), AppError> {
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM view \
         WHERE id = $1 AND is_active = true AND scope = 'system' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let owner = owner.ok_or(AppError::NotFound)?;
    hooks::check_row_owner(recording, &owner)
}

/// The admin create's write, transaction-scoped (D-785 §3: one
/// implementation per write, shared with the changeset applier). Stamps the
/// recording's layer; the caller records and commits.
pub(crate) async fn create_view_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    actor: Uuid,
    body: &ViewBody,
) -> Result<ViewDetail, AppError> {
    let layer = recording.stamp()?;
    if body.is_default {
        clear_other_defaults(tx, body.entity_logical_name, None).await?;
    }
    // P-environment-promotion §5 step 5: an admin write marks the row
    // `is_customized`; `uq_core_view_name_shared` makes a duplicate (entity, name)
    // a 409, not a 500.
    sqlx::query(
        "INSERT INTO view (id, name, icon, entity_logical_name, sql_query_ref, table_definition, \
             is_default, is_active, is_customized, kind, view_metadata, scope, created_at, created_by, \
             owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, true, true, $8, $9, 'system', NOW(), $10, $11)",
    )
    .bind(id).bind(body.name.trim()).bind(body.icon.trim()).bind(body.entity_logical_name).bind(body.sql_query_ref)
    .bind(&body.table_definition).bind(body.is_default).bind(&body.kind).bind(&body.view_metadata)
    .bind(actor).bind(layer.as_str())
    .execute(&mut **tx).await.map_err(map_unique_violation)?;
    read_view_in_tx(tx, id).await
}

/// The admin PATCH's write, transaction-scoped: owner check, then the full
/// replace. `NotFound` for a missing, retired or non-system view.
pub(crate) async fn update_view_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    body: &ViewBody,
) -> Result<ViewDetail, AppError> {
    lock_view_owner(tx, recording, id).await?;
    if body.is_default {
        clear_other_defaults(tx, body.entity_logical_name, Some(id)).await?;
    }
    let changed = sqlx::query(
        "UPDATE view SET name=$2, icon=$3, entity_logical_name=$4, sql_query_ref=$5, table_definition=$6, \
             is_default=$7, is_customized=true, kind=$8, view_metadata=$9 \
         WHERE id=$1 AND is_active=true AND scope='system'",
    ).bind(id).bind(body.name.trim()).bind(body.icon.trim()).bind(body.entity_logical_name).bind(body.sql_query_ref)
     .bind(&body.table_definition).bind(body.is_default).bind(&body.kind).bind(&body.view_metadata)
     .execute(&mut **tx).await.map_err(map_unique_violation)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    read_view_in_tx(tx, id).await
}

/// The admin DELETE's write (a soft retire), transaction-scoped.
pub(crate) async fn retire_view_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
) -> Result<ViewDetail, AppError> {
    lock_view_owner(tx, recording, id).await?;
    let changed = sqlx::query(
        "UPDATE view SET is_active=false, is_default=false, is_customized=true \
         WHERE id=$1 AND is_active=true AND scope='system'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    read_view_in_tx(tx, id).await
}

/// The recorded op for a system view row: target `{entity, view}` by
/// logical names (D-374: a view's key is `(entity, name)`).
fn view_op(op: Op, row: &ViewDetail) -> Result<RecordedOp, AppError> {
    hooks::recorded(
        op,
        "view",
        row.id,
        serde_json::json!({ "entity": row.entity_name, "view": row.name }),
        row,
    )
}

/// Reads and row-locks the active system view `id` before an admin PATCH
/// changes it — the old document the view diff compares against.
async fn lock_view_before_update(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
) -> Result<Option<ViewDetail>, AppError> {
    let sql = format!(
        "{VIEW_SELECT} WHERE v.id = $1 AND v.is_active = true AND v.scope = 'system' FOR UPDATE OF v"
    );
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// `true` for a lowercase logical identifier (`[a-z][a-z0-9_]*`), the shape
/// the changeset catalogue requires of a column `name`.
fn is_logical_name(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// `set_view_columns`'s `columns` when a PATCH changed only the view's
/// columns (design §4.2): the new `table_definition` is a non-empty list of
/// column objects with distinct logical names, and applying it to the old
/// document yields the new one exactly (compared as JSON values, so key
/// order does not matter). `None` otherwise — the PATCH records `upsert_view`.
/// A system view has no default sort of its own (it is the stored query's
/// `ORDER BY`), so a recorded `set_view_columns` never carries `sort`.
fn columns_only_change(before: &ViewDetail, after: &ViewDetail) -> Option<Value> {
    if before.table_definition == after.table_definition {
        return None;
    }
    let columns = after
        .table_definition
        .as_array()
        .filter(|c| !c.is_empty())?;
    let mut seen = std::collections::HashSet::new();
    for column in columns {
        let name = column.get("name").and_then(Value::as_str)?;
        if !is_logical_name(name) || !seen.insert(name) {
            return None;
        }
    }
    let mut applied = serde_json::to_value(before).ok()?;
    let fields = applied.as_object_mut()?;
    fields.insert("table_definition".into(), after.table_definition.clone());
    let after_value = serde_json::to_value(after).ok()?;
    (applied == after_value).then(|| after.table_definition.clone())
}

/// The op an admin PATCH of a system view records: `set_view_columns` when
/// only the columns changed, else `upsert_view` (design §4.2). The
/// `set_view_columns` snapshot is its `args` (`{columns}`); close translates
/// it as the identity.
fn view_patch_op(before: &ViewDetail, after: &ViewDetail) -> Result<RecordedOp, AppError> {
    match columns_only_change(before, after) {
        Some(columns) => Ok(RecordedOp {
            op: Op::SetViewColumns,
            object_kind: "view",
            object_ref: Some(after.id),
            target: serde_json::json!({ "entity": after.entity_name, "view": after.name }),
            snapshot: serde_json::json!({ "columns": columns }),
            changed: Vec::new(),
        }),
        None => view_op(Op::UpsertView, after),
    }
}

/// Update a view
///
/// Update a view. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/views/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The view")),
    request_body = ViewBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = ViewDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_view(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<ViewBody>,
) -> Result<Json<ViewDetail>, AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("view name is required".into()));
    }
    validate_view_kind_metadata(&body.kind, &body.view_metadata)?;
    validate_view_filters(
        &state,
        Some(&ctx),
        body.entity_logical_name,
        &body.view_metadata,
    )?;
    recording.preflight(&state.base.db).await?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "view",
            Some(id),
        )
        .named("view.update"),
    )
    .await?;
    // The pre-image, locked, for the view diff (design §4.2). `None` when
    // there is no such active system view: the update below is `NotFound`.
    let before = lock_view_before_update(tx.tx(), id).await?;
    let row = update_view_in_tx(tx.tx(), &recording, id, &body).await?;
    let op = match &before {
        Some(before) => view_patch_op(before, &row)?,
        None => view_op(Op::UpsertView, &row)?,
    };
    recording.record(tx.tx(), op).await?;
    tx.commit().await?;
    Ok(Json(row))
}

/// Delete a view
///
/// Delete a view. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/views/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The view")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_view(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "view",
            Some(id),
        )
        .named("view.delete"),
    )
    .await?;
    let row = retire_view_in_tx(tx.tx(), &recording, id).await?;
    recording
        .record(tx.tx(), view_op(Op::RetireView, &row)?)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Self-service personal views (D-429) ────────────────────────────────────
//
// A personal view always reuses an *existing, already-privilege-gated*
// stored query — self-service callers cannot author SQL (that stays
// Admin-only, `query_admin.rs`). "Save as my view" therefore only ever lets
// a caller name, re-column, and re-kind a query they can already execute;
// it never grants new data access. `sql_query_ref` is immutable after
// creation, matching a system view's own posture.

#[derive(Deserialize, ToSchema)]
struct CreatePersonalViewBody {
    name: String,
    #[serde(default = "default_view_icon")]
    icon: String,
    /// Entity logicalname (matches `AvailableViewsQuery.entity` — the shape a
    /// self-service caller already has, unlike the admin `ViewBody`'s
    /// `entity_logical_name: Uuid`, which requires resolving the entity's id
    /// first; that resolution happens server-side here instead).
    entity: String,
    sql_query_ref: Uuid,
    #[serde(default)]
    table_definition: Value,
    #[serde(default = "default_view_kind")]
    kind: String,
    #[serde(default)]
    view_metadata: Value,
}

#[derive(Deserialize, ToSchema)]
struct UpdatePersonalViewBody {
    name: String,
    #[serde(default = "default_view_icon")]
    icon: String,
    #[serde(default)]
    table_definition: Value,
    #[serde(default = "default_view_kind")]
    kind: String,
    #[serde(default)]
    view_metadata: Value,
}

/// Confirms `sql_query_ref` is a live, active query bound to `entity_id` (or
/// a multi-entity query, `entity_logical_name IS NULL`) and that the caller
/// holds whatever privilege it requires to execute — the exact gate
/// `query_exec::execute_stored_query` applies at run time, checked again
/// here so a personal view can never be *created* against a query the owner
/// could not themselves run.
async fn require_query_access(
    state: &EngineState,
    ctx: &Authorized<SelfService>,
    entity_id: Uuid,
    sql_query_ref: Uuid,
) -> Result<(), AppError> {
    let required_privilege: Option<String> = sqlx::query_scalar(
        "SELECT required_privilege FROM sql_query \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
           AND (entity_logical_name IS NULL OR entity_logical_name = $2)",
    )
    .bind(sql_query_ref)
    .bind(entity_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation("sql_query_ref does not name an active query for this entity".into())
    })?;
    let allowed = match required_privilege.as_deref() {
        Some(key) => ctx.is_admin || ctx.privileges.contains(key),
        None => ctx.is_admin,
    };
    if !allowed {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Create a personal view
///
/// Create a personal view. Any signed-in user.
#[utoipa::path(
    post,
    path = "/api/v1/views",
    tag = "query",
    request_body = CreatePersonalViewBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a personal view is visible to and editable by its owner only and reuses a query the caller can already execute; sharing it is the audited /share route",
    )))),
    responses(
        (status = 201, description = "Success", body = ViewDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller cannot execute the underlying query", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_personal_view(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<CreatePersonalViewBody>,
) -> Result<(StatusCode, Json<ViewDetail>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("view name is required".into()));
    }
    validate_view_kind_metadata(&body.kind, &body.view_metadata)?;
    let entity_id = resolve_live_entity_id(&state.base.db, body.entity.trim()).await?;
    require_query_access(&state, &ctx, entity_id, body.sql_query_ref).await?;
    validate_view_filters(&state, Some(&ctx), entity_id, &body.view_metadata)?;

    // Solution 7 (D-785): a personal view is a user preference and is not
    // recorded (design §1.3), so it takes the deployment's automatic layer,
    // what an unrecorded write stamps (`project` in Phase 1).
    let owner_layer = state.base.config.metadata.changesets.auto_layer;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO view (id, name, icon, entity_logical_name, sql_query_ref, table_definition, \
             is_default, is_active, is_customized, kind, view_metadata, scope, owner_ref, created_at, created_by, \
             owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, false, true, true, $7, $8, 'personal', $9, NOW(), $9, $10)",
    )
    .bind(id).bind(body.name.trim()).bind(body.icon.trim()).bind(entity_id).bind(body.sql_query_ref)
    .bind(&body.table_definition).bind(&body.kind).bind(&body.view_metadata).bind(ctx.user_id)
    .bind(owner_layer.as_str())
    .execute(&state.base.db).await.map_err(map_unique_violation)?;

    let sql = format!("{VIEW_SELECT} WHERE v.id = $1");
    let row = sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Update a personal view
///
/// Update a personal view. Any signed-in user.
#[utoipa::path(
    patch,
    path = "/api/v1/views/{id}",
    tag = "query",
    params(("id" = Uuid, Path, description = "The view")),
    request_body = UpdatePersonalViewBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a personal view is visible to and editable by its owner only and reuses a query the caller can already execute; sharing it is the audited /share route",
    )))),
    responses(
        (status = 200, description = "Success", body = ViewDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller does not own this view", body = ErrorResponse),
        (status = 404, description = "No such personal view", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_personal_view(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePersonalViewBody>,
) -> Result<Json<ViewDetail>, AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("view name is required".into()));
    }
    validate_view_kind_metadata(&body.kind, &body.view_metadata)?;
    if body
        .view_metadata
        .get("filters")
        .is_some_and(|filters| !filters.is_null())
    {
        // D-607: the filters are checked against the view's own entity,
        // which this body does not carry. Same owner/scope predicate as the
        // UPDATE below, so a view the caller cannot edit is the same 404.
        let entity_id: Uuid = sqlx::query_scalar(
            "SELECT entity_logical_name FROM view WHERE id=$1 AND owner_ref=$2 AND scope='personal' AND is_active=true",
        )
        .bind(id)
        .bind(ctx.user_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
        validate_view_filters(&state, Some(&ctx), entity_id, &body.view_metadata)?;
    }
    // Owner-only, and only ever a personal row -- once shared, only `share`
    // (never a re-`PATCH`) is allowed to have touched its scope, and this
    // route never edits a shared view (matches "personal views bypass
    // admin" -- a shared view re-enters the same governance a system view
    // has, so it is no longer the owner's alone to silently edit).
    let changed = sqlx::query(
        "UPDATE view SET name=$3, icon=$4, table_definition=$5, kind=$6, view_metadata=$7 \
         WHERE id=$1 AND owner_ref=$2 AND scope='personal' AND is_active=true",
    )
    .bind(id)
    .bind(ctx.user_id)
    .bind(body.name.trim())
    .bind(body.icon.trim())
    .bind(&body.table_definition)
    .bind(&body.kind)
    .bind(&body.view_metadata)
    .execute(&state.base.db)
    .await
    .map_err(map_unique_violation)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let sql = format!("{VIEW_SELECT} WHERE v.id = $1");
    let row = sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(row))
}

/// Delete a personal view
///
/// Delete a personal view. Any signed-in user.
#[utoipa::path(
    delete,
    path = "/api/v1/views/{id}",
    tag = "query",
    params(("id" = Uuid, Path, description = "The view")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a personal view is visible to and editable by its owner only and reuses a query the caller can already execute; sharing it is the audited /share route",
    )))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such personal view", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_personal_view(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Owner-only, and only a personal row -- a shared view can only be
    // retired through the admin surface once it has re-entered system-style
    // governance (mirrors `update_personal_view`'s posture above).
    let changed = sqlx::query(
        "UPDATE view SET is_active=false \
         WHERE id=$1 AND owner_ref=$2 AND scope='personal' AND is_active=true",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct ShareProbeRow {
    name: String,
}

/// Share a personal view
///
/// Share a personal view. Any signed-in user. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/views/{id}/share",
    tag = "query",
    params(("id" = Uuid, Path, description = "The view")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::PermissionChange)])))),
    responses(
        (status = 200, description = "Success", body = ViewDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller does not own this view", body = ErrorResponse),
        (status = 404, description = "No such personal view", body = ErrorResponse),
        (status = 409, description = "A system or shared view of this entity already has this name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn share_personal_view(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<ViewDetail>, AppError> {
    // D-429: promoting personal -> shared re-enters the same privilege gate
    // a system view uses (see the migration's column comment) -- it does
    // NOT write an `record_share` row. That table's `entity_ref` is
    // a hard FK to `entity_info`, and `view` is
    // deliberately not a registered entity (view_admin.rs's long-standing
    // comment on `reconcile_view`), so literal record-share reuse is not
    // architecturally available here without registering views as an entity
    // -- out of scope for this change.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let changed = sqlx::query(
        "UPDATE view SET scope='shared' \
         WHERE id=$1 AND owner_ref=$2 AND scope='personal' AND is_active=true",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(map_unique_violation)?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    let probe: ShareProbeRow = sqlx::query_as("SELECT name FROM view WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Security,
        entity_name: Some("view".to_owned()),
        record_id: Some(id),
        operation: AuditOperation::PermissionChange,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("view_shared".to_owned()),
        event_comment: Some(format!(
            "view '{}' promoted from personal to shared",
            probe.name
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    audit_service.write_in_tx(&mut tx, event).await?;

    tx.commit().await.map_err(AppError::internal)?;

    let sql = format!("{VIEW_SELECT} WHERE v.id = $1");
    let row = sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(row))
}

/// The single-default-per-entity invariant (`uq_core_view_default_per_entity`):
/// before a view becomes the default, every other active view of the entity
/// stops being one. Shared by `create_view`, `update_view` and
/// `reconcile_view`. System scope only — personal/shared views never
/// participate in the entity's default-list election.
async fn clear_other_defaults(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_id: Uuid,
    except: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE view SET is_default = false \
         WHERE entity_logical_name = $1 AND is_active = true AND scope = 'system' \
           AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(entity_id)
    .bind(except)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Service reconcile API (P-environment-promotion §5 step 13) ────────────────
//
// System-scope views only -- personal/shared rows are per-user runtime data,
// never bundle-exported (`bundle/export.rs`'s `export_views` filters to
// `scope = 'system'`) and never reconciled here.

/// The row a `reconcile_view` probe finds for `(entity, name)` —
/// `uq_core_view_name_shared` is a full (not partial-by-owner) constraint over
/// system/shared scope, so there is at most one, live or retired. That is
/// also why a retired view is always reactivated rather than re-inserted: a
/// second row cannot exist.
#[derive(sqlx::FromRow)]
struct ViewProbeRow {
    id: Uuid,
    icon: String,
    sql_query_ref: Uuid,
    table_definition: Value,
    is_default: bool,
    is_active: bool,
    is_customized: bool,
    kind: String,
    view_metadata: Value,
}

/// Resolves a view's query reference `(entity, name)` to the live
/// `sql_query.id` — a multi-entity query has `entity = None`.
async fn resolve_live_query_id(
    db: &attome_db::DbPool,
    entity: Option<&str>,
    name: &str,
) -> Result<Uuid, AppError> {
    let entity_id = match entity.map(str::trim).filter(|s| !s.is_empty()) {
        Some(entity) => Some(resolve_live_entity_id(db, entity).await?),
        None => None,
    };
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM sql_query \
         WHERE record_no = $1 AND entity_logical_name IS NOT DISTINCT FROM $2 \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY created_at DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(name)
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "no active stored query named '{name}' for entity {}",
            entity.unwrap_or("*")
        ))
    })
}

/// Create-or-update one view to match `desc`, keyed by `(entity, name)`.
/// Compare-first; `Seed` skips an `is_customized` row; `Admin` marks it;
/// `Bundle` carries the marker; a retired row with the same key is
/// reactivated. The query the view names must already be live (apply
/// queries before views). Returns `(view_id, outcome)`. Mirrors the admin
/// handlers: no metadata lock, change log or doorbell — `view` is
/// not in the entity metadata registry. Always writes `scope = 'system'`.
pub async fn reconcile_view(
    state: &EngineState,
    desc: &ViewDef,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("view name is required".into()));
    }
    validate_view_kind_metadata(&desc.kind, &desc.view_metadata)?;
    let db = &state.base.db;
    let entity_id = resolve_live_entity_id(db, desc.entity.trim()).await?;
    validate_view_filters(state, None, entity_id, &desc.view_metadata)?;
    let query_id =
        resolve_live_query_id(db, desc.query.entity.as_deref(), &desc.query.name).await?;
    let icon = desc.icon.trim();
    let icon = if icon.is_empty() {
        default_view_icon()
    } else {
        icon.to_owned()
    };

    let current: Option<ViewProbeRow> = sqlx::query_as(
        "SELECT id, icon, sql_query_ref, table_definition, is_default, is_active, is_customized, \
                kind, view_metadata \
         FROM view WHERE entity_logical_name = $1 AND name = $2 AND scope IN ('system', 'shared')",
    )
    .bind(entity_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let state_differs = current.as_ref().is_some_and(|row| {
        row.icon != icon
            || row.sql_query_ref != query_id
            || row.table_definition != desc.table_definition
            || row.is_default != desc.is_default
            || row.kind != desc.kind
            || row.view_metadata != desc.view_metadata
    });
    let status = current.as_ref().map(|r| (r.is_customized, r.is_active));
    let step = reconcile_step(policy, status, state_differs);
    let key = format!("{}.{name}", desc.entity);

    match step {
        ReconcileStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        ReconcileStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(view = %key, "view reconcile: seed skipped a customized view (is_customized = true)");
            Ok((id, ReconcileOutcome::SkippedCustomized))
        }
        ReconcileStep::Create | ReconcileStep::Update => {
            let mut tx = attome_db::tx::begin(db).await?;
            let existing = current.as_ref().map(|r| r.id);
            if desc.is_default {
                clear_other_defaults(&mut tx, entity_id, existing).await?;
            }
            let id = match existing {
                Some(id) => {
                    let n = sqlx::query(
                        "UPDATE view \
                         SET icon = $2, sql_query_ref = $3, table_definition = $4, is_default = $5, \
                             is_active = true, is_customized = COALESCE($6, is_customized), \
                             kind = $7, view_metadata = $8 \
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(&icon)
                    .bind(query_id)
                    .bind(&desc.table_definition)
                    .bind(desc.is_default)
                    .bind(customized_marker(policy))
                    .bind(&desc.kind)
                    .bind(&desc.view_metadata)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_unique_violation)?
                    .rows_affected();
                    if n != 1 {
                        return Err(AppError::Conflict("view row vanished during reconcile"));
                    }
                    id
                }
                None => {
                    let id = desired_id.unwrap_or_else(Uuid::now_v7);
                    sqlx::query(
                        "INSERT INTO view \
                             (id, name, icon, entity_logical_name, sql_query_ref, table_definition, \
                              is_default, is_active, is_customized, kind, view_metadata, scope, created_at, \
                              owner_layer) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9, $10, 'system', NOW(), $11)",
                    )
                    .bind(id)
                    .bind(name)
                    .bind(&icon)
                    .bind(entity_id)
                    .bind(query_id)
                    .bind(&desc.table_definition)
                    .bind(desc.is_default)
                    .bind(customized_marker(policy).unwrap_or(false))
                    .bind(&desc.kind)
                    .bind(&desc.view_metadata)
                    .bind(hooks::reconcile_layer(policy).as_str())
                    .execute(&mut *tx)
                    .await
                    // Two concurrent creates of the same key: the loser's
                    // INSERT hits `uq_core_view_name_shared` -> Conflict; a
                    // re-run finds the winner's row and converges.
                    .map_err(map_unique_violation)?;
                    id
                }
            };
            tx.commit().await.map_err(AppError::internal)?;
            let outcome = step.outcome();
            tracing::info!(view = %key, ?outcome, ?policy, "view reconcile: reconciled view");
            Ok((id, outcome))
        }
    }
}

/// `set_view_columns` (design §3.7): replace the `table_definition` of the
/// active system view keyed by `(entity, name)` with `columns`, whole.
/// Compare-first and idempotent (the same columns again is `Unchanged`);
/// `Seed` skips an `is_customized` view, `Admin` marks it, `Bundle` carries
/// the marker — the same contract as [`reconcile_view`]. `NotFound` when
/// there is no such view (the planner blocks that case first).
pub async fn set_view_columns(
    state: &EngineState,
    entity: &str,
    name: &str,
    columns: &Value,
    policy: ReconcilePolicy,
) -> Result<ReconcileOutcome, AppError> {
    if !columns.as_array().is_some_and(|c| !c.is_empty()) {
        return Err(AppError::Validation(
            "set_view_columns: columns must be a non-empty array".into(),
        ));
    }
    let db = &state.base.db;
    let entity_id = resolve_live_entity_id(db, entity.trim()).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let current: Option<(Uuid, Value, bool)> = sqlx::query_as(
        "SELECT id, table_definition, is_customized FROM view \
         WHERE entity_logical_name = $1 AND name = $2 AND scope = 'system' AND is_active = true \
         FOR UPDATE",
    )
    .bind(entity_id)
    .bind(name.trim())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (id, table_definition, is_customized) = current.ok_or(AppError::NotFound)?;
    let step = reconcile_step(
        policy,
        Some((is_customized, true)),
        table_definition != *columns,
    );
    let key = format!("{entity}.{name}");
    match step {
        ReconcileStep::Unchanged => Ok(ReconcileOutcome::Unchanged),
        ReconcileStep::SkippedCustomized => {
            tracing::info!(view = %key, "view columns: seed skipped a customized view (is_customized = true)");
            Ok(ReconcileOutcome::SkippedCustomized)
        }
        ReconcileStep::Create | ReconcileStep::Update => {
            let n = sqlx::query(
                "UPDATE view \
                 SET table_definition = $2, is_customized = COALESCE($3, is_customized) \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(columns)
            .bind(customized_marker(policy))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if n != 1 {
                return Err(AppError::Conflict(
                    "view row vanished during set_view_columns",
                ));
            }
            tx.commit().await.map_err(AppError::internal)?;
            tracing::info!(view = %key, ?policy, "view columns: replaced the view's columns");
            Ok(ReconcileOutcome::Updated)
        }
    }
}

/// Flips `is_active` on the view keyed by `(entity, name)`. Idempotent:
/// `Unchanged` when no row is in the opposite state. Retiring also clears
/// `is_default` (as `delete_view` does) so `uq_core_view_default_per_entity`
/// never blocks another view from becoming the default meanwhile.
async fn set_view_active(
    state: &EngineState,
    entity: &str,
    name: &str,
    live: bool,
) -> Result<ReconcileOutcome, AppError> {
    let db = &state.base.db;
    let entity_id = resolve_live_entity_id(db, entity.trim()).await?;
    let n = if live {
        sqlx::query(
            "UPDATE view SET is_active = true \
             WHERE entity_logical_name = $1 AND name = $2 AND scope IN ('system', 'shared') AND is_active = false",
        )
    } else {
        sqlx::query(
            "UPDATE view SET is_active = false, is_default = false \
             WHERE entity_logical_name = $1 AND name = $2 AND scope IN ('system', 'shared') AND is_active = true",
        )
    }
    .bind(entity_id)
    .bind(name.trim())
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    tracing::info!(view = %format!("{entity}.{name}"), live, "view reconcile: active flag changed");
    Ok(ReconcileOutcome::Updated)
}

/// Soft-retire (`is_active = false`) the view keyed by `(entity, name)`.
/// Idempotent. Never drops.
pub async fn retire_view(
    state: &EngineState,
    entity: &str,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_view_active(state, entity, name, false).await
}

/// Reactivate a previously retired view. Idempotent. `is_default` is not
/// restored (re-run `reconcile_view` with the desired state for that).
pub async fn reactivate_view(
    state: &EngineState,
    entity: &str,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_view_active(state, entity, name, true).await
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/views",
            get(list_available_views).post(create_personal_view),
        )
        .route(
            "/api/v1/views/{id}",
            axum::routing::patch(update_personal_view).delete(delete_personal_view),
        )
        .route(
            "/api/v1/views/{id}/share",
            axum::routing::post(share_personal_view),
        )
        .route("/api/v1/admin/views", get(list_views).post(create_view))
        .route(
            "/api/v1/admin/views/{id}",
            get(get_view).patch(update_view).delete(delete_view),
        )
        .route("/api/v1/admin/views/{id}/impact", get(view_impact))
}

/// What editing or removing a view would touch (A13-T6).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ViewImpact {
    pub id: Uuid,
    pub name: String,
    /// `system`, `shared` or `personal`.
    pub scope: String,
    /// Every user's default list for this entity.
    pub is_default: bool,
    /// The layer that owns it; a `platform` view is built in.
    pub owner_layer: String,
    /// Dashboard widgets that show it, and the dashboards they are on.
    pub dashboard_widgets: i64,
    pub dashboards: i64,
    /// Navigation entries whose route names it.
    pub sidebar_items: i64,
    /// What to tell the person about to change it.
    pub warnings: Vec<String>,
}

/// Who a view change affects
///
/// A13-T6: who would notice a change to this view: the dashboards that show
/// it, the navigation that links to it, and whether it is every user's
/// default or a built-in one. Reads only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/views/{id}/impact",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The view")),
    responses(
        (status = 200, description = "What depends on the view", body = ViewImpact),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such view", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn view_impact(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ViewImpact>, AppError> {
    let db = &state.base.db;
    let (name, scope, is_default, owner_layer): (String, String, bool, String) = sqlx::query_as(
        "SELECT name, scope, is_default, owner_layer FROM view WHERE id = $1 AND is_active = true",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let (dashboard_widgets, dashboards): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(DISTINCT p.dashboard_id) \
         FROM dashboard_widget w \
         JOIN dashboard_section s ON s.id = w.section_id \
             AND (s.is_active IS NULL OR s.is_active = true) \
         JOIN dashboard_page p ON p.id = s.page_id \
             AND (p.is_active IS NULL OR p.is_active = true) \
         WHERE w.view_id = $1 AND (w.is_active IS NULL OR w.is_active = true)",
    )
    .bind(id.to_string())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let sidebar_items: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sidebar WHERE is_deleted = false AND route LIKE '%' || $1 || '%'",
    )
    .bind(id.to_string())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(ViewImpact {
        warnings: impact_warnings(&scope, is_default, &owner_layer, dashboards, sidebar_items),
        id,
        name,
        scope,
        is_default,
        owner_layer,
        dashboard_widgets,
        dashboards,
        sidebar_items,
    }))
}

/// The warnings a view's impact gives, in the order a person should read them.
fn impact_warnings(
    scope: &str,
    is_default: bool,
    owner_layer: &str,
    dashboards: i64,
    sidebar_items: i64,
) -> Vec<String> {
    let mut out = Vec::new();
    if is_default {
        out.push("this is every user's default list for its entity".to_owned());
    }
    if scope == "shared" {
        out.push("other people use this shared view".to_owned());
    }
    if attome_model::Layer::from_stored(owner_layer) == Some(attome_model::Layer::Platform) {
        out.push("this view is built in: a platform upgrade brings its own version".to_owned());
    }
    if dashboards > 0 {
        out.push(format!("{dashboards} dashboard(s) show this view"));
    }
    if sidebar_items > 0 {
        out.push(format!(
            "{sidebar_items} navigation item(s) link to this view"
        ));
    }
    out
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_views,
    list_available_views,
    get_view,
    view_impact,
    create_view,
    update_view,
    delete_view,
    create_personal_view,
    update_personal_view,
    delete_personal_view,
    share_personal_view
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod changeset_hook_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_view_op_targets_entity_and_view_by_logical_name() {
        let row = ViewDetail {
            id: Uuid::now_v7(),
            name: "Active accounts".into(),
            icon: "las la-table".into(),
            entity_logical_name: Uuid::now_v7(),
            entity_name: "account".into(),
            sql_query_ref: Uuid::now_v7(),
            query_name: "active_accounts".into(),
            table_definition: json!([]),
            is_default: false,
            is_active: true,
            kind: "list".into(),
            view_metadata: json!({}),
            scope: "system".into(),
            owner_ref: None,
            owner_layer: "project".into(),
        };
        let op = view_op(Op::UpsertView, &row).expect("op");
        assert_eq!(
            op.target,
            json!({ "entity": "account", "view": "Active accounts" })
        );
        assert_eq!(op.snapshot["owner_layer"], "project");
        assert!(op.check().is_ok());
        assert!(view_op(Op::RetireView, &row).expect("op").check().is_ok());
    }

    fn view(table_definition: Value) -> ViewDetail {
        ViewDetail {
            id: Uuid::from_u128(1),
            name: "Active accounts".into(),
            icon: "las la-table".into(),
            entity_logical_name: Uuid::from_u128(2),
            entity_name: "account".into(),
            sql_query_ref: Uuid::from_u128(3),
            query_name: "active_accounts".into(),
            table_definition,
            is_default: false,
            is_active: true,
            kind: "list".into(),
            view_metadata: json!({}),
            scope: "system".into(),
            owner_ref: None,
            owner_layer: "project".into(),
        }
    }

    #[test]
    fn a_columns_only_patch_records_set_view_columns_with_the_whole_list() {
        let before = view(json!([{ "name": "name" }]));
        let columns = json!([
            { "name": "name", "display_name": "Name", "is_visible": true },
            { "name": "created_at" }
        ]);
        let after = view(columns.clone());
        let op = view_patch_op(&before, &after).expect("op");
        assert_eq!(op.op, Op::SetViewColumns);
        assert_eq!(
            op.target,
            json!({ "entity": "account", "view": "Active accounts" })
        );
        assert_eq!(op.snapshot, json!({ "columns": columns }));
        assert!(
            op.snapshot.get("sort").is_none(),
            "a view has no sort of its own"
        );
        assert!(op.check().is_ok(), "{:?}", op.check());
    }

    #[test]
    fn any_other_change_records_upsert_view() {
        let before = view(json!([{ "name": "name" }]));
        // Nothing changed.
        assert_eq!(
            view_patch_op(&before, &before).expect("op").op,
            Op::UpsertView
        );
        // Columns and something else changed.
        let mut renamed = view(json!([{ "name": "created_at" }]));
        renamed.name = "Renamed".into();
        assert_eq!(
            view_patch_op(&before, &renamed).expect("op").op,
            Op::UpsertView
        );
        let mut other_kind = view(json!([{ "name": "created_at" }]));
        other_kind.view_metadata = json!({ "filters": [] });
        assert_eq!(
            view_patch_op(&before, &other_kind).expect("op").op,
            Op::UpsertView
        );
    }

    #[test]
    fn columns_the_catalogue_cannot_carry_fall_back_to_upsert_view() {
        let before = view(json!([{ "name": "name" }]));
        for td in [
            json!([]),
            json!({ "columns": ["name"] }),
            json!(["name"]),
            json!([{ "label": "no name" }]),
            json!([{ "name": "Name" }]),
            json!([{ "name": "name" }, { "name": "name" }]),
        ] {
            assert_eq!(
                view_patch_op(&before, &view(td.clone())).expect("op").op,
                Op::UpsertView,
                "{td}"
            );
        }
    }

    #[test]
    fn logical_names_are_lowercase_identifiers() {
        assert!(is_logical_name("created_on2"));
        for bad in ["", "2x", "Name", "a-b", "a b"] {
            assert!(!is_logical_name(bad), "{bad}");
        }
    }

    #[test]
    fn impact_warnings_name_what_a_change_touches() {
        assert!(impact_warnings("personal", false, "customer", 0, 0).is_empty());
        let w = impact_warnings("system", true, "platform", 2, 1);
        assert_eq!(w.len(), 4);
        assert!(w[0].contains("default"));
        assert!(w.iter().any(|m| m.contains("2 dashboard")));
    }
}

#[cfg(test)]
mod mobile_options_tests {
    use super::*;

    #[test]
    fn view_mobile_options_validated() {
        let ok = serde_json::json!({"mobile": {
            "card_title": "subject", "card_lines": ["due_date", "owner_ref"],
            "swipe_start": "call", "swipe_end": "complete"
        }});
        assert!(validate_mobile_options(&ok).is_ok());
        assert!(validate_mobile_options(&serde_json::json!({})).is_ok());
        assert!(validate_mobile_options(&serde_json::json!({"mobile": null})).is_ok());
        for bad in [
            serde_json::json!({"mobile": "cards"}),
            serde_json::json!({"mobile": {"card_lines": ["a", "b", "c", "d"]}}),
            serde_json::json!({"mobile": {"swipe_end": "delete"}}),
            serde_json::json!({"mobile": {"card_title": ""}}),
            serde_json::json!({"mobile": {"layout": "grid"}}),
        ] {
            assert!(validate_mobile_options(&bad).is_err(), "{bad}");
        }
        assert!(validate_view_kind_metadata("list", &ok).is_ok());
        assert!(validate_view_kind_metadata("list", &serde_json::json!({"mobile": 3})).is_err());
    }
}
