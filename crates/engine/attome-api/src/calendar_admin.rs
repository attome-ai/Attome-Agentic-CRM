//! `/api/v1/admin/calendars*` — D-404 / M83 Phase 1.
//!
//! `calendar` + `calendar_holiday` +
//! `calendar_exception`: named business calendars (timezone, working
//! days/hours), their per-year holidays, and their per-date exceptions
//! (D-592). A holiday or an exception is identified by its date within its
//! calendar; its name is a label.
//! Mirrors `view_admin.rs`'s shape exactly (same admin-metadata-object
//! posture: not a generic XRM entity, its own CRUD, bundle-exportable via
//! the service reconcile API below) — the pattern this file was told to
//! copy. The one structural difference: calendars are not entity-scoped, so
//! every key here is a bare `name` rather than `(entity, name)`.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::calendar::InvalidCalendarDefinition;
use attome_core::changeset::{Layer, Op, RecordedOp, Recording, RecordingCtx};
use attome_metadata::provision::{ReconcileOutcome, ReconcilePolicy};
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::admin_hooks as hooks;
use crate::bundle::model::{
    CalendarDef, CalendarExceptionDef, HolidayDef, HolidayRuleDef, SeasonDef,
};
use attome_records::query_admin::{
    ReconcileStep, customized_marker, map_unique_violation, reconcile_step,
};

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct CalendarDetail {
    id: Uuid,
    name: String,
    description: Option<String>,
    tz: String,
    working_days: Vec<String>,
    hours: Value,
    is_default: bool,
    is_active: bool,
    /// Solution 7 (D-785) — the layer that owns this calendar: `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer
    /// may update or retire it (409 `layer_mismatch` otherwise).
    owner_layer: String,
    /// Z12-T4: the calendar this one inherits from.
    parent_calendar_id: Option<Uuid>,
    /// The parent's name (how a changeset names it).
    parent: Option<String>,
    /// Z12-T3: an ISO 3166 country code, such as `SA`.
    country_code: Option<String>,
    name_ar: Option<String>,
    /// Z12-T5: the calendar's content version.
    current_version: i32,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CalendarBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    tz: String,
    #[serde(default)]
    working_days: Vec<String>,
    #[serde(default = "default_hours")]
    hours: Value,
    #[serde(default)]
    is_default: bool,
    /// Z12-T6: the calendar this one inherits from; its chain may not loop
    /// or run deeper than three calendars.
    #[serde(default)]
    parent_calendar_id: Option<Uuid>,
    /// An ISO 3166 two-letter country code.
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    name_ar: Option<String>,
}

fn default_hours() -> Value {
    Value::Object(serde_json::Map::new())
}

const CALENDAR_SELECT: &str = "SELECT id, name, description, tz, working_days, hours, is_default, is_active, \
     owner_layer, parent_calendar_id, \
     (SELECT p.name FROM calendar p WHERE p.id = calendar.parent_calendar_id) AS parent, \
     country_code, name_ar, current_version FROM calendar";

/// List calendars
///
/// List calendars. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<CalendarDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_calendars(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<CalendarDetail>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let sql = format!("{CALENDAR_SELECT} WHERE is_active = true ORDER BY name LIMIT $1 OFFSET $2");
    let rows = sqlx::query_as(&sql)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar WHERE is_active = true")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

/// One calendar
///
/// One calendar. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    responses(
        (status = 200, description = "The calendar with its holiday rules and seasons", body = CalendarFull),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_calendar(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<CalendarFull>, AppError> {
    let sql = format!("{CALENDAR_SELECT} WHERE id = $1 AND is_active = true");
    let calendar: CalendarDetail = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    let rules = sqlx::query_as(&format!(
        "{RULE_SELECT} WHERE calendar_id = $1 AND is_active = true ORDER BY name"
    ))
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let seasons = sqlx::query_as(&format!(
        "{SEASON_SELECT} WHERE calendar_id = $1 AND is_active = true ORDER BY name"
    ))
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(CalendarFull {
        calendar,
        rules,
        seasons,
    }))
}

/// Z12-T6: one calendar with its holiday rules and seasons.
#[derive(Serialize, ToSchema)]
pub(crate) struct CalendarFull {
    #[serde(flatten)]
    calendar: CalendarDetail,
    rules: Vec<RuleDetail>,
    seasons: Vec<SeasonDetail>,
}

/// Create a calendar
///
/// Create a calendar. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars",
    tag = "admin",
    request_body = CalendarBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = CalendarDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_calendar(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<CalendarBody>,
) -> Result<(StatusCode, Json<CalendarDetail>), AppError> {
    validate_body(&body)?;
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = create_calendar_in_tx(&mut tx, &recording, ctx.user_id, &body).await?;
    recording
        .record(&mut tx, calendar_op(Op::UpsertCalendar, &row)?)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        row.id,
        AuditOperation::Create,
        "calendar.created",
        "calendar created",
    )
    .await;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn read_calendar_in_tx(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
) -> Result<CalendarDetail, AppError> {
    let sql = format!("{CALENDAR_SELECT} WHERE id = $1");
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// Locks the active calendar `id` and applies the owner-layer rule (D-785
/// §1): `NotFound` when there is no such calendar, 409 `layer_mismatch` when
/// another layer owns it.
async fn lock_calendar_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
) -> Result<(), AppError> {
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM calendar WHERE id = $1 AND is_active = true FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let owner = owner.ok_or(AppError::NotFound)?;
    hooks::check_row_owner(recording, &owner)
}

/// The admin create's write, transaction-scoped (D-785 §3: one
/// implementation per write, shared with the changeset applier).
pub(crate) async fn create_calendar_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    actor: Uuid,
    body: &CalendarBody,
) -> Result<CalendarDetail, AppError> {
    let layer = recording.stamp()?;
    if body.is_default {
        clear_other_defaults(tx, None).await?;
    }
    let id = Uuid::now_v7();
    if let Some(parent) = body.parent_calendar_id {
        check_parent_in_tx(tx, id, parent).await?;
    }
    sqlx::query(
        "INSERT INTO calendar (id, name, description, tz, working_days, hours, is_default, is_active, is_customized, created_at, created_by, owner_layer, \
                               parent_calendar_id, country_code, name_ar) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, true, true, NOW(), $8, $9, $10, $11, $12)",
    )
    .bind(id).bind(body.name.trim()).bind(body.description.as_deref().map(str::trim))
    .bind(body.tz.trim()).bind(&body.working_days).bind(&body.hours).bind(body.is_default)
    .bind(actor).bind(layer.as_str())
    .bind(body.parent_calendar_id).bind(country(body)).bind(name_ar(body))
    .execute(&mut **tx).await.map_err(map_unique_violation)?;
    read_calendar_in_tx(tx, id).await
}

/// The admin PATCH's write, transaction-scoped.
pub(crate) async fn update_calendar_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    body: &CalendarBody,
) -> Result<CalendarDetail, AppError> {
    lock_calendar_owner(tx, recording, id).await?;
    if body.is_default {
        clear_other_defaults(tx, Some(id)).await?;
    }
    if let Some(parent) = body.parent_calendar_id {
        check_parent_in_tx(tx, id, parent).await?;
    }
    let changed = sqlx::query(
        "UPDATE calendar SET name=$2, description=$3, tz=$4, working_days=$5, hours=$6, is_default=$7, is_customized=true, \
                parent_calendar_id=$8, country_code=$9, name_ar=$10 \
         WHERE id=$1 AND is_active=true",
    ).bind(id).bind(body.name.trim()).bind(body.description.as_deref().map(str::trim))
     .bind(body.tz.trim()).bind(&body.working_days).bind(&body.hours).bind(body.is_default)
     .bind(body.parent_calendar_id).bind(country(body)).bind(name_ar(body))
     .execute(&mut **tx).await.map_err(map_unique_violation)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    read_calendar_in_tx(tx, id).await
}

/// The admin DELETE's write (a soft retire), transaction-scoped. The SLA
/// reference guard (D-517) runs before it, outside the transaction.
pub(crate) async fn retire_calendar_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
) -> Result<CalendarDetail, AppError> {
    lock_calendar_owner(tx, recording, id).await?;
    let changed = sqlx::query(
        "UPDATE calendar SET is_active=false, is_default=false, is_customized=true WHERE id=$1 AND is_active=true",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    read_calendar_in_tx(tx, id).await
}

/// The recorded op for a calendar row: target `{calendar: <name>}` (D-404:
/// calendars are keyed by name alone).
fn calendar_op(op: Op, row: &CalendarDetail) -> Result<RecordedOp, AppError> {
    hooks::recorded(
        op,
        "calendar",
        row.id,
        serde_json::json!({ "calendar": row.name }),
        row,
    )
}

/// Update a calendar
///
/// Update a calendar. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/calendars/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = CalendarBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = CalendarDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_calendar(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<CalendarBody>,
) -> Result<Json<CalendarDetail>, AppError> {
    let actor = ctx.user_id;
    validate_body(&body)?;
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = update_calendar_in_tx(&mut tx, &recording, id, &body).await?;
    recording
        .record(&mut tx, calendar_op(Op::UpsertCalendar, &row)?)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        actor,
        id,
        AuditOperation::Update,
        "calendar.updated",
        "calendar updated",
    )
    .await;
    Ok(Json(row))
}

/// Delete a calendar
///
/// Delete a calendar. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "An active SLA policy still uses this calendar", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_calendar(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    ensure_not_referenced_by_sla_policies(&state.base.db, id).await?;
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = retire_calendar_in_tx(&mut tx, &recording, id).await?;
    recording
        .record(&mut tx, calendar_op(Op::RetireCalendar, &row)?)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    attome_audit::write_business_event(
        &state,
        "calendar",
        id,
        AuditOperation::SoftDelete,
        "calendar.deleted",
        ctx.user_id,
        None,
        None,
        "calendar deleted".to_string(),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// D-517 — refuses to retire a calendar an active SLA policy still points
/// at: deleting it would leave every such ticket's next calculation
/// unresolved. A best-effort guard, not a lock (a policy can be re-pointed
/// concurrently through the generic entity API); the runtime's explicit
/// unresolved state is what keeps a missed race safe. A deployment without
/// the service module has no policy table and nothing to check.
async fn ensure_not_referenced_by_sla_policies(
    db: &attome_db::DbPool,
    calendar_id: Uuid,
) -> Result<(), AppError> {
    let provisioned: bool =
        sqlx::query_scalar("SELECT to_regclass('service_sla_policy') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !provisioned {
        return Ok(());
    }
    let referenced: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM service_sla_policy \
         WHERE (is_active IS NULL OR is_active = true) AND lower(btrim(calendar_ref)) = $1)",
    )
    .bind(calendar_id.to_string())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if referenced {
        return Err(AppError::Conflict(
            "the calendar is used by an active SLA policy; point those policies at another calendar first",
        ));
    }
    Ok(())
}

/// Audits a calendar or holiday change with the resulting content hash
/// (D-517), so an SLA calculation's recorded hash can be matched to the
/// change that produced it. Best-effort, same posture as every
/// `write_business_event` caller.
async fn audit_calendar_change(
    state: &EngineState,
    actor: Uuid,
    calendar_id: Uuid,
    operation: AuditOperation,
    event_name: &str,
    action: &str,
) {
    let hash = match attome_core::calendar::load_calendar(&state.base.db, calendar_id).await {
        Ok(Ok(loaded)) => loaded.content_hash,
        Ok(Err(unresolved)) => format!("none ({unresolved})"),
        Err(_) => "unavailable".to_string(),
    };
    attome_audit::write_business_event(
        state,
        "calendar",
        calendar_id,
        operation,
        event_name,
        actor,
        None,
        None,
        format!("{action}; calendar content hash {hash}"),
    )
    .await;
}

fn validate_body(body: &CalendarBody) -> Result<(), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("calendar name is required".into()));
    }
    if body.tz.trim().is_empty() {
        return Err(AppError::Validation("calendar timezone is required".into()));
    }
    if let Some(code) = body.country_code.as_deref().map(str::trim)
        && !code.is_empty()
        && !(code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return Err(AppError::Validation(
            "country_code is a two-letter ISO 3166 code, such as SA".into(),
        ));
    }
    // D-517 — the same strict parser the runtime loader uses, so a definition
    // that would load as a partial calendar is rejected here instead.
    attome_core::calendar::validate_definition(&body.tz, &body.working_days, &body.hours)
        .map_err(|e| AppError::Validation(e.0))
}

fn country(body: &CalendarBody) -> Option<String> {
    body.country_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_ascii_uppercase)
}

fn name_ar(body: &CalendarBody) -> Option<&str> {
    body.name_ar
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
}

/// Z12-T6 (the Z12-T4 rules): `id` may inherit from `parent` when the
/// parent is an active calendar, the chain from the parent up does not pass
/// through `id`, and the deepest chain through `id` (its ancestors, itself
/// and its descendants) holds at most
/// [`attome_core::calendar::MAX_CALENDAR_DEPTH`] calendars.
async fn check_parent_in_tx(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
    parent: Uuid,
) -> Result<(), AppError> {
    let max = attome_core::calendar::MAX_CALENDAR_DEPTH;
    let mut above = 0usize;
    let mut next = Some(parent);
    while let Some(current) = next {
        if current == id {
            return Err(AppError::Validation(
                "a calendar cannot inherit from itself, directly or through its parents".into(),
            ));
        }
        above += 1;
        if above > max {
            break;
        }
        let row: Option<Option<Uuid>> = sqlx::query_scalar(
            "SELECT parent_calendar_id FROM calendar WHERE id = $1 AND is_active = true",
        )
        .bind(current)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        let Some(up) = row else {
            return Err(AppError::Validation(format!(
                "the parent calendar {current} is not an active calendar"
            )));
        };
        next = up;
    }
    let below: i32 = sqlx::query_scalar(
        "WITH RECURSIVE down(id, depth) AS ( \
             SELECT id, 1 FROM calendar WHERE parent_calendar_id = $1 AND is_active = true \
             UNION ALL \
             SELECT c.id, d.depth + 1 FROM calendar c JOIN down d ON c.parent_calendar_id = d.id \
              WHERE c.is_active = true AND d.depth < $2 \
         ) SELECT COALESCE(max(depth), 0) FROM down",
    )
    .bind(id)
    .bind(i32::try_from(max).unwrap_or(i32::MAX))
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if above + 1 + usize::try_from(below).unwrap_or(0) > max {
        return Err(AppError::Validation(format!(
            "calendars inherit through at most {max} levels"
        )));
    }
    Ok(())
}

/// At most one active default calendar deployment-wide
/// (`uq_core_calendar_default`). Shared by `create_calendar`, `update_calendar`
/// and `reconcile_calendar`.
async fn clear_other_defaults(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    except: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE calendar SET is_default = false \
         WHERE is_active = true AND ($1::uuid IS NULL OR id <> $1)",
    )
    .bind(except)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Holidays (nested under a calendar) ──────────────────────────────────────

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct HolidayDetail {
    id: Uuid,
    calendar_id: Uuid,
    name: String,
    #[schema(value_type = String, format = "date")]
    holiday_date: NaiveDate,
    /// Solution 7 (D-785) — the layer that owns this holiday row (it may
    /// differ from its calendar's: a project may add a holiday to a platform
    /// calendar). Only a changeset of that layer may remove it.
    owner_layer: String,
    /// AG1-T6: the same day in the deployment's Umm al-Qura calendar.
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    hijri_date: Option<HijriDateBody>,
}

/// A Hijri date on the wire (AG1-T6).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, ToSchema)]
pub(crate) struct HijriDateBody {
    year: u16,
    /// 1 (Muharram) to 12 (Dhu al-Hijjah).
    month: u8,
    day: u8,
}

impl HolidayDetail {
    /// Fills `hijri_date` from the deployment's calendar.
    fn with_hijri(mut self, state: &EngineState) -> Self {
        self.hijri_date = state
            .hijri
            .load()
            .to_hijri(self.holiday_date)
            .ok()
            .map(|h| HijriDateBody {
                year: h.year,
                month: h.month,
                day: h.day,
            });
        self
    }
}

/// The Gregorian day of a Hijri date in the deployment's calendar; a date
/// outside the Umm al-Qura table, or a day the month does not have, is a 422.
fn gregorian_of(state: &EngineState, hijri: HijriDateBody) -> Result<NaiveDate, AppError> {
    state
        .hijri
        .load()
        .to_gregorian(attome_core::calendar::hijri::HijriDate::new(
            hijri.year,
            hijri.month,
            hijri.day,
        ))
        .map_err(|_| {
            AppError::Validation(format!(
                "{}-{:02}-{:02} is not a day of the Umm al-Qura calendar (1356 to 1500 AH)",
                hijri.year, hijri.month, hijri.day
            ))
        })
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct HolidayBody {
    name: String,
    /// The Gregorian day. Give this or `hijri_date`.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = "date")]
    holiday_date: Option<NaiveDate>,
    /// AG1-T6: the day as a Hijri date, stored as its Gregorian day.
    #[serde(default)]
    hijri_date: Option<HijriDateBody>,
}

impl HolidayBody {
    fn date(&self, state: &EngineState) -> Result<NaiveDate, AppError> {
        match (self.holiday_date, self.hijri_date) {
            (Some(date), None) => Ok(date),
            (None, Some(hijri)) => gregorian_of(state, hijri),
            _ => Err(AppError::Validation(
                "give exactly one of holiday_date or hijri_date".into(),
            )),
        }
    }
}

/// `POST /api/v1/admin/calendars/{id}/holidays/hijri-recurring`.
#[derive(Deserialize, ToSchema)]
pub(crate) struct HijriRecurringBody {
    name: String,
    hijri_month: u8,
    hijri_day: u8,
    from_year: u16,
    to_year: u16,
}

/// The most Hijri years one recurring request may cover.
const MAX_RECURRING_YEARS: u16 = 30;

const HOLIDAY_SELECT: &str =
    "SELECT id, calendar_id, name, holiday_date, owner_layer FROM calendar_holiday";

/// A calendar's holidays
///
/// A calendar's holidays. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/{id}/holidays",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    responses(
        (status = 200, description = "Success", body = Vec<HolidayDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_holidays(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(calendar_id): Path<Uuid>,
) -> Result<Json<Vec<HolidayDetail>>, AppError> {
    let sql = format!(
        "{HOLIDAY_SELECT} WHERE calendar_id = $1 AND is_active = true ORDER BY holiday_date"
    );
    let rows: Vec<HolidayDetail> = sqlx::query_as(&sql)
        .bind(calendar_id)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(
        rows.into_iter().map(|r| r.with_hijri(&state)).collect(),
    ))
}

/// Add a holiday
///
/// Add a holiday. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/holidays",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = HolidayBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 201, description = "Success", body = HolidayDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The calendar already has a holiday or an exception on this date", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_holiday(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(calendar_id): Path<Uuid>,
    Json(body): Json<HolidayBody>,
) -> Result<(StatusCode, Json<HolidayDetail>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("holiday name is required".into()));
    }
    let holiday_date = body.date(&state)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM calendar WHERE id = $1 AND is_active = true)",
    )
    .bind(calendar_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    if date_is_taken(
        &state.base.db,
        "calendar_exception",
        "exception_date",
        calendar_id,
        holiday_date,
    )
    .await?
    {
        return Err(AppError::Conflict(
            "this date already has an exception; remove it before adding a holiday on the same date",
        ));
    }
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = add_holiday_in_tx(
        &mut tx,
        &recording,
        calendar_id,
        ctx.user_id,
        body.name.trim(),
        holiday_date,
    )
    .await?;
    let op = holiday_op(&mut tx, Op::AddCalendarHoliday, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.holiday_added",
        &format!("holiday {holiday_date} added"),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row.with_hijri(&state))))
}

/// Add a yearly Hijri holiday
///
/// AG1-T6: a holiday that falls on the same Hijri date every year (Eid
/// al-Fitr is 1 Shawwal), entered once: one holiday per Hijri year from
/// `from_year` to `to_year` (at most 30 years), each on its Gregorian day
/// in the deployment's Umm al-Qura calendar, all in one transaction. A 30th
/// in a year whose month has 29 days falls on the next day, the 1st of the
/// following month, as announced holidays do. Refused whole when any day
/// already has a holiday or an exception.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/holidays/hijri-recurring",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = HijriRecurringBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "One holiday per year", body = Vec<HolidayDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such calendar", body = ErrorResponse),
        (status = 409, description = "A day already has a holiday or an exception", body = ErrorResponse),
        (status = 422, description = "A date outside the Umm al-Qura calendar, or more than 30 years", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_hijri_recurring_holidays(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(calendar_id): Path<Uuid>,
    Json(body): Json<HijriRecurringBody>,
) -> Result<(StatusCode, Json<Vec<HolidayDetail>>), AppError> {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("holiday name is required".into()));
    }
    if body.to_year < body.from_year || body.to_year - body.from_year >= MAX_RECURRING_YEARS {
        return Err(AppError::Validation(format!(
            "from_year to to_year must cover 1 to {MAX_RECURRING_YEARS} years"
        )));
    }
    if !(1..=12).contains(&body.hijri_month) || !(1..=30).contains(&body.hijri_day) {
        return Err(AppError::Validation(
            "hijri_month must be 1 to 12 and hijri_day 1 to 30".into(),
        ));
    }
    let mut dates = Vec::new();
    for year in body.from_year..=body.to_year {
        let first = gregorian_of(
            &state,
            HijriDateBody {
                year,
                month: body.hijri_month,
                day: 1,
            },
        )?;
        // The month's own day, or the day after its 29th for a missing 30th.
        let date = first
            .checked_add_days(chrono::Days::new(u64::from(body.hijri_day - 1)))
            .ok_or_else(|| AppError::Validation("the date is out of range".into()))?;
        dates.push(date);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM calendar WHERE id = $1 AND is_active = true)",
    )
    .bind(calendar_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    for date in &dates {
        if date_is_taken(
            &state.base.db,
            "calendar_exception",
            "exception_date",
            calendar_id,
            *date,
        )
        .await?
        {
            return Err(AppError::Conflict(
                "one of these dates already has an exception; remove it first",
            ));
        }
    }
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut rows = Vec::with_capacity(dates.len());
    for date in &dates {
        let row =
            add_holiday_in_tx(&mut tx, &recording, calendar_id, ctx.user_id, name, *date).await?;
        let op = holiday_op(&mut tx, Op::AddCalendarHoliday, &row).await?;
        recording.record(&mut tx, op).await?;
        rows.push(row);
    }
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Create,
        "calendar.holiday_added",
        &format!(
            "{} holidays added for Hijri {}-{} ({} to {})",
            rows.len(),
            body.hijri_month,
            body.hijri_day,
            body.from_year,
            body.to_year
        ),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(rows.into_iter().map(|r| r.with_hijri(&state)).collect()),
    ))
}

/// The calendar's name (its logical key), read inside `tx` for an op's
/// target. Any state: a retired calendar keeps its name (D-021).
async fn calendar_name_in_tx(
    tx: &mut attome_db::Tx<'_>,
    calendar_id: Uuid,
) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT name FROM calendar WHERE id = $1")
        .bind(calendar_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)
}

/// Locks the active child row `id` of `calendar_id` in `table` (a
/// compile-time constant of this file, never input) and applies the
/// owner-layer rule to it (D-785 §1). `NotFound` when there is no such row.
async fn lock_date_row_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    table: &'static str,
    calendar_id: Uuid,
    id: Uuid,
) -> Result<(), AppError> {
    let sql = format!(
        "SELECT owner_layer FROM {table} \
         WHERE id = $1 AND calendar_id = $2 AND is_active = true FOR UPDATE"
    );
    let owner: Option<String> = sqlx::query_scalar(&sql)
        .bind(id)
        .bind(calendar_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    let owner = owner.ok_or(AppError::NotFound)?;
    hooks::check_row_owner(recording, &owner)
}

/// The holiday POST's write, transaction-scoped (D-785 §3
/// `add_calendar_holiday`). The calendar-exists and date-conflict checks run
/// before it. The holiday row is stamped with the recording's layer, which
/// may differ from its calendar's.
pub(crate) async fn add_holiday_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    actor: Uuid,
    name: &str,
    holiday_date: NaiveDate,
) -> Result<HolidayDetail, AppError> {
    let layer = recording.stamp()?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO calendar_holiday (id, calendar_id, name, holiday_date, is_active, created_at, created_by, owner_layer) \
         VALUES ($1, $2, $3, $4, true, NOW(), $5, $6)",
    )
    .bind(id).bind(calendar_id).bind(name).bind(holiday_date).bind(actor)
    .bind(layer.as_str())
    .execute(&mut **tx).await.map_err(map_unique_violation)?;
    let sql = format!("{HOLIDAY_SELECT} WHERE id = $1");
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The holiday DELETE's write (a soft removal), transaction-scoped (D-785 §3
/// `remove_calendar_holiday`).
pub(crate) async fn remove_holiday_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    holiday_id: Uuid,
) -> Result<HolidayDetail, AppError> {
    lock_date_row_owner(tx, recording, "calendar_holiday", calendar_id, holiday_id).await?;
    let changed = sqlx::query(
        "UPDATE calendar_holiday SET is_active=false WHERE id=$1 AND calendar_id=$2 AND is_active=true",
    )
    .bind(holiday_id)
    .bind(calendar_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let sql = format!("{HOLIDAY_SELECT} WHERE id = $1");
    sqlx::query_as(&sql)
        .bind(holiday_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The recorded op for a holiday row: target `{calendar, date}` (D-592: a
/// holiday is identified by its date within its calendar).
async fn holiday_op(
    tx: &mut attome_db::Tx<'_>,
    op: Op,
    row: &HolidayDetail,
) -> Result<RecordedOp, AppError> {
    let calendar = calendar_name_in_tx(tx, row.calendar_id).await?;
    hooks::recorded(
        op,
        "calendar_holiday",
        row.id,
        serde_json::json!({ "calendar": calendar, "date": row.holiday_date.to_string() }),
        row,
    )
}

/// Remove a holiday
///
/// Remove a holiday. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}/holidays/{holiday_id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar"), ("holiday_id" = Uuid, Path, description = "The holiday")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_holiday(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((calendar_id, holiday_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = remove_holiday_in_tx(&mut tx, &recording, calendar_id, holiday_id).await?;
    let op = holiday_op(&mut tx, Op::RemoveCalendarHoliday, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.holiday_removed",
        &format!("holiday {holiday_id} removed"),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Whether an active row of `table` already occupies `date` in the calendar.
/// `table`/`column` are compile-time constants from this file, never input.
async fn date_is_taken(
    db: &attome_db::DbPool,
    table: &'static str,
    column: &'static str,
    calendar_id: Uuid,
    date: NaiveDate,
) -> Result<bool, AppError> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {table} WHERE calendar_id = $1 AND {column} = $2 AND is_active = true)"
    );
    sqlx::query_scalar(&sql)
        .bind(calendar_id)
        .bind(date)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

// ── Exceptions (nested under a calendar, D-592) ─────────────────────────────

/// One working range on an exception's date, minutes from local midnight.
#[derive(Serialize, Deserialize, ToSchema)]
struct CalendarTimeRange {
    start_minute: u16,
    end_minute: u16,
}

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct CalendarExceptionDetail {
    id: Uuid,
    calendar_id: Uuid,
    name: String,
    #[schema(value_type = String, format = "date")]
    exception_date: NaiveDate,
    /// Empty: the date is closed. Otherwise these ranges replace the
    /// weekday's hours for that date.
    #[schema(value_type = Vec<CalendarTimeRange>)]
    ranges: Value,
    /// Solution 7 (D-785) — the layer that owns this exception row (it may
    /// differ from its calendar's). Only a changeset of that layer may
    /// remove it.
    owner_layer: String,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CalendarExceptionBody {
    name: String,
    #[schema(value_type = String, format = "date")]
    exception_date: NaiveDate,
    /// Empty (the default) closes the date.
    #[serde(default = "empty_ranges")]
    #[schema(value_type = Vec<CalendarTimeRange>)]
    ranges: Value,
}

fn empty_ranges() -> Value {
    Value::Array(Vec::new())
}

/// Parses an exception's ranges into the sorted, validated form that is
/// stored, so equal exceptions are stored identically.
fn normalized_ranges(date: NaiveDate, ranges: &Value) -> Result<Value, AppError> {
    let parsed = attome_core::calendar::parse_exception_ranges(date, ranges)
        .map_err(|e| AppError::Validation(e.0))?;
    serde_json::to_value(parsed).map_err(AppError::internal)
}

const EXCEPTION_SELECT: &str = "SELECT id, calendar_id, name, exception_date, ranges, owner_layer \
     FROM calendar_exception";

/// A calendar's exceptions
///
/// A calendar's exceptions. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/{id}/exceptions",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    responses(
        (status = 200, description = "Success", body = Vec<CalendarExceptionDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_exceptions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(calendar_id): Path<Uuid>,
) -> Result<Json<Vec<CalendarExceptionDetail>>, AppError> {
    let sql = format!(
        "{EXCEPTION_SELECT} WHERE calendar_id = $1 AND is_active = true ORDER BY exception_date"
    );
    let rows = sqlx::query_as(&sql)
        .bind(calendar_id)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(rows))
}

/// Add a calendar exception
///
/// Add a calendar exception. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/exceptions",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = CalendarExceptionBody,
    responses(
        (status = 201, description = "Success", body = CalendarExceptionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No active calendar has this id", body = ErrorResponse),
        (status = 409, description = "The calendar already has a holiday or an exception on this date", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
)]
async fn create_exception(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(calendar_id): Path<Uuid>,
    Json(body): Json<CalendarExceptionBody>,
) -> Result<(StatusCode, Json<CalendarExceptionDetail>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("exception name is required".into()));
    }
    let ranges = normalized_ranges(body.exception_date, &body.ranges)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM calendar WHERE id = $1 AND is_active = true)",
    )
    .bind(calendar_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    // A holiday on the same date would always win (attome-calendar
    // precedence), so the exception would never apply. Best-effort, like the
    // holiday-side check: a concurrent pair still resolves to "closed".
    if date_is_taken(
        &state.base.db,
        "calendar_holiday",
        "holiday_date",
        calendar_id,
        body.exception_date,
    )
    .await?
    {
        return Err(AppError::Conflict(
            "this date is a holiday; remove the holiday before adding an exception on the same date",
        ));
    }
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = add_exception_in_tx(
        &mut tx,
        &recording,
        calendar_id,
        ctx.user_id,
        body.name.trim(),
        body.exception_date,
        &ranges,
    )
    .await?;
    let op = exception_op(&mut tx, Op::AddCalendarException, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.exception_added",
        &format!("exception {} added", body.exception_date),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row)))
}

/// The exception POST's write, transaction-scoped (D-785 §3
/// `add_calendar_exception`). `ranges` must already be normalized
/// (`normalized_ranges`); the calendar-exists and date-conflict checks run
/// before it.
pub(crate) async fn add_exception_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    actor: Uuid,
    name: &str,
    exception_date: NaiveDate,
    ranges: &Value,
) -> Result<CalendarExceptionDetail, AppError> {
    let layer = recording.stamp()?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO calendar_exception (id, calendar_id, name, exception_date, ranges, is_active, created_at, created_by, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, true, NOW(), $6, $7)",
    )
    .bind(id)
    .bind(calendar_id)
    .bind(name)
    .bind(exception_date)
    .bind(ranges)
    .bind(actor)
    .bind(layer.as_str())
    .execute(&mut **tx)
    .await
    .map_err(map_unique_violation)?;
    let sql = format!("{EXCEPTION_SELECT} WHERE id = $1");
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The exception DELETE's write (a soft removal), transaction-scoped (D-785
/// §3 `remove_calendar_exception`).
pub(crate) async fn remove_exception_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    exception_id: Uuid,
) -> Result<CalendarExceptionDetail, AppError> {
    lock_date_row_owner(
        tx,
        recording,
        "calendar_exception",
        calendar_id,
        exception_id,
    )
    .await?;
    let changed = sqlx::query(
        "UPDATE calendar_exception SET is_active=false WHERE id=$1 AND calendar_id=$2 AND is_active=true",
    )
    .bind(exception_id)
    .bind(calendar_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let sql = format!("{EXCEPTION_SELECT} WHERE id = $1");
    sqlx::query_as(&sql)
        .bind(exception_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The recorded op for an exception row: target `{calendar, exception:
/// <date>}` (D-592: an exception is identified by its date).
async fn exception_op(
    tx: &mut attome_db::Tx<'_>,
    op: Op,
    row: &CalendarExceptionDetail,
) -> Result<RecordedOp, AppError> {
    let calendar = calendar_name_in_tx(tx, row.calendar_id).await?;
    hooks::recorded(
        op,
        "calendar_exception",
        row.id,
        serde_json::json!({ "calendar": calendar, "exception": row.exception_date.to_string() }),
        row,
    )
}

/// Remove a calendar exception
///
/// Remove a calendar exception. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}/exceptions/{exception_id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar"), ("exception_id" = Uuid, Path, description = "The exception")),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No active exception has this id in this calendar", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
)]
async fn delete_exception(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((calendar_id, exception_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = remove_exception_in_tx(&mut tx, &recording, calendar_id, exception_id).await?;
    let op = exception_op(&mut tx, Op::RemoveCalendarException, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.exception_removed",
        &format!("exception {exception_id} removed"),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Holiday rules and seasons (Z12-T6) ───────────────────────────────────────

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct RuleDetail {
    id: Uuid,
    calendar_id: Uuid,
    name: String,
    name_ar: Option<String>,
    /// An `attome_calendar::rules::HolidayRule`, such as
    /// `{"kind": "hijri", "month": 10, "day": 1, "span_days": 3}`.
    #[schema(value_type = Object)]
    rule: Value,
    needs_sighting: bool,
    owner_layer: String,
}

const RULE_SELECT: &str = "SELECT id, calendar_id, name, name_ar, rule, needs_sighting, owner_layer \
     FROM calendar_holiday_rule";

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct SeasonDetail {
    id: Uuid,
    calendar_id: Uuid,
    name: String,
    name_ar: Option<String>,
    /// An `attome_calendar::rules::Season`: `start` and `end` rules and the
    /// hours per weekday between them.
    #[schema(value_type = Object)]
    definition: Value,
    owner_layer: String,
}

const SEASON_SELECT: &str =
    "SELECT id, calendar_id, name, name_ar, definition, owner_layer FROM calendar_season";

/// The current Gregorian year, for checking a rule expands.
fn this_year() -> i32 {
    use chrono::Datelike;
    chrono::Utc::now().year()
}

/// A holiday rule as given: it parses, a sighted rule is a Hijri one, and it
/// expands for this year and the next.
fn check_rule(def: &HolidayRuleDef) -> Result<attome_core::calendar::rules::HolidayRule, String> {
    use attome_core::calendar::rules::{HolidayRule, expand};
    if def.name.trim().is_empty() || def.name.len() > 200 {
        return Err("a holiday rule has a name of at most 200 characters".into());
    }
    let rule: HolidayRule = serde_json::from_value(def.rule.clone())
        .map_err(|e| format!("rule '{}': {e}", def.name))?;
    if def.needs_sighting && !matches!(rule, HolidayRule::Hijri { .. }) {
        return Err(format!(
            "rule '{}': only a Hijri holiday waits for a sighting",
            def.name
        ));
    }
    for year in [this_year(), this_year() + 1] {
        expand(&rule, year).map_err(|e| format!("rule '{}': {e}", def.name))?;
    }
    Ok(rule)
}

/// A season as given: it parses and expands for this year.
fn check_season(def: &SeasonDef) -> Result<(), String> {
    use attome_core::calendar::rules::{Season, expand_season};
    if def.name.trim().is_empty() || def.name.len() > 200 {
        return Err("a season has a name of at most 200 characters".into());
    }
    let season: Season = serde_json::from_value(def.definition.clone())
        .map_err(|e| format!("season '{}': {e}", def.name))?;
    expand_season(&season, this_year()).map_err(|e| format!("season '{}': {e}", def.name))?;
    Ok(())
}

async fn calendar_exists(db: &attome_db::DbPool, calendar_id: Uuid) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM calendar WHERE id = $1 AND is_active = true)",
    )
    .bind(calendar_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// The holiday-rule POST's write, transaction-scoped (`upsert_calendar_rule`):
/// the calendar's live rule of that name is replaced, or a new one added
/// with the recording's layer.
pub(crate) async fn upsert_rule_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    actor: Uuid,
    def: &HolidayRuleDef,
) -> Result<RuleDetail, AppError> {
    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, owner_layer FROM calendar_holiday_rule \
          WHERE calendar_id = $1 AND name = $2 AND is_active = true FOR UPDATE",
    )
    .bind(calendar_id)
    .bind(def.name.trim())
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let id = match existing {
        Some((id, owner)) => {
            hooks::check_row_owner(recording, &owner)?;
            sqlx::query(
                "UPDATE calendar_holiday_rule \
                    SET name_ar = $2, rule = $3, needs_sighting = $4, row_version = row_version + 1 \
                  WHERE id = $1",
            )
            .bind(id)
            .bind(def.name_ar.as_deref())
            .bind(&def.rule)
            .bind(def.needs_sighting)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            id
        }
        None => {
            let layer = recording.stamp()?;
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO calendar_holiday_rule \
                     (id, calendar_id, name, name_ar, rule, needs_sighting, created_by, owner_layer) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(id)
            .bind(calendar_id)
            .bind(def.name.trim())
            .bind(def.name_ar.as_deref())
            .bind(&def.rule)
            .bind(def.needs_sighting)
            .bind(actor)
            .bind(layer.as_str())
            .execute(&mut **tx)
            .await
            .map_err(map_unique_violation)?;
            id
        }
    };
    sqlx::query_as(&format!("{RULE_SELECT} WHERE id = $1"))
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The holiday-rule DELETE's write (a soft removal), transaction-scoped
/// (`retire_calendar_rule`).
pub(crate) async fn retire_rule_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    rule_id: Uuid,
) -> Result<RuleDetail, AppError> {
    lock_date_row_owner(tx, recording, "calendar_holiday_rule", calendar_id, rule_id).await?;
    sqlx::query("UPDATE calendar_holiday_rule SET is_active = false WHERE id = $1")
        .bind(rule_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query_as(&format!("{RULE_SELECT} WHERE id = $1"))
        .bind(rule_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The season POST's write, transaction-scoped (`upsert_calendar_season`).
pub(crate) async fn upsert_season_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    actor: Uuid,
    def: &SeasonDef,
) -> Result<SeasonDetail, AppError> {
    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, owner_layer FROM calendar_season \
          WHERE calendar_id = $1 AND name = $2 AND is_active = true FOR UPDATE",
    )
    .bind(calendar_id)
    .bind(def.name.trim())
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let id = match existing {
        Some((id, owner)) => {
            hooks::check_row_owner(recording, &owner)?;
            sqlx::query(
                "UPDATE calendar_season SET name_ar = $2, definition = $3, \
                        row_version = row_version + 1 WHERE id = $1",
            )
            .bind(id)
            .bind(def.name_ar.as_deref())
            .bind(&def.definition)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            id
        }
        None => {
            let layer = recording.stamp()?;
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO calendar_season \
                     (id, calendar_id, name, name_ar, definition, created_by, owner_layer) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(id)
            .bind(calendar_id)
            .bind(def.name.trim())
            .bind(def.name_ar.as_deref())
            .bind(&def.definition)
            .bind(actor)
            .bind(layer.as_str())
            .execute(&mut **tx)
            .await
            .map_err(map_unique_violation)?;
            id
        }
    };
    sqlx::query_as(&format!("{SEASON_SELECT} WHERE id = $1"))
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The season DELETE's write (a soft removal), transaction-scoped
/// (`retire_calendar_season`).
pub(crate) async fn retire_season_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    calendar_id: Uuid,
    season_id: Uuid,
) -> Result<SeasonDetail, AppError> {
    lock_date_row_owner(tx, recording, "calendar_season", calendar_id, season_id).await?;
    sqlx::query("UPDATE calendar_season SET is_active = false WHERE id = $1")
        .bind(season_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query_as(&format!("{SEASON_SELECT} WHERE id = $1"))
        .bind(season_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// The recorded op for a rule: target `{calendar, rule}` (a rule is
/// identified by its name within its calendar).
async fn rule_op(
    tx: &mut attome_db::Tx<'_>,
    op: Op,
    row: &RuleDetail,
) -> Result<RecordedOp, AppError> {
    let calendar = calendar_name_in_tx(tx, row.calendar_id).await?;
    hooks::recorded(
        op,
        "calendar_holiday_rule",
        row.id,
        serde_json::json!({ "calendar": calendar, "rule": row.name }),
        row,
    )
}

/// The recorded op for a season: target `{calendar, season}`.
async fn season_op(
    tx: &mut attome_db::Tx<'_>,
    op: Op,
    row: &SeasonDetail,
) -> Result<RecordedOp, AppError> {
    let calendar = calendar_name_in_tx(tx, row.calendar_id).await?;
    hooks::recorded(
        op,
        "calendar_season",
        row.id,
        serde_json::json!({ "calendar": calendar, "season": row.name }),
        row,
    )
}

/// Add or change a holiday rule
///
/// Z12-T6: a holiday that recurs — a fixed date, the nth weekday of a month,
/// a Hijri date (optionally waiting for a moon sighting) or a one-off date —
/// named once within the calendar; posting the same name replaces it. The
/// rule must expand for this year and the next. Administrators only.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/holiday-rules",
    operation_id = "create_calendar_rule",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = HolidayRuleDef,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 201, description = "The rule as stored", body = RuleDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such calendar", body = ErrorResponse),
        (status = 409, description = "Another layer owns the rule of that name", body = ErrorResponse),
        (status = 422, description = "A rule that does not parse or expand, or a sighting on a rule that is not Hijri", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(calendar_id): Path<Uuid>,
    Json(body): Json<HolidayRuleDef>,
) -> Result<(StatusCode, Json<RuleDetail>), AppError> {
    check_rule(&body).map_err(AppError::Validation)?;
    calendar_exists(&state.base.db, calendar_id).await?;
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = upsert_rule_in_tx(&mut tx, &recording, calendar_id, ctx.user_id, &body).await?;
    let op = rule_op(&mut tx, Op::UpsertCalendarRule, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.rule_saved",
        &format!("holiday rule '{}' saved", row.name),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Remove a holiday rule
///
/// Removes a holiday rule; its sightings go with it. Administrators only.
/// Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}/holiday-rules/{rule_id}",
    operation_id = "delete_calendar_rule",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar"), ("rule_id" = Uuid, Path, description = "The rule")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such rule on this calendar", body = ErrorResponse),
        (status = 409, description = "Another layer owns the rule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_rule(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((calendar_id, rule_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = retire_rule_in_tx(&mut tx, &recording, calendar_id, rule_id).await?;
    let op = rule_op(&mut tx, Op::RetireCalendarRule, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.rule_removed",
        &format!("holiday rule '{}' removed", row.name),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Add or change a season
///
/// Z12-T6: hours that replace the usual ones between two rules (Ramadan's
/// short day, say), named once within the calendar; posting the same name
/// replaces it. The season must expand for this year. Administrators only.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/seasons",
    operation_id = "create_calendar_season",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = SeasonDef,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 201, description = "The season as stored", body = SeasonDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such calendar", body = ErrorResponse),
        (status = 409, description = "Another layer owns the season of that name", body = ErrorResponse),
        (status = 422, description = "A season that does not parse or expand", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_season(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(calendar_id): Path<Uuid>,
    Json(body): Json<SeasonDef>,
) -> Result<(StatusCode, Json<SeasonDetail>), AppError> {
    check_season(&body).map_err(AppError::Validation)?;
    calendar_exists(&state.base.db, calendar_id).await?;
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = upsert_season_in_tx(&mut tx, &recording, calendar_id, ctx.user_id, &body).await?;
    let op = season_op(&mut tx, Op::UpsertCalendarSeason, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.season_saved",
        &format!("season '{}' saved", row.name),
    )
    .await;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Remove a season
///
/// Removes a season. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}/seasons/{season_id}",
    operation_id = "delete_calendar_season",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The calendar"), ("season_id" = Uuid, Path, description = "The season")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such season on this calendar", body = ErrorResponse),
        (status = 409, description = "Another layer owns the season", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_season(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path((calendar_id, season_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = retire_season_in_tx(&mut tx, &recording, calendar_id, season_id).await?;
    let op = season_op(&mut tx, Op::RetireCalendarSeason, &row).await?;
    recording.record(&mut tx, op).await?;
    tx.commit().await.map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.season_removed",
        &format!("season '{}' removed", row.name),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Sightings (Z12-T6) ───────────────────────────────────────────────────────

/// How far a confirmed start may sit from the expected one, in days.
const MAX_SIGHTING_SHIFT_DAYS: i64 = 3;

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct SightingBody {
    rule_id: Uuid,
    hijri_year: i32,
    /// The Gregorian day the holiday starts, as announced.
    #[schema(value_type = String, format = "date")]
    confirmed_start: NaiveDate,
}

/// One sighted holiday of a Gregorian year: when it is expected to start and,
/// once confirmed, when it does.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SightingRow {
    rule_id: Uuid,
    rule_name: String,
    calendar_id: Uuid,
    hijri_year: i32,
    #[schema(value_type = String, format = "date")]
    expected_start: NaiveDate,
    #[schema(value_type = Option<String>, format = "date")]
    confirmed_start: Option<NaiveDate>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SightingQuery {
    /// The Gregorian year; this year when absent.
    year: Option<i32>,
}

/// The first day of a sighted Hijri rule in each Hijri year that starts in
/// Gregorian `year`: `(hijri_year, expected_start)`.
fn expected_starts(
    rule: &attome_core::calendar::rules::HolidayRule,
    year: i32,
) -> Result<Vec<(i32, NaiveDate)>, AppError> {
    use attome_core::calendar::rules::{HolidayRule, expand};
    let HolidayRule::Hijri { month, day, .. } = rule else {
        return Ok(Vec::new());
    };
    let first = HolidayRule::Hijri {
        month: *month,
        day: *day,
        span_days: 1,
    };
    expand(&first, year)
        .map_err(|e| AppError::Validation(e.to_string()))?
        .into_iter()
        .map(|date| {
            attome_core::calendar::hijri::to_hijri(date)
                .map(|h| (i32::from(h.year), date))
                .map_err(|e| AppError::Validation(e.to_string()))
        })
        .collect()
}

/// Confirm a sighting
///
/// Z12-T6: the day a sighted Hijri holiday really starts this Hijri year, as
/// announced. Every calendar using the rule moves the holiday from the
/// expected day to this one. At most three days from the expected start.
/// Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/calendar-sightings",
    operation_id = "confirm_calendar_sighting",
    tag = "admin",
    request_body = SightingBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The sighting as stored", body = SightingRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active rule", body = ErrorResponse),
        (status = 422, description = "The rule waits for no sighting, or the start is too far from the expected one", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn confirm_sighting(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SightingBody>,
) -> Result<Json<SightingRow>, AppError> {
    let rule: Option<(Uuid, String, Value, bool)> = sqlx::query_as(
        "SELECT calendar_id, name, rule, needs_sighting FROM calendar_holiday_rule \
          WHERE id = $1 AND is_active = true",
    )
    .bind(body.rule_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (calendar_id, rule_name, rule, needs_sighting) = rule.ok_or(AppError::NotFound)?;
    if !needs_sighting {
        return Err(AppError::Validation(
            "this rule does not wait for a sighting".into(),
        ));
    }
    let rule: attome_core::calendar::rules::HolidayRule =
        serde_json::from_value(rule).map_err(AppError::internal)?;
    let year = {
        use chrono::Datelike;
        body.confirmed_start.year()
    };
    let mut expected = None;
    for y in [year - 1, year, year + 1] {
        if let Some((_, start)) = expected_starts(&rule, y)?
            .into_iter()
            .find(|(hy, _)| *hy == body.hijri_year)
        {
            expected = Some(start);
            break;
        }
    }
    let expected = expected.ok_or_else(|| {
        AppError::Validation(format!(
            "the rule has no start in Hijri year {} near {}",
            body.hijri_year, body.confirmed_start
        ))
    })?;
    if (body.confirmed_start - expected).num_days().abs() > MAX_SIGHTING_SHIFT_DAYS {
        return Err(AppError::Validation(format!(
            "{} is more than {MAX_SIGHTING_SHIFT_DAYS} days from the expected start {expected}",
            body.confirmed_start
        )));
    }
    sqlx::query(
        "INSERT INTO calendar_sighting (rule_id, hijri_year, confirmed_start, confirmed_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (rule_id, hijri_year) DO UPDATE \
            SET confirmed_start = EXCLUDED.confirmed_start, \
                confirmed_by = EXCLUDED.confirmed_by, confirmed_at = now()",
    )
    .bind(body.rule_id)
    .bind(body.hijri_year)
    .bind(body.confirmed_start)
    .bind(ctx.user_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    audit_calendar_change(
        &state,
        ctx.user_id,
        calendar_id,
        AuditOperation::Update,
        "calendar.sighting_confirmed",
        &format!(
            "'{rule_name}' {} starts {} (expected {expected})",
            body.hijri_year, body.confirmed_start
        ),
    )
    .await;
    Ok(Json(SightingRow {
        rule_id: body.rule_id,
        rule_name,
        calendar_id,
        hijri_year: body.hijri_year,
        expected_start: expected,
        confirmed_start: Some(body.confirmed_start),
    }))
}

/// Sightings of a year
///
/// Every sighted holiday expected to start in the Gregorian year, with the
/// start confirmed so far. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/calendar-sightings",
    operation_id = "list_calendar_sightings",
    tag = "admin",
    params(SightingQuery),
    responses(
        (status = 200, description = "Expected and confirmed starts, earliest first", body = Vec<SightingRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_sightings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<SightingQuery>,
) -> Result<Json<Vec<SightingRow>>, AppError> {
    let year = query.year.unwrap_or_else(this_year);
    let rules: Vec<(Uuid, Uuid, String, Value)> = sqlx::query_as(
        "SELECT r.id, r.calendar_id, r.name, r.rule FROM calendar_holiday_rule r \
           JOIN calendar c ON c.id = r.calendar_id AND c.is_active = true \
          WHERE r.is_active = true AND r.needs_sighting = true ORDER BY r.name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let confirmed: std::collections::HashMap<(Uuid, i32), NaiveDate> =
        sqlx::query_as::<_, (Uuid, i32, NaiveDate)>(
            "SELECT rule_id, hijri_year, confirmed_start FROM calendar_sighting",
        )
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(rule, year, start)| ((rule, year), start))
        .collect();
    let mut out = Vec::new();
    for (rule_id, calendar_id, rule_name, rule) in rules {
        let Ok(rule) = serde_json::from_value(rule) else {
            continue;
        };
        for (hijri_year, expected_start) in expected_starts(&rule, year)? {
            out.push(SightingRow {
                rule_id,
                rule_name: rule_name.clone(),
                calendar_id,
                hijri_year,
                expected_start,
                confirmed_start: confirmed.get(&(rule_id, hijri_year)).copied(),
            });
        }
    }
    out.sort_by_key(|s| (s.expected_start, s.rule_name.clone()));
    Ok(Json(out))
}

// ── Assignments (Z12-T6) ─────────────────────────────────────────────────────

/// Which calendar a person or a team works to.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub(crate) struct AssignmentRow {
    subject_type: String,
    subject_id: Uuid,
    calendar_id: Uuid,
    row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct AssignmentBody {
    calendar_id: Uuid,
    /// Required to change an assignment that exists (409 when stale).
    #[serde(default)]
    row_version: Option<i64>,
}

fn check_subject_type(subject_type: &str) -> Result<(), AppError> {
    if matches!(subject_type, "user" | "team") {
        Ok(())
    } else {
        Err(AppError::Validation("subject_type is user or team".into()))
    }
}

/// A calendar assignment
///
/// The calendar a person (`user`) or a team works to. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/calendar-assignments/{subject_type}/{subject_id}",
    operation_id = "get_calendar_assignment",
    tag = "admin",
    params(("subject_type" = String, Path, description = "`user` or `team`"), ("subject_id" = Uuid, Path, description = "The user or team")),
    responses(
        (status = 200, description = "The assignment", body = AssignmentRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No calendar is assigned", body = ErrorResponse),
        (status = 422, description = "An unknown subject type", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_assignment(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((subject_type, subject_id)): Path<(String, Uuid)>,
) -> Result<Json<AssignmentRow>, AppError> {
    check_subject_type(&subject_type)?;
    sqlx::query_as(
        "SELECT subject_type, subject_id, calendar_id, row_version FROM calendar_assignment \
          WHERE subject_type = $1 AND subject_id = $2",
    )
    .bind(&subject_type)
    .bind(subject_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .map(Json)
    .ok_or(AppError::NotFound)
}

/// Assign a calendar
///
/// Sets the calendar a person or a team works to; their business time is
/// counted on it. Administrators only. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/calendar-assignments/{subject_type}/{subject_id}",
    operation_id = "put_calendar_assignment",
    tag = "admin",
    params(("subject_type" = String, Path, description = "`user` or `team`"), ("subject_id" = Uuid, Path, description = "The user or team")),
    request_body = AssignmentBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The assignment as stored", body = AssignmentRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active calendar", body = ErrorResponse),
        (status = 409, description = "The assignment exists and `row_version` is missing or stale", body = ErrorResponse),
        (status = 422, description = "An unknown subject type", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_assignment(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((subject_type, subject_id)): Path<(String, Uuid)>,
    Json(body): Json<AssignmentBody>,
) -> Result<Json<AssignmentRow>, AppError> {
    check_subject_type(&subject_type)?;
    calendar_exists(&state.base.db, body.calendar_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM calendar_assignment \
          WHERE subject_type = $1 AND subject_id = $2 FOR UPDATE",
    )
    .bind(&subject_type)
    .bind(subject_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row: AssignmentRow = match current {
        None => sqlx::query_as(
            "INSERT INTO calendar_assignment (subject_type, subject_id, calendar_id) \
             VALUES ($1, $2, $3) \
             RETURNING subject_type, subject_id, calendar_id, row_version",
        )
        .bind(&subject_type)
        .bind(subject_id)
        .bind(body.calendar_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique_violation)?,
        Some(version) => {
            if body.row_version != Some(version) {
                return Err(AppError::VersionConflict);
            }
            sqlx::query_as(
                "UPDATE calendar_assignment SET calendar_id = $3, row_version = row_version + 1 \
                  WHERE subject_type = $1 AND subject_id = $2 \
                 RETURNING subject_type, subject_id, calendar_id, row_version",
            )
            .bind(&subject_type)
            .bind(subject_id)
            .bind(body.calendar_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?
        }
    };
    tx.commit().await.map_err(AppError::internal)?;
    attome_audit::write_business_event(
        &state,
        "calendar_assignment",
        subject_id,
        AuditOperation::Update,
        "calendar.assigned",
        ctx.user_id,
        None,
        None,
        format!(
            "{subject_type} {subject_id} works to calendar {}",
            body.calendar_id
        ),
    )
    .await;
    Ok(Json(row))
}

/// Remove a calendar assignment
///
/// The person or team works to the default calendar again. Administrators
/// only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/calendar-assignments/{subject_type}/{subject_id}",
    operation_id = "delete_calendar_assignment",
    tag = "admin",
    params(("subject_type" = String, Path, description = "`user` or `team`"), ("subject_id" = Uuid, Path, description = "The user or team")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No calendar is assigned", body = ErrorResponse),
        (status = 422, description = "An unknown subject type", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_assignment(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((subject_type, subject_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, AppError> {
    check_subject_type(&subject_type)?;
    let removed =
        sqlx::query("DELETE FROM calendar_assignment WHERE subject_type = $1 AND subject_id = $2")
            .bind(&subject_type)
            .bind(subject_id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::write_business_event(
        &state,
        "calendar_assignment",
        subject_id,
        AuditOperation::Update,
        "calendar.unassigned",
        ctx.user_id,
        None,
        None,
        format!("{subject_type} {subject_id} no longer has its own calendar"),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Service reconcile API (P-environment-promotion §5 step 13) ────────────────

#[derive(sqlx::FromRow)]
struct CalendarProbeRow {
    id: Uuid,
    description: Option<String>,
    tz: String,
    working_days: Vec<String>,
    hours: Value,
    is_default: bool,
    is_active: bool,
    is_customized: bool,
    parent_calendar_id: Option<Uuid>,
    country_code: Option<String>,
    name_ar: Option<String>,
}

/// Z12-T6: whether the calendar's live rules (or seasons) differ from the
/// bundle's, by name and content. `table`/`content` are constants of this
/// file.
async fn live_named_differ(
    db: &attome_db::DbPool,
    table: &'static str,
    content: &'static str,
    calendar_id: Uuid,
    desired: &std::collections::BTreeMap<String, Value>,
) -> Result<bool, AppError> {
    let rows: Vec<(String, Value)> = sqlx::query_as(&format!(
        "SELECT name, {content} FROM {table} WHERE calendar_id = $1 AND is_active = true"
    ))
    .bind(calendar_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let live: std::collections::BTreeMap<String, Value> = rows.into_iter().collect();
    Ok(&live != desired)
}

/// A bundle's rules as the comparison sees them: name to its stored content.
fn rule_contents(rules: &[HolidayRuleDef]) -> std::collections::BTreeMap<String, Value> {
    rules
        .iter()
        .map(|r| {
            (
                r.name.trim().to_owned(),
                serde_json::json!({ "name_ar": r.name_ar, "rule": r.rule, "needs_sighting": r.needs_sighting }),
            )
        })
        .collect()
}

/// A bundle's seasons as the comparison sees them.
fn season_contents(seasons: &[SeasonDef]) -> std::collections::BTreeMap<String, Value> {
    seasons
        .iter()
        .map(|s| {
            (
                s.name.trim().to_owned(),
                serde_json::json!({ "name_ar": s.name_ar, "definition": s.definition }),
            )
        })
        .collect()
}

/// Z12-T6: makes the calendar's live rules exactly `rules`, by name.
async fn reconcile_rules(
    tx: &mut attome_db::Tx<'_>,
    calendar_id: Uuid,
    rules: &[HolidayRuleDef],
    layer: Layer,
) -> Result<(), AppError> {
    let names: Vec<String> = rules.iter().map(|r| r.name.trim().to_owned()).collect();
    sqlx::query(
        "UPDATE calendar_holiday_rule SET is_active = false \
          WHERE calendar_id = $1 AND is_active = true AND NOT (name = ANY($2))",
    )
    .bind(calendar_id)
    .bind(&names)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for rule in rules {
        let updated = sqlx::query(
            "UPDATE calendar_holiday_rule \
                SET name_ar = $3, rule = $4, needs_sighting = $5, row_version = row_version + 1 \
              WHERE calendar_id = $1 AND name = $2 AND is_active = true",
        )
        .bind(calendar_id)
        .bind(rule.name.trim())
        .bind(rule.name_ar.as_deref())
        .bind(&rule.rule)
        .bind(rule.needs_sighting)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                "INSERT INTO calendar_holiday_rule \
                     (id, calendar_id, name, name_ar, rule, needs_sighting, owner_layer) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(Uuid::now_v7())
            .bind(calendar_id)
            .bind(rule.name.trim())
            .bind(rule.name_ar.as_deref())
            .bind(&rule.rule)
            .bind(rule.needs_sighting)
            .bind(layer.as_str())
            .execute(&mut **tx)
            .await
            .map_err(map_unique_violation)?;
        }
    }
    Ok(())
}

/// Z12-T6: makes the calendar's live seasons exactly `seasons`, by name.
async fn reconcile_seasons(
    tx: &mut attome_db::Tx<'_>,
    calendar_id: Uuid,
    seasons: &[SeasonDef],
    layer: Layer,
) -> Result<(), AppError> {
    let names: Vec<String> = seasons.iter().map(|s| s.name.trim().to_owned()).collect();
    sqlx::query(
        "UPDATE calendar_season SET is_active = false \
          WHERE calendar_id = $1 AND is_active = true AND NOT (name = ANY($2))",
    )
    .bind(calendar_id)
    .bind(&names)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for season in seasons {
        let updated = sqlx::query(
            "UPDATE calendar_season SET name_ar = $3, definition = $4, \
                    row_version = row_version + 1 \
              WHERE calendar_id = $1 AND name = $2 AND is_active = true",
        )
        .bind(calendar_id)
        .bind(season.name.trim())
        .bind(season.name_ar.as_deref())
        .bind(&season.definition)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                "INSERT INTO calendar_season (id, calendar_id, name, name_ar, definition, owner_layer) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(Uuid::now_v7())
            .bind(calendar_id)
            .bind(season.name.trim())
            .bind(season.name_ar.as_deref())
            .bind(&season.definition)
            .bind(layer.as_str())
            .execute(&mut **tx)
            .await
            .map_err(map_unique_violation)?;
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct HolidayProbeRow {
    id: Uuid,
    name: String,
    holiday_date: NaiveDate,
}

#[derive(sqlx::FromRow)]
struct ExceptionProbeRow {
    id: Uuid,
    name: String,
    exception_date: NaiveDate,
    ranges: Value,
}

/// A bundle's holidays and exceptions, validated and keyed by date (D-592).
/// `exceptions` is `None` when the bundle does not manage them.
struct DesiredDates {
    holidays: std::collections::BTreeMap<NaiveDate, String>,
    exceptions: Option<std::collections::BTreeMap<NaiveDate, (String, Value)>>,
}

/// Rejects what the admin API would refuse one row at a time: two holidays or
/// two exceptions on one date, a holiday and an exception on the same date,
/// and malformed exception ranges. Exception ranges come back normalized.
fn desired_dates(
    holidays: &[HolidayDef],
    exceptions: Option<&[CalendarExceptionDef]>,
) -> Result<DesiredDates, InvalidCalendarDefinition> {
    let invalid = |message: String| InvalidCalendarDefinition(message);
    let mut by_date = std::collections::BTreeMap::new();
    for h in holidays {
        if h.name.trim().is_empty() {
            return Err(invalid(format!("holiday {} has no name", h.holiday_date)));
        }
        if by_date
            .insert(h.holiday_date, h.name.trim().to_string())
            .is_some()
        {
            return Err(invalid(format!(
                "holiday {} is listed more than once",
                h.holiday_date
            )));
        }
    }
    let exceptions = match exceptions {
        None => None,
        Some(list) => {
            let mut map = std::collections::BTreeMap::new();
            for e in list {
                let date = e.exception_date;
                if e.name.trim().is_empty() {
                    return Err(invalid(format!("exception {date} has no name")));
                }
                if by_date.contains_key(&date) {
                    return Err(invalid(format!(
                        "{date} is both a holiday and an exception; a holiday always wins, so keep one"
                    )));
                }
                let parsed = attome_core::calendar::parse_exception_ranges(date, &e.ranges)?;
                let ranges =
                    serde_json::to_value(parsed).map_err(|err| invalid(err.to_string()))?;
                if map
                    .insert(date, (e.name.trim().to_string(), ranges))
                    .is_some()
                {
                    return Err(invalid(format!(
                        "exception {date} is listed more than once"
                    )));
                }
            }
            Some(map)
        }
    };
    Ok(DesiredDates {
        holidays: by_date,
        exceptions,
    })
}

/// Create-or-update one calendar (and reconcile its holiday list) to match
/// `desc`, keyed by `name`. Compare-first, same `Seed`/`Admin`/`Bundle`
/// semantics as `view_admin::reconcile_view`. Returns `(calendar_id,
/// outcome)`.
pub async fn reconcile_calendar(
    state: &EngineState,
    desc: &CalendarDef,
    policy: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("calendar name is required".into()));
    }
    let tz = desc.tz.trim();
    // D-517 — a bundle cannot promote a calendar the runtime would reject.
    attome_core::calendar::validate_definition(tz, &desc.working_days, &desc.hours)
        .map_err(|e| AppError::Validation(format!("calendar '{name}': {}", e.0)))?;
    let desired = desired_dates(&desc.holidays, desc.exceptions.as_deref())
        .map_err(|e| AppError::Validation(format!("calendar '{name}': {}", e.0)))?;
    // Z12-T6: rules and seasons a bundle carries are checked as the admin
    // routes check them.
    for rule in desc.rules.iter().flatten() {
        check_rule(rule).map_err(|e| AppError::Validation(format!("calendar '{name}': {e}")))?;
    }
    for season in desc.seasons.iter().flatten() {
        check_season(season)
            .map_err(|e| AppError::Validation(format!("calendar '{name}': {e}")))?;
    }
    let db = &state.base.db;
    let desired_parent: Option<Uuid> = match desc.parent.as_deref().map(str::trim) {
        Some(parent) if !parent.is_empty() => Some(
            sqlx::query_scalar("SELECT id FROM calendar WHERE name = $1 AND is_active = true")
                .bind(parent)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
                .ok_or_else(|| {
                    AppError::Validation(format!(
                        "calendar '{name}': its parent '{parent}' is not an active calendar"
                    ))
                })?,
        ),
        _ => None,
    };

    let current: Option<CalendarProbeRow> = sqlx::query_as(
        "SELECT id, description, tz, working_days, hours, is_default, is_active, is_customized, \
                parent_calendar_id, country_code, name_ar \
         FROM calendar WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    // Holidays and exceptions are part of the calendar's state: before D-592
    // a bundle that changed only its holidays reconciled as Unchanged and
    // never applied them.
    let dates_differ = match current.as_ref() {
        Some(row) => live_dates_differ(db, row.id, &desired).await?,
        None => false,
    };
    // Z12-T6: rules and seasons, when the bundle carries them.
    let named_differ = match current.as_ref() {
        Some(row) => {
            let rules = match &desc.rules {
                Some(rules) => {
                    live_named_differ(
                        db,
                        "calendar_holiday_rule",
                        "jsonb_build_object('name_ar', name_ar, 'rule', rule, 'needs_sighting', needs_sighting)",
                        row.id,
                        &rule_contents(rules),
                    )
                    .await?
                }
                None => false,
            };
            let seasons = match &desc.seasons {
                Some(seasons) => {
                    live_named_differ(
                        db,
                        "calendar_season",
                        "jsonb_build_object('name_ar', name_ar, 'definition', definition)",
                        row.id,
                        &season_contents(seasons),
                    )
                    .await?
                }
                None => false,
            };
            rules || seasons
        }
        None => false,
    };
    let state_differs = current.as_ref().is_some_and(|row| {
        row.description != desc.description
            || row.tz != tz
            || row.working_days != desc.working_days
            || row.hours != desc.hours
            || row.is_default != desc.is_default
            || dates_differ
            || named_differ
            || (desired_parent.is_some() && row.parent_calendar_id != desired_parent)
            || (desc.country_code.is_some() && row.country_code != desc.country_code)
            || (desc.name_ar.is_some() && row.name_ar != desc.name_ar)
    });
    let status = current.as_ref().map(|r| (r.is_customized, r.is_active));
    let step = reconcile_step(policy, status, state_differs);

    let id = match step {
        ReconcileStep::Unchanged => current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?,
        ReconcileStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(calendar = %name, "calendar reconcile: seed skipped a customized calendar (is_customized = true)");
            id
        }
        ReconcileStep::Create | ReconcileStep::Update => {
            // The layer rows this reconcile inserts are stamped with (D-785).
            let layer = hooks::reconcile_layer(policy);
            let mut tx = attome_db::tx::begin(db).await?;
            let existing = current.as_ref().map(|r| r.id);
            if desc.is_default {
                clear_other_defaults(&mut tx, existing).await?;
            }
            let id = match existing {
                Some(id) => {
                    let n = sqlx::query(
                        "UPDATE calendar \
                         SET description = $2, tz = $3, working_days = $4, hours = $5, is_default = $6, \
                             is_active = true, is_customized = COALESCE($7, is_customized) \
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(&desc.description)
                    .bind(tz)
                    .bind(&desc.working_days)
                    .bind(&desc.hours)
                    .bind(desc.is_default)
                    .bind(customized_marker(policy))
                    .execute(&mut *tx)
                    .await
                    .map_err(map_unique_violation)?
                    .rows_affected();
                    if n != 1 {
                        return Err(AppError::Conflict("calendar row vanished during reconcile"));
                    }
                    id
                }
                None => {
                    let id = Uuid::now_v7();
                    sqlx::query(
                        "INSERT INTO calendar \
                             (id, name, description, tz, working_days, hours, is_default, is_active, is_customized, created_at, \
                              owner_layer) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, NOW(), $9)",
                    )
                    .bind(id)
                    .bind(name)
                    .bind(&desc.description)
                    .bind(tz)
                    .bind(&desc.working_days)
                    .bind(&desc.hours)
                    .bind(desc.is_default)
                    .bind(customized_marker(policy).unwrap_or(false))
                    .bind(layer.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(map_unique_violation)?;
                    id
                }
            };
            reconcile_holidays(&mut tx, id, &desired.holidays, layer).await?;
            if let Some(exceptions) = &desired.exceptions {
                reconcile_exceptions(&mut tx, id, exceptions, layer).await?;
            }
            // Z12-T6: inheritance, country, Arabic name, rules and seasons,
            // each only when the bundle carries it.
            if let Some(parent) = desired_parent {
                check_parent_in_tx(&mut tx, id, parent).await?;
                sqlx::query("UPDATE calendar SET parent_calendar_id = $2 WHERE id = $1")
                    .bind(id)
                    .bind(parent)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            }
            if desc.country_code.is_some() || desc.name_ar.is_some() {
                sqlx::query(
                    "UPDATE calendar SET country_code = COALESCE($2, country_code), \
                            name_ar = COALESCE($3, name_ar) WHERE id = $1",
                )
                .bind(id)
                .bind(desc.country_code.as_deref())
                .bind(desc.name_ar.as_deref())
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
            if let Some(rules) = &desc.rules {
                reconcile_rules(&mut tx, id, rules, layer).await?;
            }
            if let Some(seasons) = &desc.seasons {
                reconcile_seasons(&mut tx, id, seasons, layer).await?;
            }
            tx.commit().await.map_err(AppError::internal)?;
            id
        }
    };
    let outcome = step.outcome();
    tracing::info!(calendar = %name, ?outcome, ?policy, "calendar reconcile: reconciled calendar");
    Ok((id, outcome))
}

/// Whether the calendar's live holidays (or, when the bundle manages them,
/// its exceptions) differ from `desired`, compared by date, name and
/// normalized ranges.
async fn live_dates_differ(
    db: &attome_db::DbPool,
    calendar_id: Uuid,
    desired: &DesiredDates,
) -> Result<bool, AppError> {
    let holidays: Vec<HolidayProbeRow> = sqlx::query_as(
        "SELECT id, name, holiday_date FROM calendar_holiday \
         WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let live_holidays: std::collections::BTreeMap<NaiveDate, &str> = holidays
        .iter()
        .map(|h| (h.holiday_date, h.name.as_str()))
        .collect();
    let desired_holidays: std::collections::BTreeMap<NaiveDate, &str> = desired
        .holidays
        .iter()
        .map(|(date, name)| (*date, name.as_str()))
        .collect();
    if live_holidays != desired_holidays {
        return Ok(true);
    }
    let Some(desired_exceptions) = &desired.exceptions else {
        return Ok(false);
    };
    let exceptions: Vec<ExceptionProbeRow> = sqlx::query_as(
        "SELECT id, name, exception_date, ranges FROM calendar_exception \
         WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if exceptions.len() != desired_exceptions.len() {
        return Ok(true);
    }
    Ok(exceptions.iter().any(|row| {
        desired_exceptions
            .get(&row.exception_date)
            .is_none_or(|(name, ranges)| *name != row.name || *ranges != row.ranges)
    }))
}

/// Makes `calendar_holiday` for `calendar_id` match `desired`
/// exactly, keyed by `holiday_date` (D-592): deletes (soft) any date not in
/// `desired`, relabels a changed name, inserts any new date. Runs inside the
/// caller's transaction, same all-or-nothing unit as the calendar row itself.
/// Before D-592 this was keyed by name, so next year's "Eid al-Fitr" moved
/// this year's instead of being added. New rows are stamped `layer` (D-785).
async fn reconcile_holidays(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    calendar_id: Uuid,
    desired: &std::collections::BTreeMap<NaiveDate, String>,
    layer: Layer,
) -> Result<(), AppError> {
    let current: Vec<HolidayProbeRow> = sqlx::query_as(
        "SELECT id, name, holiday_date FROM calendar_holiday \
         WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let mut current_by_date = std::collections::HashMap::new();
    for row in &current {
        if desired.contains_key(&row.holiday_date) {
            current_by_date.insert(row.holiday_date, row);
            continue;
        }
        sqlx::query("UPDATE calendar_holiday SET is_active = false WHERE id = $1")
            .bind(row.id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    }

    for (date, name) in desired {
        match current_by_date.get(date) {
            Some(row) if row.name == *name => {}
            Some(row) => {
                sqlx::query("UPDATE calendar_holiday SET name = $2 WHERE id = $1")
                    .bind(row.id)
                    .bind(name)
                    .execute(&mut **tx)
                    .await
                    .map_err(AppError::internal)?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO calendar_holiday (id, calendar_id, name, holiday_date, is_active, created_at, owner_layer) \
                     VALUES ($1, $2, $3, $4, true, NOW(), $5)",
                )
                .bind(Uuid::now_v7())
                .bind(calendar_id)
                .bind(name)
                .bind(date)
                .bind(layer.as_str())
                .execute(&mut **tx)
                .await
                .map_err(map_unique_violation)?;
            }
        }
    }
    Ok(())
}

/// The exceptions counterpart of [`reconcile_holidays`]: same exact-mirror
/// semantics, keyed by `exception_date`, `ranges` already normalized.
async fn reconcile_exceptions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    calendar_id: Uuid,
    desired: &std::collections::BTreeMap<NaiveDate, (String, Value)>,
    layer: Layer,
) -> Result<(), AppError> {
    let current: Vec<ExceptionProbeRow> = sqlx::query_as(
        "SELECT id, name, exception_date, ranges FROM calendar_exception \
         WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let mut current_by_date = std::collections::HashMap::new();
    for row in &current {
        if desired.contains_key(&row.exception_date) {
            current_by_date.insert(row.exception_date, row);
            continue;
        }
        sqlx::query("UPDATE calendar_exception SET is_active = false WHERE id = $1")
            .bind(row.id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    }

    for (date, (name, ranges)) in desired {
        match current_by_date.get(date) {
            Some(row) if row.name == *name && row.ranges == *ranges => {}
            Some(row) => {
                sqlx::query("UPDATE calendar_exception SET name = $2, ranges = $3 WHERE id = $1")
                    .bind(row.id)
                    .bind(name)
                    .bind(ranges)
                    .execute(&mut **tx)
                    .await
                    .map_err(AppError::internal)?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO calendar_exception (id, calendar_id, name, exception_date, ranges, is_active, created_at, owner_layer) \
                     VALUES ($1, $2, $3, $4, $5, true, NOW(), $6)",
                )
                .bind(Uuid::now_v7())
                .bind(calendar_id)
                .bind(name)
                .bind(date)
                .bind(ranges)
                .bind(layer.as_str())
                .execute(&mut **tx)
                .await
                .map_err(map_unique_violation)?;
            }
        }
    }
    Ok(())
}

/// Soft-retire (`is_active = false`) the calendar named `name`. Idempotent.
/// Never drops, and never touches its holiday rows (an inactive calendar's
/// holidays are already unreachable through every read path).
/// D-517: refuses (409) while an active SLA policy still references it, same
/// guard as the admin delete — a promoted bundle must not strand live SLAs.
pub async fn retire_calendar(
    state: &EngineState,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    let calendar_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM calendar WHERE name = $1 AND is_active = true")
            .bind(name.trim())
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(calendar_id) = calendar_id else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    ensure_not_referenced_by_sla_policies(&state.base.db, calendar_id).await?;
    let n = sqlx::query(
        "UPDATE calendar SET is_active = false, is_default = false \
         WHERE id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    tracing::info!(calendar = %name, "calendar reconcile: retired");
    Ok(ReconcileOutcome::Updated)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/calendars",
            get(list_calendars).post(create_calendar),
        )
        .route(
            "/api/v1/admin/calendars/{id}",
            get(get_calendar)
                .patch(update_calendar)
                .delete(delete_calendar),
        )
        .route(
            "/api/v1/admin/calendars/{id}/holidays",
            get(list_holidays).post(create_holiday),
        )
        .route(
            "/api/v1/admin/calendars/{id}/holidays/hijri-recurring",
            axum::routing::post(create_hijri_recurring_holidays),
        )
        .route(
            "/api/v1/admin/calendars/{id}/holidays/{holiday_id}",
            axum::routing::delete(delete_holiday),
        )
        .route(
            "/api/v1/admin/calendars/{id}/exceptions",
            get(list_exceptions).post(create_exception),
        )
        .route(
            "/api/v1/admin/calendars/{id}/exceptions/{exception_id}",
            axum::routing::delete(delete_exception),
        )
        .route(
            "/api/v1/admin/calendars/{id}/holiday-rules",
            axum::routing::post(create_rule),
        )
        .route(
            "/api/v1/admin/calendars/{id}/holiday-rules/{rule_id}",
            axum::routing::delete(delete_rule),
        )
        .route(
            "/api/v1/admin/calendars/{id}/seasons",
            axum::routing::post(create_season),
        )
        .route(
            "/api/v1/admin/calendars/{id}/seasons/{season_id}",
            axum::routing::delete(delete_season),
        )
        .route(
            "/api/v1/calendar-sightings",
            get(list_sightings).post(confirm_sighting),
        )
        .route(
            "/api/v1/calendar-assignments/{subject_type}/{subject_id}",
            get(get_assignment)
                .put(put_assignment)
                .delete(delete_assignment),
        )
        .route(
            "/api/v1/calendars/{id}/calculate",
            axum::routing::post(calculate),
        )
        .route("/api/v1/admin/hijri-months", get(list_hijri_months))
        .route(
            "/api/v1/admin/hijri-months/{year}/{month}",
            axum::routing::put(correct_hijri_month),
        )
}

/// Z12-T10: one business-time question for a calendar.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum CalculateOp {
    /// `minutes` of working time after `from`.
    Add,
    /// The working minutes between `from` and `to`.
    Between,
    /// The first working moment at or after `from`.
    Next,
    /// Whether `from` is inside working time.
    IsWorking,
}

/// Z12-T10: `POST /api/v1/calendars/{id}/calculate`'s body.
#[derive(Debug, Deserialize, ToSchema)]
struct CalculateRequest {
    op: CalculateOp,
    from: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    to: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    minutes: Option<i64>,
    /// Answer on this person's calendar, with their absences, instead of
    /// `{id}`. Only the caller themselves, or an administrator.
    #[serde(default)]
    user_id: Option<Uuid>,
}

/// Z12-T10: the answer, and what it was computed against.
#[derive(Debug, Serialize, ToSchema)]
struct CalculateResponse {
    /// A timestamp for `add` and `next`, minutes for `between`, a boolean
    /// for `is_working`.
    result: Value,
    calendar_id: Uuid,
    calendar_version: i32,
    content_hash: String,
}

/// Business-time arithmetic
///
/// Z12-T10: business-time arithmetic on a calendar, for any signed-in
/// caller: the same answers SLA clocks use, with the calendar version and
/// content hash they were computed against.
#[utoipa::path(
    post,
    path = "/api/v1/calendars/{id}/calculate",
    tag = "calendars",
    params(("id" = Uuid, Path, description = "The calendar")),
    request_body = CalculateRequest,
    responses(
        (status = 200, description = "The answer, with the calendar version and hash", body = CalculateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Asked about another person's calendar without being an administrator", body = ErrorResponse),
        (status = 404, description = "No such active calendar", body = ErrorResponse),
        (status = 422, description = "A missing operand, or a calendar that cannot answer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "pure calculation; writes nothing")))),
)]
async fn calculate(
    State(state): State<EngineState>,
    ctx: Authorized<attome_server::authz::SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<CalculateRequest>,
) -> Result<Json<CalculateResponse>, AppError> {
    let db = &state.base.db;
    let loaded = match body.user_id {
        Some(user) if user != ctx.user_id && !ctx.is_admin => return Err(AppError::Forbidden),
        Some(user) => attome_core::calendar::load_calendar_for_user(db, user).await?,
        None => attome_core::calendar::load_calendar(db, id).await?,
    };
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(attome_core::calendar::CalendarUnresolved::NotFound) => return Err(AppError::NotFound),
        Err(unresolved) => return Err(AppError::Validation(unresolved.to_string())),
    };
    let calendar = &loaded.calendar;
    let result = match body.op {
        CalculateOp::Add => {
            let minutes = body
                .minutes
                .ok_or_else(|| AppError::Validation("add needs minutes".into()))?;
            if minutes < 0 {
                return Err(AppError::Validation("minutes must not be negative".into()));
            }
            let duration = chrono::Duration::try_minutes(minutes)
                .ok_or_else(|| AppError::Validation("minutes is too large".into()))?;
            let at = calendar
                .add_business_duration(body.from, duration)
                .map_err(|e| AppError::Validation(e.to_string()))?;
            serde_json::json!(at)
        }
        CalculateOp::Between => {
            let to = body
                .to
                .ok_or_else(|| AppError::Validation("between needs to".into()))?;
            let span = calendar
                .business_duration_between(body.from, to)
                .map_err(|e| AppError::Validation(e.to_string()))?;
            serde_json::json!(span.num_minutes())
        }
        CalculateOp::Next => {
            let at = calendar
                .next_working_moment(body.from)
                .map_err(|e| AppError::Validation(e.to_string()))?;
            serde_json::json!(at)
        }
        CalculateOp::IsWorking => serde_json::json!(calendar.is_working(body.from)),
    };
    Ok(Json(CalculateResponse {
        result,
        calendar_id: loaded.id,
        calendar_version: loaded.version,
        content_hash: loaded.content_hash,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct HijriYearQuery {
    /// The Hijri year, 1356 to 1500.
    year: u16,
}

/// Hijri months of a year
///
/// AG1-T3: one Hijri year's months as this deployment counts them, the
/// published Umm al-Qura starts with any moon-sighting corrections.
/// Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/hijri-months",
    tag = "admin",
    params(HijriYearQuery),
    responses(
        (status = 200, description = "The year's twelve months", body = PaginatedResponse<attome_core::hijri_store::HijriMonthRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "Year outside 1356 to 1500", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_hijri_months(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<HijriYearQuery>,
) -> Result<Json<PaginatedResponse<attome_core::hijri_store::HijriMonthRow>>, AppError> {
    let months = attome_core::hijri_store::year_months(&state.base.db, query.year).await?;
    let total = i64::try_from(months.len()).unwrap_or(12);
    Ok(Json(PaginatedResponse::new(months, total, 1, 12)))
}

/// `PUT /api/v1/admin/hijri-months/{year}/{month}`.
#[derive(Deserialize, ToSchema)]
struct HijriCorrection {
    /// The Gregorian day the month starts on, as announced.
    gregorian_start: NaiveDate,
    /// Who announced it, or why; kept on the audit event.
    reason: String,
}

/// Correct a Hijri month start
///
/// AG1-T3: a moon-sighting correction. The month starts on
/// `gregorian_start` (at most one day from the published table) and the
/// month before it ends the day before; both stay 29 or 30 days. Every node
/// uses the corrected calendar within 20 seconds, this one at once.
/// Administrators only; not a promotable metadata change, so it works on the
/// production profile.
#[utoipa::path(
    put,
    path = "/api/v1/admin/hijri-months/{year}/{month}",
    tag = "admin",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    params(
        ("year" = u16, Path, description = "The Hijri year"),
        ("month" = u8, Path, description = "The Hijri month, 1 to 12"),
    ),
    request_body = HijriCorrection,
    responses(
        (status = 200, description = "The year's months after the correction", body = PaginatedResponse<attome_core::hijri_store::HijriMonthRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 409, description = "Another correction is being saved", body = ErrorResponse),
        (status = 422, description = "A move of more than one day, or a month outside 29-30 days", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn correct_hijri_month(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((year, month)): Path<(u16, u8)>,
    Json(body): Json<HijriCorrection>,
) -> Result<Json<PaginatedResponse<attome_core::hijri_store::HijriMonthRow>>, AppError> {
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(AppError::Validation(
            "reason must be 1 to 500 characters".into(),
        ));
    }
    let event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Configuration,
        AuditOperation::Update,
        ctx.user_id,
        "hijri_month",
        None,
    )
    .named(format!("hijri_month.sighting:{year}-{month:02}"))
    .comment(reason.to_owned());
    let mut stx = attome_audit::security::SecurityTx::begin(&state, event).await?;
    let corrected = attome_core::hijri_store::correct_month_start_in(
        &mut stx,
        year,
        month,
        body.gregorian_start,
    )
    .await?;
    stx.commit().await?;
    state.hijri.store(std::sync::Arc::new(corrected));
    let months = attome_core::hijri_store::year_months(&state.base.db, year).await?;
    let total = i64::try_from(months.len()).unwrap_or(12);
    Ok(Json(PaginatedResponse::new(months, total, 1, 12)))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged upward by `attome_api::openapi_document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_calendars,
    get_calendar,
    create_calendar,
    update_calendar,
    delete_calendar,
    list_holidays,
    create_holiday,
    create_hijri_recurring_holidays,
    delete_holiday,
    list_exceptions,
    create_exception,
    delete_exception,
    list_hijri_months,
    correct_hijri_month,
    calculate,
    create_rule,
    delete_rule,
    create_season,
    delete_season,
    confirm_sighting,
    list_sightings,
    get_assignment,
    put_assignment,
    delete_assignment
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(working_days: &[&str], hours: Value) -> CalendarBody {
        CalendarBody {
            name: "UAE HQ".into(),
            description: None,
            tz: "Asia/Dubai".into(),
            working_days: working_days.iter().map(|d| d.to_string()).collect(),
            hours,
            is_default: false,
            parent_calendar_id: None,
            country_code: None,
            name_ar: None,
        }
    }

    fn rejection(body: &CalendarBody) -> String {
        match validate_body(body) {
            Err(AppError::Validation(message)) => message,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    fn nine_to_five() -> Value {
        json!([{ "start_minute": 540, "end_minute": 1020 }])
    }

    /// The shape the admin calendar editor sends: hours only for working days.
    #[test]
    fn the_admin_editors_shape_is_accepted() {
        let hours = json!({ "sun": nine_to_five(), "mon": nine_to_five() });
        assert!(validate_body(&body(&["sun", "mon"], hours)).is_ok());
        assert!(validate_body(&body(&[], json!({}))).is_ok());
    }

    /// D-517: before this, `"monday"` was stored and then silently dropped
    /// on load, leaving a calendar with no working time.
    #[test]
    fn an_unknown_weekday_is_rejected_at_the_door() {
        let hours = json!({ "monday": nine_to_five() });
        assert!(rejection(&body(&["monday"], hours)).contains("'monday' is not a weekday"));
    }

    #[test]
    fn overlapping_and_misplaced_hours_are_rejected() {
        let overlapping = json!({ "mon": [
            { "start_minute": 540, "end_minute": 780 },
            { "start_minute": 720, "end_minute": 1020 },
        ]});
        assert!(rejection(&body(&["mon"], overlapping)).contains("overlap"));
        let saturday_hours = json!({ "mon": nine_to_five(), "sat": nine_to_five() });
        assert!(rejection(&body(&["mon"], saturday_hours)).contains("'sat'"));
    }

    #[test]
    fn a_calendar_op_targets_the_calendar_by_name() {
        let row = CalendarDetail {
            id: Uuid::now_v7(),
            name: "UAE HQ".into(),
            description: None,
            tz: "Asia/Dubai".into(),
            working_days: vec!["sun".into()],
            hours: json!({}),
            is_default: false,
            is_active: true,
            owner_layer: "project".into(),
        };
        for op in [Op::UpsertCalendar, Op::RetireCalendar] {
            let recorded = calendar_op(op, &row).expect("op");
            assert_eq!(recorded.target, json!({ "calendar": "UAE HQ" }));
            assert!(recorded.check().is_ok());
        }
    }

    fn holiday(name: &str, y: i32, m: u32, d: u32) -> HolidayDef {
        HolidayDef {
            name: name.into(),
            holiday_date: NaiveDate::from_ymd_opt(y, m, d).unwrap(),
        }
    }

    fn exception(name: &str, y: i32, m: u32, d: u32, ranges: Value) -> CalendarExceptionDef {
        CalendarExceptionDef {
            name: name.into(),
            exception_date: NaiveDate::from_ymd_opt(y, m, d).unwrap(),
            ranges,
        }
    }

    fn dates_rejection(
        holidays: &[HolidayDef],
        exceptions: Option<&[CalendarExceptionDef]>,
    ) -> String {
        match desired_dates(holidays, exceptions) {
            Err(InvalidCalendarDefinition(reason)) => reason,
            Ok(_) => panic!("expected the bundle's dates to be rejected"),
        }
    }

    /// D-592: a holiday's name recurs every year, so two years of one holiday
    /// are two rows, not one row re-dated.
    #[test]
    fn a_recurring_holiday_name_is_one_row_per_date() {
        let desired = desired_dates(
            &[
                holiday("Eid al-Fitr", 2026, 3, 20),
                holiday("Eid al-Fitr", 2027, 3, 9),
            ],
            None,
        )
        .unwrap();
        assert_eq!(desired.holidays.len(), 2);
        assert!(
            desired.exceptions.is_none(),
            "an absent list is unmanaged, not empty"
        );
    }

    #[test]
    fn a_bundles_conflicting_dates_are_rejected() {
        let r = dates_rejection(
            &[holiday("A", 2026, 12, 2), holiday("B", 2026, 12, 2)],
            None,
        );
        assert!(r.contains("listed more than once"), "{r}");

        let r = dates_rejection(
            &[holiday("National Day", 2026, 12, 2)],
            Some(&[exception("Half day", 2026, 12, 2, json!([]))]),
        );
        assert!(r.contains("both a holiday and an exception"), "{r}");

        let r = dates_rejection(
            &[],
            Some(&[
                exception("A", 2026, 12, 24, json!([])),
                exception("B", 2026, 12, 24, json!([])),
            ]),
        );
        assert!(r.contains("listed more than once"), "{r}");

        let r = dates_rejection(
            &[],
            Some(&[exception(
                "Overnight",
                2026,
                12,
                24,
                json!([{ "start_minute": 1320, "end_minute": 360 }]),
            )]),
        );
        assert!(r.contains("cannot cross midnight"), "{r}");
    }

    #[test]
    fn exception_ranges_are_stored_sorted() {
        let desired = desired_dates(
            &[],
            Some(&[exception(
                "Split",
                2026,
                12,
                24,
                json!([
                    { "start_minute": 780, "end_minute": 900 },
                    { "start_minute": 540, "end_minute": 720 },
                ]),
            )]),
        )
        .unwrap();
        let exceptions = desired.exceptions.unwrap();
        let (_, ranges) = &exceptions[&NaiveDate::from_ymd_opt(2026, 12, 24).unwrap()];
        assert_eq!(
            *ranges,
            json!([
                { "start_minute": 540, "end_minute": 720 },
                { "start_minute": 780, "end_minute": 900 },
            ])
        );
    }

    async fn insert_bare_calendar(db: &attome_db::DbPool) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO calendar (id, name, tz, working_days, hours, owner_layer) \
             VALUES ($1, $2, 'UTC', '{}', '{}'::jsonb, 'project')",
        )
        .bind(id)
        .bind(format!("D-592 test {id}"))
        .execute(db)
        .await
        .expect("insert calendar");
        id
    }

    async fn apply_dates(db: &attome_db::DbPool, calendar_id: Uuid, desired: &DesiredDates) {
        let mut tx = attome_db::tx::begin(db).await.expect("begin");
        reconcile_holidays(&mut tx, calendar_id, &desired.holidays, Layer::Project)
            .await
            .expect("reconcile holidays");
        if let Some(exceptions) = &desired.exceptions {
            reconcile_exceptions(&mut tx, calendar_id, exceptions, Layer::Project)
                .await
                .expect("reconcile exceptions");
        }
        tx.commit().await.expect("commit");
    }

    async fn active_holidays(
        db: &attome_db::DbPool,
        calendar_id: Uuid,
    ) -> Vec<(NaiveDate, String)> {
        sqlx::query_as(
            "SELECT holiday_date, name FROM calendar_holiday \
             WHERE calendar_id = $1 AND is_active = true ORDER BY holiday_date",
        )
        .bind(calendar_id)
        .fetch_all(db)
        .await
        .expect("read holidays")
    }

    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../apps/attome/migrations");

    /// D-592 end to end against the tables: next year's "Eid al-Fitr" is
    /// added beside this year's, a holiday-only change is detected (it used
    /// to reconcile as Unchanged), re-applying is a no-op, a bundle without
    /// exceptions leaves them alone, and the loader applies an exception.
    /// Runs on its own freshly migrated database (migration 0487 is new, and
    /// the shared template is not migrated for a test).
    #[tokio::test]
    async fn holiday_and_exception_reconcile_is_keyed_by_date() {
        let fresh = attome_testkit::skip_if_no_db!(
            attome_testkit::empty_database("calendar_admin_d592").await
        );
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(180))
            .connect(fresh.url())
            .await
            .expect("connect to the empty database");
        sqlx::query("CREATE SCHEMA IF NOT EXISTS attome_dev")
            .execute(&db)
            .await
            .expect("create schema");
        MIGRATOR.run(&db).await.expect("apply every migration");
        let calendar_id = insert_bare_calendar(&db).await;

        let this_year = desired_dates(&[holiday("Eid al-Fitr", 2026, 3, 20)], Some(&[])).unwrap();
        apply_dates(&db, calendar_id, &this_year).await;

        let both_years = desired_dates(
            &[
                holiday("Eid al-Fitr", 2026, 3, 20),
                holiday("Eid al-Fitr", 2027, 3, 9),
            ],
            Some(&[exception(
                "Ramadan hours",
                2027,
                2,
                10,
                json!([{ "start_minute": 540, "end_minute": 840 }]),
            )]),
        )
        .unwrap();
        assert!(
            live_dates_differ(&db, calendar_id, &both_years)
                .await
                .unwrap(),
            "a holiday-only change must not reconcile as Unchanged"
        );
        apply_dates(&db, calendar_id, &both_years).await;
        let live = active_holidays(&db, calendar_id).await;
        assert_eq!(live.len(), 2, "{live:?}");
        assert!(
            !live_dates_differ(&db, calendar_id, &both_years)
                .await
                .unwrap(),
            "re-applying the same dates is a no-op"
        );

        let without_exceptions = desired_dates(
            &[
                holiday("Eid al-Fitr", 2026, 3, 20),
                holiday("Eid al-Fitr", 2027, 3, 9),
            ],
            None,
        )
        .unwrap();
        assert!(
            !live_dates_differ(&db, calendar_id, &without_exceptions)
                .await
                .unwrap()
        );
        apply_dates(&db, calendar_id, &without_exceptions).await;

        let loaded = attome_core::calendar::load_calendar(&db, calendar_id)
            .await
            .unwrap()
            .expect("the calendar loads");
        assert_eq!(loaded.calendar.holidays().len(), 2);
        assert_eq!(
            loaded.calendar.exceptions().len(),
            1,
            "a bundle without exceptions left the live one in place"
        );

        let deleted = desired_dates(&[holiday("Eid al-Fitr", 2027, 3, 9)], Some(&[])).unwrap();
        apply_dates(&db, calendar_id, &deleted).await;
        assert_eq!(active_holidays(&db, calendar_id).await.len(), 1);
        let loaded = attome_core::calendar::load_calendar(&db, calendar_id)
            .await
            .unwrap()
            .expect("the calendar loads");
        assert!(loaded.calendar.exceptions().is_empty());

        // A deleted holiday's date can be used again (0150's constraint
        // covered inactive rows too).
        apply_dates(&db, calendar_id, &both_years).await;
        assert_eq!(active_holidays(&db, calendar_id).await.len(), 2);
        db.close().await;
    }

    async fn test_db() -> Option<attome_db::DbPool> {
        let url = attome_testkit::migrated_db_url()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("failed to connect to DATABASE_URL"),
        )
    }

    /// D-517: a calendar an active SLA policy points at cannot be deleted;
    /// once the policy is deactivated it can. The reference match tolerates
    /// the case and whitespace a hand-entered `calendar_ref` text may carry.
    #[tokio::test]
    async fn a_calendar_an_active_sla_policy_uses_cannot_be_deleted() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        attome_security::seed::seed_for_tests(&db)
            .await
            .expect("attome_security seed");
        attome_project::seed::seed_for_tests(&db)
            .await
            .expect("attome_project seed");
        attome_service::seed::seed_for_tests(&db)
            .await
            .expect("attome_service seed");

        let calendar_id = Uuid::now_v7();
        ensure_not_referenced_by_sla_policies(&db, calendar_id)
            .await
            .expect("an unreferenced calendar may be deleted");

        let policy_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO service_sla_policy \
                 (id, name, priority, resolution_target_minutes, business_hours_start_minute, \
                  business_hours_end_minute, calendar_ref, is_active) \
             VALUES ($1, $2, 'high', 240, 540, 1020, $3, true)",
        )
        .bind(policy_id)
        .bind(format!("Guard Test Policy {policy_id}"))
        .bind(format!(" {} ", calendar_id.to_string().to_uppercase()))
        .execute(&db)
        .await
        .expect("insert service_sla_policy");

        assert!(matches!(
            ensure_not_referenced_by_sla_policies(&db, calendar_id).await,
            Err(AppError::Conflict(_))
        ));

        sqlx::query("UPDATE service_sla_policy SET is_active = false WHERE id = $1")
            .bind(policy_id)
            .execute(&db)
            .await
            .expect("deactivate policy");
        ensure_not_referenced_by_sla_policies(&db, calendar_id)
            .await
            .expect("an inactive policy no longer blocks deletion");
    }
}
