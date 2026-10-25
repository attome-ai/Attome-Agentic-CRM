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
use utoipa::ToSchema;
use uuid::Uuid;

use crate::admin_hooks as hooks;
use crate::bundle::model::{CalendarDef, CalendarExceptionDef, HolidayDef};
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
}

fn default_hours() -> Value {
    Value::Object(serde_json::Map::new())
}

const CALENDAR_SELECT: &str = "SELECT id, name, description, tz, working_days, hours, is_default, is_active, \
     owner_layer FROM calendar";

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

#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = CalendarDetail),
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
) -> Result<Json<CalendarDetail>, AppError> {
    let sql = format!("{CALENDAR_SELECT} WHERE id = $1 AND is_active = true");
    let row = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

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
    sqlx::query(
        "INSERT INTO calendar (id, name, description, tz, working_days, hours, is_default, is_active, is_customized, created_at, created_by, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, true, true, NOW(), $8, $9)",
    )
    .bind(id).bind(body.name.trim()).bind(body.description.as_deref().map(str::trim))
    .bind(body.tz.trim()).bind(&body.working_days).bind(&body.hours).bind(body.is_default)
    .bind(actor).bind(layer.as_str())
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
    let changed = sqlx::query(
        "UPDATE calendar SET name=$2, description=$3, tz=$4, working_days=$5, hours=$6, is_default=$7, is_customized=true \
         WHERE id=$1 AND is_active=true",
    ).bind(id).bind(body.name.trim()).bind(body.description.as_deref().map(str::trim))
     .bind(body.tz.trim()).bind(&body.working_days).bind(&body.hours).bind(body.is_default)
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

#[utoipa::path(
    patch,
    path = "/api/v1/admin/calendars/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
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

#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
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
    // D-517 — the same strict parser the runtime loader uses, so a definition
    // that would load as a partial calendar is rejected here instead.
    attome_core::calendar::validate_definition(&body.tz, &body.working_days, &body.hours)
        .map_err(|e| AppError::Validation(e.0))
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

#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/{id}/holidays",
    tag = "admin",
    params(("id" = Uuid, Path)),
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

#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/holidays",
    tag = "admin",
    params(("id" = Uuid, Path)),
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
    params(("id" = Uuid, Path)),
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

#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}/holidays/{holiday_id}",
    tag = "admin",
    params(("id" = Uuid, Path), ("holiday_id" = Uuid, Path)),
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

#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/{id}/exceptions",
    tag = "admin",
    params(("id" = Uuid, Path)),
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

#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/{id}/exceptions",
    tag = "admin",
    params(("id" = Uuid, Path)),
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

#[utoipa::path(
    delete,
    path = "/api/v1/admin/calendars/{id}/exceptions/{exception_id}",
    tag = "admin",
    params(("id" = Uuid, Path), ("exception_id" = Uuid, Path)),
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
    let db = &state.base.db;

    let current: Option<CalendarProbeRow> = sqlx::query_as(
        "SELECT id, description, tz, working_days, hours, is_default, is_active, is_customized \
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
    let state_differs = current.as_ref().is_some_and(|row| {
        row.description != desc.description
            || row.tz != tz
            || row.working_days != desc.working_days
            || row.hours != desc.hours
            || row.is_default != desc.is_default
            || dates_differ
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
    calculate
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
