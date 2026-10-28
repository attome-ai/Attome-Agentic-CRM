//! `GET /api/v1/resources/capacity` — M72 Resource Management's planning
//! view: per resource × requested period, how much capacity exists, how much
//! is committed (`resource_allocation`), how much was actually logged
//! (`project_time_entry`), and whether the resource is over-committed.
//! Read-only aggregate, same "compute at read time, never a stored rollup"
//! posture `summary.rs`/`portfolio_program.rs` already use for this crate's
//! other aggregation endpoints (D-368).
//!
//! **Capacity arithmetic (M83 Phase 1 — calendar-aware, not per-resource).**
//! `capacity_hours` is the platform's single default business calendar
//! (`calendar.is_default = true`, loaded through `attome_calendar`)
//! summed over `[from, to]`, net of any `resource_availability` leave
//! overlapping the period. M83 Phase 1 has no per-resource/per-team calendar
//! assignment yet (see that crate's own doc comment on scope) — every
//! resource shares the same calendar until that lands; this is a documented
//! simplification, not a bug. With no default calendar configured at all,
//! capacity uses a documented nominal Mon-Fri 09:00-17:00 UTC week; a default
//! calendar that is configured but invalid is an error, never silently
//! replaced (D-517).
//!
//! **Allocation/leave prorating.** `resource_allocation.allocation_percent`
//! and `resource_availability` leave are both date ranges, not aligned to
//! the requested period. Rather than walking day-by-day through the calendar
//! for every row (expensive, and unnecessary precision for a planning view),
//! both are prorated by calendar-day overlap against the period's *nominal*
//! capacity: `allocated_hours += allocation_percent/100 * base_capacity_hours *
//! (overlap_days / period_days)`, and leave reduces `capacity_hours` the same
//! way. `allocation_percent` is always prorated against the *nominal*
//! (pre-leave) capacity — a person allocated 50% is planned for 50% of an
//! ordinary week regardless of upcoming leave; the leave shows up instead as
//! reduced *capacity* to deliver that plan, which is exactly why
//! `over_allocated` (`allocated_hours > capacity_hours`) can flip true purely
//! from an approved leave request against an unchanged allocation.
//!
//! **Authorization — "resource read on the team" (module-master-plan M72
//! §3).** No single row here has an "owning team" to run
//! `access.rs`'s established `resolve_entity_access_level` +
//! `rls_predicate_by_column` row-level pattern against (this is a
//! cross-resource aggregate, not a single record read) — so this module
//! applies the same tiered `AccessLevel` ladder `access.rs` already resolves
//! for every other bespoke route in this crate, one level up: at query
//! *scope* instead of row ownership. `None` → forbidden outright (same
//! meaning `access.rs`'s doc comments already give it: no held role grants
//! this entity this action at all). `Team` → the caller may only query
//! resources on a `team` from `ctx.team_ids` (D-133) — an explicit `?team=`
//! outside that set is forbidden, and an unfiltered request is scoped to the
//! union of the caller's own teams rather than every resource platform-wide.
//! `BusinessUnit`/`Global` → full visibility; an explicit `?team=` is still
//! honored, but as a plain filter, not a gate. No new authorization
//! primitive is introduced — `resolve_entity_access_level` and
//! `SecurityContext.team_ids` are both used exactly as `access.rs` and
//! `rls.rs` already define them.
use attome_calendar::{BusinessCalendar, TimeRange};
use attome_core::EngineState;
use attome_security::{RecordAction, resolve_entity_access_level};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::AccessLevel;
use attome_types::{AppError, ErrorResponse, MAX_PAGE_SIZE, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{NaiveDate, NaiveTime, Utc, Weekday};
use serde::Deserialize;
use std::collections::HashSet;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::access::resource_allocation_entity_id;
use crate::auth::ResourceAllocationRead;
use crate::model::CapacityRow;

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    50
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CapacityParams {
    /// From this time (inclusive).
    pub from: NaiveDate,
    /// Up to this time (exclusive).
    pub to: NaiveDate,
    /// Restrict to resources on this `team.id` — also the
    /// authorization gate for a `Team`-tier caller; see this module's doc
    /// comment.
    pub team: Option<Uuid>,
    /// Restrict to resources holding this `resource_skill.skill` value.
    pub skill: Option<String>,
    /// One-based: page 1 is the first page.
    #[serde(default = "default_page")]
    #[param(minimum = 1)]
    pub page: i64,
    /// Rows per page.
    #[serde(default = "default_page_size")]
    pub page_size: i64,
}

/// The planning week used when the deployment has no default calendar at
/// all: Mon-Fri 09:00-17:00 UTC. A deliberate, documented nominal — not a
/// substitute for a configured calendar that fails to load (that is an
/// error, see [`load_default_calendar`]).
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
fn nominal_calendar() -> BusinessCalendar {
    BusinessCalendar::simple(
        chrono_tz::UTC,
        HashSet::from([
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
            Weekday::Fri,
        ]),
        TimeRange::new(9 * 60, 17 * 60),
    )
    .expect("a Mon-Fri 09:00-17:00 calendar is valid")
}

/// The deployment's default calendar through the shared loader
/// (`attome_core::calendar`, D-517). No default configured →
/// [`nominal_calendar`]. A default that *is* configured but cannot be used
/// (invalid definition) is an error: capacity computed against a different
/// calendar than the one the administrator set would be silently wrong.
pub(crate) async fn load_default_calendar(
    db: &attome_db::DbPool,
) -> Result<BusinessCalendar, AppError> {
    let Some(calendar_id) = attome_core::calendar::default_calendar_id(db).await? else {
        tracing::warn!(
            "resource capacity: no default calendar is configured; using the nominal Mon-Fri 09:00-17:00 UTC week"
        );
        return Ok(nominal_calendar());
    };
    match attome_core::calendar::load_calendar(db, calendar_id).await? {
        Ok(loaded) => Ok(loaded.calendar),
        Err(unresolved) => {
            tracing::error!(
                calendar_id = %calendar_id,
                reason = %unresolved,
                "resource capacity: the default calendar cannot be used; refusing to substitute another"
            );
            Err(AppError::Conflict(
                "the default business calendar is invalid; fix it under /api/v1/admin/calendars",
            ))
        }
    }
}

/// The period's nominal (pre-leave) business-hour capacity, shared by every
/// resource in the page — see this module's doc comment on why a single
/// platform-wide calendar is this phase's documented scope. `[from, to]` are
/// local dates in the calendar's own timezone.
pub fn base_capacity_hours(
    calendar: &BusinessCalendar,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<f64, AppError> {
    let local_midnight = |date: NaiveDate| {
        date.and_time(NaiveTime::MIN)
            .and_local_timezone(calendar.tz())
            .earliest()
            .map(|dt| dt.with_timezone(&Utc))
    };
    let invalid_period = || AppError::Validation("the capacity period is out of range".into());
    let start = local_midnight(from).ok_or_else(invalid_period)?;
    let end_exclusive = to
        .succ_opt()
        .and_then(local_midnight)
        .ok_or_else(invalid_period)?;
    calendar
        .business_duration_between(start, end_exclusive)
        .map(|d| d.num_seconds() as f64 / 3600.0)
        .map_err(|e| AppError::Validation(format!("cannot compute capacity for this period: {e}")))
}

/// Resolves this caller's visibility into the capacity aggregate —
/// `Ok(None)` means unrestricted (any `?team=` filter, if present, is
/// applied downstream as a plain filter, not a gate); `Ok(Some(teams))`
/// means the query must additionally restrict to resources belonging to one
/// of `teams`. See this module's doc comment for the full tier reasoning.
///
/// Takes `db`/`entity_id` rather than `&EngineState` deliberately: the only
/// thing this function needs from `EngineState` is the already-resolved
/// `resource_allocation` entity id, and keeping it out of the signature
/// lets `tests/capacity.rs`'s team-scoping test call this directly against a
/// throwaway database without constructing a full `EngineState`/metadata
/// registry — the same "call the function directly, no HTTP/state layer"
/// pattern `tests/portfolio_program.rs` already uses for this crate's other
/// bespoke routes. `pub` (not `pub(crate)`) for that same reason.
pub async fn authorize_capacity_scope(
    db: &attome_db::DbPool,
    entity_id: Uuid,
    ctx: &attome_server::security::SecurityContext,
    requested_team: Option<Uuid>,
) -> Result<Option<Vec<Uuid>>, AppError> {
    if ctx.is_admin {
        return Ok(None);
    }
    let access_level = resolve_entity_access_level(
        db,
        ctx.user_id,
        entity_id,
        "resource_allocation",
        RecordAction::Read,
    )
    .await?;

    if access_level >= AccessLevel::BusinessUnit {
        return Ok(None);
    }
    if access_level == AccessLevel::None {
        return Err(AppError::Forbidden);
    }
    // Team tier.
    if ctx.team_ids.is_empty() {
        return Err(AppError::Forbidden);
    }
    if let Some(team) = requested_team {
        if !ctx.team_ids.contains(&team) {
            return Err(AppError::Forbidden);
        }
        return Ok(Some(vec![team]));
    }
    Ok(Some(ctx.team_ids.clone()))
}

fn clamp_paging(page: i64, page_size: i64) -> (i64, i64) {
    let page = page.max(1);
    let page_size = page_size.clamp(1, MAX_PAGE_SIZE);
    (page, page_size)
}

/// `pub` — exercised directly by `tests/capacity.rs`'s over-allocation test
/// (same "call the aggregation function directly, no HTTP layer" pattern
/// `tests/portfolio_program.rs` already uses).
pub struct CapacityRowSql {
    pub id: Uuid,
    pub user_name: Option<String>,
    pub capacity_hours: f64,
    pub allocated_hours: f64,
    pub actual_hours: f64,
}

impl std::fmt::Debug for CapacityRowSql {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapacityRowSql").finish_non_exhaustive()
    }
}

/// The single aggregate query behind the whole response — one CTE per
/// ingredient (matching resources, leave overlap, allocation overlap,
/// actual hours), joined once. `team_filter`/`skill` are plain optional
/// filters; `base_hours`/`period_days` are the Rust-computed constants
/// shared by every resource in the page (see `base_capacity_hours`).
#[allow(clippy::too_many_arguments)]
pub async fn fetch_capacity_page(
    db: &attome_db::DbPool,
    from: NaiveDate,
    to: NaiveDate,
    team_filter: Option<&[Uuid]>,
    skill: Option<&str>,
    base_hours: f64,
    period_days: f64,
    limit: i64,
    offset: i64,
) -> Result<Vec<CapacityRowSql>, AppError> {
    sqlx::query_as::<_, (Uuid, Option<String>, f64, f64, f64)>(
        "WITH resources AS ( \
             SELECT u.id, u.user_name \
             FROM user_account u \
             WHERE u.is_active = true \
               AND ($3::uuid[] IS NULL OR EXISTS ( \
                     SELECT 1 FROM user_account_mm_team t \
                     WHERE t.user_ref = u.id AND t.is_deleted = false AND t.team_ref = ANY($3) \
               )) \
               AND ($4::text IS NULL OR EXISTS ( \
                     SELECT 1 FROM resource_skill s \
                     WHERE s.user_id = u.id AND s.skill = $4 \
                       AND (s.is_active IS NULL OR s.is_active = true) \
               )) \
             ORDER BY u.user_name NULLS LAST, u.id \
             LIMIT $5 OFFSET $6 \
         ), \
         leave_overlap AS ( \
             SELECT a.user_id, \
                    SUM(GREATEST(0, LEAST(a.leave_end::date, $2::date) - GREATEST(a.leave_start::date, $1::date) + 1))::float8 AS leave_days \
             FROM resource_availability a \
             WHERE (a.is_active IS NULL OR a.is_active = true) \
               AND a.leave_start::date <= $2::date AND a.leave_end::date >= $1::date \
               AND a.user_id IN (SELECT id FROM resources) \
             GROUP BY a.user_id \
         ), \
         allocation_overlap AS ( \
             SELECT al.user_id, \
                    SUM(al.allocation_percent::float8 / 100.0 * $7::float8 \
                        * (GREATEST(0, LEAST(COALESCE(al.end_date::date, $2::date), $2::date) \
                                     - GREATEST(al.start_date::date, $1::date) + 1)::float8 \
                           / $8::float8)) AS allocated_hours \
             FROM resource_allocation al \
             WHERE (al.is_active IS NULL OR al.is_active = true) \
               AND al.start_date::date <= $2::date \
               AND (al.end_date IS NULL OR al.end_date::date >= $1::date) \
               AND al.user_id IN (SELECT id FROM resources) \
             GROUP BY al.user_id \
         ), \
         actual AS ( \
             SELECT te.user_id, SUM(te.hours)::float8 AS actual_hours \
             FROM project_time_entry te \
             WHERE (te.is_active IS NULL OR te.is_active = true) \
               AND te.entry_date::date BETWEEN $1::date AND $2::date \
               AND te.user_id IN (SELECT id FROM resources) \
             GROUP BY te.user_id \
         ) \
         SELECT r.id, r.user_name, \
                GREATEST(0, $7::float8 * (1 - COALESCE(lo.leave_days, 0) / $8::float8)) AS capacity_hours, \
                COALESCE(ao.allocated_hours, 0) AS allocated_hours, \
                COALESCE(ac.actual_hours, 0) AS actual_hours \
         FROM resources r \
         LEFT JOIN leave_overlap lo ON lo.user_id = r.id \
         LEFT JOIN allocation_overlap ao ON ao.user_id = r.id \
         LEFT JOIN actual ac ON ac.user_id = r.id \
         ORDER BY r.user_name NULLS LAST, r.id",
    )
    .bind(from)
    .bind(to)
    .bind(team_filter)
    .bind(skill)
    .bind(limit)
    .bind(offset)
    .bind(base_hours)
    .bind(period_days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
    .map(|rows| {
        rows.into_iter()
            .map(
                |(id, user_name, capacity_hours, allocated_hours, actual_hours)| CapacityRowSql {
                    id,
                    user_name,
                    capacity_hours,
                    allocated_hours,
                    actual_hours,
                },
            )
            .collect()
    })
}

async fn count_matching_resources(
    db: &attome_db::DbPool,
    team_filter: Option<&[Uuid]>,
    skill: Option<&str>,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account u \
         WHERE u.is_active = true \
           AND ($1::uuid[] IS NULL OR EXISTS ( \
                 SELECT 1 FROM user_account_mm_team t \
                 WHERE t.user_ref = u.id AND t.is_deleted = false AND t.team_ref = ANY($1) \
           )) \
           AND ($2::text IS NULL OR EXISTS ( \
                 SELECT 1 FROM resource_skill s \
                 WHERE s.user_id = u.id AND s.skill = $2 \
                   AND (s.is_active IS NULL OR s.is_active = true) \
           ))",
    )
    .bind(team_filter)
    .bind(skill)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Read resource capacity
///
/// Per resource and period: the capacity there is, how much is allocated, how much was logged, and
/// whether the resource is over-committed. Computed when read.
#[utoipa::path(
    get,
    path = "/api/v1/resources/capacity",
    tag = "project",
    params(CapacityParams),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<CapacityRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or the requested team is outside their scope", body = ErrorResponse),
        (status = 422, description = "from is after to, or paging is out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn resource_capacity(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ResourceAllocationRead>>,
    Query(params): Query<CapacityParams>,
) -> Result<Json<PaginatedResponse<CapacityRow>>, AppError> {
    if params.from > params.to {
        return Err(AppError::Validation("from must not be after to".into()));
    }
    let (page, page_size) = clamp_paging(params.page, params.page_size);

    let allocation_entity_id = resource_allocation_entity_id(&state)?;
    let team_scope =
        authorize_capacity_scope(&state.base.db, allocation_entity_id, &ctx, params.team).await?;
    let team_filter: Option<Vec<Uuid>> = match team_scope {
        Some(teams) => Some(teams),
        None => params.team.map(|t| vec![t]),
    };

    let calendar = load_default_calendar(&state.base.db).await?;
    let base_hours = base_capacity_hours(&calendar, params.from, params.to)?;
    let period_days = ((params.to - params.from).num_days() + 1).max(1) as f64;

    let total = count_matching_resources(
        &state.base.db,
        team_filter.as_deref(),
        params.skill.as_deref(),
    )
    .await?;

    let offset = (page - 1) * page_size;
    let rows = fetch_capacity_page(
        &state.base.db,
        params.from,
        params.to,
        team_filter.as_deref(),
        params.skill.as_deref(),
        base_hours,
        period_days,
        page_size,
        offset,
    )
    .await?;

    let items = rows
        .into_iter()
        .map(|r| {
            let utilization_pct = if r.capacity_hours > 0.0 {
                r.allocated_hours / r.capacity_hours * 100.0
            } else {
                0.0
            };
            CapacityRow {
                resource_id: r.id,
                resource_name: r.user_name,
                capacity_hours: r.capacity_hours,
                allocated_hours: r.allocated_hours,
                actual_hours: r.actual_hours,
                utilization_pct,
                over_allocated: r.allocated_hours > r.capacity_hours,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        page,
        page_size,
        warnings: Vec::new(),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/resources/capacity", get(resource_capacity))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(resource_capacity))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
