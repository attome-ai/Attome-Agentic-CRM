//! G17-T9: intraday management.
//!
//! Every 15 minutes the `workforce_intraday` job looks at each planning
//! group with `intraday_enabled` (workforce pack 0003) and a published
//! schedule today:
//!
//! 1. reads the actual volume of the elapsed intervals through an
//!    [`ActualsSource`] (by default [`TicketActuals`]: service tickets
//!    created on the group's channel, until G16 stores actuals);
//! 2. scales the rest of the day's forecast by actual over forecast so far
//!    ([`trend`], bounded to half and three times) and recomputes the
//!    requirement of the remaining intervals;
//! 3. compares it with the published assignments and, for each run of
//!    intervals short (or over) by more than one person, writes one
//!    `wfm_offer` in `proposed`: **overtime** when short, **VTO** (voluntary
//!    time off) when over ([`proposals`]). An offer is keyed by group, kind
//!    and start (`proposal_key`), so a run never proposes it twice.
//!
//! A planner sends an offer (`POST /api/v1/workforce/offers/{id}/send`,
//! `wfm_offer.update`): it becomes `sent` and the group's people are told —
//! those off shift then for overtime, those on shift for VTO. The first
//! person to accept (`POST /api/v1/workforce/offers/{id}/accept`) takes it,
//! guarded on `sent`: overtime adds their shift to today's published
//! schedule (and books it), VTO trims their shift out of that time. Both
//! steps are audited. Moving breaks and lending people between groups are
//! not proposed yet.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::admin::{event, notify};
use crate::build_job::coverage_of;
use crate::staffing::{ChannelKind, IntervalForecast, PlanningGroup, requirement_for_group};

/// The registered job.
pub const JOB: &str = "workforce_intraday";

/// `wfm_offer.update`: who sends offers.
#[derive(Debug)]
pub struct OfferSend;

impl PrivilegeKey for OfferSend {
    const KEY: &'static str = "wfm_offer.update";
}

/// Where actual volume comes from.
pub trait ActualsSource {
    /// Contacts that arrived in `[from, to)` for a group on `channel`.
    fn volume(
        &self,
        state: &EngineState,
        channel: ChannelKind,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<f64, AppError>> + Send;
}

/// Service tickets created on the group's channel (until G16 stores
/// actuals): voice is `phone`, chat is `chat` and `web_chat`, email is
/// `email`, and case work counts every ticket.
#[derive(Debug, Clone, Copy, Default)]
pub struct TicketActuals;

impl ActualsSource for TicketActuals {
    async fn volume(
        &self,
        state: &EngineState,
        channel: ChannelKind,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<f64, AppError> {
        let channels: &[&str] = match channel {
            ChannelKind::Voice => &["phone"],
            ChannelKind::Chat => &["chat", "web_chat"],
            ChannelKind::Email => &["email"],
            ChannelKind::Case => &[],
        };
        let channels: Vec<String> = channels.iter().map(|c| (*c).to_owned()).collect();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM service_ticket \
              WHERE created_at >= $1 AND created_at < $2 \
                AND (cardinality($3::text[]) = 0 OR channel::text = ANY($3)) \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(from)
        .bind(to)
        .bind(&channels)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        Ok(count as f64)
    }
}

/// Actual over forecast so far, bounded to 0.5..3 (1 with no forecast so
/// far). Pure.
pub fn trend(actual: f64, forecast: f64) -> f64 {
    if forecast <= 0.0 || !actual.is_finite() {
        return 1.0;
    }
    (actual / forecast).clamp(0.5, 3.0)
}

/// One proposed offer.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    /// `overtime` or `vto`.
    pub kind: &'static str,
    /// First and one-past-last interval index.
    pub from: usize,
    pub to: usize,
    /// The largest gap in the run, in people.
    pub people: u32,
}

/// Runs of remaining intervals short or over by more than one person.
/// Intervals before `first_remaining` are past and never proposed. Pure.
pub fn proposals(requirement: &[u32], coverage: &[u32], first_remaining: usize) -> Vec<Proposal> {
    let mut out = Vec::new();
    let mut current: Option<Proposal> = None;
    for i in first_remaining..requirement.len().min(coverage.len()) {
        let (need, have) = (requirement[i], coverage[i]);
        let kind = if need > have + 1 {
            Some(("overtime", need - have))
        } else if have > need + 1 {
            Some(("vto", have - need))
        } else {
            None
        };
        match (kind, current.as_mut()) {
            (Some((k, gap)), Some(p)) if p.kind == k && p.to == i => {
                p.to = i + 1;
                p.people = p.people.max(gap);
            }
            (Some((k, gap)), _) => {
                if let Some(p) = current.take() {
                    out.push(p);
                }
                current = Some(Proposal {
                    kind: k,
                    from: i,
                    to: i + 1,
                    people: gap,
                });
            }
            (None, _) => {
                if let Some(p) = current.take() {
                    out.push(p);
                }
            }
        }
    }
    out.extend(current);
    out
}

/// `(id, channel, sl pct, sl secs, interval, shrinkage, concurrency, backlog, aht)`.
type GroupRow = (
    Uuid,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// One tick for every intraday group. Answers the offers proposed.
pub async fn tick<A: ActualsSource>(
    state: &EngineState,
    actuals: &A,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'wfm_planning_group' \
            AND column_name = 'intraday_enabled')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Ok(0);
    }
    let groups: Vec<GroupRow> = sqlx::query_as(
        "SELECT id, channel::text, service_level_target_pct::float8, service_level_seconds::float8, \
                interval_minutes::text, shrinkage_pct::float8, concurrency::float8, \
                backlog_hours::float8, aht_seconds::float8 \
           FROM wfm_planning_group \
          WHERE intraday_enabled = true AND (is_active IS NULL OR is_active = true) LIMIT 200",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut made = 0;
    for g in groups {
        match group_tick(state, actuals, &g, now).await {
            Ok(n) => made += n,
            Err(error) => tracing::warn!(group = %g.0, %error, "intraday: group skipped"),
        }
    }
    Ok(made)
}

async fn group_tick<A: ActualsSource>(
    state: &EngineState,
    actuals: &A,
    g: &GroupRow,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let db = &state.base.db;
    let (id, chan, pct, secs, interval, shrink, conc, backlog, aht) = g.clone();
    let interval_minutes: u32 = interval
        .as_deref()
        .and_then(|i| i.trim().parse().ok())
        .filter(|i: &u32| *i == 15 || *i == 30)
        .unwrap_or(30);
    let channel = match chan.as_deref() {
        Some("chat") => ChannelKind::Chat,
        Some("email") => ChannelKind::Email,
        Some("case") => ChannelKind::Case,
        _ => ChannelKind::Voice,
    };
    let group = PlanningGroup {
        id,
        channel,
        aht_secs: aht.filter(|a| *a > 0.0).unwrap_or(180.0),
        target_pct: pct.unwrap_or(80.0),
        target_secs: secs.unwrap_or(20.0),
        concurrency: conc.filter(|c| *c >= 1.0).unwrap_or(1.0),
        backlog_hours: backlog.unwrap_or(8.0),
        shrinkage_pct: shrink.unwrap_or(0.0),
    };
    let today: NaiveDate = now.date_naive();
    let midnight = today.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let schedule: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM wfm_schedule WHERE planning_group_ref = $1 AND status = 'published' \
            AND period_from::date <= $2 AND period_to::date >= $2 \
            AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(id)
    .bind(today)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(schedule) = schedule else {
        return Ok(0);
    };
    let rows: Vec<(DateTime<Utc>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT interval_start::timestamptz, volume::float8, digital_share::float8 \
           FROM wfm_forecast_interval \
          WHERE planning_group_ref = $1 AND interval_start::timestamptz >= $2 \
            AND interval_start::timestamptz < $3 AND (is_active IS NULL OR is_active = true) \
          ORDER BY interval_start",
    )
    .bind(id)
    .bind(midnight)
    .bind(midnight + Duration::days(1))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut forecast: Vec<IntervalForecast> = rows
        .into_iter()
        .map(|(start, volume, digital)| IntervalForecast {
            start,
            interval_secs: f64::from(interval_minutes * 60),
            volume: volume.unwrap_or(0.0).max(0.0),
            digital_share: digital.unwrap_or(0.0),
        })
        .collect();
    let elapsed_forecast: f64 = forecast
        .iter()
        .filter(|f| f.start < now)
        .map(|f| f.volume)
        .sum();
    let actual = actuals.volume(state, channel, midnight, now).await?;
    let factor = trend(actual, elapsed_forecast);
    for f in forecast.iter_mut().filter(|f| f.start >= now) {
        f.volume *= factor;
    }
    let reqs: Vec<(DateTime<Utc>, u32)> = requirement_for_group(&group, &forecast)
        .into_iter()
        .map(|r| (r.start, r.scheduled))
        .collect();
    let requirement = crate::build_job::day_requirement(today, interval_minutes, &reqs);
    let shifts: Vec<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT start_at::timestamptz, end_at::timestamptz FROM wfm_shift_assignment \
          WHERE schedule_ref = $1 AND activity = 'work' AND start_at::date = $2 \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(schedule)
    .bind(today)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let coverage = coverage_of(today, interval_minutes, &shifts);
    let step = i64::from(interval_minutes);
    let first_remaining =
        usize::try_from(((now - midnight).num_minutes() + step - 1) / step).unwrap_or(0);
    let mut made = 0;
    for p in proposals(&requirement, &coverage, first_remaining) {
        let start = midnight + Duration::minutes(step * p.from as i64);
        let end = midnight + Duration::minutes(step * p.to as i64);
        let key = format!("{id}:{}:{}", p.kind, start.to_rfc3339());
        let inserted = sqlx::query(
            "INSERT INTO wfm_offer (id, kind, planning_group_ref, schedule_ref, start_at, end_at, \
                 status, people, proposal_key, reason) \
             SELECT $1, $2, $3, $4, $5, $6, 'proposed', $7, $8, $9 \
              WHERE NOT EXISTS (SELECT 1 FROM wfm_offer WHERE proposal_key = $8)",
        )
        .bind(Uuid::now_v7())
        .bind(p.kind)
        .bind(id)
        .bind(schedule)
        .bind(start)
        .bind(end)
        .bind(i64::from(p.people))
        .bind(&key)
        .bind(format!(
            "Volume is running at {:.0}% of forecast; {} people {} from {start} to {end}.",
            factor * 100.0,
            p.people,
            if p.kind == "overtime" {
                "short"
            } else {
                "over"
            }
        ))
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        made += inserted;
    }
    Ok(made)
}

/// An offer after a step.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OfferState {
    pub offer_id: Uuid,
    pub status: String,
    /// People told, when sent.
    pub told: usize,
}

/// `(kind, group, schedule, start, end, status)`.
type OfferRow = (
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
);

async fn offer_row(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<OfferRow, AppError> {
    sqlx::query_as(
        "SELECT kind::text, planning_group_ref, schedule_ref, start_at::timestamptz, \
                end_at::timestamptz, status::text \
           FROM wfm_offer WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn send(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<OfferState, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (kind, group, schedule, start, end, status) = offer_row(&mut tx, id).await?;
    if status.as_deref() != Some("proposed") {
        return Err(AppError::Conflict("only a proposed offer is sent"));
    }
    let (Some(start), Some(end)) = (start, end) else {
        return Err(AppError::Validation("the offer has no times".into()));
    };
    let on_shift: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_ref FROM wfm_shift_assignment WHERE schedule_ref = $1 \
           AND activity = 'work' AND start_at::timestamptz < $3 AND end_at::timestamptz > $2 \
           AND user_ref IS NOT NULL AND (is_active IS NULL OR is_active = true)",
    )
    .bind(schedule)
    .bind(start)
    .bind(end)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let members: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_ref FROM wfm_group_member WHERE planning_group_ref = $1 \
           AND user_ref IS NOT NULL AND (is_active IS NULL OR is_active = true)",
    )
    .bind(group)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let overtime = kind.as_deref() == Some("overtime");
    let audience: Vec<Uuid> = members
        .into_iter()
        .filter(|m| on_shift.contains(m) != overtime)
        .collect();
    sqlx::query(
        "UPDATE wfm_offer SET status = 'sent', modified_at = now(), modified_by = $2, \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    event(
        &mut tx,
        state,
        "wfm_offer",
        id,
        "workforce.offer_sent",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    let (subject, body) = if overtime {
        (
            "Overtime offered",
            format!(
                "Extra hours are available from {start} to {end}. Accept the offer to take them."
            ),
        )
    } else {
        (
            "Time off offered",
            format!(
                "Voluntary time off is available from {start} to {end}. Accept the offer to take it."
            ),
        )
    };
    for person in &audience {
        notify(state, *person, subject, &body).await;
    }
    Ok(OfferState {
        offer_id: id,
        status: "sent".into(),
        told: audience.len(),
    })
}

async fn accept(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<OfferState, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (kind, group, schedule, start, end, status) = offer_row(&mut tx, id).await?;
    if status.as_deref() != Some("sent") {
        return Err(AppError::Conflict(
            "this offer is not open (taken, withdrawn or not sent)",
        ));
    }
    let (Some(start), Some(end), Some(schedule)) = (start, end, schedule) else {
        return Err(AppError::Validation(
            "the offer has no times or schedule".into(),
        ));
    };
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM wfm_group_member WHERE planning_group_ref = $1 \
            AND user_ref = $2 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(group)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !member {
        return Err(AppError::NotFound);
    }
    if kind.as_deref() == Some("overtime") {
        let shift: Uuid = sqlx::query_scalar(
            "INSERT INTO wfm_shift_assignment (id, schedule_ref, user_ref, start_at, end_at, activity, \
                 created_by, owner_ref) VALUES ($1, $2, $3, $4, $5, 'work', $3, $3) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(schedule)
        .bind(ctx.user_id)
        .bind(start)
        .bind(end)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let booking: Uuid = sqlx::query_scalar(
            "INSERT INTO resource_allocation (id, user_id, regarding_entity, regarding_id, \
                 allocation_percent, start_date, end_date, created_by, owner_ref) \
             VALUES ($1, $2, 'wfm_shift_assignment', $3, 100, $4, $5, $2, $2) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.user_id)
        .bind(shift.to_string())
        .bind(start)
        .bind(end)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query("UPDATE wfm_shift_assignment SET booking_id = $2 WHERE id = $1")
            .bind(shift)
            .bind(booking.to_string())
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    } else {
        // VTO: the part of the caller's shift inside the offer goes; a
        // shift wholly inside it is taken off the schedule.
        let trimmed = sqlx::query(
            "UPDATE wfm_shift_assignment SET \
                 is_active = CASE WHEN start_at::timestamptz >= $3 AND end_at::timestamptz <= $4 \
                                  THEN false ELSE is_active END, \
                 end_at = CASE WHEN start_at::timestamptz < $3 AND end_at::timestamptz > $3 \
                               THEN $3 ELSE end_at END, \
                 start_at = CASE WHEN start_at::timestamptz >= $3 AND start_at::timestamptz < $4 \
                                      AND end_at::timestamptz > $4 THEN $4 ELSE start_at END, \
                 modified_at = now(), row_version = row_version + 1 \
              WHERE schedule_ref = $1 AND user_ref = $2 AND activity = 'work' \
                AND start_at::timestamptz < $4 AND end_at::timestamptz > $3 \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(schedule)
        .bind(ctx.user_id)
        .bind(start)
        .bind(end)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if trimmed == 0 {
            return Err(AppError::Validation(
                "you are not on shift during this time off".into(),
            ));
        }
    }
    let taken = sqlx::query(
        "UPDATE wfm_offer SET status = 'taken', user_ref = $2, modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1 AND status = 'sent'",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if taken == 0 {
        return Err(AppError::Conflict("someone took this offer first"));
    }
    event(
        &mut tx,
        state,
        "wfm_offer",
        id,
        "workforce.offer_accepted",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(OfferState {
        offer_id: id,
        status: "taken".into(),
        told: 0,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/offers/{id}/send",
    operation_id = "post_workforce_offer_send",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The proposed offer")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Sent", body = OfferState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_offer.update", body = ErrorResponse),
        (status = 404, description = "No such offer", body = ErrorResponse),
        (status = 409, description = "Not a proposed offer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Sends a proposed intraday offer.
///
/// The group's people who could take it are told: off shift then for
/// overtime, on shift for time off.
async fn post_send(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OfferSend>>,
    Path(id): Path<Uuid>,
) -> Result<Json<OfferState>, AppError> {
    Ok(Json(send(&state, &ctx, id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/offers/{id}/accept",
    operation_id = "post_workforce_offer_accept",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The sent offer")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Taken", body = OfferState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such offer, or not for the caller's group", body = ErrorResponse),
        (status = 409, description = "Not open, or someone took it first", body = ErrorResponse),
        (status = 422, description = "Time off for someone not on shift then", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Takes a sent offer.
///
/// Overtime adds the caller's shift to today's schedule; time off trims
/// their shift. The first to accept takes it.
async fn post_accept(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<OfferState>, AppError> {
    Ok(Json(accept(&state, &ctx, id).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/workforce/offers/{id}/send", post(post_send))
        .route("/api/v1/workforce/offers/{id}/accept", post(post_accept))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_send, post_accept), components(schemas(OfferState)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod intraday_tests {
    use super::*;

    #[test]
    fn the_trend_is_actual_over_forecast_within_bounds() {
        assert_eq!(trend(130.0, 100.0), 1.3);
        assert_eq!(trend(10.0, 100.0), 0.5);
        assert_eq!(trend(900.0, 100.0), 3.0);
        assert_eq!(trend(5.0, 0.0), 1.0);
    }

    #[test]
    fn short_runs_become_overtime_and_over_runs_vto() {
        let requirement = [5, 5, 8, 8, 8, 4, 2, 2];
        let coverage = [5, 5, 5, 5, 6, 4, 6, 6];
        let p = proposals(&requirement, &coverage, 1);
        assert_eq!(
            p,
            vec![
                Proposal {
                    kind: "overtime",
                    from: 2,
                    to: 5,
                    people: 3
                },
                Proposal {
                    kind: "vto",
                    from: 6,
                    to: 8,
                    people: 4
                },
            ]
        );
    }

    #[test]
    fn a_gap_of_one_person_and_past_intervals_are_left_alone() {
        assert!(proposals(&[3, 3], &[2, 4], 0).is_empty());
        assert!(
            proposals(&[9, 3], &[1, 3], 1).is_empty(),
            "the short interval is past"
        );
    }

    #[test]
    fn thirty_percent_above_forecast_needs_more_people() {
        let group = PlanningGroup {
            id: Uuid::nil(),
            channel: ChannelKind::Voice,
            aht_secs: 180.0,
            target_pct: 80.0,
            target_secs: 20.0,
            concurrency: 1.0,
            backlog_hours: 8.0,
            shrinkage_pct: 0.0,
        };
        let f = |v: f64| IntervalForecast {
            start: Utc::now(),
            interval_secs: 1800.0,
            volume: v,
            digital_share: 0.0,
        };
        let base = requirement_for_group(&group, &[f(100.0)])[0].scheduled;
        let up = requirement_for_group(&group, &[f(100.0 * trend(130.0, 100.0))])[0].scheduled;
        assert!(
            up >= base + 2,
            "{up} vs {base}: enough for an overtime offer"
        );
    }
}
