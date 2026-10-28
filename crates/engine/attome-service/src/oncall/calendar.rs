//! H7-T2: the on-call calendar. `GET /api/v1/service/oncall/schedules/{id}/calendar`
//! answers who is on call on one stored schedule (itsm pack 0003's
//! `oncall_schedule` with its layers, members and overrides) over a range of
//! at most [`MAX_RANGE_DAYS`] days, as stretches from
//! [`super::timeline`]. The schedule is read through the record engine
//! first, so a caller who may not read it gets a 404.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{OnCall, Stretch};
use crate::auth::OncallScheduleRead;

/// The longest range one calendar request covers.
pub const MAX_RANGE_DAYS: i64 = 62;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CalendarQuery {
    /// The range's start (inclusive).
    pub from: DateTime<Utc>,
    /// The range's end (exclusive), at most 62 days after `from`.
    pub to: DateTime<Utc>,
}

/// One stretch with one person on call.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OnCallStretchView {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub user_id: Uuid,
    /// The person's user name, when their account still exists.
    pub user_name: Option<String>,
    /// `override` (someone swapped in) or `layer` (the rotation).
    pub via: String,
    /// The rotation layer, lowest first; absent for an override.
    pub layer: Option<usize>,
}

/// Refuses an empty, reversed or too long range. Pure.
pub fn check_range(from: DateTime<Utc>, to: DateTime<Utc>) -> Result<(), AppError> {
    if to <= from {
        return Err(AppError::Validation("to must be after from".into()));
    }
    if to - from > Duration::days(MAX_RANGE_DAYS) {
        return Err(AppError::Validation(format!(
            "the range is at most {MAX_RANGE_DAYS} days"
        )));
    }
    Ok(())
}

fn view(stretch: &Stretch, names: &std::collections::HashMap<Uuid, String>) -> OnCallStretchView {
    let (via, layer) = match stretch.on_call {
        OnCall::Override { .. } => ("override", None),
        OnCall::Layer { layer, .. } => ("layer", Some(layer)),
    };
    let user_id = stretch.on_call.user();
    OnCallStretchView {
        start: stretch.start,
        end: stretch.end,
        user_id,
        user_name: names.get(&user_id).cloned(),
        via: via.to_owned(),
        layer,
    }
}

/// Who is on call on schedule `id` over `[from, to)`.
pub async fn calendar(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    id: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<OnCallStretchView>, AppError> {
    check_range(from, to)?;
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('oncall_schedule') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Err(AppError::NotFound);
    }
    attome_records::entity_crud::read_record(state, ctx, "oncall_schedule", id).await?;
    let schedule = crate::major_incident::load_schedule(state, id, from).await?;
    let stretches = super::timeline(&schedule, from, to).ok_or_else(|| {
        AppError::Validation(
            "this schedule changes hands too often to show over this range; choose a shorter one"
                .into(),
        )
    })?;
    let mut users: Vec<Uuid> = stretches.iter().map(|s| s.on_call.user()).collect();
    users.sort_unstable();
    users.dedup();
    let names: std::collections::HashMap<Uuid, String> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, user_name FROM user_account WHERE id = ANY($1)",
    )
    .bind(&users)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    Ok(stretches.iter().map(|s| view(s, &names)).collect())
}

/// Who is on call over a range
///
/// H7-T2: the stretches of one on-call schedule over at most 62 days, in time order, each with the person on call and whether the rotation or an override put them there; gaps with nobody on call are left out. The whole answer is on page 1.
#[utoipa::path(
    get,
    path = "/api/v1/service/oncall/schedules/{id}/calendar",
    operation_id = "get_oncall_calendar",
    tag = "service",
    params(("id" = Uuid, Path, description = "The on-call schedule"), CalendarQuery),
    responses(
        (status = 200, description = "Every stretch in the range, whole on page 1", body = PaginatedResponse<OnCallStretchView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such schedule for this caller, or on-call is not installed", body = ErrorResponse),
        (status = 422, description = "The range is reversed, longer than 62 days, or holds too many handovers", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_calendar(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OncallScheduleRead>>,
    Path(id): Path<Uuid>,
    Query(query): Query<CalendarQuery>,
) -> Result<Json<PaginatedResponse<OnCallStretchView>>, AppError> {
    let items = calendar(&state, &ctx, id, query.from, query.to).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/service/oncall/schedules/{id}/calendar",
        get(get_calendar),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_calendar), components(schemas(OnCallStretchView)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_is_bounded() {
        let from = DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_default();
        assert!(check_range(from, from + Duration::days(7)).is_ok());
        assert!(check_range(from, from).is_err());
        assert!(check_range(from, from + Duration::days(MAX_RANGE_DAYS + 1)).is_err());
    }
}
