//! I2-T1: technicians who can take a work order, ranked.
//!
//! `GET /api/v1/service/work-orders/{id}/candidates` answers the
//! technicians (users with an active `technician_profile`, field-service
//! pack 0009) that pass every hard rule, best first. It proposes; nothing is
//! assigned.
//!
//! **Hard rules** ([`passes`]):
//! - **skills**: every skill the job needs (the work order's
//!   `required_skills`, else its incident type's: `skill` or `skill:level`,
//!   comma separated) is in the technician's `resource_skill` rows at that
//!   level or above;
//! - **territory**: when the sales territories are installed and the work
//!   order's account is in one or more territories (`account_territory`),
//!   the technician is a current `territory_member` of one of them;
//! - **hours**: when the job has a scheduled window, the technician is not
//!   on leave in it (`resource_availability`) and, when workforce shifts are
//!   installed, has a shift (`wfm_shift_assignment`) covering it;
//! - **parts**: the technician's van (`stock_location_code`) has every part
//!   line available, unless the caller asks with `include_without_parts`
//!   (a technician may collect them on the way); the missing parts are
//!   listed either way.
//!
//! **Score** ([`rank`]): the travel estimate (straight-line distance from
//! the technician's base to the site at [`SPEED_KMH`], with a [`DETOUR`]
//! factor; unknown when either has no coordinates) and the slack to the
//! job's due time (`scheduled_end`): a technician who arrives late ranks
//! after every one on time, then shorter travel first, then more slack,
//! then fewer missing parts. A rule whose data is missing (no territory on
//! the account, no window) is not applied, and the answer says which rules
//! were.

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Assumed average speed for the travel estimate.
pub const SPEED_KMH: f64 = 40.0;
/// Road distance over straight-line distance.
pub const DETOUR: f64 = 1.3;
/// Most candidates answered.
pub const MAX_CANDIDATES: usize = 20;
/// Most technicians considered.
const MAX_TECHNICIANS: i64 = 2_000;
const EARTH_RADIUS_KM: f64 = 6_371.0;

/// `work_order.update`: who dispatches.
#[derive(Debug)]
pub struct WorkOrderDispatch;

impl PrivilegeKey for WorkOrderDispatch {
    const KEY: &'static str = "work_order.update";
}

/// A skill a job needs.
#[derive(Debug, Clone, PartialEq)]
pub struct NeededSkill {
    pub skill: String,
    pub min_level: Option<f64>,
}

/// Parses `required_skills` (`skill` or `skill:level`, comma separated;
/// names compared case-insensitively). Pure.
pub fn parse_skills(raw: Option<&str>) -> Vec<NeededSkill> {
    raw.unwrap_or_default()
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let (name, level) = match part.rsplit_once(':') {
                Some((name, level)) => match level.trim().parse::<f64>() {
                    Ok(level) if level.is_finite() => (name, Some(level)),
                    _ => (part, None),
                },
                None => (part, None),
            };
            let skill = name.trim().to_lowercase();
            (!skill.is_empty()).then_some(NeededSkill {
                skill,
                min_level: level,
            })
        })
        .collect()
}

/// Great-circle distance in kilometres. Pure.
pub fn distance_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (lat1, lon1) = (a.0.to_radians(), a.1.to_radians());
    let (lat2, lon2) = (b.0.to_radians(), b.1.to_radians());
    let h = ((lat2 - lat1) / 2.0).sin().powi(2)
        + lat1.cos() * lat2.cos() * ((lon2 - lon1) / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * h.sqrt().min(1.0).asin()
}

/// The travel estimate in whole minutes, `None` without both points. Pure.
pub fn travel_minutes(base: Option<(f64, f64)>, site: Option<(f64, f64)>) -> Option<i64> {
    let km = distance_km(base?, site?) * DETOUR;
    Some((km / SPEED_KMH * 60.0).ceil() as i64)
}

/// What the finder knows about one technician.
#[derive(Debug, Clone, Default)]
pub struct Technician {
    pub user_id: Uuid,
    /// Skill name (lower case) to level (`None`: no level recorded).
    pub skills: HashMap<String, Option<f64>>,
    pub territories: HashSet<Uuid>,
    /// `None` when shifts are not known.
    pub on_shift: Option<bool>,
    pub on_leave: bool,
    /// Product to available quantity on the van.
    pub stock: HashMap<Uuid, f64>,
    pub base: Option<(f64, f64)>,
}

/// What the finder knows about the job.
#[derive(Debug, Clone, Default)]
pub struct Job {
    pub skills: Vec<NeededSkill>,
    /// Empty: no territory rule.
    pub territories: HashSet<Uuid>,
    /// Whether the job has a window, so the hours rule applies.
    pub has_window: bool,
    /// Product to quantity needed.
    pub parts: HashMap<Uuid, f64>,
    pub site: Option<(f64, f64)>,
    pub now: DateTime<Utc>,
    pub due_by: Option<DateTime<Utc>>,
}

/// One ranked candidate.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Candidate {
    pub user_id: Uuid,
    /// Minutes to the site, when both points are known.
    pub travel_minutes: Option<i64>,
    /// Minutes between arrival (now plus travel) and the job's due time;
    /// negative when late.
    pub slack_minutes: Option<i64>,
    /// Parts the van lacks.
    pub missing_parts: Vec<Uuid>,
}

fn has_skills(job: &Job, tech: &Technician) -> bool {
    skills_cover(&tech.skills, &job.skills)
}

/// Whether `have` (skill name in lower case to level) holds every `need`,
/// each at its minimum level when one is set. Pure.
pub fn skills_cover(have: &HashMap<String, Option<f64>>, need: &[NeededSkill]) -> bool {
    need.iter().all(|need| match have.get(&need.skill) {
        None => false,
        Some(level) => match need.min_level {
            None => true,
            Some(min) => level.is_some_and(|l| l >= min),
        },
    })
}

fn missing_parts(job: &Job, tech: &Technician) -> Vec<Uuid> {
    let mut missing: Vec<Uuid> = job
        .parts
        .iter()
        .filter(|(product, needed)| tech.stock.get(product).copied().unwrap_or(0.0) < **needed)
        .map(|(product, _)| *product)
        .collect();
    missing.sort();
    missing
}

/// Whether a technician passes every hard rule. Pure.
pub fn passes(job: &Job, tech: &Technician, include_without_parts: bool) -> bool {
    has_skills(job, tech)
        && (job.territories.is_empty() || !job.territories.is_disjoint(&tech.territories))
        && (!job.has_window || (!tech.on_leave && tech.on_shift != Some(false)))
        && (include_without_parts || missing_parts(job, tech).is_empty())
}

/// The candidates that pass, best first, at most [`MAX_CANDIDATES`]. Pure.
pub fn rank(job: &Job, techs: &[Technician], include_without_parts: bool) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = techs
        .iter()
        .filter(|t| passes(job, t, include_without_parts))
        .map(|t| {
            let travel = travel_minutes(t.base, job.site);
            let slack = job.due_by.map(|due| {
                let arrive = job.now + chrono::Duration::minutes(travel.unwrap_or(0));
                (due - arrive).num_minutes()
            });
            Candidate {
                user_id: t.user_id,
                travel_minutes: travel,
                slack_minutes: slack,
                missing_parts: missing_parts(job, t),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        let late = |c: &Candidate| c.slack_minutes.is_some_and(|s| s < 0);
        late(a)
            .cmp(&late(b))
            .then_with(|| {
                a.travel_minutes
                    .unwrap_or(i64::MAX)
                    .cmp(&b.travel_minutes.unwrap_or(i64::MAX))
            })
            .then_with(|| {
                b.slack_minutes
                    .unwrap_or(i64::MIN)
                    .cmp(&a.slack_minutes.unwrap_or(i64::MIN))
            })
            .then_with(|| a.missing_parts.len().cmp(&b.missing_parts.len()))
            .then_with(|| a.user_id.cmp(&b.user_id))
    });
    out.truncate(MAX_CANDIDATES);
    out
}

/// The answer.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CandidateList {
    pub work_order_id: Uuid,
    /// The hard rules applied: `skills`, `territory`, `hours`, `parts`.
    pub rules: Vec<String>,
    pub candidates: Vec<Candidate>,
}

/// `(account, start, end, own skills, type skills, lat, lon)`.
type JobRow = (
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<String>,
    Option<f64>,
    Option<f64>,
);

/// `(user, van location, base latitude, base longitude)`.
type ProfileRow = (Uuid, Option<String>, Option<f64>, Option<f64>);

async fn exists(db: &attome_db::DbPool, table: &str) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

fn point(lat: Option<f64>, lon: Option<f64>) -> Option<(f64, f64)> {
    match (lat, lon) {
        (Some(lat), Some(lon))
            if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) =>
        {
            Some((lat, lon))
        }
        _ => None,
    }
}

/// Finds and ranks the candidates for one work order.
pub async fn find(
    state: &EngineState,
    work_order: Uuid,
    include_without_parts: bool,
    now: DateTime<Utc>,
) -> Result<CandidateList, AppError> {
    let db = &state.base.db;
    if !exists(db, "technician_profile").await? {
        return Err(AppError::NotFound);
    }
    let row: Option<JobRow> = sqlx::query_as(
        "SELECT wo.account_ref, wo.scheduled_start::timestamptz, wo.scheduled_end::timestamptz, \
                wo.required_skills, it.required_skills, \
                wo.site_latitude::float8, wo.site_longitude::float8 \
           FROM work_order wo \
           LEFT JOIN incident_type it ON it.id = wo.incident_type_ref \
          WHERE wo.id = $1 AND (wo.is_active IS NULL OR wo.is_active = true)",
    )
    .bind(work_order)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((account, start, end, own_skills, type_skills, lat, lon)) = row else {
        return Err(AppError::NotFound);
    };
    let skills = match parse_skills(own_skills.as_deref()) {
        s if s.is_empty() => parse_skills(type_skills.as_deref()),
        s => s,
    };
    let parts: Vec<(Uuid, f64)> = sqlx::query_as(
        "SELECT product_ref, SUM(COALESCE(quantity, 1))::float8 FROM work_order_line \
          WHERE work_order_ref = $1 AND line_kind = 'part' AND product_ref IS NOT NULL \
            AND (is_active IS NULL OR is_active = true) \
          GROUP BY product_ref",
    )
    .bind(work_order)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut rules = vec!["skills".to_owned(), "parts".to_owned()];

    let mut job = Job {
        skills,
        parts: parts.into_iter().collect(),
        site: point(lat, lon),
        now,
        due_by: end,
        ..Job::default()
    };
    let window = match (start, end) {
        (Some(s), Some(e)) => Some((s, e)),
        (Some(s), None) => Some((s, s)),
        (None, Some(e)) => Some((e, e)),
        (None, None) => None,
    };
    job.has_window = window.is_some();
    if job.has_window {
        rules.push("hours".to_owned());
    }
    let territories_installed =
        exists(db, "account_territory").await? && exists(db, "territory_member").await?;
    if territories_installed && let Some(account) = account {
        let territories: Vec<Uuid> = sqlx::query_scalar(
            "SELECT territory_ref FROM account_territory \
              WHERE account_ref = $1 AND territory_ref IS NOT NULL \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(account)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        job.territories = territories.into_iter().collect();
        if !job.territories.is_empty() {
            rules.push("territory".to_owned());
        }
    }

    let profiles: Vec<ProfileRow> = sqlx::query_as(
        "SELECT user_ref, stock_location_code, base_latitude::float8, base_longitude::float8 \
           FROM technician_profile \
          WHERE user_ref IS NOT NULL AND (is_active IS NULL OR is_active = true) \
          ORDER BY user_ref LIMIT $1",
    )
    .bind(MAX_TECHNICIANS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let users: Vec<Uuid> = profiles.iter().map(|p| p.0).collect();
    let mut techs: HashMap<Uuid, Technician> = profiles
        .iter()
        .map(|(user, _, lat, lon)| {
            (
                *user,
                Technician {
                    user_id: *user,
                    base: point(*lat, *lon),
                    ..Technician::default()
                },
            )
        })
        .collect();

    let skill_rows: Vec<(Uuid, String, Option<f64>)> = sqlx::query_as(
        "SELECT user_id, skill, skill_level::float8 FROM resource_skill \
          WHERE user_id = ANY($1) AND is_active IS NOT FALSE",
    )
    .bind(&users)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (user, skill, level) in skill_rows {
        if let Some(t) = techs.get_mut(&user) {
            let entry = t.skills.entry(skill.trim().to_lowercase()).or_insert(level);
            if level > *entry {
                *entry = level;
            }
        }
    }

    if !job.territories.is_empty() {
        let today = now.date_naive();
        let members: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT user_ref, territory_ref FROM territory_member \
              WHERE user_ref = ANY($1) AND territory_ref IS NOT NULL \
                AND (is_active IS NULL OR is_active = true) \
                AND (starts_on IS NULL OR starts_on::date <= $2) \
                AND (ends_on IS NULL OR ends_on::date >= $2)",
        )
        .bind(&users)
        .bind(today)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (user, territory) in members {
            if let Some(t) = techs.get_mut(&user) {
                t.territories.insert(territory);
            }
        }
    }

    if let Some((from, to)) = window {
        let on_leave: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT user_id FROM resource_availability \
              WHERE user_id = ANY($1) AND is_active IS NOT FALSE \
                AND leave_start::timestamptz <= $3 AND leave_end::timestamptz >= $2",
        )
        .bind(&users)
        .bind(from)
        .bind(to)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for user in on_leave {
            if let Some(t) = techs.get_mut(&user) {
                t.on_leave = true;
            }
        }
        if exists(db, "wfm_shift_assignment").await? {
            let on_shift: HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
                "SELECT DISTINCT user_ref FROM wfm_shift_assignment \
                  WHERE user_ref = ANY($1) AND (is_active IS NULL OR is_active = true) \
                    AND start_at::timestamptz <= $2 AND end_at::timestamptz >= $3",
            )
            .bind(&users)
            .bind(from)
            .bind(to)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
            for t in techs.values_mut() {
                t.on_shift = Some(on_shift.contains(&t.user_id));
            }
        }
    }

    if !job.parts.is_empty() {
        let locations: Vec<String> = profiles
            .iter()
            .filter_map(|p| p.1.as_deref().map(str::trim))
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        let products: Vec<Uuid> = job.parts.keys().copied().collect();
        let balances: Vec<(String, Uuid, f64)> = sqlx::query_as(
            "SELECT location_code, product_ref, COALESCE(available, on_hand - COALESCE(reserved, 0), 0)::float8 \
               FROM stock_balance \
              WHERE location_code = ANY($1) AND product_ref = ANY($2) \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&locations)
        .bind(&products)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let by_location: HashMap<String, Vec<Uuid>> =
            profiles.iter().fold(HashMap::new(), |mut acc, p| {
                if let Some(l) = p.1.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
                    acc.entry(l.to_owned()).or_default().push(p.0);
                }
                acc
            });
        for (location, product, available) in balances {
            for user in by_location.get(&location).into_iter().flatten() {
                if let Some(t) = techs.get_mut(user) {
                    *t.stock.entry(product).or_insert(0.0) += available;
                }
            }
        }
    }

    let techs: Vec<Technician> = users.iter().filter_map(|u| techs.remove(u)).collect();
    Ok(CandidateList {
        work_order_id: work_order,
        rules,
        candidates: rank(&job, &techs, include_without_parts),
    })
}

/// The query.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CandidateQuery {
    /// Also answer technicians whose van lacks parts (default false).
    #[serde(default)]
    pub include_without_parts: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/service/work-orders/{id}/candidates",
    operation_id = "get_work_order_candidates",
    tag = "service",
    params(("id" = Uuid, Path, description = "The work order"), CandidateQuery),
    responses(
        (status = 200, description = "The ranked candidates", body = CandidateList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks work_order.update", body = ErrorResponse),
        (status = 404, description = "No such work order, or field service is not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Ranks the technicians who can take a work order.
///
/// Technicians pass the hard rules (skills, territory, hours and van
/// parts) and are ordered on-time first, then by travel estimate and SLA
/// slack. Nothing is assigned: the dispatcher picks.
async fn get_candidates(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkOrderDispatch>>,
    Path(id): Path<Uuid>,
    Query(query): Query<CandidateQuery>,
) -> Result<Json<CandidateList>, AppError> {
    // The caller must see the work order itself.
    attome_records::entity_crud::read_record(&state, &ctx, "work_order", id).await?;
    Ok(Json(
        find(&state, id, query.include_without_parts, Utc::now()).await?,
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/service/work-orders/{id}/candidates",
        get(get_candidates),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_candidates), components(schemas(Candidate, CandidateList)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tech(n: u128) -> Technician {
        Technician {
            user_id: Uuid::from_u128(n),
            ..Technician::default()
        }
    }

    fn at(h: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1)
            .and_then(|d| d.and_hms_opt(h, 0, 0))
            .expect("a real time")
            .and_utc()
    }

    #[test]
    fn skills_parse_with_optional_levels() {
        assert_eq!(
            parse_skills(Some(" HVAC:3, electrical ,,gas:x")),
            vec![
                NeededSkill {
                    skill: "hvac".into(),
                    min_level: Some(3.0)
                },
                NeededSkill {
                    skill: "electrical".into(),
                    min_level: None
                },
                NeededSkill {
                    skill: "gas:x".into(),
                    min_level: None
                },
            ]
        );
        assert!(parse_skills(None).is_empty());
    }

    #[test]
    fn hard_rules_filter_skills_territory_hours_and_parts() {
        let territory = Uuid::from_u128(100);
        let part = Uuid::from_u128(200);
        let job = Job {
            skills: parse_skills(Some("hvac:2")),
            territories: [territory].into_iter().collect(),
            has_window: true,
            parts: [(part, 2.0)].into_iter().collect(),
            now: at(8),
            ..Job::default()
        };
        let mut good = tech(1);
        good.skills.insert("hvac".into(), Some(3.0));
        good.territories.insert(territory);
        good.on_shift = Some(true);
        good.stock.insert(part, 5.0);
        assert!(passes(&job, &good, false));

        let mut low = good.clone();
        low.skills.insert("hvac".into(), Some(1.0));
        assert!(!passes(&job, &low, false), "skill level too low");
        let mut away = good.clone();
        away.territories.clear();
        assert!(!passes(&job, &away, false), "outside the territory");
        let mut off = good.clone();
        off.on_shift = Some(false);
        assert!(!passes(&job, &off, false), "no shift covers the window");
        let mut leave = good.clone();
        leave.on_leave = true;
        assert!(!passes(&job, &leave, false), "on leave");
        let mut empty_van = good.clone();
        empty_van.stock.insert(part, 1.0);
        assert!(!passes(&job, &empty_van, false), "the van lacks a part");
        assert!(passes(&job, &empty_van, true), "unless asked to include");
        let mut unknown_shifts = good.clone();
        unknown_shifts.on_shift = None;
        assert!(passes(&job, &unknown_shifts, false), "shifts not installed");
    }

    #[test]
    fn rules_without_data_do_not_apply() {
        let job = Job::default();
        let mut t = tech(1);
        t.on_leave = true;
        assert!(passes(&job, &t, false), "no window: hours not checked");
    }

    #[test]
    fn travel_is_estimated_from_the_straight_line() {
        // Riyadh to Al Kharj, about 89 km in a straight line.
        let riyadh = (24.7136, 46.6753);
        let kharj = (24.1556, 47.3120);
        let km = distance_km(riyadh, kharj);
        assert!((85.0..95.0).contains(&km), "{km}");
        // 89 km x 1.3 at 40 km/h.
        let minutes = travel_minutes(Some(riyadh), Some(kharj)).expect("both points");
        assert!((170..180).contains(&minutes), "{minutes}");
        assert_eq!(travel_minutes(None, Some(kharj)), None);
        assert_eq!(travel_minutes(Some(riyadh), Some(riyadh)), Some(0));
    }

    #[test]
    fn on_time_first_then_shorter_travel_then_more_slack() {
        let site = (24.7136, 46.6753);
        let job = Job {
            site: Some(site),
            now: at(8),
            due_by: Some(at(10)),
            ..Job::default()
        };
        let mut near = tech(1);
        near.base = Some((24.72, 46.68));
        let mut mid = tech(2);
        mid.base = Some((24.80, 46.75));
        let mut far = tech(3);
        far.base = Some((26.40, 50.10)); // Dammam: hours away, late
        let unknown = tech(4);
        let ranked = rank(&job, &[far.clone(), unknown, mid, near], false);
        let order: Vec<u128> = ranked.iter().map(|c| c.user_id.as_u128()).collect();
        assert_eq!(order, vec![1, 2, 4, 3]);
        assert!(
            ranked[3].slack_minutes.is_some_and(|s| s < 0),
            "Dammam is late"
        );
        assert_eq!(ranked[2].travel_minutes, None);
    }

    #[test]
    fn at_most_twenty_candidates() {
        let techs: Vec<Technician> = (0..30).map(tech).collect();
        assert_eq!(rank(&Job::default(), &techs, false).len(), MAX_CANDIDATES);
    }
}
