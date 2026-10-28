//! Country holiday packs (roadmap Z12-T7): one official calendar per Gulf
//! country, applied through the same writes the admin calendar and
//! holiday-rule routes use, and the yearly reminder to review next year's
//! Hijri holiday dates.
//!
//! A pack carries the country's statutory holidays as rules (a Hijri Eid
//! waits for the moon sighting), each citing the government text it comes
//! from. Packs exist for the countries whose holiday spans an official
//! source states: Saudi Arabia (HRSD), the UAE (Cabinet Resolution 27 of
//! 2024, on u.ae) and Oman (Royal Decree 88/2022). Working hours are a
//! starting point of 08:00 to 16:00 (the eight-hour day the labour laws
//! cap), not an official figure; a deployment changes them on its calendar,
//! and a re-applied pack leaves them alone. Ramadan hours are not in a pack:
//! the laws cap the hours for Muslim workers and set no clock times.

use std::collections::BTreeMap;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::bundle::model::{HolidayRuleDef, SeasonDef};
use crate::calendar_admin as admin;

/// The packs, by lower-case country code.
const PACKS: &[(&str, &str)] = &[
    ("ae", include_str!("ae.json")),
    ("om", include_str!("om.json")),
    ("sa", include_str!("sa.json")),
];

/// One holiday in a pack: a [`HolidayRuleDef`] and the text it comes from.
#[derive(Debug, Clone, Deserialize)]
pub struct PackRule {
    pub name: String,
    pub name_ar: String,
    pub rule: Value,
    #[serde(default)]
    pub needs_sighting: bool,
    pub source_url: String,
}

/// One country's pack, as its JSON file holds it.
#[derive(Debug, Clone, Deserialize)]
pub struct Pack {
    pub country_code: String,
    pub name: String,
    pub name_ar: String,
    pub tz: String,
    pub working_days: Vec<String>,
    pub hours: Value,
    pub holiday_rules: Vec<PackRule>,
    #[serde(default)]
    pub seasons: Vec<SeasonDef>,
    pub source_url: String,
    pub reviewed_for_year: i32,
}

impl Pack {
    fn rule_defs(&self) -> Vec<HolidayRuleDef> {
        self.holiday_rules
            .iter()
            .map(|r| HolidayRuleDef {
                name: r.name.clone(),
                name_ar: Some(r.name_ar.clone()),
                rule: r.rule.clone(),
                needs_sighting: r.needs_sighting,
            })
            .collect()
    }
}

/// A pack as the list shows it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PackSummary {
    /// The code `apply` takes, such as `sa`.
    pub code: String,
    pub country_code: String,
    pub name: String,
    pub name_ar: String,
    pub tz: String,
    /// The holidays, by name.
    pub holidays: Vec<String>,
    pub source_url: String,
    /// The year the dates and spans were last checked against the source.
    pub reviewed_for_year: i32,
}

/// The pack for `code` (`sa`, any case).
pub fn pack(code: &str) -> Option<Pack> {
    let code = code.trim().to_ascii_lowercase();
    PACKS
        .iter()
        .find(|(c, _)| *c == code)
        .and_then(|(_, text)| serde_json::from_str(text).ok())
}

/// Every pack, in code order.
pub fn list() -> Vec<PackSummary> {
    PACKS
        .iter()
        .filter_map(|(code, _)| pack(code).map(|p| (code, p)))
        .map(|(code, p)| PackSummary {
            code: (*code).to_owned(),
            holidays: p.holiday_rules.iter().map(|r| r.name.clone()).collect(),
            country_code: p.country_code,
            name: p.name,
            name_ar: p.name_ar,
            tz: p.tz,
            source_url: p.source_url,
            reviewed_for_year: p.reviewed_for_year,
        })
        .collect()
}

/// What applying a pack did.
#[derive(Debug, Serialize, ToSchema)]
pub struct AppliedPack {
    pub calendar_id: Uuid,
    /// The calendar was created by this apply (not found by country).
    pub created: bool,
    /// Holiday rules added or changed; 0 when the calendar already matched.
    pub rules_changed: usize,
    pub seasons_changed: usize,
}

/// List the country holiday packs
///
/// Z12-T7: the official holiday packs this server carries, with the source
/// each one cites and the year it was last reviewed. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/calendars/packs",
    tag = "admin",
    responses(
        (status = 200, description = "The packs", body = Vec<PackSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_packs(_ctx: Authorized<Privilege<area::Automation>>) -> Json<Vec<PackSummary>> {
    Json(list())
}

/// Apply a country holiday pack
///
/// Z12-T7: creates the country's calendar, or updates the active calendar
/// whose `country_code` matches, with the pack's holiday rules. An existing
/// calendar keeps its name, working days and hours; only rules that differ
/// are written, so applying twice changes nothing the second time. Recorded
/// in the open changeset as calendar and rule writes. Administrators only.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/calendars/packs/{code}/apply",
    tag = "admin",
    params(("code" = String, Path, description = "The pack, such as `sa`")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the apply did", body = AppliedPack),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such pack", body = ErrorResponse),
        (status = 409, description = "Another layer owns the calendar or one of its rules", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn apply_pack(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    recording: RecordingCtx,
    Path(code): Path<String>,
) -> Result<Json<AppliedPack>, AppError> {
    let pack = pack(&code).ok_or(AppError::NotFound)?;
    let rules = pack.rule_defs();
    for rule in &rules {
        admin::check_rule(rule).map_err(AppError::Validation)?;
    }
    for season in &pack.seasons {
        admin::check_season(season).map_err(AppError::Validation)?;
    }
    recording.preflight(&state.base.db).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Two applies at once would both miss the calendar and create two.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-api/calendar-pack:{}", pack.country_code))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this pack is being applied already; try again",
        ));
    }
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM calendar WHERE country_code = $1 AND is_active = true \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(&pack.country_code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (calendar_id, created) = match existing {
        Some(id) => (id, false),
        None => {
            let body: admin::CalendarBody = serde_json::from_value(serde_json::json!({
                "name": pack.name,
                "description": format!("Official holidays ({})", pack.source_url),
                "tz": pack.tz,
                "working_days": pack.working_days,
                "hours": pack.hours,
                "country_code": pack.country_code,
                "name_ar": pack.name_ar,
            }))
            .map_err(AppError::internal)?;
            let row = admin::create_calendar_in_tx(&mut tx, &recording, ctx.user_id, &body).await?;
            recording
                .record(&mut tx, admin::calendar_op(Op::UpsertCalendar, &row)?)
                .await?;
            (row.id, true)
        }
    };

    let live: BTreeMap<String, (Option<String>, Value, bool)> =
        sqlx::query_as::<_, (String, Option<String>, Value, bool)>(
            "SELECT name, name_ar, rule, needs_sighting FROM calendar_holiday_rule \
          WHERE calendar_id = $1 AND is_active = true",
        )
        .bind(calendar_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(name, name_ar, rule, sighting)| (name, (name_ar, rule, sighting)))
        .collect();
    let mut rules_changed = 0;
    for def in &rules {
        let same = live
            .get(def.name.trim())
            .is_some_and(|(name_ar, rule, sighting)| {
                *name_ar == def.name_ar && *rule == def.rule && *sighting == def.needs_sighting
            });
        if same {
            continue;
        }
        let row =
            admin::upsert_rule_in_tx(&mut tx, &recording, calendar_id, ctx.user_id, def).await?;
        let op = admin::rule_op(&mut tx, Op::UpsertCalendarRule, &row).await?;
        recording.record(&mut tx, op).await?;
        rules_changed += 1;
    }

    let live_seasons: BTreeMap<String, (Option<String>, Value)> =
        sqlx::query_as::<_, (String, Option<String>, Value)>(
            "SELECT name, name_ar, definition FROM calendar_season \
          WHERE calendar_id = $1 AND is_active = true",
        )
        .bind(calendar_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(name, name_ar, definition)| (name, (name_ar, definition)))
        .collect();
    let mut seasons_changed = 0;
    for def in &pack.seasons {
        let same = live_seasons
            .get(def.name.trim())
            .is_some_and(|(name_ar, definition)| {
                *name_ar == def.name_ar && *definition == def.definition
            });
        if same {
            continue;
        }
        let row =
            admin::upsert_season_in_tx(&mut tx, &recording, calendar_id, ctx.user_id, def).await?;
        let op = admin::season_op(&mut tx, Op::UpsertCalendarSeason, &row).await?;
        recording.record(&mut tx, op).await?;
        seasons_changed += 1;
    }
    tx.commit().await.map_err(AppError::internal)?;

    if created || rules_changed > 0 || seasons_changed > 0 {
        admin::audit_calendar_change(
            &state,
            ctx.user_id,
            calendar_id,
            AuditOperation::Update,
            "calendar.pack_applied",
            &format!(
                "holiday pack '{}' applied: {rules_changed} rules and {seasons_changed} seasons changed",
                pack.country_code
            ),
        )
        .await;
    }
    Ok(Json(AppliedPack {
        calendar_id,
        created,
        rules_changed,
        seasons_changed,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/calendars/packs", get(list_packs))
        .route(
            "/api/v1/admin/calendars/packs/{code}/apply",
            post(apply_pack),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_packs, apply_pack))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── The yearly review reminder ───────────────────────────────────────────────

/// The job type of the daily review check.
pub const REVIEW_JOB: &str = "calendar.yearly_review";

/// One Hijri holiday's expected first day next year.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedHoliday {
    pub calendar: String,
    pub holiday: String,
    pub first_day: chrono::NaiveDate,
}

/// The reminder's text for `year` in `locale` (`ar` or English). Pure.
pub fn review_text(year: i32, expected: &[ExpectedHoliday], locale: &str) -> (String, String) {
    let arabic = locale.starts_with("ar");
    let lines = expected
        .iter()
        .map(|e| format!("{}: {} {}", e.calendar, e.holiday, e.first_day))
        .collect::<Vec<_>>()
        .join("\n");
    if arabic {
        (
            format!("راجع العطلات الهجرية لعام {year}"),
            format!(
                "هذه هي التواريخ المتوقعة للعطلات الهجرية في {year} وفق تقويم أم القرى. أكّدها أو صحّحها عند الإعلان الرسمي أو رؤية الهلال:\n{lines}"
            ),
        )
    } else {
        (
            format!("Review the Hijri holidays for {year}"),
            format!(
                "These are the expected first days of the Hijri holidays in {year} by the Umm al-Qura calendar. Confirm or correct them when the official announcement or the moon sighting comes:\n{lines}"
            ),
        )
    }
}

/// The daily check: in December (the default calendar's zone, UTC without
/// one) the first run of the year claims the next year's row in
/// `calendar_review_notice` and, in the same transaction, sends every
/// active administrator the expected first days of next year's Hijri
/// holidays. The claimed row is what keeps it to once a year on every node
/// and through restarts. Returns how many reminders it sent.
pub async fn yearly_review(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let tz: Option<String> = sqlx::query_scalar(
        "SELECT tz FROM calendar WHERE is_default = true AND is_active = true LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let tz: chrono_tz::Tz = tz.and_then(|t| t.parse().ok()).unwrap_or(chrono_tz::UTC);
    let today = chrono::Utc::now().with_timezone(&tz).date_naive();
    if today.month() != 12 {
        return Ok(0);
    }
    let year = today.year() + 1;

    let rules: Vec<(String, String, Value)> = sqlx::query_as(
        "SELECT c.name, r.name, r.rule FROM calendar_holiday_rule r \
           JOIN calendar c ON c.id = r.calendar_id \
          WHERE r.is_active = true AND c.is_active = true AND r.rule->>'kind' = 'hijri' \
          ORDER BY c.name, r.name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut expected = Vec::new();
    for (calendar, holiday, rule) in rules {
        let Ok(rule) = serde_json::from_value::<attome_core::calendar::rules::HolidayRule>(rule)
        else {
            continue;
        };
        if let Ok(dates) = attome_core::calendar::rules::expand(&rule, year)
            && let Some(first_day) = dates.first().copied()
        {
            expected.push(ExpectedHoliday {
                calendar,
                holiday,
                first_day,
            });
        }
    }
    expected.sort_by(|a, b| {
        a.first_day
            .cmp(&b.first_day)
            .then(a.calendar.cmp(&b.calendar))
    });
    let recipients = crate::quality_score::admin_recipients(db).await?;

    let mut tx = attome_db::tx::begin(db).await?;
    let claimed: Option<i32> = sqlx::query_scalar(
        "INSERT INTO calendar_review_notice (year) VALUES ($1) \
         ON CONFLICT (year) DO NOTHING RETURNING year",
    )
    .bind(year)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if claimed.is_none() || expected.is_empty() {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(0);
    }
    for user in &recipients {
        let locale: String = state.user_locale(*user).chars().take(2).collect();
        let (subject, body) = review_text(year, &expected, &locale);
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale,
            recipient_user_ref: Some(*user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(subject),
            body_html: None,
            body_text: Some(body),
            route: Some("/xrm/admin/calendars".to_owned()),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch_in_tx(
            &mut tx,
            &state.base.config.notification,
            request,
            None,
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(recipients.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::calendar::rules::{HolidayRule, expand};

    #[test]
    fn every_pack_parses_and_expands_for_2026() {
        for (code, _) in PACKS {
            let pack = pack(code).unwrap_or_else(|| panic!("pack {code} parses"));
            assert_eq!(pack.country_code.to_ascii_lowercase(), *code);
            assert!(
                pack.source_url.starts_with("https://"),
                "{code}: source_url"
            );
            attome_core::calendar::validate_definition(&pack.tz, &pack.working_days, &pack.hours)
                .unwrap_or_else(|e| panic!("{code}: {}", e.0));
            for def in pack.rule_defs() {
                crate::calendar_admin::check_rule(&def).unwrap_or_else(|e| panic!("{code}: {e}"));
                let rule: HolidayRule = serde_json::from_value(def.rule.clone()).expect("rule");
                let dates = expand(&rule, 2026).expect("expands");
                assert!(!dates.is_empty(), "{code}: {} falls in 2026", def.name);
            }
            for rule in &pack.holiday_rules {
                assert!(
                    rule.source_url.starts_with("https://"),
                    "{code}: {}",
                    rule.name
                );
                assert!(!rule.name_ar.trim().is_empty(), "{code}: {}", rule.name);
            }
            let eids = pack
                .holiday_rules
                .iter()
                .filter(|r| r.name.starts_with("Eid al-") && r.needs_sighting)
                .count();
            assert!(eids >= 2, "{code}: both Eids wait for a sighting");
        }
    }

    #[test]
    fn saudi_pack_has_its_four_holidays() {
        let names: Vec<String> = pack("SA")
            .expect("sa")
            .holiday_rules
            .into_iter()
            .map(|r| r.name)
            .collect();
        for want in ["Founding Day", "National Day", "Eid al-Fitr", "Eid al-Adha"] {
            assert!(names.iter().any(|n| n == want), "{want}");
        }
    }

    #[test]
    fn oman_eid_al_fitr_runs_29_ramadan_to_3_shawwal() {
        use attome_core::calendar::hijri::{self, HijriDate};
        let pack = pack("om").expect("om");
        let mut dates = Vec::new();
        for r in pack
            .holiday_rules
            .iter()
            .filter(|r| r.name.starts_with("Eid al-Fitr"))
        {
            let rule: HolidayRule = serde_json::from_value(r.rule.clone()).expect("rule");
            dates.extend(expand(&rule, 2026).expect("expands"));
        }
        dates.sort_unstable();
        dates.dedup();
        let first = hijri::from_hijri(HijriDate::new(1447, 9, 29)).expect("29 Ramadan");
        let last = hijri::from_hijri(HijriDate::new(1447, 10, 3)).expect("3 Shawwal");
        assert_eq!(dates.first(), Some(&first));
        assert_eq!(dates.last(), Some(&last));
        assert_eq!(dates.len() as i64, (last - first).num_days() + 1);
    }

    #[test]
    fn review_text_lists_each_holiday_in_the_reader_language() {
        let expected = [ExpectedHoliday {
            calendar: "Saudi Arabia".into(),
            holiday: "Eid al-Fitr".into(),
            first_day: chrono::NaiveDate::from_ymd_opt(2027, 3, 9).expect("date"),
        }];
        let (subject, body) = review_text(2027, &expected, "en");
        assert!(subject.contains("2027"));
        assert!(body.contains("Saudi Arabia: Eid al-Fitr 2027-03-09"));
        let (subject, _) = review_text(2027, &expected, "ar");
        assert!(subject.starts_with("راجع"));
    }
}
