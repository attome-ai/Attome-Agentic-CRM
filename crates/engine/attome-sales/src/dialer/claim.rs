//! Claim next (roadmap D21-T4): a caller takes the next pending member of a
//! call list. One statement claims it (`FOR UPDATE SKIP LOCKED`), so two
//! callers never get the same member. The claimed member is then checked:
//!
//! - do not call (`do_not_call` on the record) — skipped;
//! - no active `sales_calls` consent, when the deployment defines that
//!   purpose — skipped;
//! - the record's attempts reached the list's `max_attempts_per_record` —
//!   skipped;
//! - outside calling hours for the number's country, or today's attempts
//!   reached `max_attempts_per_day` — snoozed until later.
//!
//! A failed check stores its reason on the member and the next member is
//! tried, at most [`MAX_LOOPS`] times per call; each skip writes a business
//! event. A member that passes is returned to the caller.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::hours::{CallingHours, country_of, within_calling_hours};

/// Most members looked at per call.
pub const MAX_LOOPS: usize = 50;

/// Why a member was passed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    Hours,
    DoNotContact,
    NoConsent,
    MaxAttempts,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hours => "hours",
            Self::DoNotContact => "do_not_contact",
            Self::NoConsent => "no_consent",
            Self::MaxAttempts => "max_attempts",
        }
    }

    /// Hours and the daily limit pass with time; the others do not.
    pub fn snoozes(self) -> bool {
        matches!(self, Self::Hours)
    }
}

/// What a claimed member's checks see.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberFacts {
    pub phone: Option<String>,
    pub do_not_call: bool,
    /// `None` when the deployment requires no consent for sales calls.
    pub has_consent: Option<bool>,
    pub attempts: u32,
    pub attempts_today: u32,
    pub max_attempts: Option<u32>,
    pub max_per_day: Option<u32>,
}

/// The first failed check, if any (pure).
pub fn check(
    facts: &MemberFacts,
    hours: &[CallingHours],
    now: DateTime<Utc>,
) -> Option<(SkipReason, Option<DateTime<Utc>>)> {
    if facts.do_not_call {
        return Some((SkipReason::DoNotContact, None));
    }
    if facts.has_consent == Some(false) {
        return Some((SkipReason::NoConsent, None));
    }
    if facts.max_attempts.is_some_and(|m| facts.attempts >= m) {
        return Some((SkipReason::MaxAttempts, None));
    }
    if facts.max_per_day.is_some_and(|m| facts.attempts_today >= m) {
        let tomorrow = (now.date_naive() + Duration::days(1))
            .and_hms_opt(0, 0, 0)
            .map(|t| t.and_utc());
        return Some((SkipReason::Hours, tomorrow));
    }
    let allowed = facts
        .phone
        .as_deref()
        .and_then(country_of)
        .is_some_and(|(country, tz)| within_calling_hours(hours, country, now, tz));
    if !allowed {
        return Some((SkipReason::Hours, Some(now + Duration::hours(1))));
    }
    None
}

/// The member a caller got.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct ClaimedMember {
    pub member_id: Uuid,
    pub entity_name: String,
    pub record_id: String,
    pub phone: Option<String>,
}

/// A member passed over on the way, with its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct SkippedMember {
    pub member_id: Uuid,
    pub reason: SkipReason,
}

/// The answer to a claim.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct ClaimResult {
    /// `None` when no callable member is left.
    pub member: Option<ClaimedMember>,
    pub skipped: Vec<SkippedMember>,
}

type Claimed = (Uuid, String, String, Option<f64>);

async fn facts_for(
    state: &EngineState,
    list: Uuid,
    entity: &str,
    record: &str,
    attempts: u32,
    now: DateTime<Utc>,
) -> Result<MemberFacts, AppError> {
    let db = &state.base.db;
    let registry = state.entities.load();
    let Some(meta) = registry.get(entity) else {
        return Ok(MemberFacts {
            phone: None,
            do_not_call: false,
            has_consent: None,
            attempts,
            attempts_today: 0,
            max_attempts: None,
            max_per_day: None,
        });
    };
    let has_dnc = meta.attrs.iter().any(|a| a.logicalname == "do_not_call");
    let has_phone = meta.attrs.iter().any(|a| a.logicalname == "phone");
    let table = attome_core::quote_ident(&meta.logicalname);
    drop(registry);
    let dnc_col = if has_dnc {
        "COALESCE(t.do_not_call, false)"
    } else {
        "false"
    };
    let phone_col = if has_phone {
        "t.phone::text"
    } else {
        "NULL::text"
    };
    let record_id = Uuid::parse_str(record).map_err(|_| AppError::NotFound)?;
    let row: Option<(Option<String>, bool)> = sqlx::query_as(&format!(
        "SELECT {phone_col}, {dnc_col} FROM {table} t WHERE t.id = $1"
    ))
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (phone, do_not_call) = row.unwrap_or((None, false));
    let has_purposes: bool =
        sqlx::query_scalar("SELECT to_regclass('audit_consent_purpose') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let purpose: Option<Uuid> = if has_purposes {
        sqlx::query_scalar(
            "SELECT id FROM audit_consent_purpose WHERE key = 'sales_calls' \
             AND (is_active IS NULL OR is_active = true) LIMIT 1",
        )
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    } else {
        None
    };
    let has_consent = match purpose {
        None => None,
        Some(purpose) => Some(
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM audit_consent WHERE purpose_ref = $1 \
                 AND regarding_entity = $2 AND regarding_id = $3 AND status = 'granted')",
            )
            .bind(purpose)
            .bind(entity)
            .bind(record)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?,
        ),
    };
    let limits: Option<(Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT max_attempts_per_record::float8, max_attempts_per_day::float8 \
         FROM call_list WHERE id = $1",
    )
    .bind(list)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (max_attempts, max_per_day) = limits.unwrap_or((None, None));
    let attempts_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM call_attempt a JOIN call_list_member m ON m.id = a.member_ref \
         WHERE m.entity_name = $1 AND m.record_id = $2 AND a.created_at::date = $3",
    )
    .bind(entity)
    .bind(record)
    .bind(now.date_naive())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let limit = |v: Option<f64>| v.filter(|v| *v >= 1.0).map(|v| v as u32);
    Ok(MemberFacts {
        phone: phone.filter(|p| !p.trim().is_empty()),
        do_not_call,
        has_consent,
        attempts,
        attempts_today: u32::try_from(attempts_today).unwrap_or(u32::MAX),
        max_attempts: limit(max_attempts),
        max_per_day: limit(max_per_day),
    })
}

/// Claims the next callable member of `list` for `user`.
pub async fn claim_next(
    state: &EngineState,
    user: Uuid,
    list: Uuid,
    now: DateTime<Utc>,
) -> Result<ClaimResult, AppError> {
    let db = &state.base.db;
    let hours: Vec<CallingHours> =
        sqlx::query_as::<_, (Option<String>, Option<f64>, Option<String>, Option<String>)>(
            "SELECT country_code, weekday::float8, start_local, end_local FROM calling_hours \
         WHERE (is_active IS NULL OR is_active = true)",
        )
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .filter_map(|(c, w, s, e)| CallingHours::parse(&c?, w?, &s?, &e?))
        .collect();
    let mut skipped = Vec::new();
    for _ in 0..MAX_LOOPS {
        let claimed: Option<Claimed> = sqlx::query_as(
            "UPDATE call_list_member SET member_status = 'claimed', claimed_by = $2, \
                 claimed_at = $3, modified_at = now(), row_version = row_version + 1 \
             WHERE id = (SELECT id FROM call_list_member \
                 WHERE list_ref = $1 AND member_status = 'pending' \
                   AND (next_attempt_after IS NULL OR next_attempt_after <= $3) \
                   AND (is_active IS NULL OR is_active = true) \
                 ORDER BY position NULLS LAST, id FOR UPDATE SKIP LOCKED LIMIT 1) \
             RETURNING id, entity_name, record_id, attempts::float8",
        )
        .bind(list)
        .bind(user)
        .bind(now)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let Some((member, entity, record, attempts)) = claimed else {
            return Ok(ClaimResult {
                member: None,
                skipped,
            });
        };
        let attempts = attempts.map(|a| a.max(0.0) as u32).unwrap_or(0);
        let facts = facts_for(state, list, &entity, &record, attempts, now).await?;
        match check(&facts, &hours, now) {
            None => {
                return Ok(ClaimResult {
                    member: Some(ClaimedMember {
                        member_id: member,
                        entity_name: entity,
                        record_id: record,
                        phone: facts.phone,
                    }),
                    skipped,
                });
            }
            Some((reason, until)) => {
                let mut tx = attome_db::tx::begin(db).await?;
                sqlx::query(
                    "UPDATE call_list_member SET member_status = $2, skip_reason = $3, \
                     next_attempt_after = $4, claimed_by = NULL, claimed_at = NULL, \
                     modified_at = now(), row_version = row_version + 1 WHERE id = $1",
                )
                .bind(member)
                .bind(if reason.snoozes() {
                    "snoozed"
                } else {
                    "skipped"
                })
                .bind(reason.as_str())
                .bind(until)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                attome_audit::write_business_event_in_tx(
                    &mut tx,
                    &attome_audit::audit_service(state),
                    attome_audit::BusinessEvent::new(
                        "call_list_member",
                        member,
                        attome_audit::AuditOperation::Update,
                        "call_skipped",
                        user,
                    )
                    .comment(format!("call skipped: {}", reason.as_str())),
                )
                .await?;
                attome_db::tx::commit(tx).await?;
                skipped.push(SkippedMember {
                    member_id: member,
                    reason,
                });
            }
        }
    }
    Ok(ClaimResult {
        member: None,
        skipped,
    })
}

/// `call_list.call`: may take members from call lists and call them.
#[derive(Debug)]
pub struct CallListCall;

impl attome_server::authz::PrivilegeKey for CallListCall {
    const KEY: &'static str = "call_list.call";
}

/// Claim the next call
///
/// Takes the list's next pending member for the caller, so two callers never get the same one; a
/// member marked do-not-call, or without sales-call consent where that is required, is skipped.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/call-lists/{id}/claim",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The call list")),
    responses(
        (status = 200, description = "The next callable member, or null when none is left; members passed over are listed with their reasons", body = ClaimResult),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller lacks call_list.call, or the list is someone else's shared list and the caller lacks call_list.share", body = attome_types::ErrorResponse),
        (status = 404, description = "No such call list", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_claim(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<CallListCall>>,
    axum::extract::Path(list): axum::extract::Path<Uuid>,
) -> Result<axum::Json<ClaimResult>, AppError> {
    super::sharing::require_list_use(&state, &ctx, list).await?;
    Ok(axum::Json(
        claim_next(&state, ctx.user_id, list, Utc::now()).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_claim),
    components(schemas(ClaimResult, ClaimedMember, SkippedMember, SkipReason))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveTime, TimeZone};

    fn facts() -> MemberFacts {
        MemberFacts {
            phone: Some("+966501234567".into()),
            do_not_call: false,
            has_consent: None,
            attempts: 0,
            attempts_today: 0,
            max_attempts: Some(3),
            max_per_day: Some(2),
        }
    }

    fn every_day() -> Vec<CallingHours> {
        (1..=7)
            .map(|d| CallingHours {
                country: "SA".into(),
                weekday: d,
                start: NaiveTime::from_hms_opt(9, 0, 0).unwrap_or_default(),
                end: NaiveTime::from_hms_opt(18, 0, 0).unwrap_or_default(),
            })
            .collect()
    }

    fn noon_riyadh() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn a_callable_member_passes() {
        assert_eq!(check(&facts(), &every_day(), noon_riyadh()), None);
    }

    #[test]
    fn each_check_has_its_reason() {
        let hours = every_day();
        let now = noon_riyadh();
        let reason = |f: MemberFacts| check(&f, &hours, now).map(|(r, _)| r);
        assert_eq!(
            reason(MemberFacts {
                do_not_call: true,
                ..facts()
            }),
            Some(SkipReason::DoNotContact)
        );
        assert_eq!(
            reason(MemberFacts {
                has_consent: Some(false),
                ..facts()
            }),
            Some(SkipReason::NoConsent)
        );
        assert_eq!(
            reason(MemberFacts {
                attempts: 3,
                ..facts()
            }),
            Some(SkipReason::MaxAttempts)
        );
        assert_eq!(
            reason(MemberFacts {
                attempts_today: 2,
                ..facts()
            }),
            Some(SkipReason::Hours),
            "the daily limit snoozes until tomorrow"
        );
        let night = Utc
            .with_ymd_and_hms(2026, 11, 3, 20, 0, 0)
            .single()
            .unwrap_or_default();
        assert!(matches!(
            check(&facts(), &hours, night),
            Some((SkipReason::Hours, Some(_)))
        ));
        assert_eq!(
            reason(MemberFacts {
                phone: None,
                ..facts()
            }),
            Some(SkipReason::Hours),
            "no number to place in a country is never in hours"
        );
    }
}
