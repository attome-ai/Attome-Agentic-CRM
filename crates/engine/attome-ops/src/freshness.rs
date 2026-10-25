//! AB4-T9: how fresh each kind of recovery drill is.
//!
//! [`freshness`] judges one kind from its stored evidence (`ops_drill_run`)
//! and its schedule's cadence (weekly 7 days, monthly 31, quarterly 92; 31
//! without a schedule):
//!
//! - `fresh`: the last run passed, within the period;
//! - `failed`: the last run did not pass (its failing checks are named);
//! - `stale`: the last passing run is older than the period;
//! - `never`: no run.
//!
//! The answer is cached per node for an hour (a copy of what the database
//! says, rebuilt on expiry) and dropped whenever evidence is uploaded
//! ([`invalidate`]), so another feature (the release gate, the agent tools)
//! can ask as often as it likes. `GET /api/v1/ops/drills/freshness`
//! (`ops.read`) answers every kind. The daily `ops_drill_freshness` job
//! notifies every holder of `ops.read` once per stale or failed kind,
//! naming the failing checks; nothing about records is in the message.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{Json, Router, extract::State, routing::get};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::evidence::EvidenceKind;
use crate::upgrades::OpsRead;

/// The registered daily job.
pub const JOB: &str = "ops_drill_freshness";

/// How long one evaluation is reused.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Every drill kind, as stored.
pub const KINDS: [EvidenceKind; 7] = [
    EvidenceKind::Restore,
    EvidenceKind::Failover,
    EvidenceKind::Chaos,
    EvidenceKind::Upgrade,
    EvidenceKind::Secrets,
    EvidenceKind::Recovery,
    EvidenceKind::Drain,
];

static CACHE: LazyLock<Mutex<HashMap<String, (Instant, Freshness)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// One kind's freshness.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Freshness {
    pub kind: String,
    /// `fresh`, `stale`, `failed` or `never`.
    pub status: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_ok_run_at: Option<DateTime<Utc>>,
    /// How old a passing run may be.
    pub period_days: i64,
    /// The checks the last run failed (or skipped).
    pub failing_checks: Vec<String>,
}

/// The period a cadence allows. Pure.
pub fn period_days(cadence: Option<&str>) -> i64 {
    match cadence {
        Some("weekly") => 7,
        Some("quarterly") => 92,
        _ => 31,
    }
}

/// The checks of a stored signed report that did not pass. Pure.
pub fn failing_checks(signed: &Value) -> Vec<String> {
    signed["evidence"]["checks"]
        .as_array()
        .map(|checks| {
            checks
                .iter()
                .filter(|c| c["result"].as_str() != Some("pass"))
                .filter_map(|c| c["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The status from the last run and the last passing run. Pure.
pub fn judge(
    now: DateTime<Utc>,
    period_days: i64,
    last_run: Option<(DateTime<Utc>, bool)>,
    last_ok_run_at: Option<DateTime<Utc>>,
) -> &'static str {
    match last_run {
        None => "never",
        Some((_, false)) => "failed",
        Some(_) => match last_ok_run_at {
            Some(at) if now - at <= chrono::Duration::days(period_days) => "fresh",
            _ => "stale",
        },
    }
}

/// Drops every cached evaluation; called when evidence arrives.
pub fn invalidate() {
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
}

/// One kind's freshness, from the cache when it is under an hour old.
pub async fn freshness(db: &DbPool, kind: EvidenceKind) -> Result<Freshness, AppError> {
    let name = crate::drills::kind_name(kind);
    if let Some((at, cached)) = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&name)
        && at.elapsed() < CACHE_TTL
    {
        return Ok(cached.clone());
    }
    let cadence: Option<String> =
        sqlx::query_scalar("SELECT cadence FROM ops_drill_schedule WHERE kind = $1 AND enabled")
            .bind(&name)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let last: Option<(DateTime<Utc>, bool, Value)> = sqlx::query_as(
        "SELECT finished_at, overall_ok, evidence FROM ops_drill_run \
          WHERE kind = $1 ORDER BY finished_at DESC, id DESC LIMIT 1",
    )
    .bind(&name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let last_ok_run_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(finished_at) FROM ops_drill_run WHERE kind = $1 AND overall_ok",
    )
    .bind(&name)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let period = period_days(cadence.as_deref());
    let status = judge(
        Utc::now(),
        period,
        last.as_ref().map(|(at, ok, _)| (*at, *ok)),
        last_ok_run_at,
    );
    let fresh = Freshness {
        kind: name.clone(),
        status: status.to_owned(),
        last_run_at: last.as_ref().map(|(at, _, _)| *at),
        last_ok_run_at,
        period_days: period,
        failing_checks: match &last {
            Some((_, false, signed)) => failing_checks(signed),
            _ => Vec::new(),
        },
    };
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(name, (Instant::now(), fresh.clone()));
    Ok(fresh)
}

/// Every kind's freshness.
pub async fn all(db: &DbPool) -> Result<Vec<Freshness>, AppError> {
    let mut out = Vec::with_capacity(KINDS.len());
    for kind in KINDS {
        out.push(freshness(db, kind).await?);
    }
    Ok(out)
}

/// Drill freshness
///
/// AB4-T9: for every drill kind, `fresh`, `stale`, `failed` or `never`,
/// with when it last ran and passed and the checks it failed. Needs
/// `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/drills/freshness",
    tag = "ops",
    operation_id = "list_ops_drill_freshness",
    responses(
        (status = 200, description = "Every drill kind", body = PaginatedResponse<Freshness>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_freshness(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
) -> Result<Json<PaginatedResponse<Freshness>>, AppError> {
    let items = all(&state.base.db).await?;
    let n = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, n, 1, n.max(1))))
}

/// Everyone who holds `key`, directly or through a role.
async fn privilege_holders(db: &DbPool, key: &str) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT su.id FROM user_account su \
          WHERE (su.is_active IS NULL OR su.is_active = true) \
            AND (EXISTS (SELECT 1 FROM user_account_mm_privilege up \
                           JOIN privilege p ON p.id = up.privilege_ref \
                          WHERE up.user_ref = su.id AND up.is_active = true AND p.is_active = true \
                            AND p.key = $1) \
                 OR EXISTS (SELECT 1 FROM user_account_mm_role ur \
                              JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
                              JOIN privilege p ON p.id = rp.privilege_ref \
                             WHERE ur.user_ref = su.id AND ur.is_deleted = false \
                               AND rp.is_deleted = false AND p.is_active = true AND p.key = $1)) \
          ORDER BY su.created_at, su.id",
    )
    .bind(key)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The notification for a stale or failed kind. Pure.
pub fn message(f: &Freshness) -> (String, String) {
    let subject = format!("Recovery drill \"{}\" is {}", f.kind, f.status);
    let mut body = match f.status.as_str() {
        "failed" => format!(
            "The last {} drill failed. Failing checks: {}.",
            f.kind,
            if f.failing_checks.is_empty() {
                "none named".to_owned()
            } else {
                f.failing_checks.join(", ")
            }
        ),
        _ => format!(
            "No {} drill has passed in the last {} days.",
            f.kind, f.period_days
        ),
    };
    body.push_str(
        " Run it from the drill host (`attome drill readiness`, then the drill), as the \
         drill host guide's \"Running drills\" section describes.",
    );
    (subject, body)
}

/// The daily check: one notification per stale or failed kind to every
/// holder of `ops.read`; answers how many kinds were reported.
pub async fn notify_stale(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let bad: Vec<Freshness> = all(db)
        .await?
        .into_iter()
        .filter(|f| f.status == "stale" || f.status == "failed")
        .collect();
    if bad.is_empty() {
        return Ok(0);
    }
    let recipients = privilege_holders(db, OpsRead::KEY).await?;
    for f in &bad {
        let (subject, body) = message(f);
        tracing::warn!(kind = %f.kind, status = %f.status, "recovery drill needs attention");
        for user in &recipients {
            let request = attome_notification::dispatch::DispatchRequest {
                template_key: None,
                locale: "en".to_owned(),
                recipient_user_ref: Some(*user),
                is_global: false,
                organization_ref: None,
                channels: None,
                subject: Some(subject.clone()),
                body_html: None,
                body_text: Some(body.clone()),
                route: Some("/xrm/ops".to_owned()),
                variables: HashMap::new(),
                priority: "high".to_owned(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            if let Err(error) = attome_notification::dispatch::create_dispatch(
                db,
                &state.base.config.notification,
                request,
            )
            .await
            {
                tracing::error!(%error, %user, kind = %f.kind, "drill freshness notification failed");
            }
        }
    }
    Ok(bad.len())
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ops/drills/freshness", get(list_freshness))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_freshness), components(schemas(Freshness)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn at(days_ago: i64) -> DateTime<Utc> {
        Utc::now() - chrono::Duration::days(days_ago)
    }

    #[test]
    fn fresh_after_ok_upload() {
        assert_eq!(
            judge(Utc::now(), 31, Some((at(2), true)), Some(at(2))),
            "fresh"
        );
    }

    #[test]
    fn failed_lists_failing_checks() {
        assert_eq!(
            judge(Utc::now(), 31, Some((at(1), false)), Some(at(20))),
            "failed"
        );
        let signed = json!({ "evidence": { "checks": [
            { "name": "audit_chain_verify", "result": "pass" },
            { "name": "sample_api_reads", "result": "fail" },
            { "name": "scratch_destroyed", "result": "skipped" }
        ]}});
        assert_eq!(
            failing_checks(&signed),
            ["sample_api_reads", "scratch_destroyed"]
        );
        let f = Freshness {
            kind: "restore".into(),
            status: "failed".into(),
            last_run_at: Some(at(1)),
            last_ok_run_at: None,
            period_days: 31,
            failing_checks: failing_checks(&signed),
        };
        let (subject, body) = message(&f);
        assert!(subject.contains("restore"));
        assert!(body.contains("sample_api_reads"));
    }

    #[test]
    fn stale_after_period() {
        assert_eq!(
            judge(Utc::now(), 7, Some((at(8), true)), Some(at(8))),
            "stale"
        );
        assert_eq!(period_days(Some("weekly")), 7);
        assert_eq!(period_days(Some("quarterly")), 92);
        assert_eq!(period_days(None), 31);
    }

    #[test]
    fn never_without_runs() {
        assert_eq!(judge(Utc::now(), 31, None, None), "never");
    }
}
