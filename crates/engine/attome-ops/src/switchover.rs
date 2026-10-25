//! AB2-T8: a planned database switchover, under two-person control.
//!
//! `POST /api/v1/ops/cluster/switchover` (`ops.cluster.switchover`) never
//! touches the cluster. It submits an `ops.switchover` approval whose only
//! step names the Operations role and needs a person (an agent never
//! decides it), and the approval engine never lets the requester decide
//! their own request, so a second person must approve. The answer is 202
//! with the approval's id.
//!
//! The engine carries an approved switchover out itself, from the request's
//! `approved` state (D-551): the 15-second `ops_cluster_poll` job calls
//! [`run_approved`], which takes the cluster-wide advisory lock
//! (`attome-ops/switchover:cluster`), claims the request (the claim is what
//! makes the call happen once) and only then, outside any transaction, asks
//! Patroni (`POST /switchover`, 30 seconds) to move the leader. A switchover
//! Patroni refuses or no node answers is not retried: the request is
//! invalidated and `ops.switchover_failed` names why. A completed one is an
//! `ops_failover_event` row of kind `switchover` (who asked, how long it
//! took) and `ops.switchover_completed`.

use std::time::{Duration, Instant};

use attome_approval::{ApprovalPlan, ApprovalStep, OnTimeout, StepMode};
use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::OpsError;

/// The approval action a switchover waits on.
pub const ACTION_SWITCHOVER: &str = "ops.switchover";

/// The role whose members (but never the requester) approve.
const APPROVER_ROLE: &str = "Operations";

/// The advisory-lock key one switchover at a time runs under.
const LOCK_KEY: &str = "attome-ops/switchover:cluster";

/// How long Patroni may take to switch over.
const SWITCHOVER_TIMEOUT: Duration = Duration::from_secs(30);

/// The most approved switchovers one run looks at.
const BATCH: i64 = 5;

/// `ops.cluster.switchover`: who asks for a planned switchover.
#[derive(Debug)]
pub struct OpsClusterSwitchover;

impl PrivilegeKey for OpsClusterSwitchover {
    const KEY: &'static str = "ops.cluster.switchover";
}

/// A switchover asked for.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SwitchoverRequest {
    /// The member to promote; Patroni picks one when absent.
    #[serde(default)]
    pub candidate: Option<String>,
    /// Why, for the approver and the audit trail (10 to 500 characters).
    pub reason: String,
}

/// The approval a switchover waits on.
#[derive(Debug, Serialize, ToSchema)]
pub struct SwitchoverApproval {
    pub approval_id: Uuid,
    pub status: String,
}

/// Checks a request. Pure.
pub fn check_request(body: &SwitchoverRequest) -> Result<(), AppError> {
    let reason = body.reason.trim().chars().count();
    if !(10..=500).contains(&reason) {
        return Err(AppError::Validation(
            "reason is 10 to 500 characters".into(),
        ));
    }
    if let Some(candidate) = body.candidate.as_deref()
        && !member_name_ok(candidate)
    {
        return Err(AppError::Validation(
            "candidate is a Patroni member name".into(),
        ));
    }
    Ok(())
}

fn member_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// The body Patroni's `POST /switchover` takes. Pure.
pub fn patroni_body(leader: &str, candidate: Option<&str>) -> Value {
    match candidate {
        Some(candidate) => json!({ "leader": leader, "candidate": candidate }),
        None => json!({ "leader": leader }),
    }
}

/// Ask for a planned switchover
///
/// AB2-T8: submits an approval a second person in the Operations role
/// decides; nothing touches the cluster until then. Needs
/// `ops.cluster.switchover` and a configured Patroni cluster. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/cluster/switchover",
    tag = "ops",
    operation_id = "request_ops_switchover",
    request_body = SwitchoverRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Submitted)])))),
    responses(
        (status = 202, description = "The approval the switchover waits on", body = SwitchoverApproval),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.cluster.switchover", body = ErrorResponse),
        (status = 422, description = "A reason out of bounds, a bad candidate name, no Patroni cluster configured, or no Operations role to approve", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn request_switchover(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsClusterSwitchover>>,
    Json(body): Json<SwitchoverRequest>,
) -> Result<(StatusCode, Json<SwitchoverApproval>), AppError> {
    check_request(&body)?;
    if state.base.config.ops.patroni_api_urls.is_empty() {
        return Err(AppError::Validation(
            "no Patroni cluster is configured (ops.patroni_api_urls)".into(),
        ));
    }
    let role: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(APPROVER_ROLE)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let role = role.ok_or_else(|| {
        AppError::Validation("no Operations role exists to approve a switchover".into())
    })?;
    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec![format!("role:{role}")],
            sla_minutes: None,
            on_timeout: OnTimeout::Escalate,
            // `requires_human` is on by default: an agent never decides it.
            extras: Default::default(),
        }],
    };
    let request = attome_audit::approval::gate_with_plan_regarding(
        &state,
        ACTION_SWITCHOVER,
        json!({ "candidate": body.candidate, "reason": body.reason.trim() }),
        ctx.user_id,
        plan,
        None,
    )
    .await?;
    tracing::info!(approval_id = %request.id, "database switchover requested");
    Ok((
        StatusCode::ACCEPTED,
        Json(SwitchoverApproval {
            approval_id: request.id,
            status: request.status.to_string(),
        }),
    ))
}

fn internal(e: impl std::fmt::Display) -> OpsError {
    OpsError::Internal(e.to_string())
}

/// Carries out every approved switchover (at most [`BATCH`] a run), one at a
/// time under the cluster lock; answers how many ran. Nothing without
/// Patroni URLs.
pub async fn run_approved(state: &EngineState) -> Result<usize, OpsError> {
    let urls = &state.base.config.ops.patroni_api_urls;
    if urls.is_empty() {
        return Ok(0);
    }
    let waiting: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM approval_request \
          WHERE action_type = $1 AND status = 'approved' AND executed_at IS NULL \
          ORDER BY requested_at LIMIT $2",
    )
    .bind(ACTION_SWITCHOVER)
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(internal)?;
    let mut ran = 0;
    for id in waiting {
        if run_one(state, id).await? {
            ran += 1;
        }
    }
    Ok(ran)
}

/// Claims and runs one approved switchover; `false` when another node holds
/// the lock or the request is no longer this run's.
async fn run_one(state: &EngineState, id: Uuid) -> Result<bool, OpsError> {
    let db = &state.base.db;
    let mut lock = attome_db::tx::begin(db).await.map_err(internal)?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(LOCK_KEY)
        .fetch_one(&mut *lock)
        .await
        .map_err(internal)?;
    if !locked {
        return Ok(false);
    }
    let request = attome_approval::get(db, id).await.map_err(internal)?;
    if request.status != attome_approval::ApprovalStatus::Approved || request.executed_at.is_some()
    {
        return Ok(false);
    }
    let claimed = match attome_approval::claim_execution(
        db,
        request.id,
        request.row_version,
        attome_approval::POLICY_ACTOR_ID,
    )
    .await
    {
        Ok(claimed) => claimed,
        Err(AppError::Conflict(_)) => return Ok(false),
        Err(e) => return Err(internal(e)),
    };
    // The claim is the once-only guard from here on; the lock is not held
    // across the call to Patroni.
    attome_db::tx::commit(lock).await.map_err(internal)?;

    let candidate = claimed.payload["candidate"].as_str().map(str::to_owned);
    let reason = claimed.payload["reason"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let started = Instant::now();
    let started_at = chrono::Utc::now();
    let outcome = call_patroni(
        &state.base.config.ops.patroni_api_urls,
        candidate.as_deref(),
    )
    .await;
    let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);

    match outcome {
        Ok(old_leader) => {
            attome_approval::complete_execution(db, claimed.id, claimed.row_version)
                .await
                .map_err(internal)?;
            let now = crate::cluster::fetch_cluster(&state.base.config.ops.patroni_api_urls)
                .await
                .ok();
            let leader = now.as_ref().and_then(|c| c.leader());
            let new_leader = leader
                .map(|m| m.name.clone())
                .or_else(|| candidate.clone())
                .unwrap_or_else(|| "unknown".into());
            let timeline = leader.and_then(|m| m.timeline);
            let mut tx = attome_db::tx::begin(db).await.map_err(internal)?;
            let event: Option<Uuid> = sqlx::query_scalar(
                "INSERT INTO ops_failover_event (id, kind, old_leader, new_leader, timeline, \
                        started_at, ended_at, duration_ms, cause, initiated_by) \
                 VALUES (uuidv7(), 'switchover', $1, $2, $3, $4, now(), $5, $6, $7) \
                 ON CONFLICT (kind, new_leader, timeline) DO NOTHING RETURNING id",
            )
            .bind(&old_leader)
            .bind(&new_leader)
            .bind(timeline)
            .bind(started_at)
            .bind(duration_ms)
            .bind(&reason)
            .bind(claimed.requested_by)
            .fetch_optional(&mut *tx)
            .await
            .map_err(internal)?;
            write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::Update,
                    claimed.requested_by,
                    "ops_failover_event",
                    event,
                )
                .named("ops.switchover_completed")
                .comment(format!(
                    "switchover {old_leader} -> {new_leader} in {duration_ms} ms (approval {})",
                    claimed.id
                )),
            )
            .await
            .map_err(internal)?;
            attome_db::tx::commit(tx).await.map_err(internal)?;
            tracing::warn!(from = %old_leader, to = %new_leader, duration_ms, "database switchover completed");
        }
        Err(why) => {
            attome_approval::invalidate_execution(db, claimed.id, claimed.row_version)
                .await
                .map_err(internal)?;
            let mut tx = attome_db::tx::begin(db).await.map_err(internal)?;
            write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::Update,
                    claimed.requested_by,
                    "approval_request",
                    Some(claimed.id),
                )
                .named("ops.switchover_failed")
                .comment(format!("switchover not done: {why}")),
            )
            .await
            .map_err(internal)?;
            attome_db::tx::commit(tx).await.map_err(internal)?;
            tracing::error!(approval_id = %claimed.id, %why, "database switchover failed");
        }
    }
    Ok(true)
}

/// Asks the first answering Patroni node to switch over; answers the old
/// leader, or why it was not done (Patroni's status, or no node answering).
async fn call_patroni(urls: &[String], candidate: Option<&str>) -> Result<String, String> {
    let cluster = crate::cluster::fetch_cluster(urls)
        .await
        .map_err(|e| format!("the cluster could not be read: {e}"))?;
    let leader = cluster
        .leader()
        .map(|m| m.name.clone())
        .ok_or_else(|| "the cluster has no leader".to_owned())?;
    let purpose = attome_outbound::http::Purpose::public("patroni")
        .with_private_urls(urls.iter().map(String::as_str))
        .no_redirects();
    let http = attome_outbound::http::client(purpose, |b| b.timeout(SWITCHOVER_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let body = patroni_body(&leader, candidate);
    for url in urls {
        let target = format!("{}/switchover", url.trim_end_matches('/'));
        match http.post(&target).json(&body).send().await {
            Ok(answer) if answer.status().is_success() => return Ok(leader),
            // A node that answered decided: another node would refuse alike.
            Ok(answer) => {
                return Err(format!(
                    "Patroni answered HTTP {}",
                    answer.status().as_u16()
                ));
            }
            Err(error) => {
                tracing::warn!(%target, %error, "patroni switchover: node did not answer")
            }
        }
    }
    Err("no Patroni node answered".into())
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ops/cluster/switchover", post(request_switchover))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(request_switchover),
    components(schemas(SwitchoverRequest, SwitchoverApproval))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(reason: &str, candidate: Option<&str>) -> SwitchoverRequest {
        SwitchoverRequest {
            candidate: candidate.map(str::to_owned),
            reason: reason.into(),
        }
    }

    #[test]
    fn a_request_needs_a_reason_and_a_member_name() {
        assert!(check_request(&body("planned kernel patching", None)).is_ok());
        assert!(check_request(&body("planned kernel patching", Some("db-2"))).is_ok());
        assert!(check_request(&body("too short", None)).is_err());
        assert!(check_request(&body(&"x".repeat(501), None)).is_err());
        assert!(check_request(&body("planned kernel patching", Some("db 2; rm"))).is_err());
        assert!(check_request(&body("planned kernel patching", Some(""))).is_err());
    }

    #[test]
    fn patroni_is_asked_with_the_leader_and_any_candidate() {
        assert_eq!(patroni_body("db1", None), json!({ "leader": "db1" }));
        assert_eq!(
            patroni_body("db1", Some("db2")),
            json!({ "leader": "db1", "candidate": "db2" })
        );
    }

    #[tokio::test]
    async fn approved_switchover_calls_fake_patroni_once() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let router = axum::Router::new()
            .route(
                "/cluster",
                axum::routing::get(|| async {
                    Json(json!({ "members": [
                        { "name": "db1", "role": "leader", "timeline": 2 },
                        { "name": "db2", "role": "replica", "timeline": 2 }
                    ]}))
                }),
            )
            .route(
                "/switchover",
                axum::routing::post(move |Json(body): Json<Value>| {
                    let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(body, json!({ "leader": "db1", "candidate": "db2" }));
                        "Successfully switched over to \"db2\""
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        let urls = vec![format!("http://{addr}")];
        assert_eq!(call_patroni(&urls, Some("db2")).await.as_deref(), Ok("db1"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
