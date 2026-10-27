//! M9-T3: approve or reject from email.
//!
//! Every minute a sweep ([`SWEEP_JOB`]) finds pending plan-bearing requests
//! whose current step has not been emailed yet (`approval_email_round`,
//! migration 0213). For each one it mails every approver who may decide that
//! step now (`my_work_approvals::is_eligible`: an approver of the step who
//! is not the requester and may read the record). Each mail carries its own
//! link token (`approval_email_link`). A token is `{public_id}.{secret}`:
//! the secret is 244 random bits stored only as a peppered HMAC (the
//! password-reset scheme). It lasts [`LINK_TTL_HOURS`] or until the request
//! expires, belongs to one approver, one request and one step, and works
//! once.
//!
//! The link opens the web page `/approval-link`, with the token in the URL
//! fragment so it never reaches a server log or a `Referer`. The page reads
//! the request through `POST /api/v1/approvals/email-link`. A low-risk
//! request, one whose action type is listed in the `approval.email_decide_actions`
//! setting, is decided there through `POST /api/v1/approvals/email-link/decide`,
//! as the approver, by the same path as the decide route. Every other request
//! is high-risk: the page only offers to open the request page, which needs
//! sign-in (and that route's own checks). A malformed, unknown, wrong or
//! expired token is 401. A used one, or one whose step has passed, is 409. A
//! decision that fails releases the token for another try.
//!
//! The `approval.email_links` setting turns the emails off. Only requests
//! whose step started within the last day are emailed, so turning it on
//! does not mail an old backlog.

use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::approval_process::ChangedAttribute;

/// The registered job type of the sweep (no payload).
pub const SWEEP_JOB: &str = "approval_email_links";

/// How long a link works, at most.
pub const LINK_TTL_HOURS: i64 = 72;

/// Approvers mailed per request step.
const MAX_APPROVERS: usize = 25;

/// Requests one sweep handles.
const SWEEP_BATCH: i64 = 100;

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepSummary {
    pub steps: usize,
    pub links: usize,
}

fn setting(state: &EngineState, key: &str) -> Option<Value> {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
}

/// Whether a request of `action_type` may be decided straight from its link.
pub fn decide_here(state: &EngineState, action_type: &str) -> bool {
    setting(state, "approval.email_decide_actions")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .any(|a| a.as_str() == Some(action_type))
}

/// A new link secret: two random v4 UUIDs (244 random bits) as hex.
fn new_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Splits a presented token into its public id and secret.
pub fn parse_token(token: &str) -> Option<(Uuid, &str)> {
    let (public_id, secret) = token.trim().split_once('.')?;
    let public_id = Uuid::parse_str(public_id).ok()?;
    (secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some((public_id, secret))
}

/// Issues one approver's link for `request`'s current step, in `tx`; the
/// bearer token to mail. Fails on a second link for the same approver and
/// step (unique key).
pub async fn issue_link_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    request: &attome_approval::ApprovalRequest,
    approver_id: Uuid,
) -> Result<String, AppError> {
    let public_id = Uuid::now_v7();
    let secret = new_secret();
    let secret_hash =
        attome_auth::apikey_hash::hash_peppered_secret(&state.base.pepper_ring(), &secret);
    let expires_at = (Utc::now() + chrono::Duration::hours(LINK_TTL_HOURS)).min(request.expires_at);
    sqlx::query(
        "INSERT INTO approval_email_link \
             (public_id, secret_hash, request_id, approver_id, step, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(public_id)
    .bind(&secret_hash)
    .bind(request.id)
    .bind(approver_id)
    .bind(request.step)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(format!("{public_id}.{secret}"))
}

/// The mail text for one approver.
fn mail_body(request: &attome_approval::ApprovalRequest, requester: &str, link: &str) -> String {
    let title = request
        .payload
        .get("process_name")
        .and_then(Value::as_str)
        .unwrap_or(&request.action_type);
    let mut body = format!("{requester} asks for your approval: {title}.");
    if let Some(reason) = request.payload.get("reason").and_then(Value::as_str) {
        body.push_str(&format!(" Why: {reason}."));
    }
    for change in crate::approval_process::changes_of(&request.payload) {
        body.push_str(&format!(
            " {}: {} → {}.",
            change.attribute,
            show(&change.from),
            show(&change.to)
        ));
    }
    body.push_str(&format!(
        " Open the request to approve or reject it: {link} (the link works once, for you only)."
    ));
    body
}

fn show(v: &Value) -> String {
    match v {
        Value::Null => "—".to_owned(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// M9-T3: mails the approvers of every pending request step not mailed yet.
pub async fn sweep(state: &EngineState) -> Result<SweepSummary, AppError> {
    let mut summary = SweepSummary::default();
    if setting(state, "approval.email_links").and_then(|v| v.as_bool()) == Some(false) {
        return Ok(summary);
    }
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT r.id FROM approval_request r \
          WHERE r.status = 'pending' AND r.plan IS NOT NULL AND r.expires_at > now() \
            AND COALESCE(r.step_started_at, r.requested_at) > now() - interval '1 day' \
            AND NOT EXISTS (SELECT 1 FROM approval_email_round e \
                             WHERE e.request_id = r.id AND e.step = r.step) \
          ORDER BY r.requested_at, r.id LIMIT $1",
    )
    .bind(SWEEP_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for id in due {
        match mail_step(state, id).await {
            Ok(links) => {
                summary.steps += 1;
                summary.links += links;
            }
            Err(error) => {
                tracing::warn!(request_id = %id, %error, "approval email links: step not mailed; the next sweep tries again");
            }
        }
    }
    Ok(summary)
}

/// Mails one request's current step; the links issued.
async fn mail_step(state: &EngineState, request_id: Uuid) -> Result<usize, AppError> {
    let request = attome_approval::get(&state.base.db, request_id).await?;
    let Some(plan) = &request.plan else {
        return Ok(0);
    };
    let Some(step) = usize::try_from(request.step)
        .ok()
        .and_then(|i| plan.steps.get(i))
    else {
        return Ok(0);
    };
    let (_, _, allowed, _) =
        attome_audit::approval::resolve_step_approvers(state, step, &request).await?;
    let mut approvers = Vec::new();
    for user_id in allowed.into_iter().take(MAX_APPROVERS) {
        let Ok(ctx) = state.base.security.resolve(user_id).await else {
            continue;
        };
        if crate::my_work_approvals::is_eligible(state, &ctx, &request).await? {
            approvers.push(user_id);
        }
    }
    let recipients: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, email FROM user_account \
          WHERE id = ANY($1) AND is_active AND email IS NOT NULL AND email <> ''",
    )
    .bind(&approvers)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let requester: Option<String> =
        sqlx::query_scalar("SELECT user_name FROM user_account WHERE id = $1")
            .bind(request.requested_by)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let requester = requester.unwrap_or_else(|| "Someone".to_owned());

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // One sweep per step, whichever node gets here first.
    let claimed = sqlx::query(
        "INSERT INTO approval_email_round (request_id, step) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
    )
    .bind(request.id)
    .bind(request.step)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if claimed == 0 {
        return Ok(0);
    }
    let frontend = state.base.config.frontend_url();
    // J12-T2: each approver's push, sent after the commit (no I/O inside
    // the transaction) with the same single-use token as their email.
    let low_risk = decide_here(state, &request.action_type);
    let mut pushes: Vec<(Uuid, attome_notification::push::PushMessage)> =
        Vec::with_capacity(recipients.len());
    for (user_id, email) in &recipients {
        let bearer = issue_link_in_tx(&mut tx, state, &request, *user_id).await?;
        let link = format!("{frontend}/approval-link#{bearer}");
        let subject = format!(
            "Approval needed: {}",
            request
                .payload
                .get("process_name")
                .and_then(Value::as_str)
                .unwrap_or(&request.action_type)
        );
        pushes.push((
            *user_id,
            attome_notification::push::PushMessage {
                title: subject.clone(),
                body: format!("{requester} asks for your decision"),
                route: Some(format!("/approval-link#{bearer}")),
                actions: attome_notification::push::approval_actions(&bearer, low_risk),
            },
        ));
        let (subject, text_body, html_body) = attome_email::templates::generic_notification(
            &subject,
            &mail_body(&request, &requester, &link),
        );
        let delivery_id = Uuid::now_v7();
        attome_email::delivery::record_queued_in_tx(
            &mut tx,
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::Generic,
            email,
            &subject,
            Some(*user_id),
            None,
            None,
        )
        .await
        .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
                to: email.clone(),
                subject,
                text_body,
                html_body: Some(html_body),
                delivery_id: Some(delivery_id),
                from_override: None,
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: Vec::new(),
                stream: Default::default(),
                list_unsubscribe: None,
            })),
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    // A push that fails is logged; the email and the token stand.
    for (user_id, message) in &pushes {
        if let Err(error) =
            attome_notification::push::send_to_user(state, Some(*user_id), message).await
        {
            tracing::warn!(%user_id, %error, "approval push not delivered");
        }
    }
    Ok(recipients.len())
}

/// A presented link.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = ApprovalEmailLinkBody)]
pub struct LinkBody {
    /// The token from the emailed link.
    pub token: String,
}

/// A decision through a link.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LinkDecideBody {
    pub token: String,
    /// `approve` or `reject`.
    pub decision: String,
    /// Optional, at most 2000 characters.
    #[serde(default)]
    pub comment: Option<String>,
}

/// What a link's page shows.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkView {
    pub request_id: Uuid,
    pub action_type: String,
    pub title: Option<String>,
    pub status: String,
    pub requested_by_name: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub changes: Vec<ChangedAttribute>,
    /// `true`: decide on this page; `false`: open the request page and sign in.
    pub decide_here: bool,
    pub link_expires_at: DateTime<Utc>,
}

/// The outcome of a decision through a link.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkDecided {
    pub request_id: Uuid,
    pub status: String,
}

#[derive(sqlx::FromRow)]
struct LinkRow {
    id: Uuid,
    secret_hash: String,
    request_id: Uuid,
    approver_id: Uuid,
    step: i32,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
}

/// The link a token names, its secret verified and unexpired; the request
/// it is for, still pending at the link's step and approver still active.
async fn resolve_link(
    state: &EngineState,
    token: &str,
) -> Result<(LinkRow, attome_approval::ApprovalRequest), AppError> {
    let Some((public_id, secret)) = parse_token(token) else {
        return Err(AppError::Unauthorized);
    };
    let row: Option<LinkRow> = sqlx::query_as(
        "SELECT id, secret_hash, request_id, approver_id, step, expires_at, used_at \
           FROM approval_email_link WHERE public_id = $1",
    )
    .bind(public_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let ring = state.base.pepper_ring();
    let Some(row) = row else {
        // The same hashing work as a hit, so a miss is not faster.
        let _ = attome_auth::apikey_hash::hash_peppered_secret(&ring, secret);
        return Err(AppError::Unauthorized);
    };
    match attome_auth::apikey_hash::verify_peppered_secret(&ring, secret, &row.secret_hash).await? {
        attome_auth::VerifyOutcome::Fail => return Err(AppError::Unauthorized),
        attome_auth::VerifyOutcome::Ok | attome_auth::VerifyOutcome::OkNeedsRehash => {}
    }
    if row.expires_at <= Utc::now() {
        return Err(AppError::Unauthorized);
    }
    if row.used_at.is_some() {
        return Err(AppError::Conflict("this link has been used"));
    }
    let request = attome_approval::get(&state.base.db, row.request_id).await?;
    if request.status != attome_approval::ApprovalStatus::Pending || request.step != row.step {
        return Err(AppError::Conflict(
            "this request has been decided or has moved to another step",
        ));
    }
    let active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(row.approver_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if active != Some(true) {
        return Err(AppError::Unauthorized);
    }
    Ok((row, request))
}

/// Open an emailed approval link
///
/// Open an emailed approval link.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/email-link",
    tag = "approvals",
    operation_id = "read_approval_email_link",
    description = "Reads the request an emailed approval link is for (M9-T3), without using the link: what is asked, by whom, why, the changes, and whether it may be decided on the link's page (`decide_here`) or needs the signed-in request page. Public: the token is the credential.",
    request_body = LinkBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "reads the request a link names; the token is presented in the body, not the URL"
    )))),
    responses(
        (status = 200, description = "The request", body = LinkView),
        (status = 401, description = "Malformed, unknown, wrong or expired link", body = ErrorResponse),
        (status = 409, description = "The link was used, or the request was decided or moved on", body = ErrorResponse),
    ),
)]
async fn read_link(
    State(state): State<EngineState>,
    Json(body): Json<LinkBody>,
) -> Result<Json<LinkView>, AppError> {
    let (row, request) = resolve_link(&state, &body.token).await?;
    let requester: Option<String> =
        sqlx::query_scalar("SELECT user_name FROM user_account WHERE id = $1")
            .bind(request.requested_by)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let text = |key: &str| {
        request
            .payload
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    Ok(Json(LinkView {
        request_id: request.id,
        title: text("process_name"),
        reason: text("reason"),
        changes: crate::approval_process::changes_of(&request.payload),
        decide_here: decide_here(&state, &request.action_type),
        action_type: request.action_type,
        status: request.status.to_string(),
        requested_by_name: requester,
        requested_at: request.requested_at,
        link_expires_at: row.expires_at,
    }))
}

/// Decide through an emailed link
///
/// Decide through an emailed link. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/email-link/decide",
    tag = "approvals",
    operation_id = "decide_by_approval_email_link",
    description = "Approves or rejects a low-risk request from its emailed link (M9-T3), as the link's approver, by the same path as `POST /api/v1/approvals/{id}/decide`. The link works once; a decision that fails releases it. A high-risk request (its action type not in `approval.email_decide_actions`) is refused: open the request page and sign in. Public: the token is the credential.",
    request_body = LinkDecideBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Approved),
        (attome_audit::AuditCategory::Security, attome_audit::AuditOperation::DecisionDigest),
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute),
    ])))),
    responses(
        (status = 200, description = "Decided", body = LinkDecided),
        (status = 401, description = "Malformed, unknown, wrong or expired link", body = ErrorResponse),
        (status = 403, description = "High-risk: decide on the request page after signing in", body = ErrorResponse),
        (status = 409, description = "The link was used, or the request was decided or moved on", body = ErrorResponse),
        (status = 422, description = "Not approve or reject, or the comment is too long", body = ErrorResponse),
    ),
)]
async fn decide_by_link(
    State(state): State<EngineState>,
    Json(body): Json<LinkDecideBody>,
) -> Result<Json<LinkDecided>, AppError> {
    if !matches!(body.decision.as_str(), "approve" | "reject") {
        return Err(AppError::Validation(
            "decision must be \"approve\" or \"reject\"".into(),
        ));
    }
    let comment = attome_approval::normalize_decision_comment(body.comment.as_deref())?;
    let (row, request) = resolve_link(&state, &body.token).await?;
    if !decide_here(&state, &request.action_type) {
        return Err(AppError::Forbidden);
    }
    // Single use: claim the link, then decide; a failed decision gives it back.
    let claimed = sqlx::query(
        "UPDATE approval_email_link SET used_at = now() WHERE id = $1 AND used_at IS NULL",
    )
    .bind(row.id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if claimed == 0 {
        return Err(AppError::Conflict("this link has been used"));
    }
    match crate::approval_admin::decide_as(
        &state,
        row.approver_id,
        request.id,
        &body.decision,
        request.row_version,
        comment,
    )
    .await
    {
        Ok(status) => Ok(Json(LinkDecided {
            request_id: request.id,
            status,
        })),
        Err(error) => {
            if let Err(release) =
                sqlx::query("UPDATE approval_email_link SET used_at = NULL WHERE id = $1")
                    .bind(row.id)
                    .execute(&state.base.db)
                    .await
            {
                tracing::warn!(link_id = %row.id, error = %release, "approval email link: decision failed and the link could not be released");
            }
            Err(error)
        }
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/approvals/email-link", post(read_link))
        .route("/api/v1/approvals/email-link/decide", post(decide_by_link))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(read_link, decide_by_link))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_email_link_tokens_parse_only_in_their_own_shape() {
        let public_id = Uuid::now_v7();
        let secret = new_secret();
        assert_eq!(secret.len(), 64);
        let token = format!("{public_id}.{secret}");
        assert_eq!(parse_token(&token), Some((public_id, secret.as_str())));
        assert_eq!(parse_token("nope"), None);
        assert_eq!(parse_token(&format!("{public_id}.short")), None);
        assert_eq!(parse_token(&format!("not-a-uuid.{secret}")), None);
        assert_ne!(new_secret(), new_secret());
    }
}
