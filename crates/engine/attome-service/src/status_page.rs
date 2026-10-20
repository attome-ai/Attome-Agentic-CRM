//! H8-T1: the public status page.
//!
//! The records are the ITSM pack's (changeset 0002): `status_component`
//! (with its status), `status_incident` and `status_maintenance`, their
//! `status_update`s, and `status_subscriber`s. Staff keep them through the
//! ordinary record screens and API.
//!
//! - `GET /api/v1/status` (public) answers the page: the overall status
//!   (the worst public component's), the public components by group, open
//!   incidents and current or coming maintenance with their latest updates,
//!   and incidents resolved in the last week. The answer is built at most
//!   once every [`CACHE_SECS`] seconds per node (a snapshot rebuilt from the
//!   records; losing it costs one rebuild) and sent with the same
//!   `Cache-Control` max-age.
//! - `POST /api/v1/status/subscribe` (public) takes an email and sends a
//!   confirmation link (a signed token, seven days); at most one an hour per
//!   address, and the answer is the same either way, so the route tells no
//!   one who is subscribed. Opening the link shows a button; its POST
//!   confirms. Every update email carries an unsubscribe link of the same
//!   kind.
//! - **Notices**: the `status_page_notify` job reads the change feed
//!   (consumer `attome-service/status_notify`) and, for each new update
//!   with `notify_subscribers` set and not yet sent, emails every confirmed
//!   subscriber in their language and stamps `notified_at`, so an update is
//!   sent once. Notices go by email directly: the routed notify API (M15)
//!   is not built. The same job writes the static copy of the page
//!   (H8-T2, [`crate::status_static`]) when any status record changed.

use std::sync::Mutex;
use std::time::Instant;

use attome_core::EngineState;
use attome_html::escape_html;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// How long a built page is served before it is built again.
pub const CACHE_SECS: u64 = 30;
/// The change-feed consumer of the notice job.
pub const CONSUMER: &str = "attome-service/status_notify";
/// The registered notice job.
pub const JOB: &str = "status_page_notify";
const LINK_DOMAIN: &str = "attome-service/status-subscriber";
const LINK_DAYS: i64 = 7;
/// Updates shown per incident or maintenance.
const UPDATES_SHOWN: usize = 5;
/// Subscribers one update emails at most.
const MAX_RECIPIENTS: i64 = 10_000;

/// The component statuses, from best to worst.
pub const COMPONENT_STATUSES: &[&str] = &[
    "operational",
    "maintenance",
    "degraded",
    "partial_outage",
    "major_outage",
];

/// How bad a status is (higher is worse); an unknown one is operational.
/// Pure.
pub fn severity(status: &str) -> usize {
    COMPONENT_STATUSES
        .iter()
        .position(|s| *s == status)
        .unwrap_or(0)
}

/// The page's overall status: the worst of the components'. Pure.
pub fn overall<'a>(statuses: impl IntoIterator<Item = &'a str>) -> &'static str {
    let worst = statuses.into_iter().map(severity).max().unwrap_or(0);
    COMPONENT_STATUSES[worst]
}

/// One component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StatusComponent {
    pub id: Uuid,
    pub name: String,
    pub name_ar: Option<String>,
    pub status: String,
}

/// A group of components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StatusGroup {
    pub name: Option<String>,
    pub components: Vec<StatusComponent>,
}

/// One update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StatusUpdate {
    pub status: Option<String>,
    pub body: String,
    pub body_ar: Option<String>,
    pub at: DateTime<Utc>,
}

/// An incident or maintenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StatusEvent {
    pub id: Uuid,
    pub title: String,
    pub title_ar: Option<String>,
    pub status: Option<String>,
    pub impact: Option<String>,
    pub component_id: Option<Uuid>,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub updates: Vec<StatusUpdate>,
}

/// The public page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct StatusPage {
    pub overall: String,
    pub groups: Vec<StatusGroup>,
    pub incidents: Vec<StatusEvent>,
    pub maintenance: Vec<StatusEvent>,
    pub recently_resolved: Vec<StatusEvent>,
    pub generated_at: DateTime<Utc>,
}

/// Components in display order, grouped in the order groups first appear.
/// Pure.
pub fn group_components(rows: Vec<(Option<String>, StatusComponent)>) -> Vec<StatusGroup> {
    let mut groups: Vec<StatusGroup> = Vec::new();
    for (group, component) in rows {
        match groups.iter_mut().find(|g| g.name == group) {
            Some(g) => g.components.push(component),
            None => groups.push(StatusGroup {
                name: group,
                components: vec![component],
            }),
        }
    }
    groups
}

type EventRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// A row as read by the query below (clippy::type_complexity).
type Row4 = Vec<(
    Option<Uuid>,
    Option<String>,
    String,
    Option<String>,
    DateTime<Utc>,
)>;

async fn updates_for(
    state: &EngineState,
    column: &str,
    ids: &[Uuid],
) -> Result<Vec<(Uuid, StatusUpdate)>, AppError> {
    // `column` is one of two constants below, never input.
    let sql = format!(
        "SELECT {}, status::text, body, body_ar, created_at FROM status_update \
          WHERE {} = ANY($1) AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC",
        attome_core::quote_ident(column),
        attome_core::quote_ident(column)
    );
    let rows: Row4 = sqlx::query_as(&sql)
        .bind(ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(owner, status, body, body_ar, at)| {
            Some((
                owner?,
                StatusUpdate {
                    status,
                    body,
                    body_ar,
                    at,
                },
            ))
        })
        .collect())
}

fn attach(rows: Vec<EventRow>, updates: &[(Uuid, StatusUpdate)]) -> Vec<StatusEvent> {
    rows.into_iter()
        .map(
            |(id, title, title_ar, status, impact, component_id, starts_at, ends_at)| StatusEvent {
                id,
                title,
                title_ar,
                status,
                impact,
                component_id,
                starts_at,
                ends_at,
                updates: updates
                    .iter()
                    .filter(|(owner, _)| *owner == id)
                    .take(UPDATES_SHOWN)
                    .map(|(_, u)| u.clone())
                    .collect(),
            },
        )
        .collect()
}

/// A row as read by the query below (clippy::type_complexity).
type Row3 = Vec<(Uuid, String, Option<String>, Option<String>, Option<String>)>;

/// Builds the page from the records.
pub async fn build(state: &EngineState) -> Result<StatusPage, AppError> {
    let db = &state.base.db;
    let components: Row3 = sqlx::query_as(
        "SELECT id, name, name_ar, group_name, status::text FROM status_component \
              WHERE COALESCE(is_public, true) AND (is_active IS NULL OR is_active = true) \
              ORDER BY display_order NULLS LAST, name",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let overall = overall(
        components
            .iter()
            .map(|c| c.4.as_deref().unwrap_or("operational")),
    )
    .to_owned();
    let groups = group_components(
        components
            .into_iter()
            .map(|(id, name, name_ar, group, status)| {
                (
                    group,
                    StatusComponent {
                        id,
                        name,
                        name_ar,
                        status: status.unwrap_or_else(|| "operational".into()),
                    },
                )
            })
            .collect(),
    );
    let open: Vec<EventRow> = sqlx::query_as(
        "SELECT id, title, title_ar, status::text, impact::text, component_ref, \
                started_at::timestamptz, resolved_at::timestamptz FROM status_incident \
          WHERE COALESCE(is_public, true) AND (is_active IS NULL OR is_active = true) \
            AND COALESCE(status::text, 'investigating') <> 'resolved' \
          ORDER BY started_at DESC NULLS LAST LIMIT 50",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let resolved: Vec<EventRow> = sqlx::query_as(
        "SELECT id, title, title_ar, status::text, impact::text, component_ref, \
                started_at::timestamptz, resolved_at::timestamptz FROM status_incident \
          WHERE COALESCE(is_public, true) AND (is_active IS NULL OR is_active = true) \
            AND status::text = 'resolved' AND resolved_at::timestamptz >= now() - interval '7 days' \
          ORDER BY resolved_at DESC LIMIT 20",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let maintenance: Vec<EventRow> = sqlx::query_as(
        "SELECT id, title, title_ar, status::text, NULL::text, component_ref, \
                starts_at::timestamptz, ends_at::timestamptz FROM status_maintenance \
          WHERE COALESCE(is_public, true) AND (is_active IS NULL OR is_active = true) \
            AND COALESCE(status::text, 'scheduled') <> 'completed' \
          ORDER BY starts_at NULLS LAST LIMIT 50",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let incident_ids: Vec<Uuid> = open.iter().chain(&resolved).map(|r| r.0).collect();
    let maintenance_ids: Vec<Uuid> = maintenance.iter().map(|r| r.0).collect();
    let incident_updates = updates_for(state, "incident_ref", &incident_ids).await?;
    let maintenance_updates = updates_for(state, "maintenance_ref", &maintenance_ids).await?;
    Ok(StatusPage {
        overall,
        groups,
        incidents: attach(open, &incident_updates),
        maintenance: attach(maintenance, &maintenance_updates),
        recently_resolved: attach(resolved, &incident_updates),
        generated_at: Utc::now(),
    })
}

/// The node's last built page. A rebuildable snapshot: losing it costs one
/// build; it never decides anything.
static CACHE: Mutex<Option<(Instant, StatusPage)>> = Mutex::new(None);

async fn cached(state: &EngineState) -> Result<StatusPage, AppError> {
    if let Ok(guard) = CACHE.lock()
        && let Some((at, page)) = guard.as_ref()
        && at.elapsed().as_secs() < CACHE_SECS
    {
        return Ok(page.clone());
    }
    let page = build(state).await?;
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((Instant::now(), page.clone()));
    }
    Ok(page)
}

#[utoipa::path(
    get,
    path = "/api/v1/status",
    operation_id = "get_status_page",
    tag = "service",
    responses(
        (status = 200, description = "The status page", body = StatusPage),
        (status = 404, description = "The service module is not licensed", body = ErrorResponse),
    ),
)]
/// The public status page (no sign-in), rebuilt at most every 30 seconds.
async fn get_status(State(state): State<EngineState>) -> Result<Response, AppError> {
    if state
        .modules
        .load()
        .require(attome_modules::MODULE_SERVICE)
        .is_err()
    {
        return Err(AppError::NotFound);
    }
    let page = cached(&state).await?;
    Ok((
        [(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=30"),
        )],
        Json(page),
    )
        .into_response())
}

// ── Subscribers ─────────────────────────────────────────────────────────────

/// A subscription request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct StatusSubscribe {
    pub email: String,
    /// `en` (the default) or `ar`: the language of the emails.
    #[serde(default)]
    pub language: Option<String>,
}

/// A link's token (`?token=`, or the page's form field).
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct StatusToken {
    pub token: String,
}

fn link_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

fn token_for(state: &EngineState, purpose: &str, email: &str) -> Result<String, AppError> {
    attome_auth::signed_link::sign(
        &link_secret(state)?,
        LINK_DOMAIN,
        &format!("{purpose}|{email}"),
        (Utc::now() + Duration::days(LINK_DAYS)).timestamp(),
    )
    .ok_or_else(|| AppError::internal("could not sign the link"))
}

/// The email a token names for `purpose`, while it is valid.
fn email_of(state: &EngineState, purpose: &str, token: &str) -> Result<String, AppError> {
    let subject = attome_auth::signed_link::verify(
        &link_secret(state)?,
        LINK_DOMAIN,
        token.trim(),
        Utc::now().timestamp(),
    )
    .ok_or(AppError::NotFound)?;
    subject
        .strip_prefix(&format!("{purpose}|"))
        .map(str::to_owned)
        .ok_or(AppError::NotFound)
}

fn link(state: &EngineState, path: &str, token: &str) -> String {
    format!(
        "{}{path}?token={token}",
        state.base.config.frontend_url().trim_end_matches('/')
    )
}

fn email_job(to: &str, subject: String, text: String) -> attome_core::jobs::EngineJob {
    attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
        to: to.to_owned(),
        subject,
        text_body: text,
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
    }))
}

/// A plausible address. Pure.
pub fn email_ok(email: &str) -> bool {
    let e = email.trim();
    let mut parts = e.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(l), Some(d), None) if !l.is_empty() && d.contains('.') && !d.ends_with('.')
    ) && !e.chars().any(char::is_whitespace)
        && e.len() <= 254
}

/// A row as read by the query below (clippy::type_complexity).
type Row2 = Option<(
    Uuid,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
)>;

#[utoipa::path(
    post,
    path = "/api/v1/status/subscribe",
    operation_id = "post_status_subscribe",
    tag = "service",
    request_body = StatusSubscribe,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "A confirmation is on its way (the same answer for any address)"),
        (status = 404, description = "The service module is not licensed", body = ErrorResponse),
        (status = 422, description = "Not an email address", body = ErrorResponse),
    ),
)]
/// Asks to receive status updates by email: a confirmation link is sent.
async fn post_subscribe(
    State(state): State<EngineState>,
    Json(body): Json<StatusSubscribe>,
) -> Result<StatusCode, AppError> {
    if state
        .modules
        .load()
        .require(attome_modules::MODULE_SERVICE)
        .is_err()
    {
        return Err(AppError::NotFound);
    }
    let email = body.email.trim().to_lowercase();
    if !email_ok(&email) {
        return Err(AppError::Validation("email: an email address".into()));
    }
    let language = match body.language.as_deref() {
        Some("ar") => "ar",
        _ => "en",
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // One pending request an hour per address; confirmed subscribers are
    // not told again. The answer is the same either way.
    let existing: Row2 = sqlx::query_as(
        "SELECT id, confirmed_at::timestamptz, unsubscribed_at::timestamptz, \
                    COALESCE(modified_at, created_at) \
               FROM status_subscriber WHERE lower(email) = $1 \
                AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let send = match existing {
        Some((_, Some(_), None, _)) => false,
        Some((id, _, _, touched)) => {
            if Utc::now() - touched < Duration::hours(1) {
                false
            } else {
                sqlx::query(
                    "UPDATE status_subscriber SET language = $2, modified_at = now(), \
                         row_version = row_version + 1 WHERE id = $1",
                )
                .bind(id)
                .bind(language)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                true
            }
        }
        None => {
            sqlx::query(
                "INSERT INTO status_subscriber (email, language, is_active, row_version) \
                 VALUES ($1, $2, true, 0)",
            )
            .bind(&email)
            .bind(language)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            true
        }
    };
    if send {
        let url = link(
            &state,
            "/api/v1/status/confirm",
            &token_for(&state, "confirm", &email)?,
        );
        attome_jobs::enqueue_in_tx(
            &mut tx,
            email_job(
                &email,
                "Confirm status updates / تأكيد الاشتراك في تحديثات الحالة".into(),
                format!(
                    "Open this link within {LINK_DAYS} days to receive status updates by email:\n\n{url}\n\n\
                     افتح هذا الرابط خلال {LINK_DAYS} أيام لتلقي تحديثات الحالة بالبريد:\n\n{url}\n"
                ),
            ),
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::ACCEPTED)
}

/// The page a link opens: one button whose POST acts, so a mail scanner
/// that fetches the link changes nothing. Pure.
pub fn action_page(path: &str, token: &str, en: &str, ar: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>Status updates</title></head><body style=\"font:16px system-ui,sans-serif;max-inline-size:32rem;margin:2rem auto\">\
         <form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"token\" value=\"{}\">\
         <p>{}</p><p dir=\"rtl\" lang=\"ar\">{}</p><button type=\"submit\">OK / موافق</button></form></body></html>",
        escape_html(path),
        escape_html(token),
        escape_html(en),
        escape_html(ar)
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/status/confirm",
    operation_id = "get_status_confirm",
    tag = "service",
    params(StatusToken),
    responses((status = 200, description = "A page with a confirm button", content_type = "text/html")),
)]
/// The confirmation page; its button confirms.
async fn get_confirm(Query(q): Query<StatusToken>) -> axum::response::Html<String> {
    axum::response::Html(action_page(
        "/api/v1/status/confirm",
        q.token.trim(),
        "Confirm that you want status updates by email.",
        "أكّد رغبتك في تلقي تحديثات الحالة بالبريد.",
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/status/confirm",
    operation_id = "post_status_confirm",
    tag = "service",
    request_body(content = StatusToken, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Confirmed", content_type = "text/html"),
        (status = 404, description = "The link is not valid", body = ErrorResponse),
    ),
)]
/// Confirms a subscription.
async fn post_confirm(
    State(state): State<EngineState>,
    axum::Form(form): axum::Form<StatusToken>,
) -> Result<axum::response::Html<&'static str>, AppError> {
    let email = email_of(&state, "confirm", &form.token)?;
    let changed = sqlx::query(
        "UPDATE status_subscriber SET confirmed_at = now(), unsubscribed_at = NULL, \
             modified_at = now(), row_version = row_version + 1 \
          WHERE lower(email) = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&email)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    Ok(axum::response::Html(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Subscribed</title></head>\
         <body style=\"font:16px system-ui,sans-serif;max-inline-size:32rem;margin:2rem auto\">\
         <p>You will receive status updates.</p><p dir=\"rtl\" lang=\"ar\">ستصلك تحديثات الحالة.</p></body></html>",
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/status/unsubscribe",
    operation_id = "get_status_unsubscribe",
    tag = "service",
    params(StatusToken),
    responses((status = 200, description = "A page with an unsubscribe button", content_type = "text/html")),
)]
/// The unsubscribe page; its button unsubscribes.
async fn get_unsubscribe(Query(q): Query<StatusToken>) -> axum::response::Html<String> {
    axum::response::Html(action_page(
        "/api/v1/status/unsubscribe",
        q.token.trim(),
        "Stop status updates by email.",
        "أوقف تحديثات الحالة بالبريد.",
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/status/unsubscribe",
    operation_id = "post_status_unsubscribe",
    tag = "service",
    request_body(content = StatusToken, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Unsubscribed", content_type = "text/html"),
        (status = 404, description = "The link is not valid", body = ErrorResponse),
    ),
)]
/// Stops a subscriber's emails.
async fn post_unsubscribe(
    State(state): State<EngineState>,
    axum::Form(form): axum::Form<StatusToken>,
) -> Result<axum::response::Html<&'static str>, AppError> {
    let email = email_of(&state, "unsubscribe", &form.token)?;
    sqlx::query(
        "UPDATE status_subscriber SET unsubscribed_at = now(), modified_at = now(), \
             row_version = row_version + 1 WHERE lower(email) = $1",
    )
    .bind(&email)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(axum::response::Html(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Unsubscribed</title></head>\
         <body style=\"font:16px system-ui,sans-serif;max-inline-size:32rem;margin:2rem auto\">\
         <p>You will not receive status updates.</p><p dir=\"rtl\" lang=\"ar\">لن تصلك تحديثات الحالة.</p></body></html>",
    ))
}

// ── Notices ─────────────────────────────────────────────────────────────────

/// An update's notice, in the subscriber's language. Pure.
pub fn notice(
    title: &str,
    title_ar: Option<&str>,
    body: &str,
    body_ar: Option<&str>,
    arabic: bool,
    unsubscribe: &str,
) -> (String, String) {
    if arabic {
        let title = title_ar.filter(|t| !t.trim().is_empty()).unwrap_or(title);
        let body = body_ar.filter(|b| !b.trim().is_empty()).unwrap_or(body);
        (
            format!("تحديث الحالة: {title}"),
            format!("{body}\n\nلإيقاف هذه الرسائل: {unsubscribe}\n"),
        )
    } else {
        (
            format!("Status update: {title}"),
            format!("{body}\n\nTo stop these emails: {unsubscribe}\n"),
        )
    }
}

type UpdateRow = (Option<String>, Option<String>, String, Option<String>);

/// A row as read by the query below (clippy::type_complexity).
type Row1 = Option<(Option<Uuid>, Option<Uuid>, String, Option<String>)>;

/// Emails one update to every confirmed subscriber, once.
async fn notify_update(state: &EngineState, update: Uuid) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Claim the update: only an unsent one with notices on is sent.
    let claimed: Row1 = sqlx::query_as(
        "UPDATE status_update SET notified_at = now() \
          WHERE id = $1 AND notified_at IS NULL AND COALESCE(notify_subscribers, false) \
            AND (is_active IS NULL OR is_active = true) \
          RETURNING incident_ref, maintenance_ref, body, body_ar",
    )
    .bind(update)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((incident, maintenance, body, body_ar)) = claimed else {
        attome_db::tx::commit(tx).await?;
        return Ok(false);
    };
    let title: Option<UpdateRow> = if let Some(i) = incident {
        sqlx::query_as(
            "SELECT title, title_ar, ''::text, NULL::text FROM status_incident WHERE id = $1",
        )
        .bind(i)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
    } else if let Some(m) = maintenance {
        sqlx::query_as(
            "SELECT title, title_ar, ''::text, NULL::text FROM status_maintenance WHERE id = $1",
        )
        .bind(m)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
    } else {
        None
    };
    let (title, title_ar) = title
        .map(|(t, a, _, _)| (t.unwrap_or_default(), a))
        .unwrap_or_default();
    let subscribers: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT email, language::text FROM status_subscriber \
          WHERE confirmed_at IS NOT NULL AND unsubscribed_at IS NULL \
            AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $1",
    )
    .bind(MAX_RECIPIENTS)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for (email, language) in &subscribers {
        let unsubscribe = link(
            state,
            "/api/v1/status/unsubscribe",
            &token_for(state, "unsubscribe", email)?,
        );
        let (subject, text) = notice(
            &title,
            title_ar.as_deref(),
            &body,
            body_ar.as_deref(),
            language.as_deref() == Some("ar"),
            &unsubscribe,
        );
        attome_jobs::enqueue_in_tx(&mut tx, email_job(email, subject, text))
            .await
            .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// One tick of the notice job; see the module doc. Returns the updates sent.
pub async fn notify_tick(state: &EngineState) -> Result<usize, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, 500).await?;
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut sent = 0;
    // H8-T2: any status record changed, so the static page is out of date.
    if events.iter().any(|e| {
        e.entity_logicalname.starts_with("status_") && e.entity_logicalname != "status_subscriber"
    }) && let Err(error) = crate::status_static::publish(state).await
    {
        tracing::warn!(%error, "status page: the static copy was not written");
    }
    for event in events
        .iter()
        .filter(|e| e.entity_logicalname == "status_update" && e.operation == "create")
    {
        if notify_update(state, event.record_id).await? {
            sent += 1;
        }
    }
    attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(sent)
}

pub(crate) fn routes() -> Router<attome_core::EngineState> {
    Router::new()
        .route("/api/v1/status", get(get_status))
        .route(
            "/api/v1/status/subscribe",
            axum::routing::post(post_subscribe),
        )
        .route(
            "/api/v1/status/confirm",
            get(get_confirm).post(post_confirm),
        )
        .route(
            "/api/v1/status/unsubscribe",
            get(get_unsubscribe).post(post_unsubscribe),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_status,
        post_subscribe,
        get_confirm,
        post_confirm,
        get_unsubscribe,
        post_unsubscribe
    ),
    components(schemas(
        StatusPage,
        StatusGroup,
        StatusComponent,
        StatusEvent,
        StatusUpdate,
        StatusSubscribe,
        StatusToken
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(name: &str, status: &str) -> StatusComponent {
        StatusComponent {
            id: Uuid::now_v7(),
            name: name.into(),
            name_ar: None,
            status: status.into(),
        }
    }

    #[test]
    fn status_page_overall_is_the_worst_component() {
        assert_eq!(
            overall(["operational", "degraded", "maintenance"]),
            "degraded"
        );
        assert_eq!(overall(["operational", "major_outage"]), "major_outage");
        assert_eq!(overall(Vec::<&str>::new()), "operational");
        assert_eq!(overall(["mystery"]), "operational");
    }

    #[test]
    fn status_page_groups_keep_their_first_order() {
        let groups = group_components(vec![
            (Some("API".into()), component("REST", "operational")),
            (Some("Web".into()), component("Site", "degraded")),
            (Some("API".into()), component("Webhooks", "operational")),
            (None, component("Email", "operational")),
        ]);
        let names: Vec<_> = groups.iter().map(|g| g.name.clone()).collect();
        assert_eq!(names, vec![Some("API".into()), Some("Web".into()), None]);
        assert_eq!(groups[0].components.len(), 2);
    }

    #[test]
    fn status_page_notice_follows_the_subscriber_language() {
        let (subject, text) = notice(
            "Slow API",
            Some("بطء الواجهة"),
            "Looking into it.",
            None,
            true,
            "https://x/u",
        );
        assert_eq!(subject, "تحديث الحالة: بطء الواجهة");
        assert!(
            text.starts_with("Looking into it."),
            "no Arabic body: the English one"
        );
        assert!(text.contains("https://x/u"));
        let (subject, _) = notice(
            "Slow API",
            Some("بطء الواجهة"),
            "Looking into it.",
            None,
            false,
            "u",
        );
        assert_eq!(subject, "Status update: Slow API");
    }

    #[test]
    fn status_page_links_escape_their_token() {
        let page = action_page("/api/v1/status/confirm", "a\"b<c", "Confirm", "أكّد");
        assert!(page.contains("value=\"a&quot;b&lt;c\""));
        assert!(email_ok("ops@example.com"));
        assert!(!email_ok("ops@example"));
    }
}
