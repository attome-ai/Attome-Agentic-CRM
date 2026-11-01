//! AB11-T6: people and tools that follow the public status.
//!
//! - Staff (`ops.incident.publish`): `GET/POST /api/v1/ops/status-subscribers`
//!   and `DELETE /api/v1/ops/status-subscribers/{id}`. A subscriber staff
//!   add is confirmed at once (they vouch for the consent).
//! - Anyone, while the status is published (`ops.status.enabled`, the ops
//!   module on; 404 otherwise, the same answer either way):
//!   `POST /api/v1/public/status/subscribe` `{channel, address, components,
//!   consent: true}` answers 202 and sends a confirmation link (an email, or
//!   a POST to the webhook); `GET /api/v1/public/status/confirm?token=`
//!   confirms (the token is single use and stored only as its SHA-256);
//!   `GET /api/v1/public/status/unsubscribe?token=` ends the subscription in
//!   one click (the token is `<id>.<HMAC under the API-key pepper>`, so
//!   nothing is stored for it, and it works once: an ended subscription
//!   answers 404); `GET /api/v1/public/status/feed.rss` is the public
//!   incidents and their updates as RSS 2.0. All four are bypass-listed and
//!   limited per address ([`SUBSCRIBE_PER_ADDRESS_PER_MINUTE`]).
//! - Channels: `email` and `webhook`; a webhook address must be `https` and
//!   pass the outbound guard (no private or metadata address). `sms` and
//!   `whatsapp` answer 422 `channel not available`: no SMS or WhatsApp sender
//!   serves status notices yet.
//! - Delivery ([`deliver_due`], every minute with the status watch):
//!   published updates of public incidents from the last day, after the
//!   subscriber confirmed, and upcoming public maintenance, for the
//!   components the subscriber follows (none listed: all), at most
//!   [`DELIVERIES_PER_RUN`] a run. Each (subscriber, item) is claimed once in
//!   `ops_status_delivery`; an email goes out as a durable `SendEmail` job in
//!   the claim's transaction, a webhook POST after it (a failed POST frees
//!   the claim for the next run). Every notice carries the unsubscribe link.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::incidents::OpsIncidentPublish;
use crate::static_page::escape;

/// Subscribe, confirm and unsubscribe calls one address may make a minute.
pub const SUBSCRIBE_PER_ADDRESS_PER_MINUTE: i32 = 10;
/// Notices one delivery run sends at most.
pub const DELIVERIES_PER_RUN: u64 = 50;
/// The channels that exist.
const CHANNELS: [&str; 2] = ["email", "webhook"];
/// The longest address.
const MAX_ADDRESS: usize = 500;
/// How long a webhook call may take.
const WEBHOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One subscriber, as staff see it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct StatusSubscriber {
    pub id: Uuid,
    /// `email` or `webhook`.
    pub channel: String,
    pub address: String,
    /// The component keys followed; empty for all.
    pub components: Vec<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, channel, address, components, confirmed_at, created_at";

/// A subscription request.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SubscribeBody {
    /// `email` or `webhook`.
    pub channel: String,
    pub address: String,
    #[serde(default)]
    pub components: Vec<String>,
    /// The subscriber agrees to receive status notices; required.
    #[serde(default)]
    pub consent: bool,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TokenQuery {
    pub token: String,
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn new_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn unsubscribe_input(id: Uuid) -> String {
    format!("ops-status-unsubscribe:{id}")
}

/// The one-click unsubscribe token of subscriber `id`.
fn unsubscribe_token(state: &EngineState, id: Uuid) -> String {
    let mac = state.base.pepper_ring().hash(&unsubscribe_input(id));
    format!("{id}.{mac}")
}

/// `text` as a URL query value: unreserved characters as they are, every
/// other byte as `%XX`. Pure.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn public_link(state: &EngineState, path: &str, token: &str) -> String {
    format!(
        "{}{path}?token={}",
        state.base.config.frontend_url().trim_end_matches('/'),
        percent_encode(token)
    )
}

/// A channel and address a subscriber may use, or why not. Pure (the
/// webhook's address is screened by the outbound guard separately).
pub fn address_problem(channel: &str, address: &str) -> Option<String> {
    if matches!(channel, "sms" | "whatsapp") {
        return Some("channel not available".into());
    }
    if !CHANNELS.contains(&channel) {
        return Some("channel is email or webhook".into());
    }
    let address = address.trim();
    if address.is_empty() || address.chars().count() > MAX_ADDRESS {
        return Some("address is required (500 characters at most)".into());
    }
    match channel {
        "email" => {
            let mut parts = address.split('@');
            let ok = matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some(local), Some(domain), None)
                    if !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
                        && !domain.ends_with('.')
            ) && !address.chars().any(|c| c.is_whitespace() || c.is_control());
            (!ok).then_some("not an email address".to_owned())
        }
        _ => (!address.starts_with("https://")).then_some("a webhook address is https".to_owned()),
    }
}

fn require_published(state: &EngineState) -> Result<(), AppError> {
    if crate::public_status::published(state) {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// The caller's connection, which the server always records; absent only
/// for a request built in a test.
type Peer = Option<Extension<ConnectInfo<std::net::SocketAddr>>>;

async fn rate_limit(state: &EngineState, peer: Peer, headers: &HeaderMap) -> Result<(), AppError> {
    let peer = peer.map_or(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        |Extension(ConnectInfo(addr))| addr.ip(),
    );
    let ip = attome_server::middleware::client_ip::client_ip_from_parts(
        peer,
        headers,
        &state.base.config,
    );
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &format!("ops:rl:status-subscribe:{ip}"),
        SUBSCRIBE_PER_ADDRESS_PER_MINUTE,
    )
    .await?;
    if outcome.allowed {
        Ok(())
    } else {
        Err(AppError::TooManyRequests {
            retry_after_secs: None,
        })
    }
}

async fn guard_webhook(address: &str) -> Result<(), AppError> {
    let url = reqwest::Url::parse(address.trim())
        .map_err(|_| AppError::Validation("not a webhook address".into()))?;
    attome_outbound::http::guard::validate_url(&url)
        .await
        .map_err(|_| AppError::Validation("the webhook address is not reachable from here".into()))
}

fn components_of(body: &SubscribeBody) -> Result<Vec<String>, AppError> {
    if body.components.len() > 50 || body.components.iter().any(|c| c.is_empty() || c.len() > 64) {
        return Err(AppError::Validation(
            "components are up to 50 component keys".into(),
        ));
    }
    Ok(body.components.clone())
}

fn email_message(to: &str, subject: String, text: String) -> attome_email::EmailMessage {
    attome_email::EmailMessage {
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
        stream: Default::default(),
        list_unsubscribe: None,
    }
}

async fn post_json(url: &str, body: &Value) -> Result<(), AppError> {
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("ops-status-subscriber").no_redirects(),
        |b| b.timeout(WEBHOOK_TIMEOUT),
    )
    .map_err(AppError::internal)?;
    match client.post(url).json(body).send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(AppError::internal(format!(
            "the webhook answered HTTP {}",
            response.status().as_u16()
        ))),
        Err(error) => Err(AppError::internal(error.without_url())),
    }
}

// ── Staff ─────────────────────────────────────────────────────────────────

/// Status subscribers
///
/// AB11-T6: the people and tools that receive status notices, newest first. `ops.incident.publish`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/status-subscribers",
    tag = "ops",
    operation_id = "list_ops_status_subscribers",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The subscribers", body = PaginatedResponse<StatusSubscriber>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_subscribers(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<StatusSubscriber>>, AppError> {
    let window = q.window();
    let items: Vec<StatusSubscriber> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_status_subscriber WHERE unsubscribed_at IS NULL \
          ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ops_status_subscriber WHERE unsubscribed_at IS NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a status subscriber
///
/// AB11-T6: staff add an email address or a webhook, confirmed at once (they vouch for the consent,
/// which `consent` must say). `ops.incident.publish`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/status-subscribers",
    tag = "ops",
    operation_id = "create_ops_status_subscriber",
    request_body = SubscribeBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The subscriber", body = StatusSubscriber),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
        (status = 422, description = "No consent, an unknown or unavailable channel, or a bad address", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_subscriber(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Json(body): Json<SubscribeBody>,
) -> Result<(StatusCode, Json<StatusSubscriber>), AppError> {
    if !body.consent {
        return Err(AppError::Validation("consent is required".into()));
    }
    if let Some(problem) = address_problem(&body.channel, &body.address) {
        return Err(AppError::Validation(problem));
    }
    if body.channel == "webhook" {
        guard_webhook(&body.address).await?;
    }
    let components = components_of(&body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let subscriber: StatusSubscriber = sqlx::query_as(&format!(
        "INSERT INTO ops_status_subscriber \
             (channel, address, components, consent_at, confirmed_at, created_by) \
         VALUES ($1, $2, $3, now(), now(), $4) RETURNING {COLUMNS}"
    ))
    .bind(&body.channel)
    .bind(body.address.trim())
    .bind(&components)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "ops_status_subscriber",
            subscriber.id,
            attome_audit::AuditOperation::Create,
            "ops.status_subscriber_added",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(subscriber)))
}

/// Remove a status subscriber
///
/// AB11-T6: ends a subscription; nothing more is sent to it. `ops.incident.publish`. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/ops/status-subscribers/{id}",
    tag = "ops",
    operation_id = "delete_ops_status_subscriber",
    params(("id" = Uuid, Path, description = "The subscriber")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Ended"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
        (status = 404, description = "No such subscriber", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_subscriber(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let ended = sqlx::query(
        "UPDATE ops_status_subscriber SET unsubscribed_at = now(), confirm_token_hash = NULL \
          WHERE id = $1 AND unsubscribed_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if ended == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "ops_status_subscriber",
            id,
            attome_audit::AuditOperation::SoftDelete,
            "ops.status_subscriber_removed",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Public ────────────────────────────────────────────────────────────────

/// Follow the status
///
/// AB11-T6: subscribe an email address or a webhook to status notices, with consent; a confirmation
/// link is sent to it, and nothing else until it is opened. 404 unless the status is published.
#[utoipa::path(
    post,
    path = "/api/v1/public/status/subscribe",
    tag = "ops",
    operation_id = "subscribe_public_status",
    request_body = SubscribeBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "A confirmation link was sent"),
        (status = 404, description = "This deployment does not publish its status", body = ErrorResponse),
        (status = 422, description = "No consent, an unknown or unavailable channel, or a bad address", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    ),
)]
async fn subscribe(
    State(state): State<EngineState>,
    peer: Peer,
    headers: HeaderMap,
    Json(body): Json<SubscribeBody>,
) -> Result<StatusCode, AppError> {
    require_published(&state)?;
    rate_limit(&state, peer, &headers).await?;
    if !body.consent {
        return Err(AppError::Validation("consent is required".into()));
    }
    if let Some(problem) = address_problem(&body.channel, &body.address) {
        return Err(AppError::Validation(problem));
    }
    if body.channel == "webhook" {
        guard_webhook(&body.address).await?;
    }
    let components = components_of(&body)?;
    let address = body.address.trim().to_owned();
    let token = new_secret();
    let link = public_link(&state, "/api/v1/public/status/confirm", &token);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO ops_status_subscriber (channel, address, components, consent_at, confirm_token_hash) \
         VALUES ($1, $2, $3, now(), $4) RETURNING id",
    )
    .bind(&body.channel)
    .bind(&address)
    .bind(&components)
    .bind(sha256_hex(&token))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "ops_status_subscriber",
            id,
            attome_audit::AuditOperation::Create,
            "ops.status_subscription_requested",
            Uuid::nil(),
        ),
    )
    .await?;
    if body.channel == "email" {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::SendEmail(Box::new(email_message(
                &address,
                "Confirm your status subscription / أكّد اشتراكك في حالة الخدمة".into(),
                format!(
                    "Open this link to receive service status notices:\n{link}\n\n\
                     افتح هذا الرابط لتصلك إشعارات حالة الخدمة:\n{link}\n\n\
                     If you did not ask for this, ignore this message.\n\
                     إن لم تطلب ذلك فتجاهل هذه الرسالة.\n"
                ),
            ))),
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    if body.channel == "webhook" {
        // After the commit: no I/O inside the transaction. A webhook that
        // cannot be reached is never confirmed and gets nothing.
        let notice = json!({ "type": "subscription_confirm", "confirm_url": link });
        if let Err(error) = post_json(&address, &notice).await {
            tracing::info!(%id, %error, "status subscription: the webhook did not take the confirmation");
        }
    }
    Ok(StatusCode::ACCEPTED)
}

fn page(english: &str, arabic: &str) -> Response {
    Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{en}</title></head><body><p>{en}</p><p lang=\"ar\" dir=\"rtl\">{ar}</p></body></html>",
        en = escape(english),
        ar = escape(arabic),
    ))
    .into_response()
}

/// Confirm a status subscription
///
/// AB11-T6: the link a subscription request sent; it works once. 404 for an unknown or used link, or
/// while the status is not published.
#[utoipa::path(
    get,
    path = "/api/v1/public/status/confirm",
    tag = "ops",
    operation_id = "confirm_public_status_subscription",
    params(TokenQuery),
    responses(
        (status = 200, description = "Confirmed (an HTML page)", body = String, content_type = "text/html"),
        (status = 404, description = "No such link", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    ),
)]
async fn confirm(
    State(state): State<EngineState>,
    peer: Peer,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Result<Response, AppError> {
    require_published(&state)?;
    rate_limit(&state, peer, &headers).await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE ops_status_subscriber SET confirmed_at = now(), confirm_token_hash = NULL \
          WHERE confirm_token_hash = $1 AND unsubscribed_at IS NULL RETURNING id",
    )
    .bind(sha256_hex(q.token.trim()))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if id.is_none() {
        return Err(AppError::NotFound);
    }
    Ok(page(
        "Your subscription to service status notices is confirmed.",
        "تم تأكيد اشتراكك في إشعارات حالة الخدمة.",
    ))
}

/// Unsubscribe from status notices
///
/// AB11-T6: the one-click link every notice carries; it ends the subscription, and a second use
/// answers 404.
#[utoipa::path(
    get,
    path = "/api/v1/public/status/unsubscribe",
    tag = "ops",
    operation_id = "unsubscribe_public_status",
    params(TokenQuery),
    responses(
        (status = 200, description = "Unsubscribed (an HTML page)", body = String, content_type = "text/html"),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    ),
)]
async fn unsubscribe(
    State(state): State<EngineState>,
    peer: Peer,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Result<Response, AppError> {
    require_published(&state)?;
    rate_limit(&state, peer, &headers).await?;
    let (id, mac) = q.token.trim().split_once('.').ok_or(AppError::NotFound)?;
    let id = Uuid::parse_str(id).map_err(|_| AppError::NotFound)?;
    let ring = state.base.pepper_ring();
    let verified =
        attome_auth::apikey_hash::verify_peppered_secret(&ring, &unsubscribe_input(id), mac)
            .await?;
    if matches!(verified, attome_auth::apikey_hash::VerifyOutcome::Fail) {
        return Err(AppError::NotFound);
    }
    let ended = sqlx::query(
        "UPDATE ops_status_subscriber SET unsubscribed_at = now(), confirm_token_hash = NULL \
          WHERE id = $1 AND unsubscribed_at IS NULL",
    )
    .bind(id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if ended == 0 {
        return Err(AppError::NotFound);
    }
    Ok(page(
        "You will receive no more service status notices.",
        "لن تصلك إشعارات حالة الخدمة بعد الآن.",
    ))
}

/// One public incident update, as the feed and the notices carry it.
#[derive(Debug, Clone, sqlx::FromRow)]
struct PublicItem {
    update_id: Uuid,
    incident_id: Uuid,
    title_en: String,
    title_ar: Option<String>,
    stage: String,
    body_en: String,
    body_ar: Option<String>,
    components: Vec<String>,
    published_at: DateTime<Utc>,
}

const PUBLIC_UPDATES: &str = "SELECT u.id AS update_id, i.id AS incident_id, i.title_en, i.title_ar, \
            u.stage, u.body_en, u.body_ar, i.components, u.published_at \
       FROM ops_incident_update u JOIN ops_incident i ON i.id = u.incident_id \
      WHERE i.audience = 'public' AND i.state <> 'draft'";

/// The public incidents and their updates as RSS 2.0, newest first. Pure.
fn rss(items: &[PublicItem], link: &str, now: DateTime<Utc>) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<rss version=\"2.0\"><channel>\
         <title>Service status</title><link>{link}</link>\
         <description>Public incidents and their updates</description>\
         <lastBuildDate>{now}</lastBuildDate>\n",
        link = escape(link),
        now = now.to_rfc2822(),
    );
    for item in items {
        out.push_str(&format!(
            "<item><title>{title} ({stage})</title><description>{body}</description>\
             <guid isPermaLink=\"false\">{guid}</guid><pubDate>{at}</pubDate></item>\n",
            title = escape(&item.title_en),
            stage = escape(&item.stage),
            body = escape(&item.body_en),
            guid = item.update_id,
            at = item.published_at.to_rfc2822(),
        ));
    }
    out.push_str("</channel></rss>\n");
    out
}

/// Public status feed
///
/// AB11-T6: the public incidents and their updates from the last 30 days as RSS 2.0, newest first.
/// 404 unless the status is published.
#[utoipa::path(
    get,
    path = "/api/v1/public/status/feed.rss",
    tag = "ops",
    operation_id = "get_public_status_feed",
    responses(
        (status = 200, description = "RSS 2.0", body = String, content_type = "application/rss+xml"),
        (status = 404, description = "This deployment does not publish its status", body = ErrorResponse),
    ),
)]
async fn feed(State(state): State<EngineState>) -> Result<Response, AppError> {
    require_published(&state)?;
    let items: Vec<PublicItem> = sqlx::query_as(&format!(
        "{PUBLIC_UPDATES} AND u.published_at > now() - interval '30 days' \
          ORDER BY u.published_at DESC LIMIT 100"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let link = format!(
        "{}/api/v1/public/status",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    let mut response = rss(&items, &link, Utc::now()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/rss+xml; charset=utf-8"),
    );
    Ok(response)
}

// ── Delivery ──────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct Recipient {
    id: Uuid,
    channel: String,
    address: String,
    components: Vec<String>,
    confirmed_at: DateTime<Utc>,
}

/// An upcoming public maintenance window: id, titles, components, start, end.
type MaintenanceRow = (
    Uuid,
    String,
    Option<String>,
    Vec<String>,
    DateTime<Utc>,
    DateTime<Utc>,
);

/// A notice: its key, components and text.
struct Notice {
    key: String,
    components: Vec<String>,
    at: Option<DateTime<Utc>>,
    subject: String,
    text: String,
    payload: Value,
}

/// The maintenance notices due for a window starting in `lead`: the
/// announcement always, the 24-hour reminder inside the last day and the
/// 1-hour reminder inside the last hour, as (key suffix, subject prefix).
/// Pure.
fn maintenance_notices(lead: chrono::Duration) -> Vec<(&'static str, &'static str)> {
    let mut out = vec![("", "Planned maintenance")];
    if lead <= chrono::Duration::hours(24) && lead > chrono::Duration::hours(1) {
        out.push(("_24h", "Maintenance tomorrow"));
    }
    if lead <= chrono::Duration::hours(1) {
        out.push(("_1h", "Maintenance within the hour"));
    }
    out
}

fn follows(subscriber: &[String], item: &[String]) -> bool {
    subscriber.is_empty() || item.iter().any(|c| subscriber.contains(c))
}

/// Sends the notices that are due; how many were sent.
pub async fn deliver_due(state: &EngineState) -> Result<u64, AppError> {
    if !crate::public_status::published(state) {
        return Ok(0);
    }
    let recipients: Vec<Recipient> = sqlx::query_as(
        "SELECT id, channel, address, components, confirmed_at FROM ops_status_subscriber \
          WHERE confirmed_at IS NOT NULL AND unsubscribed_at IS NULL ORDER BY id LIMIT 5000",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if recipients.is_empty() {
        return Ok(0);
    }
    let updates: Vec<PublicItem> = sqlx::query_as(&format!(
        "{PUBLIC_UPDATES} AND u.published_at > now() - interval '1 day' ORDER BY u.published_at"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let maintenance: Vec<MaintenanceRow> = sqlx::query_as(
        "SELECT id, title_en, title_ar, components, starts_at, ends_at FROM ops_maintenance \
              WHERE audience = 'public' AND cancelled_at IS NULL AND starts_at > now() \
              ORDER BY starts_at",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut notices: Vec<Notice> = updates
        .iter()
        .map(|u| Notice {
            key: format!("update:{}", u.update_id),
            components: u.components.clone(),
            at: Some(u.published_at),
            subject: format!("{} ({})", u.title_en, u.stage),
            text: format!(
                "{}\n{}\n\n{}\n{}\n",
                u.title_en,
                u.body_en,
                u.title_ar.as_deref().unwrap_or(&u.title_en),
                u.body_ar.as_deref().unwrap_or(&u.body_en)
            ),
            payload: json!({
                "type": "incident_update", "incident_id": u.incident_id, "title_en": u.title_en,
                "title_ar": u.title_ar, "stage": u.stage, "body_en": u.body_en,
                "body_ar": u.body_ar, "components": u.components, "published_at": u.published_at,
            }),
        })
        .collect();
    let now = Utc::now();
    notices.extend(
        maintenance
            .iter()
            .flat_map(|(id, en, ar, components, starts, ends)| {
                let when = format!(
                    "{} - {}",
                    crate::static_page::dual_date(*starts, false),
                    crate::static_page::dual_date(*ends, false)
                );
                let when_ar = format!(
                    "{} - {}",
                    crate::static_page::dual_date(*starts, true),
                    crate::static_page::dual_date(*ends, true)
                );
                let title_ar = ar.as_deref().unwrap_or(en);
                // AB11-T5: the announcement, then the reminders 24 hours and
                // 1 hour before, each once.
                maintenance_notices(*starts - now)
                    .into_iter()
                    .map(|(kind, prefix)| Notice {
                        key: format!("maintenance{kind}:{id}"),
                        components: components.clone(),
                        at: None,
                        subject: format!("{prefix}: {en}"),
                        text: format!("{en}\n{when}\n\n{title_ar}\n{when_ar}\n"),
                        payload: json!({
                            "type": format!("maintenance{kind}"), "maintenance_id": id,
                            "title_en": en, "title_ar": ar, "components": components,
                            "starts_at": starts, "ends_at": ends,
                        }),
                    })
                    .collect::<Vec<_>>()
            }),
    );
    let mut sent = 0;
    'outer: for recipient in &recipients {
        for notice in &notices {
            if sent >= DELIVERIES_PER_RUN {
                break 'outer;
            }
            if !follows(&recipient.components, &notice.components)
                || notice.at.is_some_and(|at| at <= recipient.confirmed_at)
            {
                continue;
            }
            let unsubscribe = public_link(
                state,
                "/api/v1/public/status/unsubscribe",
                &unsubscribe_token(state, recipient.id),
            );
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let claimed = sqlx::query(
                "INSERT INTO ops_status_delivery (subscriber_id, item_key) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(recipient.id)
            .bind(&notice.key)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if claimed == 0 {
                continue;
            }
            if recipient.channel == "email" {
                attome_jobs::enqueue_in_tx(
                    &mut tx,
                    attome_core::jobs::EngineJob::SendEmail(Box::new(email_message(
                        &recipient.address,
                        notice.subject.clone(),
                        format!(
                            "{}\nUnsubscribe / إلغاء الاشتراك: {unsubscribe}\n",
                            notice.text
                        ),
                    ))),
                )
                .await
                .map_err(AppError::internal)?;
                attome_db::tx::commit(tx).await?;
            } else {
                attome_db::tx::commit(tx).await?;
                let mut payload = notice.payload.clone();
                payload["unsubscribe_url"] = json!(unsubscribe);
                if let Err(error) = post_json(&recipient.address, &payload).await {
                    tracing::info!(subscriber = %recipient.id, %error, "status notice not taken; tried again next run");
                    sqlx::query(
                        "DELETE FROM ops_status_delivery WHERE subscriber_id = $1 AND item_key = $2",
                    )
                    .bind(recipient.id)
                    .bind(&notice.key)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    continue;
                }
            }
            sent += 1;
        }
    }
    Ok(sent)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ops/status-subscribers",
            get(list_subscribers).post(create_subscriber),
        )
        .route(
            "/api/v1/ops/status-subscribers/{id}",
            delete(delete_subscriber),
        )
}

/// The anonymous routes, merged outside the licence gate with
/// [`crate::public_status::public_routes`].
pub fn public_routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/public/status/subscribe", post(subscribe))
        .route("/api/v1/public/status/confirm", get(confirm))
        .route("/api/v1/public/status/unsubscribe", get(unsubscribe))
        .route("/api/v1/public/status/feed.rss", get(feed))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_subscribers,
        create_subscriber,
        delete_subscriber,
        subscribe,
        confirm,
        unsubscribe,
        feed
    ),
    components(schemas(StatusSubscriber, SubscribeBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_and_addresses() {
        assert_eq!(address_problem("email", "ops@example.com"), None);
        assert!(address_problem("email", "not an address").is_some());
        assert!(address_problem("email", "a@b").is_some());
        assert_eq!(
            address_problem("webhook", "https://status.example.com/hook"),
            None
        );
        assert!(address_problem("webhook", "http://status.example.com/hook").is_some());
        assert_eq!(
            address_problem("sms", "+966500000000").as_deref(),
            Some("channel not available")
        );
        assert_eq!(
            address_problem("whatsapp", "+966500000000").as_deref(),
            Some("channel not available")
        );
        assert!(address_problem("pigeon", "x").is_some());
    }

    #[test]
    fn maintenance_reminders_come_a_day_and_an_hour_before() {
        let kinds = |hours: i64| -> Vec<&str> {
            maintenance_notices(chrono::Duration::hours(hours))
                .into_iter()
                .map(|(kind, _)| kind)
                .collect()
        };
        assert_eq!(kinds(72), vec![""]);
        assert_eq!(kinds(20), vec!["", "_24h"]);
        assert_eq!(kinds(1), vec!["", "_1h"]);
    }

    #[test]
    fn a_subscriber_follows_its_components_or_all() {
        let records = vec!["records".to_owned()];
        assert!(follows(&[], &records));
        assert!(follows(&records, &records));
        assert!(!follows(&["email".to_owned()], &records));
    }

    #[test]
    fn the_feed_escapes_what_it_carries() {
        let item = PublicItem {
            update_id: Uuid::now_v7(),
            incident_id: Uuid::now_v7(),
            title_en: "Payments <slow>".into(),
            title_ar: None,
            stage: "identified".into(),
            body_en: "A & B".into(),
            body_ar: None,
            components: Vec::new(),
            published_at: Utc::now(),
        };
        let xml = rss(
            &[item],
            "https://example.com/api/v1/public/status",
            Utc::now(),
        );
        assert!(xml.contains("Payments &lt;slow&gt; (identified)"));
        assert!(xml.contains("A &amp; B"));
        assert!(xml.starts_with("<?xml"));
    }
}
