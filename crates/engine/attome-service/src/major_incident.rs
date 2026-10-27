//! H1-T2: the major incident flow on a service ticket.
//!
//! - `POST /api/v1/service/tickets/{id}/major-incident` **declares** it:
//!   the ticket becomes `major` with `declared_at` and a commander
//!   (`major_incident_manager`, the caller unless named); whoever is on
//!   call on the chosen `oncall_schedule` (itsm pack 0003, resolved by
//!   [`crate::oncall::on_call`]) and the commander are paged (a high
//!   priority notification); a bridge is opened on the video provider named
//!   (J7: `teams`, `meet`, `zoom` or `jitsi`) and kept in `bridge_url`; and
//!   a `status_incident` with a first `status_update` (`investigating`,
//!   subscribers notified by the H8 notice job) is posted, public unless
//!   asked otherwise.
//! - `POST .../major-incident/children` **links** other tickets to it
//!   (`parent_ticket_id`).
//! - `POST .../major-incident/resolve` **resolves** it: `restored_at` on
//!   the ticket, the status incident `resolved` with a last update.
//!
//! Declaring twice answers the first declaration (`already_declared`;
//! `declared_at` marks it, since `major` alone may be a flag set by hand):
//! the ticket's row is the claim, taken under its advisory lock
//! (`attome-service/major-incident:{ticket}`) before anyone is paged. A
//! bridge the provider refuses does not stop the declaration: the answer
//! carries `bridge_error` and the commander adds one by hand. Every write
//! goes through the record engine as the caller (record rules, audit,
//! change feed). The bridge call is made outside any transaction.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Duration, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::oncall::{Layer, Override, Schedule};

const TICKET: &str = "service_ticket";
/// Most children linked in one call.
const MAX_CHILDREN: usize = 200;
/// How long a bridge is booked for.
const BRIDGE_HOURS: i64 = 4;

/// `service_ticket.update`: who runs a major incident.
#[derive(Debug)]
pub struct TicketUpdate;

impl PrivilegeKey for TicketUpdate {
    const KEY: &'static str = "service_ticket.update";
}

/// The advisory lock key of one ticket's declaration. Pure.
pub fn lock_key(ticket: Uuid) -> String {
    format!("attome-service/major-incident:{ticket}")
}

/// A stored layer, as read.
#[derive(Debug, Clone, PartialEq)]
pub struct LayerRow {
    pub id: Uuid,
    pub order: f64,
    pub handover_at: Option<DateTime<Utc>>,
    pub shift_hours: Option<f64>,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    pub until_at: Option<DateTime<Utc>>,
}

fn time_of(raw: Option<&str>) -> Option<NaiveTime> {
    let raw = raw?.trim();
    NaiveTime::parse_from_str(raw, "%H:%M")
        .or_else(|_| NaiveTime::parse_from_str(raw, "%H:%M:%S"))
        .ok()
}

/// Builds the schedule [`crate::oncall`] reads from stored rows: layers
/// lowest `layer_order` first, each with its members in `position` order;
/// a layer with no handover or no shift length is left out, as is a daily
/// window with only one end. Pure.
pub fn schedule_of(
    layers: &[LayerRow],
    members: &[(Uuid, Uuid, f64)],
    overrides: &[(Uuid, DateTime<Utc>, DateTime<Utc>)],
) -> Schedule {
    let mut by_layer: HashMap<Uuid, Vec<(f64, Uuid)>> = HashMap::new();
    for (layer, user, position) in members {
        by_layer.entry(*layer).or_default().push((*position, *user));
    }
    let mut sorted: Vec<&LayerRow> = layers.iter().collect();
    sorted.sort_by(|a, b| a.order.total_cmp(&b.order).then(a.id.cmp(&b.id)));
    let layers = sorted
        .into_iter()
        .filter_map(|row| {
            let handover = row.handover_at?;
            let hours = row.shift_hours.filter(|h| h.is_finite() && *h > 0.0)?;
            let mut people = by_layer.get(&row.id).cloned().unwrap_or_default();
            people.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
            let window = match (
                time_of(row.window_start.as_deref()),
                time_of(row.window_end.as_deref()),
            ) {
                (Some(from), Some(to)) => Some((from, to)),
                _ => None,
            };
            Some(Layer {
                members: people.into_iter().map(|(_, user)| user).collect(),
                handover,
                shift: Duration::minutes((hours * 60.0).round() as i64),
                daily_window: window,
                until: row.until_at,
            })
        })
        .collect();
    Schedule {
        layers,
        overrides: overrides
            .iter()
            .filter(|(_, start, end)| end > start)
            .map(|(user, start, end)| Override {
                user: *user,
                start: *start,
                end: *end,
            })
            .collect(),
    }
}

/// Who is paged: the person on call and the commander, once each. Pure.
pub fn paged(on_call: Option<Uuid>, commander: Uuid) -> Vec<Uuid> {
    match on_call {
        Some(user) if user != commander => vec![user, commander],
        _ => vec![commander],
    }
}

/// The first status update's text. Pure.
pub fn declared_text(title: &str) -> (String, String) {
    (
        format!("We are investigating: {title}. Updates follow here."),
        format!("نحقق في: {title}. سننشر التحديثات هنا."),
    )
}

/// The last status update's text. Pure.
pub fn resolved_text(message: Option<&str>) -> (String, String) {
    match message.map(str::trim).filter(|m| !m.is_empty()) {
        Some(m) => (m.to_owned(), m.to_owned()),
        None => (
            "This incident is resolved. Thank you for your patience.".to_owned(),
            "تم حل هذه المشكلة. شكراً لصبركم.".to_owned(),
        ),
    }
}

/// What to declare.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DeclareBody {
    /// The commander; the caller when absent.
    pub commander_id: Option<Uuid>,
    /// The on-call schedule to page.
    pub schedule_id: Option<Uuid>,
    /// `teams`, `meet`, `zoom` or `jitsi`: open a bridge there.
    pub bridge_provider: Option<String>,
    /// The status page title; the ticket's subject when absent.
    pub status_title: Option<String>,
    pub status_title_ar: Option<String>,
    /// The affected status component.
    pub component_id: Option<Uuid>,
    /// `minor`, `major` (default) or `critical`.
    pub impact: Option<String>,
    /// Show it on the public status page (default true).
    pub public: Option<bool>,
}

/// The declaration.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Declared {
    pub ticket_id: Uuid,
    pub already_declared: bool,
    pub commander_id: Option<Uuid>,
    /// The people paged now (none when already declared).
    pub paged: Vec<Uuid>,
    pub bridge_url: Option<String>,
    pub bridge_error: Option<String>,
    pub status_incident_id: Option<Uuid>,
}

/// The tickets to link.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChildrenBody {
    pub ticket_ids: Vec<Uuid>,
}

/// The linked tickets.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ChildrenLinked {
    pub ticket_id: Uuid,
    pub linked: Vec<Uuid>,
}

/// How it was resolved.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[schema(as = MajorIncidentResolveBody)]
pub struct ResolveBody {
    /// The last status update; a standard text when absent.
    pub message: Option<String>,
}

/// The resolution.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(as = MajorIncidentResolved)]
pub struct Resolved {
    pub ticket_id: Uuid,
    pub restored_at: DateTime<Utc>,
    pub status_incident_id: Option<Uuid>,
}

async fn installed(state: &EngineState) -> Result<(), AppError> {
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('oncall_schedule') IS NOT NULL \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = 'service_ticket' \
                   AND column_name = 'declared_at')",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if ready {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

fn text<'a>(data: &'a Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

/// Declared once `declared_at` is set; a ticket someone only flagged
/// `major` has not been declared (nobody was paged).
fn declared(data: &Value) -> bool {
    data.get("declared_at").is_some_and(|v| !v.is_null())
}

fn uuid_of(data: &Value, key: &str) -> Option<Uuid> {
    text(data, key).and_then(|s| Uuid::parse_str(s).ok())
}

/// `(id, order, handover, shift hours, window start, window end, until)`.
type StoredLayer = (
    Uuid,
    Option<f64>,
    Option<DateTime<Utc>>,
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
);

/// Who is on call on a schedule now.
async fn on_call_now(
    state: &EngineState,
    schedule: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, AppError> {
    let db = &state.base.db;
    let layers: Vec<StoredLayer> = sqlx::query_as(
        "SELECT id, layer_order::float8, handover_at::timestamptz, shift_hours::float8, \
                window_start, window_end, until_at::timestamptz \
           FROM oncall_layer WHERE schedule_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(schedule)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let layer_ids: Vec<Uuid> = layers.iter().map(|l| l.0).collect();
    let members: Vec<(Uuid, Uuid, f64)> = sqlx::query_as(
        "SELECT layer_ref, user_ref, COALESCE(position, 0)::float8 FROM oncall_layer_member \
          WHERE layer_ref = ANY($1) AND user_ref IS NOT NULL \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&layer_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let overrides: Vec<(Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT user_ref, starts_at::timestamptz, ends_at::timestamptz FROM oncall_override \
          WHERE schedule_ref = $1 AND user_ref IS NOT NULL AND starts_at IS NOT NULL \
            AND ends_at IS NOT NULL AND (is_active IS NULL OR is_active = true) \
            AND ends_at::timestamptz > $2",
    )
    .bind(schedule)
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<LayerRow> = layers
        .into_iter()
        .map(
            |(id, order, handover_at, shift_hours, window_start, window_end, until_at)| LayerRow {
                id,
                order: order.unwrap_or(0.0),
                handover_at,
                shift_hours,
                window_start,
                window_end,
                until_at,
            },
        )
        .collect();
    let schedule = schedule_of(&rows, &members, &overrides);
    Ok(crate::oncall::on_call(&schedule, now).map(crate::oncall::OnCall::user))
}

async fn page(state: &EngineState, users: &[Uuid], ticket: Uuid, subject: &str) {
    for user in users {
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(*user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(format!("Major incident: {subject}")),
            body_html: None,
            body_text: Some(format!(
                "A major incident was declared: {subject}. Join the bridge on the ticket."
            )),
            route: Some(format!("/xrm/entity/{TICKET}/{ticket}")),
            variables: HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(error) = attome_notification::dispatch::create_dispatch(
            &state.base.db,
            &state.base.config.notification,
            req,
        )
        .await
        {
            tracing::warn!(%ticket, %user, %error, "major incident: page failed");
        }
    }
}

/// Declares a major incident on a ticket.
pub async fn declare(
    state: &EngineState,
    ctx: &SecurityContext,
    ticket: Uuid,
    body: &DeclareBody,
    now: DateTime<Utc>,
) -> Result<Declared, AppError> {
    installed(state).await?;
    let impact = body.impact.as_deref().unwrap_or("major");
    if !matches!(impact, "minor" | "major" | "critical") {
        return Err(AppError::Validation(
            "impact: minor, major or critical".into(),
        ));
    }
    let commander = body.commander_id.unwrap_or(ctx.user_id);

    // The claim: the ticket row, under the ticket's lock.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(ticket))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "the major incident is being declared by someone else",
        ));
    }
    let record = attome_records::entity_crud::read_record(state, ctx, TICKET, ticket).await?;
    let data = record.data();
    if declared(data) {
        return Ok(Declared {
            ticket_id: ticket,
            already_declared: true,
            commander_id: uuid_of(data, "major_incident_manager"),
            paged: Vec::new(),
            bridge_url: text(data, "bridge_url").map(str::to_owned),
            bridge_error: None,
            status_incident_id: uuid_of(data, "status_incident_ref"),
        });
    }
    let subject = text(data, "title").unwrap_or("Major incident").to_owned();
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        TICKET,
        ticket,
        record.row_version(),
        json!({
            "major": true,
            "declared_at": now.to_rfc3339(),
            "major_incident_manager": commander,
            "oncall_schedule_ref": body.schedule_id,
        }),
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            TICKET,
            ticket,
            attome_audit::AuditOperation::Update,
            "major_incident.declared",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    // Page on-call and the commander.
    let on_call = match body.schedule_id {
        Some(schedule) => on_call_now(state, schedule, now).await?,
        None => None,
    };
    let paged = paged(on_call, commander);
    page(state, &paged, ticket, &subject).await;

    // The bridge, outside any transaction.
    let (bridge_url, bridge_error) = match body.bridge_provider.as_deref() {
        Some(provider) => {
            match attome_integration::connector::adapters::video::create(
                state,
                ctx.user_id,
                &attome_integration::connector::adapters::video::MeetingRequest {
                    provider: provider.to_owned(),
                    subject: format!("Bridge: {subject}").chars().take(255).collect(),
                    start: now,
                    end: now + Duration::hours(BRIDGE_HOURS),
                },
            )
            .await
            {
                Ok(meeting) => (Some(meeting.join_url), None),
                Err(AppError::Validation(message)) => (None, Some(message)),
                Err(error) => {
                    tracing::warn!(%ticket, %error, "major incident: no bridge");
                    (None, Some("the bridge could not be opened".to_owned()))
                }
            }
        }
        None => (None, None),
    };

    // The status page.
    let title = body
        .status_title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or(&subject)
        .to_owned();
    let mut incident = json!({
        "title": title,
        "impact": impact,
        "status": "investigating",
        "started_at": now.to_rfc3339(),
        "is_public": body.public.unwrap_or(true),
    });
    if let Some(ar) = body
        .status_title_ar
        .as_deref()
        .filter(|t| !t.trim().is_empty())
    {
        incident["title_ar"] = json!(ar.trim());
    }
    if let Some(component) = body.component_id {
        incident["component_ref"] = json!(component);
    }
    let (status_incident, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "status_incident",
        incident,
    )
    .await?;
    let (en, ar) = declared_text(&title);
    attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "status_update",
        json!({
            "incident_ref": status_incident,
            "status": "investigating",
            "body": en,
            "body_ar": ar,
            "notify_subscribers": true,
        }),
    )
    .await?;

    // Keep the bridge and the status incident on the ticket.
    let record = attome_records::entity_crud::read_record(state, ctx, TICKET, ticket).await?;
    let mut patch = json!({ "status_incident_ref": status_incident });
    if let Some(url) = &bridge_url {
        patch["bridge_url"] = json!(url);
    }
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        TICKET,
        ticket,
        record.row_version(),
        patch,
    )
    .await?;
    Ok(Declared {
        ticket_id: ticket,
        already_declared: false,
        commander_id: Some(commander),
        paged,
        bridge_url,
        bridge_error,
        status_incident_id: Some(status_incident),
    })
}

/// Links child tickets to a declared major incident.
pub async fn link_children(
    state: &EngineState,
    ctx: &SecurityContext,
    ticket: Uuid,
    children: &[Uuid],
) -> Result<ChildrenLinked, AppError> {
    installed(state).await?;
    if children.is_empty() || children.len() > MAX_CHILDREN {
        return Err(AppError::Validation(format!(
            "ticket_ids: 1 to {MAX_CHILDREN} tickets"
        )));
    }
    let parent = attome_records::entity_crud::read_record(state, ctx, TICKET, ticket).await?;
    if !declared(parent.data()) {
        return Err(AppError::Conflict("declare the major incident first"));
    }
    let mut linked = Vec::with_capacity(children.len());
    for child in children {
        if *child == ticket || linked.contains(child) {
            continue;
        }
        let record = attome_records::entity_crud::read_record(state, ctx, TICKET, *child).await?;
        if uuid_of(record.data(), "parent_ticket_id") != Some(ticket) {
            attome_records::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                TICKET,
                *child,
                record.row_version(),
                json!({ "parent_ticket_id": ticket }),
            )
            .await?;
        }
        linked.push(*child);
    }
    Ok(ChildrenLinked {
        ticket_id: ticket,
        linked,
    })
}

/// Resolves a declared major incident.
pub async fn resolve(
    state: &EngineState,
    ctx: &SecurityContext,
    ticket: Uuid,
    body: &ResolveBody,
    now: DateTime<Utc>,
) -> Result<Resolved, AppError> {
    installed(state).await?;
    let record = attome_records::entity_crud::read_record(state, ctx, TICKET, ticket).await?;
    let data = record.data();
    if !declared(data) {
        return Err(AppError::Conflict("declare the major incident first"));
    }
    let status_incident = uuid_of(data, "status_incident_ref");
    if let Some(restored) = data
        .get("restored_at")
        .and_then(attome_core::timer::date_value)
    {
        // Resolved before: answer it again.
        return Ok(Resolved {
            ticket_id: ticket,
            restored_at: restored,
            status_incident_id: status_incident,
        });
    }
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        TICKET,
        ticket,
        record.row_version(),
        json!({ "restored_at": now.to_rfc3339() }),
    )
    .await?;
    if let Some(incident) = status_incident {
        let row = attome_records::entity_crud::read_record(state, ctx, "status_incident", incident)
            .await?;
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            ctx.user_id,
            "status_incident",
            incident,
            row.row_version(),
            json!({ "status": "resolved", "resolved_at": now.to_rfc3339() }),
        )
        .await?;
        let (en, ar) = resolved_text(body.message.as_deref());
        attome_records::entity_crud::create_record_for(
            state,
            ctx,
            ctx.user_id,
            "status_update",
            json!({
                "incident_ref": incident,
                "status": "resolved",
                "body": en,
                "body_ar": ar,
                "notify_subscribers": true,
            }),
        )
        .await?;
    }
    Ok(Resolved {
        ticket_id: ticket,
        restored_at: now,
        status_incident_id: status_incident,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/service/tickets/{id}/major-incident",
    operation_id = "post_major_incident",
    tag = "service",
    params(("id" = Uuid, Path, description = "The service ticket")),
    request_body = DeclareBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Declared, or the earlier declaration", body = Declared),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.update", body = ErrorResponse),
        (status = 404, description = "No such ticket, or ITSM is not installed", body = ErrorResponse),
        (status = 409, description = "Someone else is declaring it", body = ErrorResponse),
        (status = 422, description = "An unknown impact", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Declares a major incident on a ticket.
///
/// Sets the commander, pages whoever is on call on the chosen schedule and
/// the commander, opens a bridge on the video provider named, and posts a
/// status page incident. Declaring again answers the first declaration.
async fn post_declare(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<DeclareBody>,
) -> Result<Json<Declared>, AppError> {
    Ok(Json(declare(&state, &ctx, id, &body, Utc::now()).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/service/tickets/{id}/major-incident/children",
    operation_id = "post_major_incident_children",
    tag = "service",
    params(("id" = Uuid, Path, description = "The major incident's ticket")),
    request_body = ChildrenBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The tickets now linked", body = ChildrenLinked),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.update", body = ErrorResponse),
        (status = 404, description = "No such ticket", body = ErrorResponse),
        (status = 409, description = "Not declared as a major incident", body = ErrorResponse),
        (status = 422, description = "No tickets, or too many", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Links tickets to a major incident.
///
/// Each ticket gets the major incident as its parent; a ticket already
/// linked is answered as linked.
async fn post_children(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ChildrenBody>,
) -> Result<Json<ChildrenLinked>, AppError> {
    Ok(Json(
        link_children(&state, &ctx, id, &body.ticket_ids).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/service/tickets/{id}/major-incident/resolve",
    operation_id = "post_major_incident_resolve",
    tag = "service",
    params(("id" = Uuid, Path, description = "The major incident's ticket")),
    request_body = ResolveBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Resolved, or the earlier resolution", body = Resolved),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks service_ticket.update", body = ErrorResponse),
        (status = 404, description = "No such ticket", body = ErrorResponse),
        (status = 409, description = "Not declared as a major incident", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Resolves a major incident.
///
/// Records the restore time on the ticket, resolves its status page
/// incident and posts the last update to subscribers.
async fn post_resolve(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveBody>,
) -> Result<Json<Resolved>, AppError> {
    Ok(Json(resolve(&state, &ctx, id, &body, Utc::now()).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/service/tickets/{id}/major-incident",
            post(post_declare),
        )
        .route(
            "/api/v1/service/tickets/{id}/major-incident/children",
            post(post_children),
        )
        .route(
            "/api/v1/service/tickets/{id}/major-incident/resolve",
            post(post_resolve),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_declare, post_children, post_resolve),
    components(schemas(
        DeclareBody,
        Declared,
        ChildrenBody,
        ChildrenLinked,
        ResolveBody,
        Resolved
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(h: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1)
            .and_then(|d| d.and_hms_opt(h, 0, 0))
            .expect("a real time")
            .and_utc()
    }

    fn user(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn layer(id: u128, order: f64, hours: f64) -> LayerRow {
        LayerRow {
            id: Uuid::from_u128(id),
            order,
            handover_at: Some(at(0)),
            shift_hours: Some(hours),
            window_start: None,
            window_end: None,
            until_at: None,
        }
    }

    #[test]
    fn stored_rows_build_the_rotation_in_member_order() {
        let weekly = layer(10, 0.0, 8.0);
        let members = [
            (weekly.id, user(2), 2.0),
            (weekly.id, user(1), 1.0),
            (weekly.id, user(3), 3.0),
        ];
        let schedule = schedule_of(&[weekly], &members, &[]);
        assert_eq!(schedule.layers.len(), 1);
        assert_eq!(schedule.layers[0].members, vec![user(1), user(2), user(3)]);
        let who = |h| crate::oncall::on_call(&schedule, at(h)).map(crate::oncall::OnCall::user);
        assert_eq!(who(1), Some(user(1)));
        assert_eq!(who(9), Some(user(2)), "the second turn of eight hours");
        assert_eq!(who(17), Some(user(3)));
    }

    #[test]
    fn a_higher_layer_and_an_override_win() {
        let base = layer(10, 0.0, 24.0);
        let mut nights = layer(11, 1.0, 24.0);
        nights.window_start = Some("18:00".into());
        nights.window_end = Some("06:00".into());
        let members = [(base.id, user(1), 0.0), (nights.id, user(2), 0.0)];
        let schedule = schedule_of(&[nights.clone(), base.clone()], &members, &[]);
        let who =
            |s: &Schedule, h| crate::oncall::on_call(s, at(h)).map(crate::oncall::OnCall::user);
        assert_eq!(who(&schedule, 12), Some(user(1)), "daytime: the base layer");
        assert_eq!(who(&schedule, 20), Some(user(2)), "night: the higher layer");
        let with_override = schedule_of(&[nights, base], &members, &[(user(9), at(19), at(23))]);
        assert_eq!(who(&with_override, 20), Some(user(9)));
    }

    #[test]
    fn unusable_layers_are_left_out() {
        let mut no_handover = layer(1, 0.0, 8.0);
        no_handover.handover_at = None;
        let no_shift = layer(2, 0.0, 0.0);
        let mut half_window = layer(3, 0.0, 8.0);
        half_window.window_start = Some("09:00".into());
        let schedule = schedule_of(&[no_handover, no_shift, half_window], &[], &[]);
        assert_eq!(schedule.layers.len(), 1);
        assert_eq!(
            schedule.layers[0].daily_window, None,
            "one end only: all day"
        );
        let backwards = schedule_of(&[], &[], &[(user(1), at(5), at(4))]);
        assert!(backwards.overrides.is_empty());
    }

    #[test]
    fn on_call_and_the_commander_are_paged_once_each() {
        assert_eq!(paged(Some(user(1)), user(2)), vec![user(1), user(2)]);
        assert_eq!(paged(Some(user(2)), user(2)), vec![user(2)]);
        assert_eq!(paged(None, user(2)), vec![user(2)]);
    }

    #[test]
    fn status_texts_are_bilingual_with_a_custom_resolution() {
        let (en, ar) = declared_text("Payments down");
        assert!(en.contains("Payments down") && ar.contains("Payments down"));
        let (en, _) = resolved_text(Some("  Fixed by failover.  "));
        assert_eq!(en, "Fixed by failover.");
        let (en, ar) = resolved_text(Some("   "));
        assert!(en.contains("resolved"));
        assert!(!ar.is_empty());
    }

    #[test]
    fn each_ticket_has_its_own_lock() {
        assert_ne!(lock_key(user(1)), lock_key(user(2)));
        assert!(lock_key(user(1)).starts_with("attome-service/major-incident:"));
    }
}
