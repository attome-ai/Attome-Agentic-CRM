//! Event registration (roadmap E21-T2): register people for a marketing
//! event up to its capacity, put the rest on the waitlist, promote the
//! first waiting person when someone cancels, and check people in by the
//! code on their ticket.
//!
//! Every change runs under the event's lock
//! (`attome-marketing/event:{id}`), so two registrations never take the last
//! seat. A ticket's code is random and unguessable (two v4 UUIDs, 244 random
//! bits), unique per registration; the QR code shows it.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// `marketing_event_registration.create`: may register people.
#[derive(Debug)]
pub struct RegistrationCreate;

impl PrivilegeKey for RegistrationCreate {
    const KEY: &'static str = "marketing_event_registration.create";
}

/// `marketing_event_registration.update`: may cancel and check people in.
#[derive(Debug)]
pub struct RegistrationUpdate;

impl PrivilegeKey for RegistrationUpdate {
    const KEY: &'static str = "marketing_event_registration.update";
}

/// The statuses that hold a seat.
pub const SEATED: [&str; 3] = ["registered", "confirmed", "attended"];

/// A new ticket code.
pub fn ticket_code() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Where a new registration goes, given the seats taken.
pub fn placement(capacity: Option<i64>, seated: i64) -> &'static str {
    match capacity {
        Some(cap) if cap > 0 && seated >= cap => "waitlisted",
        _ => "registered",
    }
}

async fn lock(tx: &mut attome_db::Tx<'_>, event: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-marketing/event:{event}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "this event's registrations are being changed; retry",
        ))
    }
}

async fn seats(tx: &mut attome_db::Tx<'_>, event: Uuid) -> Result<(Option<i64>, i64), AppError> {
    let capacity: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT capacity::bigint FROM marketing_event \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(event)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(capacity) = capacity else {
        return Err(AppError::NotFound);
    };
    let seated: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_event_registration \
         WHERE event_ref = $1 AND status = ANY($2) AND (is_active IS NULL OR is_active = true)",
    )
    .bind(event)
    .bind(&SEATED[..])
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok((capacity, seated))
}

/// Keeps the event's `full`/`open` status in step with its seats.
async fn sync_status(
    tx: &mut attome_db::Tx<'_>,
    event: Uuid,
    capacity: Option<i64>,
    seated: i64,
) -> Result<(), AppError> {
    let full = capacity.is_some_and(|c| c > 0 && seated >= c);
    sqlx::query(
        "UPDATE marketing_event SET status = $2, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND status IN ('open', 'full') AND status <> $2",
    )
    .bind(event)
    .bind(if full { "full" } else { "open" })
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn audit(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    record: Uuid,
    operation: AuditOperation,
    name: &str,
    actor: Uuid,
    comment: String,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "marketing_event_registration",
            record,
            operation,
            name,
            actor,
        )
        .comment(comment),
    )
    .await?;
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MarketingRegistrationBody {
    #[serde(default)]
    pub contact_ref: Option<Uuid>,
    #[serde(default)]
    pub lead_ref: Option<Uuid>,
    pub attendee_name: String,
    #[serde(default)]
    pub attendee_email: Option<String>,
    /// `form`, `portal`, `import` or `staff` (default).
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingRegistration {
    pub registration_id: Uuid,
    /// `registered` or `waitlisted`.
    pub status: String,
    /// The ticket code the QR shows.
    pub ticket_code: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/events/{id}/registrations",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The event")),
    request_body = MarketingRegistrationBody,
    responses(
        (status = 201, description = "Registered, or waitlisted when the event is full", body = MarketingRegistration),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_event_registration.create", body = ErrorResponse),
        (status = 404, description = "No such event", body = ErrorResponse),
        (status = 409, description = "The event is closed, cancelled or done, or busy", body = ErrorResponse),
        (status = 422, description = "No attendee name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_marketing_registration(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RegistrationCreate>>,
    Path(event): Path<Uuid>,
    Json(body): Json<MarketingRegistrationBody>,
) -> Result<(StatusCode, Json<MarketingRegistration>), AppError> {
    let name = body.attendee_name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("attendee_name is required".into()));
    }
    let source = body.source.as_deref().unwrap_or("staff");
    if !matches!(source, "form" | "portal" | "import" | "staff") {
        return Err(AppError::Validation(
            "source is form, portal, import or staff".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, event).await?;
    let event_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM marketing_event WHERE id = $1")
            .bind(event)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    if matches!(
        event_status.as_deref(),
        Some("closed" | "cancelled" | "done" | "draft")
    ) {
        return Err(AppError::Conflict("the event is not taking registrations"));
    }
    let (capacity, seated) = seats(&mut tx, event).await?;
    let status = placement(capacity, seated);
    let code = ticket_code();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO marketing_event_registration \
           (event_ref, contact_ref, lead_ref, attendee_name, attendee_email, status, qr_code, \
            registered_at, source, owner_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9) RETURNING id",
    )
    .bind(event)
    .bind(body.contact_ref)
    .bind(body.lead_ref)
    .bind(name)
    .bind(body.attendee_email.as_deref().map(str::trim))
    .bind(status)
    .bind(&code)
    .bind(source)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let seated = seated + i64::from(status == "registered");
    sync_status(&mut tx, event, capacity, seated).await?;
    audit(
        &mut tx,
        &state,
        id,
        AuditOperation::Create,
        "marketing.event_registered",
        ctx.user_id,
        status.to_owned(),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(MarketingRegistration {
            registration_id: id,
            status: status.into(),
            ticket_code: code,
        }),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingCancelled {
    pub registration_id: Uuid,
    /// The waiting registration that took the freed seat.
    pub promoted: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/events/{id}/registrations/{registration_id}/cancel",
    tag = "marketing",
    params(
        ("id" = Uuid, Path, description = "The event"),
        ("registration_id" = Uuid, Path, description = "The registration"),
    ),
    responses(
        (status = 200, description = "Cancelled; the first waiting person takes the seat", body = MarketingCancelled),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_event_registration.update", body = ErrorResponse),
        (status = 404, description = "No such registration for this event", body = ErrorResponse),
        (status = 409, description = "Already cancelled or attended, or the event is busy", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_marketing_registration_cancel(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RegistrationUpdate>>,
    Path((event, registration)): Path<(Uuid, Uuid)>,
) -> Result<Json<MarketingCancelled>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, event).await?;
    let status: Option<Option<String>> = sqlx::query_scalar(
        "SELECT status FROM marketing_event_registration \
         WHERE id = $1 AND event_ref = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(registration)
    .bind(event)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(status) = status else {
        return Err(AppError::NotFound);
    };
    if matches!(status.as_deref(), Some("cancelled" | "attended")) {
        return Err(AppError::Conflict(
            "the registration is already cancelled or attended",
        ));
    }
    let held_seat = status.as_deref().is_some_and(|s| SEATED.contains(&s));
    sqlx::query(
        "UPDATE marketing_event_registration SET status = 'cancelled', modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(registration)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut promoted = None;
    if held_seat {
        promoted = sqlx::query_scalar(
            "UPDATE marketing_event_registration SET status = 'registered', modified_at = now(), \
                 row_version = row_version + 1 \
             WHERE id = (SELECT id FROM marketing_event_registration \
                 WHERE event_ref = $1 AND status = 'waitlisted' \
                   AND (is_active IS NULL OR is_active = true) \
                 ORDER BY registered_at NULLS LAST, id LIMIT 1) \
             RETURNING id",
        )
        .bind(event)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    let (capacity, seated) = seats(&mut tx, event).await?;
    sync_status(&mut tx, event, capacity, seated).await?;
    audit(
        &mut tx,
        &state,
        registration,
        AuditOperation::Update,
        "marketing.event_registration_cancelled",
        ctx.user_id,
        promoted.map_or_else(|| "no one waiting".to_owned(), |p| format!("promoted {p}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(MarketingCancelled {
        registration_id: registration,
        promoted,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MarketingCheckInBody {
    /// The code on the ticket.
    pub ticket_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingCheckedIn {
    pub registration_id: Uuid,
    pub attendee_name: Option<String>,
    /// False when the person had already been checked in.
    pub first_check_in: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/events/{id}/check-in",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The event")),
    request_body = MarketingCheckInBody,
    responses(
        (status = 200, description = "Checked in (a repeat scan answers the same, not twice)", body = MarketingCheckedIn),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_event_registration.update", body = ErrorResponse),
        (status = 404, description = "No registration for this event has that code", body = ErrorResponse),
        (status = 409, description = "The registration is cancelled or still waiting", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_marketing_check_in(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RegistrationUpdate>>,
    Path(event): Path<Uuid>,
    Json(body): Json<MarketingCheckInBody>,
) -> Result<Json<MarketingCheckedIn>, AppError> {
    let code = body.ticket_code.trim();
    if code.is_empty() || code.len() > 128 {
        return Err(AppError::NotFound);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, status, attendee_name FROM marketing_event_registration \
         WHERE event_ref = $1 AND qr_code = $2 AND (is_active IS NULL OR is_active = true) \
         FOR UPDATE",
    )
    .bind(event)
    .bind(code)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((id, status, name)) = row else {
        return Err(AppError::NotFound);
    };
    match status.as_deref() {
        Some("cancelled" | "waitlisted") => {
            return Err(AppError::Conflict(
                "the registration is cancelled or still waiting",
            ));
        }
        Some("attended") => {
            attome_db::tx::commit(tx).await?;
            return Ok(Json(MarketingCheckedIn {
                registration_id: id,
                attendee_name: name,
                first_check_in: false,
            }));
        }
        _ => {}
    }
    sqlx::query(
        "UPDATE marketing_event_registration SET status = 'attended', checked_in_at = now(), \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit(
        &mut tx,
        &state,
        id,
        AuditOperation::Update,
        "marketing.event_checked_in",
        ctx.user_id,
        String::new(),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(MarketingCheckedIn {
        registration_id: id,
        attendee_name: name,
        first_check_in: true,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_marketing_registration,
        post_marketing_registration_cancel,
        post_marketing_check_in
    ),
    components(schemas(
        MarketingRegistrationBody,
        MarketingRegistration,
        MarketingCancelled,
        MarketingCheckInBody,
        MarketingCheckedIn
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_seat_goes_then_the_waitlist_starts() {
        assert_eq!(placement(Some(2), 1), "registered");
        assert_eq!(placement(Some(2), 2), "waitlisted");
        // No capacity, or zero, means no limit.
        assert_eq!(placement(None, 500), "registered");
        assert_eq!(placement(Some(0), 500), "registered");
    }

    #[test]
    fn ticket_codes_are_long_and_unique() {
        let (a, b) = (ticket_code(), ticket_code());
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }
}
