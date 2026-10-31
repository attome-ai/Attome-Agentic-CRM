//! F9-T6: partner recruiting, from a public application to onboarding.
//!
//! - **Apply** ([`submit`], the portal's `/{keyword}/api/v1/partner/applications`,
//!   rate-limited and CAPTCHA-checked as sign-up is): a `partner_application`
//!   row, with the account it matches by name or email domain when there is
//!   one. No account is made or changed.
//! - **Decide** ([`approve_in_tx`] and [`reject`], the portal's admin route
//!   `POST /api/v1/partner/applications/{id}/decision`, because the partner's
//!   administrator is a portal member and that crate provisions them): a
//!   person decides, as with registrations. Approval marks the matched account
//!   a partner, or creates one, and gives it a contact for the administrator.
//! - **Agreement** ([`send_agreement`],
//!   `POST /api/v1/partner/applications/{id}/agreement`): a separate step so a
//!   failed send can be retried; an e-sign envelope to the applicant.
//! - **Onboarding** ([`onboarding_tick`], hourly): e-sign emits no event, so
//!   the job looks for completed agreements and adds the three items, due at
//!   30, 60 and 90 days. The approval of the partner's first registration
//!   finishes `first_registered_deal` ([`finish_first_deal`]).

use attome_audit::{AuditOperation, BusinessEvent, write_business_event_in_tx};
use attome_core::EngineState;
use attome_document::esign::{NewEnvelope, NewSigner, create_envelope, send_envelope};
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::support::{installed, lock, person_only, require};

/// The registered hourly job.
pub const ONBOARDING_JOB: &str = "partner_onboarding";
const ENTITY: &str = "partner_application";
const BATCH: i64 = 500;
/// What each onboarding item is, and the days it has.
const ITEMS: [(&str, i32); 3] = [
    ("training", 30),
    ("first_certification", 60),
    ("first_registered_deal", 90),
];
/// Mail providers anyone can use, which say nothing about a company.
const SHARED_DOMAINS: [&str; 7] = [
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "icloud.com",
    "outlook.com",
    "proton.me",
    "yahoo.com",
];

/// What an applicant sends.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct Application {
    pub company_name: String,
    pub contact_name: String,
    pub contact_email: String,
    #[serde(default)]
    pub contact_phone: Option<String>,
}

/// The application's row, as a decision reads it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApplicationRow {
    pub company_name: String,
    pub contact_name: Option<String>,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
    pub matched_account_ref: Option<Uuid>,
    pub status: Option<String>,
}

/// What an approval made.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Approved {
    pub partner_account_id: Uuid,
    pub contact_id: Uuid,
}

/// `POST /api/v1/partner/applications/{id}/agreement`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AgreementBody {
    /// The `attome_document` record holding the agreement.
    pub document_id: Uuid,
}

/// The envelope sent.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AgreementSent {
    pub envelope_id: Uuid,
}

/// The part of an address after the `@`, lower-cased. Pure.
pub fn email_domain(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    let domain = domain.to_lowercase();
    (!local.is_empty() && domain.contains('.')).then_some(domain)
}

/// The domain to match companies by: none for a shared mail provider. Pure.
pub fn company_domain(email: &str) -> Option<String> {
    email_domain(email).filter(|d| !SHARED_DOMAINS.contains(&d.as_str()))
}

/// A name as it compares: lower case, single spaces. Pure.
pub fn normalised_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn checked_text(value: &str, field: &str, max: usize) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{field}: 1 to {max} characters"
        )));
    }
    Ok(value.to_owned())
}

async fn matching_account(
    state: &EngineState,
    name: &str,
    domain: Option<&str>,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM account \
          WHERE is_active AND (lower(btrim(regexp_replace(name, '\\s+', ' ', 'g'))) = $1 \
                OR ($2::text IS NOT NULL AND lower(email_domain) = $2)) \
          ORDER BY id LIMIT 1",
    )
    .bind(name)
    .bind(domain)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Records an application. Nobody is signed in: `Uuid::nil()` is the actor.
pub async fn submit(state: &EngineState, application: &Application) -> Result<Uuid, AppError> {
    let company = checked_text(&application.company_name, "company_name", 200)?;
    let contact = checked_text(&application.contact_name, "contact_name", 200)?;
    let email = checked_text(&application.contact_email, "contact_email", 254)?.to_lowercase();
    if email_domain(&email).is_none() {
        return Err(AppError::Validation("contact_email: not an address".into()));
    }
    let phone = application
        .contact_phone
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| checked_text(p, "contact_phone", 50))
        .transpose()?;
    let matched = matching_account(
        state,
        &normalised_name(&company),
        company_domain(&email).as_deref(),
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO partner_application \
           (company_name, contact_name, contact_email, contact_phone, matched_account_ref, status) \
         VALUES ($1, $2, $3, $4, $5, 'submitted') RETURNING id",
    )
    .bind(&company)
    .bind(&contact)
    .bind(&email)
    .bind(&phone)
    .bind(matched)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            ENTITY,
            id,
            AuditOperation::Create,
            "partner.application_submitted",
            Uuid::nil(),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(id)
}

/// A live application under its lock, or `NotFound`.
async fn lock_application(
    tx: &mut attome_db::Tx<'_>,
    id: Uuid,
) -> Result<ApplicationRow, AppError> {
    lock(tx, format!("attome-partner/application:{id}")).await?;
    sqlx::query_as(
        "SELECT company_name, contact_name, contact_email, contact_phone, \
                matched_account_ref, status \
           FROM partner_application WHERE id = $1 AND is_active",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Who may decide: a person with update access on the application.
pub async fn may_decide(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<(), AppError> {
    person_only(ctx)?;
    require(state, ctx, ENTITY, id, RecordAction::Update).await
}

/// Rejects a submitted application, with a reason.
pub async fn reject(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    reason: &str,
) -> Result<(), AppError> {
    may_decide(state, ctx, id).await?;
    let reason = checked_text(reason, "reason", 2000)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row = lock_application(&mut tx, id).await?;
    if row.status.as_deref() != Some("submitted") {
        return Err(AppError::Conflict("the application is already decided"));
    }
    sqlx::query(
        "UPDATE partner_application SET status = 'rejected', decision_reason = $2, \
                modified_by = $3, modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(&reason)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            ENTITY,
            id,
            AuditOperation::Update,
            "partner.application_rejected",
            ctx.user_id,
        )
        .comment(reason),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

/// An application's status, then its company and contact fields as read.
type ApplicantRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Approves inside the caller's transaction, which also provisions the portal
/// member: marks or creates the partner account and adds the contact. The
/// caller has already passed [`may_decide`].
pub async fn approve_in_tx(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    actor: Uuid,
    id: Uuid,
) -> Result<(ApplicationRow, Approved), AppError> {
    let row = lock_application(tx, id).await?;
    if row.status.as_deref() != Some("submitted") {
        return Err(AppError::Conflict("the application is already decided"));
    }
    let partner: Uuid = match row.matched_account_ref {
        Some(account) => sqlx::query_scalar(
            "UPDATE account SET is_partner = true, modified_by = $2, modified_at = now(), \
                    row_version = row_version + 1 \
              WHERE id = $1 AND is_active RETURNING id",
        )
        .bind(account)
        .bind(actor)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::Conflict(
            "the matched account is no longer active",
        ))?,
        None => sqlx::query_scalar(
            "INSERT INTO account (name, is_partner, created_by, modified_by) \
             VALUES ($1, true, $2, $2) RETURNING id",
        )
        .bind(&row.company_name)
        .bind(actor)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?,
    };
    let contact: Uuid = sqlx::query_scalar(
        "INSERT INTO contact (full_name, email, phone, account_ref, created_by, modified_by) \
         VALUES ($1, $2, $3, $4, $5, $5) RETURNING id",
    )
    .bind(row.contact_name.as_deref().unwrap_or(&row.company_name))
    .bind(&row.contact_email)
    .bind(&row.contact_phone)
    .bind(partner)
    .bind(actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE partner_application SET status = 'approved', matched_account_ref = $2, \
                modified_by = $3, modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(partner)
    .bind(actor)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            ENTITY,
            id,
            AuditOperation::Update,
            "partner.application_approved",
            actor,
        )
        .comment(format!("partner account {partner}")),
    )
    .await?;
    Ok((
        row,
        Approved {
            partner_account_id: partner,
            contact_id: contact,
        },
    ))
}

/// Sends the agreement to the applicant of an approved application. Once an
/// envelope is recorded a second call is a conflict.
pub async fn send_agreement(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    document: Uuid,
) -> Result<Uuid, AppError> {
    may_decide(state, ctx, id).await?;
    let row: Option<ApplicantRow> = sqlx::query_as(
        "SELECT company_name, contact_name, contact_email, status, agreement_envelope_id \
               FROM partner_application WHERE id = $1 AND is_active",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (company, name, email, status, sent) = row.ok_or(AppError::NotFound)?;
    if status.as_deref() != Some("approved") {
        return Err(AppError::Conflict("the application is not approved"));
    }
    if sent.is_some() {
        return Err(AppError::Conflict("the agreement was already sent"));
    }
    let email = email.ok_or(AppError::Validation(
        "the application has no contact email".into(),
    ))?;
    let envelope = create_envelope(
        state,
        ctx,
        &NewEnvelope {
            title: format!("Partner agreement: {company}"),
            document_ids: vec![document],
            signers: vec![NewSigner {
                name: name.unwrap_or(company),
                email,
                role: None,
                order: None,
            }],
        },
    )
    .await?;
    let claimed = sqlx::query(
        "UPDATE partner_application SET agreement_envelope_id = $2, modified_by = $3, \
                modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND agreement_envelope_id IS NULL",
    )
    .bind(id)
    .bind(envelope.to_string())
    .bind(ctx.user_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() != 1 {
        return Err(AppError::Conflict("the agreement was already sent"));
    }
    send_envelope(state, ctx, envelope).await?;
    Ok(envelope)
}

/// The hourly job: adds the three items for each newly signed agreement.
/// Answers how many partners started onboarding.
pub async fn onboarding_tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db, ENTITY, "agreement_envelope_id").await? {
        return Ok(0);
    }
    let signed: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT a.id, a.matched_account_ref FROM partner_application a \
           JOIN esign_envelope e ON e.id::text = a.agreement_envelope_id \
          WHERE e.status = 'completed' AND a.onboarding_started_at IS NULL \
            AND a.matched_account_ref IS NOT NULL \
          ORDER BY a.id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let audit = attome_audit::audit_service(state);
    let mut started = 0;
    for (application, partner) in signed {
        let mut tx = attome_db::tx::begin(db).await?;
        let claimed = sqlx::query(
            "UPDATE partner_application SET onboarding_started_at = now(), modified_at = now(), \
                    row_version = row_version + 1 \
              WHERE id = $1 AND onboarding_started_at IS NULL",
        )
        .bind(application)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if claimed.rows_affected() != 1 {
            continue;
        }
        for (kind, days) in ITEMS {
            sqlx::query(
                "INSERT INTO partner_onboarding_item (partner_account_ref, kind, due_on) \
                 VALUES ($1, $2, now() + make_interval(days => $3))",
            )
            .bind(partner)
            .bind(kind)
            .bind(days)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        write_business_event_in_tx(
            &mut tx,
            &audit,
            BusinessEvent::new(
                ENTITY,
                application,
                AuditOperation::Update,
                "partner.onboarding_started",
                Uuid::nil(),
            ),
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        started += 1;
    }
    Ok(started)
}

/// Finishes the partner's `first_registered_deal` item, when it is open.
pub async fn finish_first_deal(tx: &mut attome_db::Tx<'_>, partner: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE partner_onboarding_item SET done_on = now(), modified_at = now(), \
                row_version = row_version + 1 \
          WHERE partner_account_ref = $1 AND kind = 'first_registered_deal' AND done_on IS NULL",
    )
    .bind(partner)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Send the partner agreement
///
/// F9-T6: an e-sign envelope to the applicant of an approved application. A person with update
/// access sends it, once; when it is signed the partner's onboarding items appear. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/applications/{id}/agreement",
    operation_id = "partner_application_agreement",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The application")),
    request_body = AgreementBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Sent", body = AgreementSent),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such application the caller may read", body = ErrorResponse),
        (status = 409, description = "Not approved, or already sent", body = ErrorResponse),
        (status = 422, description = "The document cannot be signed", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_agreement(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<AgreementBody>,
) -> Result<Json<AgreementSent>, AppError> {
    send_agreement(&state, &ctx, id, body.document_id)
        .await
        .map(|envelope_id| Json(AgreementSent { envelope_id }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/partner/applications/{id}/agreement",
        post(post_agreement),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_agreement),
    components(schemas(AgreementBody, AgreementSent, Application, Approved))
)]
pub(crate) struct RecruitingApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_mail_domain_matches_no_company() {
        assert_eq!(company_domain("Sara@Acme.SA").as_deref(), Some("acme.sa"));
        assert_eq!(company_domain("sara@gmail.com"), None);
        assert_eq!(company_domain("not an address"), None);
        assert_eq!(company_domain("@acme.sa"), None);
    }

    #[test]
    fn names_compare_without_case_or_extra_spaces() {
        assert_eq!(normalised_name("  Acme   Trading "), "acme trading");
    }

    #[test]
    fn three_items_due_by_ninety_days() {
        assert_eq!(ITEMS.len(), 3);
        assert_eq!(ITEMS[2], ("first_registered_deal", 90));
    }
}
