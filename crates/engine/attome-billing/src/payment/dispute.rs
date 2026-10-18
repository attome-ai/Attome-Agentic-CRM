//! Disputes (roadmap F5-T10): a chargeback the gateway reports becomes a
//! `payment_dispute`, and a person gathers the evidence and submits it to
//! the gateway (nothing is submitted automatically).
//!
//! - [`open_dispute_in_tx`] (from the gateway event job) records the
//!   dispute with its evidence deadline (the gateway's, or seven days),
//!   marks the payment `disputed`, and tells each Finance Manager in the
//!   app.
//! - [`dispute_evidence`] (`GET /api/v1/billing/disputes/{id}/evidence`,
//!   `payment_dispute.read`) lists what can answer it: the PDF of each
//!   invoice the payment paid, and the files attached (K1) to those invoices
//!   and to the order its payment link was for, read through the document
//!   records, with no new storage.

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{Duration, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::gateway::DisputeOpened;

/// Days to answer a dispute when the gateway names no deadline.
pub const DEFAULT_EVIDENCE_DAYS: i64 = 7;

/// The role told about a new dispute.
const FINANCE_ROLE: &str = "Finance Manager";

/// Records a chargeback against the payment with this gateway reference;
/// `false` when the same dispute is open already.
pub async fn open_dispute_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    system_id: Uuid,
    gateway_reference: &str,
    dispute: &DisputeOpened,
    actor: Uuid,
) -> Result<bool, AppError> {
    let payment: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, name FROM customer_payment \
         WHERE gateway_system_ref = $1 AND gateway_reference = $2 \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY id LIMIT 1 FOR UPDATE",
    )
    .bind(system_id.to_string())
    .bind(gateway_reference)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (payment, name) = payment.ok_or_else(|| {
        AppError::Validation(format!(
            "no payment has the gateway reference {gateway_reference}"
        ))
    })?;
    let open: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM payment_dispute \
           WHERE payment_ref = $1 AND COALESCE(status, 'open') IN ('open', 'evidence_submitted') \
             AND reason_code IS NOT DISTINCT FROM $2 \
             AND (is_active IS NULL OR is_active = true))",
    )
    .bind(payment)
    .bind(dispute.reason_code.as_deref())
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if open {
        return Ok(false);
    }
    let due = dispute
        .evidence_due
        .unwrap_or_else(|| Utc::now().date_naive() + Duration::days(DEFAULT_EVIDENCE_DAYS));
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO payment_dispute (id, payment_ref, amount, reason_code, evidence_due, status, \
             created_by, owner_ref, owner_type, is_active, row_version) \
         VALUES ($1, $2, $3::numeric, $4, $5, 'open', $6, $6, 0, true, 0)",
    )
    .bind(id)
    .bind(payment)
    .bind(dispute.amount.to_string())
    .bind(dispute.reason_code.as_deref())
    .bind(due.and_hms_opt(0, 0, 0).map(|d| d.and_utc()))
    .bind(actor)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE customer_payment SET status = 'disputed', modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(payment)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        tx,
        "payment_dispute",
        id,
        ChangeOperation::Create,
        "billing.dispute.opened",
    )
    .await?;
    emit_named(
        tx,
        "customer_payment",
        payment,
        ChangeOperation::Update,
        "billing.payment.disputed",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "payment_dispute",
            id,
            attome_audit::AuditOperation::Create,
            "billing.dispute_opened",
            actor,
        ),
    )
    .await?;
    let finance: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT ur.user_ref FROM user_account_mm_role ur \
         JOIN role r ON r.id = ur.role_ref \
         JOIN user_account u ON u.id = ur.user_ref \
         WHERE r.name = $1 AND ur.is_deleted = false AND r.is_deleted = false \
           AND u.is_active = true \
         LIMIT 100",
    )
    .bind(FINANCE_ROLE)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let payment_name = name.unwrap_or_else(|| payment.to_string());
    for user in finance {
        attome_notification::dispatch::create_dispatch_in_tx(
            tx,
            &state.base.config.notification,
            attome_notification::dispatch::DispatchRequest {
                template_key: None,
                locale: "en".to_owned(),
                recipient_user_ref: Some(user),
                is_global: false,
                organization_ref: None,
                channels: Some(vec!["in_app".to_owned()]),
                subject: Some(format!(
                    "Payment {payment_name} is disputed | اعتراض على الدفعة {payment_name}"
                )),
                body_html: None,
                body_text: Some(format!(
                    "A chargeback of {} was opened. Evidence is due by {due}.\n\
                     فُتح اعتراض بمبلغ {}. آخر موعد للأدلة {due}.",
                    dispute.amount, dispute.amount
                )),
                route: Some(format!("/payment_dispute/{id}")),
                variables: std::collections::HashMap::new(),
                priority: "high".to_owned(),
                escalate_after_minutes: None,
                escalate_channels: None,
            },
            Some("billing.dispute"),
        )
        .await?;
    }
    Ok(true)
}

/// One document that can answer a dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DocumentRef {
    /// `invoice_document` (the invoice's PDF) or `attachment` (a K1 file).
    pub kind: String,
    /// The record it belongs to.
    pub entity: String,
    pub record_id: Uuid,
    /// The file field to download it from.
    pub field: String,
    /// The `attome_document` row, for an attachment.
    pub document_id: Option<Uuid>,
    pub name: Option<String>,
    pub folder: Option<String>,
}

type DocumentRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The evidence a dispute can draw on, for a caller who can read it.
pub async fn dispute_evidence(
    state: &EngineState,
    ctx: &SecurityContext,
    dispute: Uuid,
) -> Result<Vec<DocumentRef>, AppError> {
    let scope = crate::scope::read_scope(state, ctx, "payment_dispute", "d", 2).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT d.payment_ref FROM payment_dispute d \
         WHERE d.id = $1 AND (d.is_active IS NULL OR d.is_active = true) {rls}"
    );
    let payment: Option<(Option<Uuid>,)> =
        crate::scope::bind_scope(sqlx::query_as(&sql).bind(dispute), &scope)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let payment = payment.and_then(|p| p.0).ok_or(AppError::NotFound)?;
    // The invoices it paid (or was charged for, or linked to), and the order
    // its link was for.
    let invoices: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT i.id, i.invoice_number, i.document FROM invoice i \
         WHERE i.id IN ( \
             SELECT a.invoice_ref FROM payment_allocation a \
             WHERE a.payment_ref = $1 AND (a.is_active IS NULL OR a.is_active = true) \
             UNION SELECT p.charged_invoice_ref FROM customer_payment p WHERE p.id = $1 \
             UNION SELECT l.invoice_ref FROM customer_payment p \
                 JOIN payment_link l ON l.id = p.payment_link_ref WHERE p.id = $1) \
         ORDER BY i.id",
    )
    .bind(payment)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let order: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT l.order_ref FROM customer_payment p JOIN payment_link l ON l.id = p.payment_link_ref \
         WHERE p.id = $1",
    )
    .bind(payment)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out: Vec<DocumentRef> = invoices
        .iter()
        .filter(|(_, _, document)| document.as_deref().is_some_and(|d| !d.is_empty()))
        .map(|(id, number, _)| DocumentRef {
            kind: "invoice_document".into(),
            entity: "invoice".into(),
            record_id: *id,
            field: "document".into(),
            document_id: None,
            name: number.clone(),
            folder: None,
        })
        .collect();
    let mut records: Vec<(String, Uuid)> = invoices
        .iter()
        .map(|(id, _, _)| ("invoice".to_owned(), *id))
        .collect();
    if let Some(order) = order.flatten() {
        records.push(("order".to_owned(), order));
    }
    for (entity, record) in records {
        let documents: Vec<DocumentRow> = sqlx::query_as(
            "SELECT id, name, folder, file, entity_name FROM attome_document \
             WHERE entity_name = $1 AND record_id = $2 AND is_active IS NOT FALSE \
             ORDER BY folder NULLS FIRST, name, id",
        )
        .bind(&entity)
        .bind(record.to_string())
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        out.extend(documents.into_iter().filter(|d| d.3.is_some()).map(
            |(id, name, folder, _, _)| DocumentRef {
                kind: "attachment".into(),
                entity: "attome_document".into(),
                record_id: id,
                field: "file".into(),
                document_id: Some(id),
                name,
                folder,
            },
        ));
    }
    Ok(out)
}

/// `payment_dispute.read`: may read disputes.
#[derive(Debug)]
pub struct DisputeRead;

impl attome_server::authz::PrivilegeKey for DisputeRead {
    const KEY: &'static str = "payment_dispute.read";
}

#[utoipa::path(
    get,
    path = "/api/v1/billing/disputes/{id}/evidence",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The dispute")),
    responses(
        (status = 200, description = "The documents that can answer it (page 1 holds them all)", body = attome_types::PaginatedResponse<DocumentRef>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read disputes", body = attome_types::ErrorResponse),
        (status = 404, description = "No such dispute in the caller's scope", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_evidence(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<DisputeRead>>,
    axum::extract::Path(dispute): axum::extract::Path<Uuid>,
) -> Result<axum::Json<attome_types::PaginatedResponse<DocumentRef>>, AppError> {
    let items = dispute_evidence(&state, &ctx, dispute).await?;
    let total = items.len() as i64;
    Ok(axum::Json(attome_types::PaginatedResponse::new(
        items,
        total,
        1,
        total.max(1),
    )))
}

/// This module's routes, for the OpenAPI document.
#[derive(Debug, utoipa::OpenApi)]
#[openapi(paths(get_evidence), components(schemas(DocumentRef)))]
pub struct ApiDocFragment;
