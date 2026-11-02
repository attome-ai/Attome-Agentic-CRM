//! F5-T14, read part: what a portal user sees of their account's payments:
//! the issued invoices still open, and the saved payment methods.
//!
//! The portal routes (`attome-portal`, `GET /{keyword}/api/v1/billing/
//! invoices/open` and `GET /{keyword}/api/v1/billing/payment-methods`)
//! answer only while [`PORTAL_SETTING`] is on, and only for the portal
//! user's own account, from their contact. A saved method's `token` and
//! gateway are never read here, so they cannot reach the portal.
//!
//! Changes (V2-D1588 (1)) run as the portal's service user, the audit event
//! naming the portal user: [`pay_invoice`] makes a payment link for an open
//! invoice of the account (the customer pays on the hosted page, F5-T8), and
//! [`remove_method`] deletes one of the account's saved methods through the
//! record engine.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// The setting that opens the portal routes (off by default).
pub const PORTAL_SETTING: &str = "billing.portal.payments";
/// Rows answered per list.
const MAX_ROWS: i64 = 200;

/// An issued invoice with an amount still open.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalInvoice {
    pub id: Uuid,
    pub invoice_number: Option<String>,
    pub currency: Option<String>,
    /// As stored, decimals in text.
    pub grand_total: Option<String>,
    pub open_total: Option<String>,
    /// `open`, `partly_paid` or `overdue`.
    pub payment_status: Option<String>,
    pub issued_date: Option<String>,
    pub due_date: Option<String>,
}

/// A saved payment method, without its token.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalPaymentMethod {
    pub id: Uuid,
    pub brand: Option<String>,
    pub last4: Option<String>,
    pub expiry_month: Option<i32>,
    pub expiry_year: Option<i32>,
    pub is_default: Option<bool>,
}

/// Whether the portal routes are open.
pub fn portal_on(state: &EngineState) -> bool {
    let Some(descriptor) = attome_core::setting_registry().get(PORTAL_SETTING) else {
        return false;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_bool().unwrap_or(false)
}

/// `account`'s issued invoices with an amount open, oldest due first.
pub async fn open_invoices(
    state: &EngineState,
    account: Uuid,
) -> Result<Vec<PortalInvoice>, AppError> {
    sqlx::query_as(
        "SELECT id, invoice_number, currency, grand_total::text AS grand_total, \
                open_total::text AS open_total, payment_status::text AS payment_status, \
                issued_date::text AS issued_date, due_date::text AS due_date \
           FROM invoice \
          WHERE account_ref = $1 \
            AND COALESCE(status::text, 'draft') IN ('issued', 'sent', 'overdue') \
            AND COALESCE(payment_status::text, 'open') IN ('open', 'partly_paid', 'overdue') \
            AND open_total > 0 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY due_date NULLS LAST, id LIMIT $2",
    )
    .bind(account)
    .bind(MAX_ROWS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// `account`'s saved payment methods, the default first. The token column
/// is not selected.
pub async fn payment_methods(
    state: &EngineState,
    account: Uuid,
) -> Result<Vec<PortalPaymentMethod>, AppError> {
    sqlx::query_as(
        "SELECT id, brand, last4, expiry_month::int4 AS expiry_month, \
                expiry_year::int4 AS expiry_year, is_default \
           FROM saved_payment_method \
          WHERE account_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY is_default DESC NULLS LAST, created_at DESC, id LIMIT $2",
    )
    .bind(account)
    .bind(MAX_ROWS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// A payment link for `invoice` of `account` (an issued invoice with an
/// amount open), made as the portal's service user `ctx` for `behalf`.
pub async fn pay_invoice(
    state: &EngineState,
    ctx: &SecurityContext,
    behalf: &str,
    account: Uuid,
    invoice: Uuid,
) -> Result<super::link::LinkCreated, AppError> {
    let open = open_invoices(state, account).await?;
    if !open.iter().any(|i| i.id == invoice) {
        return Err(AppError::NotFound);
    }
    super::link::create_link_on_behalf(
        state,
        ctx,
        &super::link::LinkRequest {
            invoice_id: Some(invoice),
            ..Default::default()
        },
        Some(behalf),
    )
    .await
}

/// Deletes `method`, a saved payment method of `account`, as the portal's
/// service user `ctx` for `behalf`.
pub async fn remove_method(
    state: &EngineState,
    ctx: &SecurityContext,
    behalf: &str,
    account: Uuid,
    method: Uuid,
) -> Result<(), AppError> {
    let mine: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM saved_payment_method \
                         WHERE id = $1 AND account_ref = $2 \
                           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(method)
    .bind(account)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !mine {
        return Err(AppError::NotFound);
    }
    ctx.require("saved_payment_method", "delete")?;
    let mut origin = attome_records::entity_mutation::DeleteOrigin::new(
        attome_records::entity_mutation::DeleteKind::Portal,
    );
    origin.reason = Some(format!("on behalf of {behalf}"));
    attome_records::entity_crud::delete_record_for(
        state,
        ctx,
        ctx.user_id,
        "saved_payment_method",
        method,
        None,
        &origin,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_carries_no_token() {
        let method = PortalPaymentMethod {
            id: Uuid::nil(),
            brand: Some("visa".into()),
            last4: Some("4242".into()),
            expiry_month: Some(12),
            expiry_year: Some(2030),
            is_default: Some(true),
        };
        let json = serde_json::to_value(&method).unwrap();
        assert!(json.get("token").is_none());
        assert!(json.get("gateway_system_ref").is_none());
    }
}
