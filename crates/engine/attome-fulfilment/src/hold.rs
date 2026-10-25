//! F6-T6: holds that stop a fulfilment order from being released.
//!
//! [`evaluate_holds`] runs before a release and opens, at most once per kind
//! while one is open:
//!
//! - `credit` when the order's account fails F5's credit check
//!   (`attome_billing::payment::credit::credit_check`) for the order's
//!   grand total;
//! - `prepayment` when the order's payment terms ask for payment in advance
//!   (invoices do not link to orders yet, so a person clears it once paid);
//! - `address` when a goods order has no delivery address.
//!
//! Fraud checks and `manual` holds are opened by people through the generic
//! record path. [`release`] (`POST /api/v1/fulfilment/orders/{id}/release`)
//! refuses with 409 while any hold is open and otherwise marks the order
//! `released`; [`clear_hold`] (`POST /api/v1/fulfilment/holds/{id}/clear`)
//! needs `fulfilment_hold.release` and records who cleared it and why.

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

/// Payment terms that mean payment before shipping.
pub const PREPAID_TERMS: &[&str] = &[
    "prepaid",
    "prepayment",
    "advance",
    "cash_in_advance",
    "payment_in_advance",
];

/// Whether `terms` asks for payment in advance. Pure.
pub fn needs_prepayment(terms: Option<&str>) -> bool {
    terms.is_some_and(|t| {
        let t = t.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        PREPAID_TERMS.contains(&t.as_str())
    })
}

/// The holds an order should carry. Pure.
pub fn holds_for(
    credit_allowed: bool,
    payment_terms: Option<&str>,
    has_goods: bool,
    delivery_address: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut holds = Vec::new();
    if !credit_allowed {
        holds.push((
            "credit",
            "the customer's credit check refused this order".to_owned(),
        ));
    }
    if needs_prepayment(payment_terms) {
        holds.push((
            "prepayment",
            "the payment terms ask for payment before shipping".to_owned(),
        ));
    }
    if has_goods && delivery_address.is_none_or(|a| a.trim().is_empty()) {
        holds.push(("address", "the order has no delivery address".to_owned()));
    }
    holds
}

/// `fulfilment_order.update`: who releases an order.
#[derive(Debug)]
pub struct FulfilmentOrderUpdate;

impl PrivilegeKey for FulfilmentOrderUpdate {
    const KEY: &'static str = "fulfilment_order.update";
}

/// `fulfilment_hold.release`: who clears a hold.
#[derive(Debug)]
pub struct FulfilmentHoldRelease;

impl PrivilegeKey for FulfilmentHoldRelease {
    const KEY: &'static str = "fulfilment_hold.release";
}

/// Opens the holds `fulfilment_order` should carry and has not; returns
/// the kinds opened.
pub async fn evaluate_holds(
    state: &EngineState,
    fulfilment_order: Uuid,
    actor: Uuid,
) -> Result<Vec<&'static str>, AppError> {
    let db = &state.base.db;
    type Header = (
        Uuid,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let header: Option<Header> = sqlx::query_as(
        "SELECT o.id, o.account_ref, o.grand_total::text, o.payment_terms, o.delivery_address \
           FROM fulfilment_order f JOIN \"order\" o ON o.id = f.order_ref \
          WHERE f.id = $1 AND (f.is_active IS NULL OR f.is_active = true)",
    )
    .bind(fulfilment_order)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (_order, account, total, terms, address) = header.ok_or(AppError::NotFound)?;
    let has_goods: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM fulfilment_order_line \
                         WHERE fulfilment_order_ref = $1 AND line_kind::text = 'goods' \
                           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(fulfilment_order)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let credit_allowed = match account {
        Some(account) => {
            let extra = total
                .as_deref()
                .and_then(|t| Decimal::from_str(t).ok())
                .unwrap_or(Decimal::ZERO);
            attome_billing::payment::credit::credit_check(state, account, extra)
                .await
                .map(|c| c.allowed)
                .unwrap_or(true)
        }
        None => true,
    };
    let wanted = holds_for(
        credit_allowed,
        terms.as_deref(),
        has_goods,
        address.as_deref(),
    );
    let mut opened = Vec::new();
    let mut tx = attome_db::tx::begin(db).await?;
    for (kind, reason) in wanted {
        let id = Uuid::now_v7();
        let inserted = sqlx::query(
            "INSERT INTO fulfilment_hold (id, fulfilment_order_ref, kind, reason, created_by, owner_ref) \
             SELECT $1, $2, $3, $4, $5, $5 \
              WHERE NOT EXISTS (SELECT 1 FROM fulfilment_hold \
                                 WHERE fulfilment_order_ref = $2 AND kind::text = $3 \
                                   AND released_at IS NULL \
                                   AND (is_active IS NULL OR is_active = true))",
        )
        .bind(id)
        .bind(fulfilment_order)
        .bind(kind)
        .bind(&reason)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if inserted > 0 {
            change_feed::emit_tx(&mut tx, "fulfilment_hold", id, ChangeOperation::Create).await?;
            opened.push(kind);
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok(opened)
}

/// A release's outcome.
#[derive(Debug, Serialize, ToSchema)]
pub struct Released {
    pub fulfilment_order_id: Uuid,
    pub status: String,
}

/// Release a fulfilment order
///
/// F6-T6: opens the holds the order should carry, then refuses while any
/// hold is open; otherwise the order is `released` for picking.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/orders/{id}/release",
    operation_id = "fulfilment_order_release",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The fulfilment order")),
    responses(
        (status = 200, description = "Released", body = Released),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_order.update", body = ErrorResponse),
        (status = 404, description = "No such fulfilment order", body = ErrorResponse),
        (status = 409, description = "A hold is open, or the order is not a draft or on hold", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Activated)])))),
)]
pub(crate) async fn release(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FulfilmentOrderUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Released>, AppError> {
    let opened = evaluate_holds(&state, id, ctx.user_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let open: Vec<String> = sqlx::query_scalar(
        "SELECT kind::text FROM fulfilment_hold \
          WHERE fulfilment_order_ref = $1 AND released_at IS NULL \
            AND (is_active IS NULL OR is_active = true) ORDER BY kind",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !open.is_empty() {
        tracing::info!(%id, holds = ?open, newly = ?opened, "fulfilment order held");
        return Err(AppError::Conflict(
            "the fulfilment order has an open hold; clear it first",
        ));
    }
    let updated = sqlx::query(
        "UPDATE fulfilment_order SET status = 'released', modified_at = now(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND status::text IN ('draft', 'on_hold') \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::Conflict(
            "only a draft or held fulfilment order is released",
        ));
    }
    change_feed::emit_tx(&mut tx, "fulfilment_order", id, ChangeOperation::Update).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "fulfilment_order",
            id,
            AuditOperation::Activated,
            "fulfilment.released",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(Released {
        fulfilment_order_id: id,
        status: "released".into(),
    }))
}

/// Why a hold is cleared.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearHold {
    /// Why the hold no longer applies (1 to 500 characters).
    pub note: String,
}

/// Clear a fulfilment hold
///
/// F6-T6: marks the hold released, with who and why; the order can then be
/// released once no other hold is open.
#[utoipa::path(
    post,
    path = "/api/v1/fulfilment/holds/{id}/clear",
    operation_id = "fulfilment_hold_clear",
    tag = "fulfilment",
    params(("id" = Uuid, Path, description = "The hold")),
    request_body = ClearHold,
    responses(
        (status = 204, description = "Cleared"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks fulfilment_hold.release", body = ErrorResponse),
        (status = 404, description = "No such open hold", body = ErrorResponse),
        (status = 422, description = "An empty or too long note", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Approved)])))),
)]
pub(crate) async fn clear_hold(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<FulfilmentHoldRelease>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ClearHold>,
) -> Result<axum::http::StatusCode, AppError> {
    let note = body.note.trim();
    if note.is_empty() || note.chars().count() > 500 {
        return Err(AppError::Validation("note is 1 to 500 characters".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let cleared = sqlx::query(
        "UPDATE fulfilment_hold SET released_by = $2, released_at = now(), \
                reason = reason || E'\\n' || $3, modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND released_at IS NULL AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .bind(ctx.user_id)
    .bind(format!("cleared: {note}"))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if cleared == 0 {
        return Err(AppError::NotFound);
    }
    change_feed::emit_tx(&mut tx, "fulfilment_hold", id, ChangeOperation::Update).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(&state),
        BusinessEvent::new(
            "fulfilment_hold",
            id,
            AuditOperation::Approved,
            "fulfilment.hold_cleared",
            ctx.user_id,
        )
        .comment(note.to_owned()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/fulfilment/orders/{id}/release", post(release))
        .route("/api/v1/fulfilment/holds/{id}/clear", post(clear_hold))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(release, clear_hold))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_blocks_release_on_credit_prepayment_and_address() {
        let all = holds_for(false, Some("Cash in advance"), true, Some("  "));
        let kinds: Vec<&str> = all.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, ["credit", "prepayment", "address"]);
        assert!(holds_for(true, Some("net 30"), true, Some("Riyadh 12345")).is_empty());
        // A services-only order needs no address.
        assert!(holds_for(true, None, false, None).is_empty());
        assert!(needs_prepayment(Some("Pre-paid".replace('-', "").as_str())));
        assert!(!needs_prepayment(None));
    }
}
