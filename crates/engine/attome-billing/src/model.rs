//! `EngineModel` registration: mounted only when the `billing` module is on.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_BILLING, ModuleId};
use axum::{
    Router,
    routing::{get, post},
};

/// Registered in `attome::boot::register_engines`.
#[derive(Debug)]
pub struct BillingModel;

impl EngineModel for BillingModel {
    fn name(&self) -> &'static str {
        "attome-billing"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_BILLING
    }

    fn owned_entities(&self) -> &'static [&'static str] {
        &[]
    }

    fn routes(&self) -> Router<EngineState> {
        // F3-T7: metered usage ingest.
        Router::new()
            .route("/api/v1/billing/usage", post(crate::usage::post_usage))
            .route(
                "/api/v1/billing/metrics/recurring",
                get(crate::metrics::get_recurring),
            )
            // F4-T5: a draft invoice's lines and totals.
            .route(
                "/api/v1/billing/invoices/{id}/recompute",
                post(crate::invoice::post_recompute),
            )
            // F4-T6: issuing a draft.
            .route(
                "/api/v1/billing/invoices/{id}/issue",
                post(crate::issue::post_issue),
            )
            // F4-T7: corrections of an issued invoice.
            .route(
                "/api/v1/billing/invoices/{id}/credit-notes",
                post(crate::notes::post_credit_note),
            )
            .route(
                "/api/v1/billing/invoices/{id}/debit-notes",
                post(crate::notes::post_debit_note),
            )
            .route(
                "/api/v1/billing/invoices/{id}/cancel",
                post(crate::notes::post_cancel),
            )
            // F5-T3: manual payments, reversal and applying credit.
            .route(
                "/api/v1/billing/payments",
                post(crate::payment::service::post_payment),
            )
            .route(
                "/api/v1/billing/payments/{id}/reverse",
                post(crate::payment::service::post_reverse),
            )
            .route(
                "/api/v1/billing/accounts/{id}/apply-credit",
                post(crate::payment::service::post_apply_credit),
            )
            // AG2-T3: the invoice's e-invoice.
            .route(
                "/api/v1/billing/invoices/{id}/einvoice",
                get(crate::einvoice::get_einvoice),
            )
            // F4-T12: writing off a balance.
            .route(
                "/api/v1/billing/invoices/{id}/write-off",
                post(crate::writeoff::post_write_off),
            )
            // F4-T8: deposits and pro forma invoices.
            .route(
                "/api/v1/billing/invoices/{id}/apply-deposit",
                post(crate::deposit::post_apply_deposit),
            )
            .route(
                "/api/v1/billing/invoices/{id}/convert-pro-forma",
                post(crate::deposit::post_convert_pro_forma),
            )
            // F4-T9: invoices other features ask for.
            .route(
                "/api/v1/billing/invoice-requests",
                post(crate::requests::post_request),
            )
            // F4-T11: statements and ageing.
            .route(
                "/api/v1/billing/accounts/{id}/statement",
                get(crate::statements::get_statement),
            )
            .route("/api/v1/billing/ageing", get(crate::statements::get_ageing))
            .route(
                "/api/v1/billing/ageing/totals",
                get(crate::statements::get_ageing_totals),
            )
    }
}
