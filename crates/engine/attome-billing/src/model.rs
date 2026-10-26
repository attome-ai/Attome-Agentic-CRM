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

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for BillingModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

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
            // F3-T8: billing runs.
            .route(
                "/api/v1/billing/runs/preview",
                post(crate::billing_run::post_preview),
            )
            .route("/api/v1/billing/runs", post(crate::billing_run::post_run))
            // F3-T6: the subscription service.
            .route(
                "/api/v1/billing/subscriptions",
                post(crate::subscription::routes::post_subscription),
            )
            .route(
                "/api/v1/billing/subscriptions/{id}",
                get(crate::subscription::routes::get_subscription),
            )
            .route(
                "/api/v1/billing/subscriptions/{id}/amendments",
                post(crate::subscription::routes::post_amendment),
            )
            .route(
                "/api/v1/billing/subscriptions/{id}/amendments/{amendment_id}/reverse",
                post(crate::subscription::routes::post_reverse_amendment),
            )
            .route(
                "/api/v1/billing/subscriptions/{id}/cancel",
                post(crate::subscription::routes::post_cancel),
            )
            .route(
                "/api/v1/billing/subscriptions/{id}/pause",
                post(crate::subscription::routes::post_pause),
            )
            .route(
                "/api/v1/billing/subscriptions/{id}/resume",
                post(crate::subscription::routes::post_resume),
            )
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
            // F5-T7: a payment gateway's webhook (bypass-listed; the
            // adapter verifies it).
            .route(
                "/api/v1/billing/gateways/{system}/webhook",
                post(crate::gateway::webhook::post_webhook),
            )
            // F5-T8: payment links, and the payment page's two public calls
            // (bypass-listed; the link's secret is the credential).
            .route(
                "/api/v1/billing/payment-links",
                post(crate::payment::link::post_link),
            )
            .route("/api/v1/pay/{token}", get(crate::payment::link::get_pay))
            .route(
                "/api/v1/pay/{token}/checkout",
                post(crate::payment::link::post_checkout),
            )
            // F5-T10: refunds, and the evidence a dispute can draw on.
            .route(
                "/api/v1/billing/payments/{id}/refunds",
                post(crate::payment::refund::post_refund),
            )
            .route(
                "/api/v1/billing/disputes/{id}/evidence",
                get(crate::payment::dispute::get_evidence),
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
            // F5-T12: an account's credit limit, open balance and hold.
            .route(
                "/api/v1/billing/accounts/{id}/credit",
                get(crate::payment::credit::get_credit),
            )
    }
}
