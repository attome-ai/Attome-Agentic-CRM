//! The payment gateway seam (roadmap F5-T4).
//!
//! Attome never processes card data: a payment runs through the customer's
//! own merchant account at a tokenising gateway. Each gateway is an
//! integration system of kind `payment_gateway` (its base URL, its
//! credential in the integration secret store) and an adapter implementing
//! [`PaymentGateway`]: Moyasar and HyperPay first (V2-D346; adapters in F5-T5
//! and F5-T6).
//!
//! - [`choose_gateway`] picks the integration system for a payment from the
//!   rules in the `billing.gateway.rules` setting: the first rule whose
//!   currency, country and amount range match wins.
//! - [`GatewayHttp`] is the one HTTP client adapters call through: the SSRF
//!   guard's client (no private or link-local targets, no redirects to
//!   them) with a 15-second timeout. Tests point it at a local fake.
//! - Credentials are resolved for each call ([`credential`]) and never kept
//!   in memory beyond it; nothing here logs a secret or a full token. No
//!   adapter call happens inside a database transaction.

pub mod hyperpay;
pub mod moyasar;
pub mod webhook;

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The setting holding the gateway rules (a JSON array of [`GatewayRule`]).
pub const RULES_SETTING: &str = "billing.gateway.rules";

/// How long one gateway call may take.
pub const GATEWAY_TIMEOUT_SECS: u64 = 15;

/// A payment method a gateway can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    Card,
    Mada,
    ApplePay,
    StcPay,
    Tabby,
    Tamara,
}

/// What a checkout is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckoutRequest {
    pub amount: Decimal,
    pub currency: String,
    /// What the payer sees, in their language.
    pub description: String,
    /// Where the gateway sends the payer back.
    pub return_url: String,
    /// Attome's reference, echoed in the gateway's events.
    pub reference: String,
    /// One per attempt, so a retried call never charges twice.
    pub idempotency_key: String,
    pub methods: Vec<Method>,
}

/// A checkout the payer completes: a hosted page they are sent to
/// (Moyasar), or a payment form Attome's pay page embeds (HyperPay's
/// COPYandPAY widget). Exactly one of the two is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkout {
    pub redirect_url: Option<String>,
    pub widget: Option<CheckoutWidget>,
    pub gateway_reference: String,
}

/// A gateway's payment form, embedded by the pay page: the script, its
/// subresource-integrity hash when the gateway gives one, and the brands
/// the form offers. The form posts back to the checkout's `return_url`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutWidget {
    pub script_url: String,
    pub integrity: Option<String>,
    pub brands: String,
}

/// Where a payment stands at the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayStatus {
    Pending,
    Succeeded {
        amount: Decimal,
        fee: Option<Decimal>,
    },
    Failed {
        reason: String,
    },
    Refunded {
        amount: Decimal,
    },
}

/// A settlement the gateway paid out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payout {
    pub payout_reference: String,
    pub day: NaiveDate,
    pub gross: Decimal,
    pub fees: Decimal,
    pub net: Decimal,
    pub currency: String,
    /// The gateway references of the payments it settles.
    pub payments: Vec<String>,
}

/// A saved card as Attome keeps it: the brand and last four digits only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedCard {
    pub brand: String,
    pub last4: String,
    /// Whether the gateway will charge the token.
    pub active: bool,
}

/// One event a gateway's webhook reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayEvent {
    /// The gateway's own event id (deduplicated on receipt).
    pub event_id: String,
    pub gateway_reference: String,
    pub status: GatewayStatus,
}

/// Why a gateway call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// The gateway refused the request (bad card, wrong amount): final.
    #[error("the gateway refused it: {0}")]
    Refused(String),
    /// A webhook whose signature does not verify.
    #[error("the webhook signature does not verify")]
    BadSignature,
    /// No answer, a timeout or a 5xx: try again later.
    #[error("the gateway could not be reached: {0}")]
    Unavailable(String),
}

impl From<GatewayError> for AppError {
    fn from(e: GatewayError) -> Self {
        match e {
            GatewayError::Refused(m) => AppError::Validation(m),
            GatewayError::BadSignature => AppError::Forbidden,
            GatewayError::Unavailable(_) => {
                AppError::CapabilityUnavailable("the payment gateway could not be reached")
            }
        }
    }
}

/// A boxed future, for the object-safe trait.
pub type GatewayFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, GatewayError>> + Send + 'a>>;

/// One payment gateway. Every method is a network call made outside any
/// transaction; `secret` is the system's credential, resolved for the call.
pub trait PaymentGateway: Send + Sync {
    /// The gateway's name (`moyasar`, `hyperpay`).
    fn name(&self) -> &'static str;
    fn supported_methods(&self) -> &'static [Method];
    fn create_checkout<'a>(
        &'a self,
        secret: &'a str,
        request: &'a CheckoutRequest,
    ) -> GatewayFuture<'a, Checkout>;
    fn get_status<'a>(
        &'a self,
        secret: &'a str,
        gateway_reference: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus>;
    fn charge_token<'a>(
        &'a self,
        secret: &'a str,
        token: &'a str,
        amount: Decimal,
        currency: &'a str,
        idempotency_key: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus>;
    fn refund<'a>(
        &'a self,
        secret: &'a str,
        gateway_reference: &'a str,
        amount: Decimal,
        idempotency_key: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus>;
    fn list_payouts<'a>(
        &'a self,
        secret: &'a str,
        day: NaiveDate,
    ) -> GatewayFuture<'a, Vec<Payout>>;
    /// The card behind a saved token: its brand and last four digits, and
    /// nothing else from the gateway's answer.
    fn saved_card<'a>(&'a self, secret: &'a str, token: &'a str) -> GatewayFuture<'a, SavedCard>;
    /// Verifies a webhook and reads its events; `webhook_secret` is the
    /// signing secret the gateway was configured with.
    fn verify_webhook(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        webhook_secret: &str,
    ) -> Result<Vec<GatewayEvent>, GatewayError>;
}

/// The HTTP client gateway adapters call through.
#[derive(Debug, Clone)]
pub struct GatewayHttp {
    /// The gateway's API base URL, from its integration system.
    pub base_url: String,
    client: HttpClient,
}

#[derive(Debug, Clone)]
enum HttpClient {
    Guarded(std::sync::Arc<attome_server::ssrf_guard::GuardedClient>),
    #[cfg(any(test, feature = "test-support"))]
    Plain(reqwest::Client),
}

impl GatewayHttp {
    /// The SSRF-guarded client for `base_url`.
    pub fn new(base_url: &str) -> Result<Self, AppError> {
        let client = attome_server::ssrf_guard::GuardedClient::new(GATEWAY_TIMEOUT_SECS)
            .map_err(AppError::internal)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client: HttpClient::Guarded(std::sync::Arc::new(client)),
        })
    }

    /// A plain client for a local fake gateway in tests (the guard refuses
    /// loopback addresses by design).
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            client: HttpClient::Plain(
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(GATEWAY_TIMEOUT_SECS))
                    .build()
                    .unwrap_or_default(),
            ),
        }
    }

    /// A request to `path` under the base URL.
    pub fn request(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> Result<reqwest::RequestBuilder, GatewayError> {
        let url = reqwest::Url::parse(&format!("{}{path}", self.base_url))
            .map_err(|e| GatewayError::Refused(format!("bad gateway URL: {e}")))?;
        match &self.client {
            HttpClient::Guarded(client) => client
                .request(method, url)
                .map_err(|e| GatewayError::Refused(format!("gateway URL refused: {e}"))),
            #[cfg(any(test, feature = "test-support"))]
            HttpClient::Plain(client) => Ok(client.request(method, url)),
        }
    }
}

/// The adapter for a gateway name, calling through `http`, when one is
/// built.
pub fn gateway_for(name: &str, http: GatewayHttp) -> Option<Box<dyn PaymentGateway>> {
    match name {
        "moyasar" => Some(Box::new(moyasar::MoyasarGateway::new(http))),
        "hyperpay" => Some(Box::new(hyperpay::HyperPayGateway::new(http))),
        _ => None,
    }
}

/// One rule choosing a gateway; empty conditions match anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRule {
    /// The `payment_gateway` integration system to use.
    pub system_id: Uuid,
    pub currency: Option<String>,
    /// ISO 3166-1 alpha-2 of the payer.
    pub country: Option<String>,
    pub min: Option<Decimal>,
    pub max: Option<Decimal>,
}

/// The first rule matching the payment, or none.
pub fn choose_gateway(
    rules: &[GatewayRule],
    currency: &str,
    country: &str,
    amount: Decimal,
) -> Option<Uuid> {
    rules
        .iter()
        .find(|r| {
            r.currency
                .as_deref()
                .is_none_or(|c| c.eq_ignore_ascii_case(currency))
                && r.country
                    .as_deref()
                    .is_none_or(|c| c.eq_ignore_ascii_case(country))
                && r.min.is_none_or(|m| amount >= m)
                && r.max.is_none_or(|m| amount <= m)
        })
        .map(|r| r.system_id)
}

/// The rules from the `billing.gateway.rules` setting (empty when unset or
/// unreadable, with a warning).
pub fn rules(state: &EngineState) -> Vec<GatewayRule> {
    let Some(descriptor) = attome_core::setting_registry().get(RULES_SETTING) else {
        return Vec::new();
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    match serde_json::from_value::<Vec<GatewayRule>>(value) {
        Ok(rules) => rules,
        Err(e) => {
            tracing::warn!(error = %e, "billing: the gateway rules do not read; no gateway is chosen");
            Vec::new()
        }
    }
}

/// A gateway system's name, adapter, base URL and credential reference.
#[derive(Debug, Clone)]
pub struct GatewaySystem {
    pub id: Uuid,
    pub name: String,
    /// The adapter ([`gateway_for`]): the system's `config.gateway`, or its
    /// name in lower case.
    pub adapter: String,
    pub base_url: String,
    /// The user the system acts as, for attribution.
    pub service_principal: Option<Uuid>,
    credential_ref: Option<String>,
}

type SystemRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Reads an active `payment_gateway` integration system.
pub async fn system(state: &EngineState, id: Uuid) -> Result<GatewaySystem, AppError> {
    let row: Option<SystemRow> = sqlx::query_as(
        "SELECT name, base_url, credential_ref, config::text, service_principal_ref::text          FROM integration_system          WHERE id = $1 AND kind = 'payment_gateway' AND COALESCE(status, 'active') = 'active'            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (name, base_url, credential_ref, config, principal) = row.ok_or(AppError::NotFound)?;
    let adapter = config
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|c| c.get("gateway").and_then(|g| g.as_str()).map(str::to_owned))
        .unwrap_or_else(|| name.trim().to_ascii_lowercase());
    Ok(GatewaySystem {
        id,
        name,
        adapter,
        base_url: base_url.unwrap_or_default(),
        service_principal: principal.and_then(|p| Uuid::parse_str(p.trim()).ok()),
        credential_ref,
    })
}

/// The system's secret, resolved for one call. Never cache it.
///
/// A gateway's credential is the secret its adapter reads (Moyasar's secret
/// key, or HyperPay's JSON); when it is a JSON object, its `webhook_secret`
/// is the secret webhooks are verified with ([`webhook_secret`]).
pub async fn credential(
    state: &EngineState,
    system: &GatewaySystem,
) -> Result<zeroize::Zeroizing<String>, AppError> {
    // The same live key ring the integration admin stores credentials with.
    let ring = state.base.secrets.load().integration_credential_key.clone();
    let secret = attome_integration::credential::resolve(
        &state.base.db,
        &ring,
        system.credential_ref.as_deref(),
    )
    .await?
    .ok_or_else(|| {
        AppError::Validation(format!("the gateway {} has no credential", system.name))
    })?;
    Ok(zeroize::Zeroizing::new(secret))
}

/// The webhook secret in a gateway credential (its JSON `webhook_secret`).
pub fn webhook_secret(credential: &str) -> Option<zeroize::Zeroizing<String>> {
    let value: serde_json::Value = serde_json::from_str(credential).ok()?;
    value
        .get("webhook_secret")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| zeroize::Zeroizing::new(s.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        currency: Option<&str>,
        country: Option<&str>,
        min: Option<i64>,
        max: Option<i64>,
    ) -> GatewayRule {
        GatewayRule {
            system_id: Uuid::now_v7(),
            currency: currency.map(str::to_owned),
            country: country.map(str::to_owned),
            min: min.map(Decimal::from),
            max: max.map(Decimal::from),
        }
    }

    #[test]
    fn gateway_rule_by_currency() {
        let sar = rule(Some("SAR"), None, None, None);
        let big_aed = rule(Some("AED"), None, Some(1000), None);
        let anything = rule(None, None, None, None);
        let rules = vec![sar.clone(), big_aed.clone(), anything.clone()];
        assert_eq!(
            choose_gateway(&rules, "sar", "SA", Decimal::from(5)),
            Some(sar.system_id)
        );
        assert_eq!(
            choose_gateway(&rules, "AED", "AE", Decimal::from(5000)),
            Some(big_aed.system_id)
        );
        assert_eq!(
            choose_gateway(&rules, "AED", "AE", Decimal::from(50)),
            Some(anything.system_id)
        );
    }

    #[test]
    fn gateway_rule_none_matches() {
        let rules = vec![
            rule(Some("SAR"), Some("SA"), None, Some(10_000)),
            rule(Some("KWD"), None, None, None),
        ];
        assert_eq!(choose_gateway(&rules, "SAR", "AE", Decimal::from(5)), None);
        assert_eq!(
            choose_gateway(&rules, "SAR", "SA", Decimal::from(20_000)),
            None
        );
        assert_eq!(choose_gateway(&[], "SAR", "SA", Decimal::ONE), None);
    }
}
