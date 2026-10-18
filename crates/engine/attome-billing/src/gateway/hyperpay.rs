//! The HyperPay adapter (roadmap F5-T6).
//!
//! HyperPay runs on the OPPWA platform (`https://eu-prod.oppwa.com`, test
//! `https://eu-test.oppwa.com`): a bearer access token, form-encoded
//! requests, amounts as decimal strings with two places, and a result code
//! on every answer.
//!
//! - **The credential** is a JSON object: `access_token`, and `entity_ids`
//!   by method (`card`, `mada`, `apple_pay`, `stc_pay`, `tabby`, `tamara`,
//!   and optionally `recurring` for token charges). HyperPay takes mada on
//!   its own entity, so one checkout's methods must share one entity.
//! - **The gateway reference** is the `merchantTransactionId` Attome sends,
//!   derived from the idempotency key ([`merchant_transaction_id`]). Every
//!   transaction for the order (the debit, its refunds) carries it, so
//!   status, refunds, webhooks and settlement records all find the payment
//!   by it through HyperPay's transaction query.
//! - **Checkout** is a COPYandPAY checkout (`POST /v1/checkouts`): a form
//!   the pay page embeds ([`super::CheckoutWidget`], with its
//!   subresource-integrity hash). A key whose order is already paid is
//!   refused rather than offered a second checkout.
//! - **Token charge** is `POST /v1/registrations/{token}/payments` as a
//!   merchant-initiated unscheduled payment; a retry with the same key finds
//!   the earlier transaction by query and never charges twice.
//! - **Refund** is `RF` on the debit, tagged with the refund's own key in a
//!   custom parameter; a retry finds that refund and never refunds twice.
//! - **Payouts** come from the settlement reports (summary, then each
//!   aggregation's records).
//! - **Webhooks** are AES-256-GCM encrypted with the webhook's hex key; the
//!   IV and tag travel in the `X-Initialization-Vector` and
//!   `X-Authentication-Tag` headers. A body that does not decrypt and
//!   authenticate is refused.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Checkout, CheckoutRequest, CheckoutWidget, GatewayError, GatewayEvent, GatewayFuture,
    GatewayHttp, GatewayStatus, Method, PaymentGateway, Payout, SavedCard,
};

/// HyperPay's methods.
const METHODS: &[Method] = &[
    Method::Card,
    Method::Mada,
    Method::ApplePay,
    Method::StcPay,
    Method::Tabby,
    Method::Tamara,
];

/// The custom parameter carrying a refund's idempotency key.
const REFUND_KEY: &str = "ATTOME_refund_key";

/// The UUID namespace merchant transaction ids are derived in.
const MTX_NAMESPACE: Uuid = Uuid::from_u128(0x0192_6d1e_7c4b_7a39_9a51_6f2b_8c3d_4e60);

/// The most settlement-record pages one aggregation reads (100 a page).
const MAX_PAGES: u32 = 50;

/// The HyperPay gateway. It holds no credential: it comes with each call.
#[derive(Debug, Clone)]
pub struct HyperPayGateway {
    http: GatewayHttp,
}

/// The credential, parsed for one call.
struct Credential {
    access_token: Zeroizing<String>,
    entity_ids: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawCredential {
    access_token: String,
    #[serde(default)]
    entity_ids: std::collections::BTreeMap<String, String>,
}

impl Credential {
    fn parse(secret: &str) -> Result<Self, GatewayError> {
        let raw: RawCredential = serde_json::from_str(secret).map_err(|_| {
            GatewayError::Refused(
                "the HyperPay credential must be JSON with access_token and entity_ids".into(),
            )
        })?;
        Ok(Self {
            access_token: Zeroizing::new(raw.access_token),
            entity_ids: raw.entity_ids,
        })
    }

    /// The entity for a method; mada never falls back to the card entity.
    fn entity(&self, method: Method) -> Result<&str, GatewayError> {
        let key = method_key(method);
        self.entity_ids
            .get(key)
            .or_else(|| {
                matches!(method, Method::Card | Method::ApplePay)
                    .then(|| self.entity_ids.get("card"))
                    .flatten()
            })
            .map(String::as_str)
            .ok_or_else(|| GatewayError::Refused(format!("no HyperPay entity for {key}")))
    }

    /// The entity token charges use.
    fn recurring_entity(&self) -> Result<&str, GatewayError> {
        self.entity_ids
            .get("recurring")
            .or_else(|| self.entity_ids.get("card"))
            .map(String::as_str)
            .ok_or_else(|| GatewayError::Refused("no HyperPay entity for token charges".into()))
    }

    /// Every configured entity, once each.
    fn entities(&self) -> Vec<&str> {
        let mut all: Vec<&str> = self.entity_ids.values().map(String::as_str).collect();
        all.sort_unstable();
        all.dedup();
        all
    }
}

fn method_key(method: Method) -> &'static str {
    match method {
        Method::Card => "card",
        Method::Mada => "mada",
        Method::ApplePay => "apple_pay",
        Method::StcPay => "stc_pay",
        Method::Tabby => "tabby",
        Method::Tamara => "tamara",
    }
}

fn brands(method: Method) -> &'static str {
    match method {
        Method::Card => "VISA MASTER",
        Method::Mada => "MADA",
        Method::ApplePay => "APPLEPAY",
        Method::StcPay => "STC_PAY",
        Method::Tabby => "TABBY",
        Method::Tamara => "TAMARA",
    }
}

/// HyperPay's merchant transaction id for an idempotency key: the key when
/// it fits HyperPay's 8 to 255 safe characters, otherwise a UUID derived
/// from it.
pub fn merchant_transaction_id(idempotency_key: &str) -> String {
    let fits = (8..=255).contains(&idempotency_key.len())
        && idempotency_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'));
    if fits {
        idempotency_key.to_owned()
    } else {
        Uuid::new_v5(&MTX_NAMESPACE, idempotency_key.as_bytes()).to_string()
    }
}

/// How a result code reads (HyperPay's documented code groups).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Success,
    Pending,
    Failed,
}

fn outcome(code: &str) -> Outcome {
    let starts = |p: &str| code.starts_with(p);
    // ^(000\.000\.|000\.100\.1|000\.[36])
    if starts("000.000.") || starts("000.100.1") || starts("000.3") || starts("000.6") {
        Outcome::Success
    // ^(000\.200) and the documented waiting codes ^(800\.400\.5|100\.400\.500)
    } else if starts("000.200") || starts("800.400.5") || starts("100.400.500") {
        Outcome::Pending
    } else {
        Outcome::Failed
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ResultCode {
    #[serde(default)]
    code: String,
    #[serde(default)]
    description: String,
}

/// One transaction as HyperPay reports it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    #[serde(default)]
    id: String,
    #[serde(default)]
    payment_type: String,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    result: ResultCode,
    #[serde(default)]
    merchant_transaction_id: Option<String>,
    #[serde(default)]
    custom_parameters: Option<serde_json::Map<String, Value>>,
}

impl Transaction {
    fn amount(&self) -> Decimal {
        self.amount
            .as_deref()
            .and_then(|a| a.parse().ok())
            .unwrap_or_default()
    }

    fn outcome(&self) -> Outcome {
        outcome(&self.result.code)
    }

    /// A debit that took money (`DB`, or a capture `CP`).
    fn is_debit(&self) -> bool {
        matches!(self.payment_type.as_str(), "DB" | "CP")
    }

    fn is_refund(&self) -> bool {
        self.payment_type == "RF"
    }

    fn refund_key(&self) -> Option<&str> {
        self.custom_parameters
            .as_ref()
            .and_then(|c| c.get(REFUND_KEY))
            .and_then(Value::as_str)
    }
}

/// Where an order stands from its transactions.
fn order_status(transactions: &[Transaction]) -> GatewayStatus {
    let succeeded = |t: &&Transaction| t.outcome() == Outcome::Success;
    let refunded: Decimal = transactions
        .iter()
        .filter(|t| t.is_refund())
        .filter(succeeded)
        .map(Transaction::amount)
        .sum();
    if refunded > Decimal::ZERO {
        return GatewayStatus::Refunded { amount: refunded };
    }
    let paid: Decimal = transactions
        .iter()
        .filter(|t| t.is_debit())
        .filter(succeeded)
        .map(Transaction::amount)
        .sum();
    if paid > Decimal::ZERO {
        // HyperPay reports no fee per payment; settlement reports carry it.
        return GatewayStatus::Succeeded {
            amount: paid,
            fee: None,
        };
    }
    if transactions
        .iter()
        .any(|t| !t.is_refund() && t.outcome() == Outcome::Pending)
    {
        return GatewayStatus::Pending;
    }
    match transactions
        .iter()
        .rev()
        .find(|t| t.is_debit() || t.payment_type == "PA")
    {
        Some(failed) if failed.outcome() == Outcome::Failed => GatewayStatus::Failed {
            reason: reason(&failed.result),
        },
        // No attempt yet (an open checkout), or an authorisation not captured.
        _ => GatewayStatus::Pending,
    }
}

fn reason(result: &ResultCode) -> String {
    let text = if result.description.trim().is_empty() {
        format!("HyperPay result {}", result.code)
    } else {
        format!("{} ({})", result.description, result.code)
    };
    text.chars().take(200).collect()
}

/// A single transaction's status (a charge's answer).
fn transaction_status(t: &Transaction) -> GatewayStatus {
    match t.outcome() {
        Outcome::Success if t.is_refund() => GatewayStatus::Refunded { amount: t.amount() },
        Outcome::Success if t.is_debit() => GatewayStatus::Succeeded {
            amount: t.amount(),
            fee: None,
        },
        Outcome::Success | Outcome::Pending => GatewayStatus::Pending,
        Outcome::Failed => GatewayStatus::Failed {
            reason: reason(&t.result),
        },
    }
}

/// An amount as HyperPay takes it: two decimal places, positive.
fn amount_text(amount: Decimal) -> Result<String, GatewayError> {
    if amount <= Decimal::ZERO || amount.round_dp(2) != amount {
        return Err(GatewayError::Refused(format!(
            "{amount} is not a payable HyperPay amount (two decimal places)"
        )));
    }
    Ok(format!("{amount:.2}"))
}

/// A reference as one URL path segment; anything else is refused.
fn segment(id: &str) -> Result<&str, GatewayError> {
    if !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Ok(id)
    } else {
        Err(GatewayError::Refused("not a HyperPay reference".into()))
    }
}

impl HyperPayGateway {
    pub fn new(http: GatewayHttp) -> Self {
        Self { http }
    }

    /// One call: the bearer token, a JSON answer. A transport failure, a 429
    /// or a 5xx is `Unavailable`; a rejected token is a refusal; any other
    /// answer is returned for the caller to read (HyperPay answers a
    /// declined payment with a 400 and its result code).
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        credential: &Credential,
    ) -> Result<(reqwest::StatusCode, Value), GatewayError> {
        let response = request
            .bearer_auth(credential.access_token.as_str())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| GatewayError::Unavailable(e.without_url().to_string()))?;
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(GatewayError::Unavailable(format!(
                "HyperPay answered {status}"
            )));
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(GatewayError::Refused(
                "HyperPay refused the gateway's credential".into(),
            ));
        }
        let text = response
            .text()
            .await
            .map_err(|e| GatewayError::Unavailable(e.without_url().to_string()))?;
        let value = serde_json::from_str(&text).map_err(|_| {
            GatewayError::Unavailable(format!(
                "HyperPay answered {status} with a body that is not JSON"
            ))
        })?;
        Ok((status, value))
    }

    /// Every transaction carrying `merchant_transaction_id`, on any of the
    /// credential's entities.
    async fn transactions(
        &self,
        credential: &Credential,
        merchant_transaction_id: &str,
    ) -> Result<Vec<(String, Transaction)>, GatewayError> {
        let mut found = Vec::new();
        for entity in credential.entities() {
            let request = self.http.request(
                reqwest::Method::GET,
                &with_query(
                    "/v1/query",
                    &[
                        ("entityId", entity),
                        ("merchantTransactionId", merchant_transaction_id),
                    ],
                ),
            )?;
            let (_, value) = self.send(request, credential).await?;
            // "No transactions found" is an answer with no payments.
            let payments: Vec<Transaction> = value
                .get("payments")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| {
                    GatewayError::Unavailable(format!("HyperPay's query does not read: {e}"))
                })?
                .unwrap_or_default();
            found.extend(
                payments
                    .into_iter()
                    .filter(|t| {
                        t.merchant_transaction_id.as_deref() == Some(merchant_transaction_id)
                    })
                    .map(|t| (entity.to_owned(), t)),
            );
        }
        Ok(found)
    }

    /// A transaction answer (charge, refund), read whatever its HTTP status.
    fn transaction_of(
        status: reqwest::StatusCode,
        value: Value,
    ) -> Result<Transaction, GatewayError> {
        let transaction: Transaction = serde_json::from_value(value).map_err(|e| {
            GatewayError::Unavailable(format!("HyperPay's answer does not read: {e}"))
        })?;
        if transaction.result.code.is_empty() {
            return Err(GatewayError::Refused(format!(
                "HyperPay answered {status} with no result"
            )));
        }
        Ok(transaction)
    }

    async fn aggregation_records(
        &self,
        credential: &Credential,
        entity: &str,
        aggregation: &str,
    ) -> Result<Vec<SettlementRecord>, GatewayError> {
        let mut records = Vec::new();
        for page in 1..=MAX_PAGES {
            let page_text = page.to_string();
            let request = self.http.request(
                reqwest::Method::GET,
                &with_query(
                    &format!(
                        "/reports/v2/reconciliations/aggregations/{}",
                        segment(aggregation)?
                    ),
                    &[("entityId", entity), ("pageNo", page_text.as_str())],
                ),
            )?;
            let (status, value) = self.send(request, credential).await?;
            if !status.is_success() {
                return Err(refusal(status, &value));
            }
            let detail: AggregationDetail = serde_json::from_value(value).map_err(|e| {
                GatewayError::Unavailable(format!("HyperPay's settlement does not read: {e}"))
            })?;
            records.extend(detail.records);
            if page >= detail.pages.unwrap_or(1) {
                return Ok(records);
            }
        }
        Err(GatewayError::Unavailable(format!(
            "settlement {aggregation} has more than {MAX_PAGES} pages"
        )))
    }
}

/// `path` with its query string, each pair URL-encoded.
fn with_query(path: &str, pairs: &[(&str, &str)]) -> String {
    let query: String = reqwest::Url::parse("http://query.invalid/")
        .map(|mut url| {
            url.query_pairs_mut().extend_pairs(pairs);
            url.query().unwrap_or_default().to_owned()
        })
        .unwrap_or_default();
    format!("{path}?{query}")
}

fn refusal(status: reqwest::StatusCode, value: &Value) -> GatewayError {
    let result: ResultCode = value
        .get("result")
        .cloned()
        .and_then(|r| serde_json::from_value(r).ok())
        .unwrap_or_default();
    GatewayError::Refused(format!("HyperPay answered {status}: {}", reason(&result)))
}

#[derive(Debug, Deserialize)]
struct Aggregation {
    id: String,
}

#[derive(Debug, Deserialize)]
struct AggregationList {
    #[serde(default)]
    aggregations: Vec<Aggregation>,
}

#[derive(Debug, Deserialize)]
struct AggregationDetail {
    #[serde(default)]
    records: Vec<SettlementRecord>,
    #[serde(default)]
    pages: Option<u32>,
}

/// One settlement record (HyperPay's reconciliation response parameters).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettlementRecord {
    #[serde(default)]
    record_type: String,
    #[serde(default)]
    transaction_type: String,
    #[serde(default)]
    merchant_transaction_id: Option<String>,
    settlement: Settlement,
}

#[derive(Debug, Deserialize)]
struct Settlement {
    amount: String,
    currency: String,
    #[serde(default)]
    fee: Option<String>,
    /// `POS` money in, `NEG` money out.
    #[serde(default)]
    cashflow: Option<String>,
}

impl Settlement {
    fn signed_amount(&self) -> Decimal {
        let amount: Decimal = self.amount.parse().unwrap_or_default();
        if self.cashflow.as_deref() == Some("NEG") {
            -amount
        } else {
            amount
        }
    }
}

/// One aggregation's records as a payout.
fn payout_of(reference: &str, day: NaiveDate, records: &[SettlementRecord]) -> Option<Payout> {
    let currency = records.first()?.settlement.currency.clone();
    let net: Decimal = records.iter().map(|r| r.settlement.signed_amount()).sum();
    let fees: Decimal = records
        .iter()
        .map(|r| {
            let fee: Decimal = r
                .settlement
                .fee
                .as_deref()
                .and_then(|f| f.parse().ok())
                .unwrap_or_default();
            // A FEE record is itself a charge by HyperPay.
            if r.record_type == "FEE" {
                fee + r.settlement.signed_amount().abs()
            } else {
                fee
            }
        })
        .sum();
    Some(Payout {
        payout_reference: reference.to_owned(),
        day,
        gross: net + fees,
        fees,
        net,
        currency,
        payments: records
            .iter()
            .filter(|r| r.record_type == "SETTLED" && r.transaction_type == "DEBIT")
            .filter_map(|r| r.merchant_transaction_id.clone())
            .collect(),
    })
}

impl PaymentGateway for HyperPayGateway {
    fn name(&self) -> &'static str {
        "hyperpay"
    }

    fn supported_methods(&self) -> &'static [Method] {
        METHODS
    }

    fn create_checkout<'a>(
        &'a self,
        secret: &'a str,
        request: &'a CheckoutRequest,
    ) -> GatewayFuture<'a, Checkout> {
        Box::pin(async move {
            let credential = Credential::parse(secret)?;
            let first = *request
                .methods
                .first()
                .ok_or_else(|| GatewayError::Refused("a checkout needs a method".into()))?;
            let entity = credential.entity(first)?;
            for method in &request.methods {
                if credential.entity(*method)? != entity {
                    return Err(GatewayError::Refused(format!(
                        "HyperPay takes {} on its own checkout",
                        method_key(*method)
                    )));
                }
            }
            let amount = amount_text(request.amount)?;
            let reference = merchant_transaction_id(&request.idempotency_key);
            // A paid order is not offered a second checkout.
            let earlier = self.transactions(&credential, &reference).await?;
            let earlier: Vec<Transaction> = earlier.into_iter().map(|(_, t)| t).collect();
            if matches!(
                order_status(&earlier),
                GatewayStatus::Succeeded { .. } | GatewayStatus::Refunded { .. }
            ) {
                return Err(GatewayError::Refused("this payment is already made".into()));
            }
            let currency = request.currency.to_ascii_uppercase();
            let form = [
                ("entityId", entity),
                ("amount", amount.as_str()),
                ("currency", currency.as_str()),
                ("paymentType", "DB"),
                ("merchantTransactionId", reference.as_str()),
                ("integrity", "true"),
            ];
            let http = self
                .http
                .request(reqwest::Method::POST, "/v1/checkouts")?
                .form(&form);
            let (status, value) = self.send(http, &credential).await?;
            let result: ResultCode = value
                .get("result")
                .cloned()
                .and_then(|r| serde_json::from_value(r).ok())
                .unwrap_or_default();
            let id = value.get("id").and_then(Value::as_str).unwrap_or_default();
            if !status.is_success() || outcome(&result.code) == Outcome::Failed || id.is_empty() {
                return Err(refusal(status, &value));
            }
            let mut brand_list: Vec<&str> = request.methods.iter().map(|m| brands(*m)).collect();
            brand_list.dedup();
            Ok(Checkout {
                redirect_url: None,
                widget: Some(CheckoutWidget {
                    script_url: format!(
                        "{}{}",
                        self.http.base_url,
                        with_query("/v1/paymentWidgets.js", &[("checkoutId", id)])
                    ),
                    integrity: value
                        .get("integrity")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    brands: brand_list.join(" "),
                }),
                gateway_reference: reference,
            })
        })
    }

    fn get_status<'a>(
        &'a self,
        secret: &'a str,
        gateway_reference: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async move {
            let credential = Credential::parse(secret)?;
            let found = self.transactions(&credential, gateway_reference).await?;
            let found: Vec<Transaction> = found.into_iter().map(|(_, t)| t).collect();
            Ok(order_status(&found))
        })
    }

    fn charge_token<'a>(
        &'a self,
        secret: &'a str,
        token: &'a str,
        amount: Decimal,
        currency: &'a str,
        idempotency_key: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async move {
            let credential = Credential::parse(secret)?;
            let amount = amount_text(amount)?;
            let reference = merchant_transaction_id(idempotency_key);
            // An earlier attempt with this key that reached HyperPay is the
            // answer: never a second charge.
            let earlier = self.transactions(&credential, &reference).await?;
            if let Some((_, t)) = earlier
                .iter()
                .find(|(_, t)| t.is_debit() && t.outcome() != Outcome::Failed)
            {
                return Ok(transaction_status(t));
            }
            let entity = credential.recurring_entity()?;
            let currency = currency.to_ascii_uppercase();
            let form = [
                ("entityId", entity),
                ("amount", amount.as_str()),
                ("currency", currency.as_str()),
                ("paymentType", "DB"),
                ("merchantTransactionId", reference.as_str()),
                ("standingInstruction.mode", "REPEATED"),
                ("standingInstruction.type", "UNSCHEDULED"),
                ("standingInstruction.source", "MIT"),
            ];
            let http = self
                .http
                .request(
                    reqwest::Method::POST,
                    &format!("/v1/registrations/{}/payments", segment(token)?),
                )?
                .form(&form);
            let (status, value) = self.send(http, &credential).await?;
            Ok(transaction_status(&Self::transaction_of(status, value)?))
        })
    }

    fn refund<'a>(
        &'a self,
        secret: &'a str,
        gateway_reference: &'a str,
        amount: Decimal,
        idempotency_key: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async move {
            let credential = Credential::parse(secret)?;
            let amount_text = amount_text(amount)?;
            let found = self.transactions(&credential, gateway_reference).await?;
            // This refund, made by an earlier attempt: never refund twice.
            if let Some((_, done)) = found.iter().find(|(_, t)| {
                t.is_refund()
                    && t.refund_key() == Some(idempotency_key)
                    && t.outcome() != Outcome::Failed
            }) {
                return Ok(transaction_status(done));
            }
            let (entity, debit) = found
                .iter()
                .find(|(_, t)| t.is_debit() && t.outcome() == Outcome::Success)
                .ok_or_else(|| {
                    GatewayError::Refused("no paid HyperPay payment to refund".into())
                })?;
            let refunded: Decimal = found
                .iter()
                .filter(|(_, t)| t.is_refund() && t.outcome() == Outcome::Success)
                .map(|(_, t)| t.amount())
                .sum();
            if refunded + amount > debit.amount() {
                return Err(GatewayError::Refused(
                    "the refund is more than is left of the payment".into(),
                ));
            }
            let currency = debit.currency.clone().unwrap_or_default();
            let key_param = format!("customParameters[{REFUND_KEY}]");
            let form = [
                ("entityId", entity.as_str()),
                ("amount", amount_text.as_str()),
                ("currency", currency.as_str()),
                ("paymentType", "RF"),
                ("merchantTransactionId", gateway_reference),
                (key_param.as_str(), idempotency_key),
            ];
            let http = self
                .http
                .request(
                    reqwest::Method::POST,
                    &format!("/v1/payments/{}", segment(&debit.id)?),
                )?
                .form(&form);
            let (status, value) = self.send(http, &credential).await?;
            Ok(transaction_status(&Self::transaction_of(status, value)?))
        })
    }

    fn list_payouts<'a>(
        &'a self,
        secret: &'a str,
        day: NaiveDate,
    ) -> GatewayFuture<'a, Vec<Payout>> {
        Box::pin(async move {
            let credential = Credential::parse(secret)?;
            let date = day.format("%Y-%m-%d").to_string();
            let mut payouts = Vec::new();
            for entity in credential.entities() {
                let request = self.http.request(
                    reqwest::Method::GET,
                    &with_query(
                        "/reports/v1/reconciliations/aggregations",
                        &[
                            ("entityId", entity),
                            ("date.from", date.as_str()),
                            ("date.to", date.as_str()),
                        ],
                    ),
                )?;
                let (status, value) = self.send(request, &credential).await?;
                if !status.is_success() {
                    return Err(refusal(status, &value));
                }
                let list: AggregationList = serde_json::from_value(value).map_err(|e| {
                    GatewayError::Unavailable(format!("HyperPay's settlements do not read: {e}"))
                })?;
                for aggregation in list.aggregations {
                    let records = self
                        .aggregation_records(&credential, entity, &aggregation.id)
                        .await?;
                    payouts.extend(payout_of(&aggregation.id, day, &records));
                }
            }
            Ok(payouts)
        })
    }

    fn saved_card<'a>(&'a self, _secret: &'a str, _token: &'a str) -> GatewayFuture<'a, SavedCard> {
        Box::pin(async move {
            // HyperPay reports a registration's card in the checkout result
            // and the REGISTRATION webhook, not by token lookup.
            Err(GatewayError::Refused(
                "HyperPay reports a saved card with its registration, not by lookup".into(),
            ))
        })
    }

    fn verify_webhook(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        webhook_secret: &str,
    ) -> Result<Vec<GatewayEvent>, GatewayError> {
        let plain = decrypt_webhook(headers, body, webhook_secret)?;
        let notification: Value =
            serde_json::from_slice(&plain).map_err(|_| GatewayError::BadSignature)?;
        if notification.get("type").and_then(Value::as_str) != Some("PAYMENT") {
            // Registrations, schedules, risk checks and test pings.
            return Ok(Vec::new());
        }
        let Some(payload) = notification.get("payload").cloned() else {
            return Ok(Vec::new());
        };
        let transaction: Transaction = serde_json::from_value(payload).map_err(|e| {
            GatewayError::Refused(format!("a payment event that does not read: {e}"))
        })?;
        if transaction.id.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![GatewayEvent {
            // One transaction moves (pending, then paid): each move counts.
            event_id: format!("{}:{}", transaction.id, transaction.result.code),
            gateway_reference: transaction
                .merchant_transaction_id
                .clone()
                .unwrap_or_else(|| transaction.id.clone()),
            status: transaction_status(&transaction),
        }])
    }
}

/// Decrypts and authenticates a webhook body with the hex key; any failure
/// is a bad signature.
fn decrypt_webhook(
    headers: &[(String, String)],
    body: &[u8],
    hex_key: &str,
) -> Result<Vec<u8>, GatewayError> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    };
    let key = Zeroizing::new(hex::decode(hex_key.trim()).map_err(|_| GatewayError::BadSignature)?);
    if key.len() != 32 {
        return Err(GatewayError::BadSignature);
    }
    let iv = hex::decode(header("x-initialization-vector").ok_or(GatewayError::BadSignature)?)
        .map_err(|_| GatewayError::BadSignature)?;
    let tag = hex::decode(header("x-authentication-tag").ok_or(GatewayError::BadSignature)?)
        .map_err(|_| GatewayError::BadSignature)?;
    if tag.len() != 16 {
        return Err(GatewayError::BadSignature);
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| GatewayError::BadSignature)?
        .trim();
    // The body is the hex ciphertext, or {"encryptedBody": "<hex>"}.
    let hex_body = if text.starts_with('{') {
        serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|v| {
                v.get("encryptedBody")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or(GatewayError::BadSignature)?
    } else {
        text.to_owned()
    };
    let mut sealed = hex::decode(hex_body).map_err(|_| GatewayError::BadSignature)?;
    sealed.extend_from_slice(&tag);
    let opened = match iv.len() {
        12 => Aes256Gcm::new_from_slice(&key)
            .map_err(|_| GatewayError::BadSignature)?
            .decrypt(Nonce::from_slice(&iv), sealed.as_slice()),
        16 => AesGcm::<Aes256, U16>::new_from_slice(&key)
            .map_err(|_| GatewayError::BadSignature)?
            .decrypt(aes_gcm::Nonce::<U16>::from_slice(&iv), sealed.as_slice()),
        _ => return Err(GatewayError::BadSignature),
    };
    opened.map_err(|_| GatewayError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_codes_map() {
        assert_eq!(outcome("000.000.000"), Outcome::Success);
        assert_eq!(outcome("000.100.110"), Outcome::Success);
        assert_eq!(outcome("000.300.000"), Outcome::Success);
        assert_eq!(outcome("000.600.000"), Outcome::Success);
        assert_eq!(outcome("000.200.100"), Outcome::Pending);
        assert_eq!(outcome("800.400.500"), Outcome::Pending);
        assert_eq!(outcome("800.100.151"), Outcome::Failed);
        assert_eq!(outcome("000.400.000"), Outcome::Failed);
        assert_eq!(outcome(""), Outcome::Failed);
    }

    #[test]
    fn amounts_take_two_places() {
        assert_eq!(amount_text("92".parse().unwrap()).unwrap(), "92.00");
        assert_eq!(amount_text("115.5".parse().unwrap()).unwrap(), "115.50");
        assert!(amount_text("1.005".parse().unwrap()).is_err());
        assert!(amount_text(Decimal::ZERO).is_err());
    }

    #[test]
    fn settlement_records_make_a_payout() {
        let records: Vec<SettlementRecord> = serde_json::from_value(serde_json::json!([
            { "recordType": "SETTLED", "transactionType": "DEBIT", "merchantTransactionId": "order-1",
              "settlement": { "amount": "100.00", "currency": "SAR", "fee": "2.00", "cashflow": "POS" } },
            { "recordType": "SETTLED", "transactionType": "DEBIT", "merchantTransactionId": "order-2",
              "settlement": { "amount": "50.00", "currency": "SAR", "fee": "1.00", "cashflow": "POS" } },
            { "recordType": "SETTLED", "transactionType": "REFUND", "merchantTransactionId": "order-1",
              "settlement": { "amount": "20.00", "currency": "SAR", "cashflow": "NEG" } },
            { "recordType": "FEE", "transactionType": "MONTHLY",
              "settlement": { "amount": "5.00", "currency": "SAR", "cashflow": "NEG" } }
        ]))
        .unwrap();
        let day = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let payout = payout_of("agg-1", day, &records).unwrap();
        assert_eq!(payout.net, "125.00".parse::<Decimal>().unwrap());
        assert_eq!(payout.fees, "8.00".parse::<Decimal>().unwrap());
        assert_eq!(payout.gross, payout.net + payout.fees);
        assert_eq!(payout.payments, vec!["order-1", "order-2"]);
        assert!(payout_of("agg-2", day, &[]).is_none());
    }

    #[test]
    fn merchant_transaction_ids_fit() {
        assert_eq!(
            merchant_transaction_id("invoice:abc:attempt:1"),
            "invoice:abc:attempt:1"
        );
        let short = merchant_transaction_id("k1");
        assert_eq!(short.len(), 36);
        assert_eq!(short, merchant_transaction_id("k1"));
    }
}
