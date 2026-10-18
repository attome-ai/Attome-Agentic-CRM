//! The Moyasar adapter (roadmap F5-T5).
//!
//! Moyasar's REST API (`https://api.moyasar.com/v1`), authenticated with the
//! secret key as the HTTP basic-auth user and an empty password. Amounts
//! travel in the currency's smallest unit (halalas for SAR, fils for KWD).
//!
//! - **Checkout** is a Moyasar invoice (`POST /invoices`), Moyasar's hosted
//!   payment page; the invoice id is the gateway reference. Invoices take no
//!   idempotency key, so the key travels in the invoice's metadata and a
//!   retry looks the invoice up by it (`GET /invoices?metadata[...]`) before
//!   creating one.
//! - **Token charge** is `POST /payments` with `given_id`: Moyasar returns
//!   the same payment for a repeated `given_id` (and the payment's id is the
//!   `given_id`), so a retried call never charges twice. [`given_id`] derives
//!   it from the idempotency key; it is also the payment's gateway reference.
//! - **Status** reads the invoice, or the payment when the reference is not
//!   an invoice.
//! - **Refund** reads the payment first: one already refunded is answered
//!   from the gateway's record, so a retry never refunds twice.
//! - **Payouts** are Moyasar's transfers (`GET /transfers` and their lines),
//!   which Moyasar offers to aggregation merchants; another account gets a
//!   refusal.
//! - **Webhooks** carry the endpoint's `secret_token` in the body; it is
//!   compared with the stored secret in constant time, and a payment event's
//!   reference is its invoice id when it has one (the checkout's reference),
//!   otherwise its payment id.
//! - **Saved cards**: only the brand and last four digits of a token are
//!   read; every other card field in the response is dropped unread.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    Checkout, CheckoutRequest, GatewayError, GatewayEvent, GatewayFuture, GatewayHttp,
    GatewayStatus, Method, PaymentGateway, Payout, SavedCard,
};

/// Moyasar's production API base URL (an integration system's default).
pub const BASE_URL: &str = "https://api.moyasar.com/v1";

/// The metadata key carrying a checkout's idempotency key.
const KEY_METADATA: &str = "attome_idempotency_key";

/// The most pages one listing reads (Moyasar pages hold 40 items).
const MAX_PAGES: u32 = 25;

/// The UUID namespace `given_id`s are derived in.
const GIVEN_ID_NAMESPACE: Uuid = Uuid::from_u128(0x0192_6d1e_7c4b_7a39_9a51_6f2b_8c3d_4e5f);

/// Moyasar's methods: cards (mada, Visa, Mastercard, Amex), Apple Pay and
/// STC Pay on the hosted page.
const METHODS: &[Method] = &[Method::Card, Method::Mada, Method::ApplePay, Method::StcPay];

/// The Moyasar gateway. It holds no credential: the secret key comes with
/// each call.
#[derive(Debug, Clone)]
pub struct MoyasarGateway {
    http: GatewayHttp,
    /// Where Moyasar sends a payer after a 3-D Secure step on a token charge
    /// (empty: none is sent, and a charge needing 3-D Secure is refused).
    callback_url: String,
}

impl MoyasarGateway {
    pub fn new(http: GatewayHttp) -> Self {
        Self {
            http,
            callback_url: String::new(),
        }
    }

    /// Sets the 3-D Secure return URL for token charges.
    #[must_use]
    pub fn with_callback_url(mut self, url: impl Into<String>) -> Self {
        self.callback_url = url.into();
        self
    }

    /// One call: basic auth with the secret key, a JSON answer. A transport
    /// failure, a 429 or a 5xx is `Unavailable`; any other answer is returned
    /// with its status for the caller to read.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        secret: &str,
        body: Option<&Value>,
    ) -> Result<(reqwest::StatusCode, Value), GatewayError> {
        let mut request = self
            .http
            .request(method, path)?
            .basic_auth(secret, Some(""))
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| GatewayError::Unavailable(e.without_url().to_string()))?;
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(GatewayError::Unavailable(format!(
                "Moyasar answered {status}"
            )));
        }
        let text = response
            .text()
            .await
            .map_err(|e| GatewayError::Unavailable(e.without_url().to_string()))?;
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|_| {
                GatewayError::Unavailable(format!(
                    "Moyasar answered {status} with a body that is not JSON"
                ))
            })?
        };
        Ok((status, value))
    }

    /// A call whose only good answer is a 2xx.
    async fn send_ok(
        &self,
        method: reqwest::Method,
        path: &str,
        secret: &str,
        body: Option<&Value>,
    ) -> Result<Value, GatewayError> {
        let (status, value) = self.send(method, path, secret, body).await?;
        if status.is_success() {
            Ok(value)
        } else {
            Err(refusal(status, &value))
        }
    }

    async fn payment(&self, secret: &str, id: &str) -> Result<MoyasarPayment, GatewayError> {
        let value = self
            .send_ok(
                reqwest::Method::GET,
                &format!("/payments/{}", segment(id)?),
                secret,
                None,
            )
            .await?;
        parse(value)
    }

    /// The invoice an earlier attempt with `key` created, if any.
    async fn invoice_by_key(
        &self,
        secret: &str,
        key: &str,
    ) -> Result<Option<MoyasarInvoice>, GatewayError> {
        let mut url = reqwest::Url::parse("http://query.invalid/invoices")
            .map_err(|e| GatewayError::Refused(e.to_string()))?;
        url.query_pairs_mut()
            .append_pair(&format!("metadata[{KEY_METADATA}]"), key);
        let path = format!("/invoices?{}", url.query().unwrap_or_default());
        let value = self
            .send_ok(reqwest::Method::GET, &path, secret, None)
            .await?;
        let list: InvoiceList = parse(value)?;
        // The filter is Moyasar's; the key is checked again here.
        Ok(list.invoices.into_iter().find(|i| {
            i.metadata
                .as_ref()
                .and_then(|m| m.get(KEY_METADATA))
                .and_then(Value::as_str)
                == Some(key)
        }))
    }

    async fn transfer_lines(
        &self,
        secret: &str,
        transfer: &str,
    ) -> Result<Vec<TransferLine>, GatewayError> {
        let mut lines = Vec::new();
        for page in 1..=MAX_PAGES {
            let value = self
                .send_ok(
                    reqwest::Method::GET,
                    &format!("/transfers/{}/lines?page={page}", segment(transfer)?),
                    secret,
                    None,
                )
                .await?;
            let list: LineList = parse(value)?;
            lines.extend(list.lines);
            if list.meta.and_then(|m| m.next_page).is_none() {
                return Ok(lines);
            }
        }
        Err(GatewayError::Unavailable(format!(
            "transfer {transfer} has more than {MAX_PAGES} pages of lines"
        )))
    }
}

impl PaymentGateway for MoyasarGateway {
    fn name(&self) -> &'static str {
        "moyasar"
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
            if let Some(unsupported) = request.methods.iter().find(|m| !METHODS.contains(m)) {
                return Err(GatewayError::Refused(format!(
                    "Moyasar does not offer {unsupported:?}"
                )));
            }
            let amount = to_minor(request.amount, &request.currency)?;
            if let Some(invoice) = self
                .invoice_by_key(secret, &request.idempotency_key)
                .await?
            {
                return checkout_of(invoice);
            }
            let body = json!({
                "amount": amount,
                "currency": request.currency.to_ascii_uppercase(),
                "description": request.description,
                "success_url": request.return_url,
                "back_url": request.return_url,
                "metadata": {
                    KEY_METADATA: request.idempotency_key,
                    "attome_reference": request.reference,
                },
            });
            let value = self
                .send_ok(reqwest::Method::POST, "/invoices", secret, Some(&body))
                .await?;
            checkout_of(parse(value)?)
        })
    }

    fn get_status<'a>(
        &'a self,
        secret: &'a str,
        gateway_reference: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async move {
            let path = format!("/invoices/{}", segment(gateway_reference)?);
            let (status, value) = self.send(reqwest::Method::GET, &path, secret, None).await?;
            if status.is_success() {
                return Ok(invoice_status(&parse(value)?));
            }
            if status != reqwest::StatusCode::NOT_FOUND {
                return Err(refusal(status, &value));
            }
            // Not an invoice: a token charge's payment.
            Ok(payment_status(
                &self.payment(secret, gateway_reference).await?,
            ))
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
            let minor = to_minor(amount, currency)?;
            let id = given_id(idempotency_key).to_string();
            let mut body = json!({
                "given_id": id,
                "amount": minor,
                "currency": currency.to_ascii_uppercase(),
                "description": "Attome payment",
                "source": { "type": "token", "token": token },
            });
            if !self.callback_url.is_empty() {
                body["callback_url"] = json!(self.callback_url);
            }
            let (status, value) = self
                .send(reqwest::Method::POST, "/payments", secret, Some(&body))
                .await?;
            if status.is_success() {
                return Ok(payment_status(&parse(value)?));
            }
            // "Payment is already created": an earlier attempt with this key
            // reached Moyasar; its payment is the answer.
            if status == reqwest::StatusCode::BAD_REQUEST && already_created(&value) {
                return Ok(payment_status(&self.payment(secret, &id).await?));
            }
            Err(refusal(status, &value))
        })
    }

    fn refund<'a>(
        &'a self,
        secret: &'a str,
        gateway_reference: &'a str,
        amount: Decimal,
        _idempotency_key: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async move {
            // A checkout's reference is its invoice: refund its paid payment.
            let payment_id = match self
                .send(
                    reqwest::Method::GET,
                    &format!("/invoices/{}", segment(gateway_reference)?),
                    secret,
                    None,
                )
                .await?
            {
                (status, value) if status.is_success() => {
                    let invoice: MoyasarInvoice = parse(value)?;
                    invoice
                        .payments
                        .iter()
                        .find(|p| matches!(p.status.as_str(), "paid" | "captured" | "refunded"))
                        .map(|p| p.id.clone())
                        .ok_or_else(|| {
                            GatewayError::Refused("the invoice has no paid payment".into())
                        })?
                }
                (status, _) if status == reqwest::StatusCode::NOT_FOUND => {
                    gateway_reference.to_owned()
                }
                (status, value) => return Err(refusal(status, &value)),
            };
            let payment = self.payment(secret, &payment_id).await?;
            let minor = to_minor(amount, &payment.currency)?;
            if payment.status == "refunded" {
                // Done by an earlier attempt: never refund twice.
                return Ok(payment_status(&payment));
            }
            if minor > payment.charged() {
                return Err(GatewayError::Refused(
                    "the refund is more than the payment".into(),
                ));
            }
            let value = self
                .send_ok(
                    reqwest::Method::POST,
                    &format!("/payments/{}/refund", segment(&payment_id)?),
                    secret,
                    Some(&json!({ "amount": minor })),
                )
                .await?;
            Ok(payment_status(&parse(value)?))
        })
    }

    fn list_payouts<'a>(
        &'a self,
        secret: &'a str,
        day: NaiveDate,
    ) -> GatewayFuture<'a, Vec<Payout>> {
        Box::pin(async move {
            let mut transfers = Vec::new();
            'pages: for page in 1..=MAX_PAGES {
                let value = self
                    .send_ok(
                        reqwest::Method::GET,
                        &format!("/transfers?page={page}"),
                        secret,
                        None,
                    )
                    .await?;
                let list: TransferList = parse(value)?;
                for transfer in list.transfers {
                    let on = transfer.created_at.date_naive();
                    // Newest first: past the day, nothing older matters.
                    if on < day {
                        break 'pages;
                    }
                    if on == day {
                        transfers.push(transfer);
                    }
                }
                if list.meta.and_then(|m| m.next_page).is_none() {
                    break;
                }
            }
            let mut payouts = Vec::with_capacity(transfers.len());
            for transfer in transfers {
                let lines = self.transfer_lines(secret, &transfer.id).await?;
                let exponent = exponent(&transfer.currency);
                let line_fees: i64 = lines.iter().map(|l| l.fee + l.tax).sum();
                let fees = transfer.fee + transfer.tax + line_fees;
                payouts.push(Payout {
                    payout_reference: transfer.reference.clone().unwrap_or(transfer.id.clone()),
                    day,
                    // What reached the bank, plus what Moyasar kept.
                    gross: Decimal::new(transfer.amount + fees, exponent),
                    fees: Decimal::new(fees, exponent),
                    net: Decimal::new(transfer.amount, exponent),
                    currency: transfer.currency.clone(),
                    payments: lines
                        .into_iter()
                        .filter(|l| l.kind.as_deref().is_none_or(|k| k == "payment"))
                        .filter_map(|l| l.payment_id)
                        .collect(),
                });
            }
            Ok(payouts)
        })
    }

    fn saved_card<'a>(&'a self, secret: &'a str, token: &'a str) -> GatewayFuture<'a, SavedCard> {
        Box::pin(async move {
            let value = self
                .send_ok(
                    reqwest::Method::GET,
                    &format!("/tokens/{}", segment(token)?),
                    secret,
                    None,
                )
                .await?;
            // Only these fields are read; the rest of the token is dropped.
            let token: MoyasarToken = parse(value)?;
            Ok(SavedCard {
                brand: token.brand.unwrap_or_default(),
                last4: last4(token.last_four.as_deref().unwrap_or_default()),
                active: token.status == "active",
            })
        })
    }

    fn verify_webhook(
        &self,
        _headers: &[(String, String)],
        body: &[u8],
        webhook_secret: &str,
    ) -> Result<Vec<GatewayEvent>, GatewayError> {
        // The secret is in the body, so a body that does not read cannot be
        // authenticated.
        let hook: Webhook = serde_json::from_slice(body).map_err(|_| GatewayError::BadSignature)?;
        let given = hook.secret_token.as_deref().unwrap_or_default();
        if webhook_secret.is_empty() || !same_secret(given, webhook_secret) {
            return Err(GatewayError::BadSignature);
        }
        if !hook.kind.starts_with("payment_") {
            // Card authentications and transfers are not payment events.
            return Ok(Vec::new());
        }
        let payment: MoyasarPayment = serde_json::from_value(hook.data).map_err(|e| {
            GatewayError::Refused(format!("a payment event that does not read: {e}"))
        })?;
        Ok(vec![GatewayEvent {
            event_id: hook.id,
            gateway_reference: payment
                .invoice_id
                .clone()
                .unwrap_or_else(|| payment.id.clone()),
            status: payment_status(&payment),
        }])
    }
}

/// The Moyasar payment id (`given_id`) for an idempotency key: the key
/// itself when it is a UUID, otherwise a UUID derived from it.
pub fn given_id(idempotency_key: &str) -> Uuid {
    Uuid::parse_str(idempotency_key)
        .unwrap_or_else(|_| Uuid::new_v5(&GIVEN_ID_NAMESPACE, idempotency_key.as_bytes()))
}

#[derive(Debug, Deserialize)]
struct MoyasarPayment {
    id: String,
    status: String,
    amount: i64,
    #[serde(default)]
    fee: Option<i64>,
    currency: String,
    #[serde(default)]
    refunded: i64,
    #[serde(default)]
    captured: i64,
    #[serde(default)]
    invoice_id: Option<String>,
    #[serde(default)]
    source: Option<PaymentSource>,
}

impl MoyasarPayment {
    /// What the payer was charged: the captured part of a captured payment.
    fn charged(&self) -> i64 {
        if self.status == "captured" && self.captured > 0 {
            self.captured
        } else {
            self.amount
        }
    }
}

#[derive(Debug, Deserialize)]
struct PaymentSource {
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MoyasarInvoice {
    id: String,
    status: String,
    amount: i64,
    currency: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    payments: Vec<MoyasarPayment>,
    #[serde(default)]
    metadata: Option<serde_json::Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct InvoiceList {
    #[serde(default)]
    invoices: Vec<MoyasarInvoice>,
}

#[derive(Debug, Deserialize)]
struct MoyasarToken {
    status: String,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    last_four: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    next_page: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Transfer {
    id: String,
    currency: String,
    amount: i64,
    #[serde(default)]
    fee: i64,
    #[serde(default)]
    tax: i64,
    #[serde(default)]
    reference: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct TransferList {
    #[serde(default)]
    transfers: Vec<Transfer>,
    #[serde(default)]
    meta: Option<Meta>,
}

#[derive(Debug, Deserialize)]
struct TransferLine {
    #[serde(default)]
    payment_id: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    fee: i64,
    #[serde(default)]
    tax: i64,
}

#[derive(Debug, Deserialize)]
struct LineList {
    #[serde(default)]
    lines: Vec<TransferLine>,
    #[serde(default)]
    meta: Option<Meta>,
}

#[derive(Debug, Deserialize)]
struct Webhook {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    secret_token: Option<String>,
    #[serde(default)]
    data: Value,
}

fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, GatewayError> {
    serde_json::from_value(value)
        .map_err(|e| GatewayError::Unavailable(format!("Moyasar's answer does not read: {e}")))
}

/// A 4xx answer as a refusal, with Moyasar's message (bounded).
fn refusal(status: reqwest::StatusCode, value: &Value) -> GatewayError {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return GatewayError::Refused("Moyasar refused the gateway's credential".into());
    }
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("no message");
    let message: String = message.chars().take(200).collect();
    GatewayError::Refused(format!("Moyasar answered {status}: {message}"))
}

fn already_created(value: &Value) -> bool {
    let text = |v: &Value| v.as_str().map(str::to_ascii_lowercase).unwrap_or_default();
    text(&value["message"]).contains("already created")
        || value["errors"]
            .to_string()
            .to_ascii_lowercase()
            .contains("already created")
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
        Err(GatewayError::Refused("not a Moyasar reference".into()))
    }
}

fn checkout_of(invoice: MoyasarInvoice) -> Result<Checkout, GatewayError> {
    let url = invoice
        .url
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
        .ok_or_else(|| GatewayError::Unavailable("Moyasar's invoice has no payment page".into()))?;
    Ok(Checkout {
        redirect_url: url,
        gateway_reference: invoice.id,
    })
}

fn payment_status(payment: &MoyasarPayment) -> GatewayStatus {
    let exponent = exponent(&payment.currency);
    match payment.status.as_str() {
        "paid" | "captured" => GatewayStatus::Succeeded {
            amount: Decimal::new(payment.charged(), exponent),
            fee: payment.fee.map(|f| Decimal::new(f, exponent)),
        },
        "refunded" => GatewayStatus::Refunded {
            amount: Decimal::new(payment.refunded, exponent),
        },
        "failed" => GatewayStatus::Failed {
            reason: payment
                .source
                .as_ref()
                .and_then(|s| s.message.clone())
                .filter(|m| !m.trim().is_empty())
                .unwrap_or_else(|| "the payment failed".into()),
        },
        "voided" => GatewayStatus::Failed {
            reason: "the payment was voided".into(),
        },
        // initiated, authorized (not yet charged), verified: not settled.
        _ => GatewayStatus::Pending,
    }
}

fn invoice_status(invoice: &MoyasarInvoice) -> GatewayStatus {
    let exponent = exponent(&invoice.currency);
    match invoice.status.as_str() {
        "paid" => {
            let paid = invoice
                .payments
                .iter()
                .find(|p| matches!(p.status.as_str(), "paid" | "captured"));
            GatewayStatus::Succeeded {
                amount: Decimal::new(
                    paid.map_or(invoice.amount, MoyasarPayment::charged),
                    exponent,
                ),
                fee: paid.and_then(|p| p.fee).map(|f| Decimal::new(f, exponent)),
            }
        }
        "refunded" => GatewayStatus::Refunded {
            amount: Decimal::new(invoice.payments.iter().map(|p| p.refunded).sum(), exponent),
        },
        "failed" | "expired" | "canceled" | "cancelled" => GatewayStatus::Failed {
            reason: format!("the Moyasar invoice is {}", invoice.status),
        },
        _ => GatewayStatus::Pending,
    }
}

/// The currency's minor-unit exponent (ISO 4217).
fn exponent(currency: &str) -> u32 {
    match currency.to_ascii_uppercase().as_str() {
        "BHD" | "IQD" | "JOD" | "KWD" | "LYD" | "OMR" | "TND" => 3,
        "JPY" | "KRW" => 0,
        _ => 2,
    }
}

/// An amount in the currency's smallest unit; a positive amount with no
/// finer fraction than the currency has.
fn to_minor(amount: Decimal, currency: &str) -> Result<i64, GatewayError> {
    let scaled = amount * Decimal::from(10_i64.pow(exponent(currency)));
    if scaled <= Decimal::ZERO || scaled.fract() != Decimal::ZERO {
        return Err(GatewayError::Refused(format!(
            "{amount} is not a payable {currency} amount"
        )));
    }
    i64::try_from(scaled.trunc())
        .map_err(|_| GatewayError::Refused(format!("{amount} is too large")))
}

/// The last four digits, whatever the gateway sent.
fn last4(raw: &str) -> String {
    let digits: Vec<char> = raw.chars().filter(char::is_ascii_digit).collect();
    digits[digits.len().saturating_sub(4)..].iter().collect()
}

/// Compares two secrets in constant time: their SHA-256 digests, so neither
/// the content nor the length leaks through timing.
fn same_secret(given: &str, stored: &str) -> bool {
    let (a, b) = (
        Sha256::digest(given.as_bytes()),
        Sha256::digest(stored.as_bytes()),
    );
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn minor_units_follow_the_currency() {
        assert_eq!(
            to_minor(Decimal::from_str("115.50").unwrap(), "SAR"),
            Ok(11550)
        );
        assert_eq!(
            to_minor(Decimal::from_str("1.234").unwrap(), "KWD"),
            Ok(1234)
        );
        assert!(to_minor(Decimal::from_str("1.234").unwrap(), "SAR").is_err());
        assert!(to_minor(Decimal::ZERO, "SAR").is_err());
    }

    #[test]
    fn given_id_is_stable() {
        let key = "pay-attempt-1";
        assert_eq!(given_id(key), given_id(key));
        let uuid = Uuid::now_v7();
        assert_eq!(given_id(&uuid.to_string()), uuid);
    }

    #[test]
    fn last4_keeps_four_digits() {
        assert_eq!(last4("XXXX-XXXX-XXXX-1111"), "1111");
        assert_eq!(last4("12"), "12");
    }

    #[test]
    fn secrets_compare() {
        assert!(same_secret("s3cret", "s3cret"));
        assert!(!same_secret("s3cret", "s3cre"));
        assert!(!same_secret("", "s3cret"));
    }
}
