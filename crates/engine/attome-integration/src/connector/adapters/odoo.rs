//! S12-T2: Odoo, over its JSON-RPC API (`/jsonrpc`).
//!
//! A session signs in once (`common.login` with the database, the user and
//! an API key) and then reads with `object.execute_kw` `search_read`, a
//! page of [`PAGE`] records at a time by offset:
//!
//! | Odoo model | Attome | fields |
//! |---|---|---|
//! | `res.partner` (companies) | `account` | name, phone, website, industry, email domain |
//! | `product.product` | `product` | name, internal reference as `sku`, description, `sale_ok` |
//! | `sale.order` | `order` | name, currency, order date |
//! | `account.move` (customer invoices) | `invoice` | number, total, invoice and due dates |
//!
//! Pushing writes customers only: a partner is created, or written when the
//! account already carries its Odoo id ([`OdooClient::push_customer`]).
//! The API key is a [`Secret`]; an Odoo error answer is a refusal, never
//! retried as success.

use std::collections::BTreeMap;

use attome_types::AppError;
use serde_json::{Map, Value, json};

use super::erp::{ErpKind, ErpRecord, date, email_domain, put, text};
use crate::connector::sdk::{Request, Secret, Transport};

/// Records read per call.
pub const PAGE: u64 = 200;
/// The most records one pull reads.
pub const MAX_RECORDS: usize = 100_000;

/// An Odoo connection.
pub struct OdooClient<'a> {
    pub url: String,
    pub database: String,
    pub username: String,
    pub api_key: Secret,
    pub transport: &'a dyn Transport,
    uid: Option<i64>,
    calls: u64,
}

impl std::fmt::Debug for OdooClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OdooClient")
            .field("url", &self.url)
            .field("database", &self.database)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl<'a> OdooClient<'a> {
    pub fn new(
        url: &str,
        database: &str,
        username: &str,
        api_key: Secret,
        transport: &'a dyn Transport,
    ) -> Self {
        OdooClient {
            url: url.trim_end_matches('/').to_owned(),
            database: database.to_owned(),
            username: username.to_owned(),
            api_key,
            transport,
            uid: None,
            calls: 0,
        }
    }

    async fn call(&mut self, service: &str, method: &str, args: Value) -> Result<Value, AppError> {
        self.calls += 1;
        let body = json!({
            "jsonrpc": "2.0",
            "method": "call",
            "id": self.calls,
            "params": { "service": service, "method": method, "args": args },
        });
        let answer = self
            .transport
            .send(Request {
                method: "POST".into(),
                url: format!("{}/jsonrpc", self.url),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: Some(body.to_string()),
            })
            .await?;
        if answer.status >= 400 {
            return Err(AppError::internal(format!(
                "Odoo answered {}",
                answer.status
            )));
        }
        let value: Value = serde_json::from_str(&answer.body)
            .map_err(|_| AppError::internal("Odoo answered no JSON"))?;
        if let Some(error) = value.get("error") {
            let message = error["data"]["message"]
                .as_str()
                .or(error["message"].as_str())
                .unwrap_or("error");
            return Err(AppError::Validation(format!(
                "Odoo refused the call: {message}"
            )));
        }
        Ok(value["result"].clone())
    }

    async fn uid(&mut self) -> Result<i64, AppError> {
        if let Some(uid) = self.uid {
            return Ok(uid);
        }
        let secret = self.api_key.clone();
        let result = self
            .call(
                "common",
                "login",
                json!([self.database, self.username, expose(&secret)]),
            )
            .await?;
        let uid = result
            .as_i64()
            .ok_or_else(|| AppError::Validation("Odoo refused the sign-in".into()))?;
        self.uid = Some(uid);
        Ok(uid)
    }

    async fn execute(
        &mut self,
        model: &str,
        method: &str,
        args: Value,
        kwargs: Value,
    ) -> Result<Value, AppError> {
        let uid = self.uid().await?;
        let secret = self.api_key.clone();
        self.call(
            "object",
            "execute_kw",
            json!([
                self.database,
                uid,
                expose(&secret),
                model,
                method,
                args,
                kwargs
            ]),
        )
        .await
    }

    /// Every record of `kind`.
    pub async fn pull(&mut self, kind: ErpKind) -> Result<Vec<ErpRecord>, AppError> {
        let (model, domain, fields) = model_of(kind);
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let page = self
                .execute(
                    model,
                    "search_read",
                    json!([domain]),
                    json!({ "fields": fields, "offset": offset, "limit": PAGE, "order": "id" }),
                )
                .await?;
            let rows = page.as_array().cloned().unwrap_or_default();
            let got = rows.len() as u64;
            out.extend(rows.iter().filter_map(|r| map_record(kind, r)));
            if got < PAGE || out.len() >= MAX_RECORDS {
                return Ok(out);
            }
            offset += PAGE;
        }
    }

    /// Creates or updates the partner of an Attome account; its Odoo id.
    pub async fn push_customer(
        &mut self,
        fields: &Map<String, Value>,
        odoo_id: Option<i64>,
    ) -> Result<i64, AppError> {
        let values = partner_values(fields);
        match odoo_id {
            Some(id) => {
                self.execute("res.partner", "write", json!([[id], values]), json!({}))
                    .await?;
                Ok(id)
            }
            None => self
                .execute("res.partner", "create", json!([values]), json!({}))
                .await?
                .as_i64()
                .ok_or_else(|| AppError::internal("Odoo gave no id for the new partner")),
        }
    }
}

/// The API key, for the call's body only.
fn expose(secret: &Secret) -> String {
    secret.wire_value().to_owned()
}

/// The model, domain and fields a kind reads.
pub fn model_of(kind: ErpKind) -> (&'static str, Value, Value) {
    match kind {
        ErpKind::Customer => (
            "res.partner",
            json!([["is_company", "=", true]]),
            json!([
                "id",
                "name",
                "phone",
                "email",
                "website",
                "industry_id",
                "vat"
            ]),
        ),
        ErpKind::Product => (
            "product.product",
            json!([]),
            json!(["id", "name", "default_code", "description_sale", "sale_ok"]),
        ),
        ErpKind::Order => (
            "sale.order",
            json!([]),
            json!([
                "id",
                "name",
                "date_order",
                "currency_id",
                "partner_id",
                "state"
            ]),
        ),
        ErpKind::Invoice => (
            "account.move",
            json!([["move_type", "=", "out_invoice"]]),
            json!([
                "id",
                "name",
                "amount_total",
                "invoice_date",
                "invoice_date_due",
                "state"
            ]),
        ),
    }
}

/// The display name of a many2one (`[id, "name"]`).
fn many2one_name(v: &Value) -> Option<Value> {
    v.as_array().and_then(|pair| pair.get(1)).and_then(text)
}

/// An Odoo row as an Attome record (`None` without an id).
pub fn map_record(kind: ErpKind, row: &Value) -> Option<ErpRecord> {
    let id = row["id"].as_i64()?;
    let mut f = Map::new();
    match kind {
        ErpKind::Customer => {
            put(&mut f, "name", text(&row["name"]));
            put(&mut f, "phone", text(&row["phone"]));
            put(&mut f, "website", text(&row["website"]));
            put(&mut f, "industry", many2one_name(&row["industry_id"]));
            put(&mut f, "email_domain", email_domain(&row["email"]));
        }
        ErpKind::Product => {
            put(&mut f, "name", text(&row["name"]));
            put(&mut f, "sku", text(&row["default_code"]));
            put(&mut f, "description", text(&row["description_sale"]));
            if let Some(ok) = row["sale_ok"].as_bool() {
                f.insert("is_orderable".into(), Value::Bool(ok));
            }
        }
        ErpKind::Order => {
            put(&mut f, "name", text(&row["name"]));
            put(&mut f, "ordered_on", date(&row["date_order"]));
            put(&mut f, "currency", many2one_name(&row["currency_id"]));
        }
        ErpKind::Invoice => {
            put(&mut f, "invoice_number", text(&row["name"]));
            if let Some(total) = row["amount_total"].as_f64() {
                f.insert("amount".into(), json!(total));
            }
            put(&mut f, "issued_date", date(&row["invoice_date"]));
            put(&mut f, "due_date", date(&row["invoice_date_due"]));
            f.insert("external_system_id".into(), json!(format!("odoo:{id}")));
        }
    }
    Some(ErpRecord {
        kind,
        external_id: format!("odoo:{id}"),
        fields: f,
    })
}

/// An account's fields as `res.partner` values.
pub fn partner_values(fields: &Map<String, Value>) -> Value {
    let mut values = BTreeMap::new();
    values.insert("is_company", json!(true));
    for (attome, odoo) in [("name", "name"), ("phone", "phone"), ("website", "website")] {
        if let Some(v) = fields.get(attome).and_then(text) {
            values.insert(odoo, v);
        }
    }
    json!(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::{Response, Transport};
    use std::sync::Mutex;

    /// A recorded Odoo: answers in order.
    struct Fixture {
        answers: Mutex<Vec<Value>>,
        seen: Mutex<Vec<Value>>,
    }

    impl Fixture {
        fn new(answers: Vec<Value>) -> Self {
            Fixture {
                answers: Mutex::new(answers.into_iter().rev().collect()),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for Fixture {
        fn send<'a>(
            &'a self,
            request: Request,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Response, AppError>> + Send + 'a>,
        > {
            self.seen
                .lock()
                .unwrap()
                .push(serde_json::from_str(request.body.as_deref().unwrap_or("null")).unwrap());
            let body = self.answers.lock().unwrap().pop().unwrap_or(json!({}));
            Box::pin(async move {
                Ok(Response {
                    status: 200,
                    headers: vec![],
                    body: body.to_string(),
                })
            })
        }
    }

    #[tokio::test]
    async fn erp_connectors_odoo_pulls_customers_and_invoices() {
        let fixture = Fixture::new(vec![
            json!({ "jsonrpc": "2.0", "id": 1, "result": 7 }),
            json!({ "jsonrpc": "2.0", "id": 2, "result": [
                { "id": 14, "name": "Al Noor Trading", "phone": "+966 11 444 5555",
                  "email": "sales@alnoor.sa", "website": "https://alnoor.sa",
                  "industry_id": [3, "Wholesale"], "vat": "300000000000003" },
                { "id": 15, "name": "Gulf Steel", "phone": false, "email": false,
                  "website": false, "industry_id": false, "vat": false }
            ]}),
        ]);
        let mut odoo = OdooClient::new(
            "https://erp.example.sa/",
            "prod",
            "api@attome",
            Secret::new("key"),
            &fixture,
        );
        let customers = odoo.pull(ErpKind::Customer).await.unwrap();
        assert_eq!(customers.len(), 2);
        assert_eq!(customers[0].external_id, "odoo:14");
        assert_eq!(customers[0].fields["industry"], "Wholesale");
        assert_eq!(customers[0].fields["email_domain"], "alnoor.sa");
        assert!(
            !customers[1].fields.contains_key("phone"),
            "Odoo's false is no value"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen[0]["params"]["method"], "login");
        assert_eq!(seen[1]["params"]["args"][3], "res.partner");
        assert_eq!(seen[1]["params"]["args"][1], 7, "signed in once, by uid");

        let invoice = map_record(
            ErpKind::Invoice,
            &json!({ "id": 88, "name": "INV/2026/0042", "amount_total": 1150.0,
                     "invoice_date": "2026-10-01", "invoice_date_due": "2026-10-31" }),
        )
        .unwrap();
        assert_eq!(invoice.fields["invoice_number"], "INV/2026/0042");
        assert_eq!(invoice.fields["amount"], 1150.0);
        assert_eq!(invoice.fields["due_date"], "2026-10-31");
    }

    #[tokio::test]
    async fn erp_connectors_odoo_pushes_customers_only() {
        let fixture = Fixture::new(vec![
            json!({ "result": 7 }),
            json!({ "result": 99 }),
            json!({ "result": true }),
            json!({ "error": { "message": "Odoo Server Error",
                               "data": { "message": "Access Denied" } } }),
        ]);
        let mut odoo = OdooClient::new(
            "https://erp.example.sa",
            "prod",
            "api",
            Secret::new("key"),
            &fixture,
        );
        let mut fields = Map::new();
        fields.insert("name".into(), json!("Al Noor Trading"));
        fields.insert("annual_revenue".into(), json!(5));
        assert_eq!(odoo.push_customer(&fields, None).await.unwrap(), 99);
        assert_eq!(odoo.push_customer(&fields, Some(99)).await.unwrap(), 99);
        let err = odoo.push_customer(&fields, Some(99)).await.unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("Access Denied")),
            "{err:?}"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen[1]["params"]["args"][4], "create");
        assert_eq!(seen[1]["params"]["args"][5][0]["name"], "Al Noor Trading");
        assert!(
            seen[1]["params"]["args"][5][0]
                .get("annual_revenue")
                .is_none()
        );
        assert_eq!(seen[2]["params"]["args"][4], "write");
        assert!(ErpKind::Customer.pushable() && !ErpKind::Invoice.pushable());
    }
}
