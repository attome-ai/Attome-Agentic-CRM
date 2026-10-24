//! S12-T2: SAP Business One, over its Service Layer (`/b1s/v1`).
//!
//! A session signs in once (`POST /Login` with the company database, the
//! user and the password) and sends the `B1SESSION` (and `ROUTEID`) cookie
//! it is given; a call answered 401 signs in again once. Reads are OData
//! collections followed by their `odata.nextLink` pages:
//!
//! | Service Layer | Attome | fields |
//! |---|---|---|
//! | `BusinessPartners` (customers) | `account` | name, phone, website, email domain |
//! | `Items` | `product` | name, item code as `sku`, sales item |
//! | `Orders` | `order` | document number, currency, document date |
//! | `Invoices` | `invoice` | document number, total, document and due dates |
//!
//! Pushing writes customers only: a business partner is created
//! (`cCustomer`), or patched when the account carries its card code. The
//! password is a [`Secret`].

use attome_types::AppError;
use serde_json::{Map, Value, json};

use super::erp::{ErpKind, ErpRecord, date, email_domain, put, text};
use crate::connector::sdk::{Request, Response, Secret, Transport};

/// The most pages one pull follows.
pub const MAX_PAGES: usize = 1_000;

/// A Service Layer connection.
pub struct SapB1Client<'a> {
    pub base_url: String,
    pub company_db: String,
    pub username: String,
    pub password: Secret,
    pub transport: &'a dyn Transport,
    cookie: Option<String>,
}

impl std::fmt::Debug for SapB1Client<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SapB1Client")
            .field("base_url", &self.base_url)
            .field("company_db", &self.company_db)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// The session cookie (`B1SESSION=...; ROUTEID=...`) of a login answer.
pub fn session_cookie(answer: &Response) -> Option<String> {
    let parts: Vec<String> = answer
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.split(';').next().map(|c| c.trim().to_owned()))
        .filter(|c| c.starts_with("B1SESSION=") || c.starts_with("ROUTEID="))
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// A card code quoted for an OData key (`'C20000'`, a `'` doubled).
pub fn odata_key(code: &str) -> String {
    format!("'{}'", code.replace('\'', "''"))
}

impl<'a> SapB1Client<'a> {
    pub fn new(
        base_url: &str,
        company_db: &str,
        username: &str,
        password: Secret,
        transport: &'a dyn Transport,
    ) -> Self {
        SapB1Client {
            base_url: base_url.trim_end_matches('/').to_owned(),
            company_db: company_db.to_owned(),
            username: username.to_owned(),
            password,
            transport,
            cookie: None,
        }
    }

    async fn login(&mut self) -> Result<String, AppError> {
        let body = json!({
            "CompanyDB": self.company_db,
            "UserName": self.username,
            "Password": self.password.wire_value(),
        });
        let answer = self
            .transport
            .send(Request {
                method: "POST".into(),
                url: format!("{}/Login", self.base_url),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: Some(body.to_string()),
            })
            .await?;
        if answer.status >= 400 {
            return Err(AppError::Validation(
                "SAP Business One refused the sign-in".into(),
            ));
        }
        let cookie = session_cookie(&answer)
            .ok_or_else(|| AppError::internal("the Service Layer gave no session"))?;
        self.cookie = Some(cookie.clone());
        Ok(cookie)
    }

    async fn send(
        &mut self,
        method: &str,
        url: String,
        body: Option<Value>,
    ) -> Result<Response, AppError> {
        for attempt in 0..2 {
            let cookie = match &self.cookie {
                Some(c) => c.clone(),
                None => self.login().await?,
            };
            let mut headers = vec![("Cookie".to_owned(), cookie)];
            if body.is_some() {
                headers.push(("Content-Type".into(), "application/json".into()));
            }
            let answer = self
                .transport
                .send(Request {
                    method: method.into(),
                    url: url.clone(),
                    headers,
                    body: body.as_ref().map(Value::to_string),
                })
                .await?;
            // An expired session signs in again, once.
            if answer.status == 401 && attempt == 0 {
                self.cookie = None;
                continue;
            }
            if answer.status >= 400 {
                let message = serde_json::from_str::<Value>(&answer.body)
                    .ok()
                    .and_then(|v| v["error"]["message"]["value"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("status {}", answer.status));
                return Err(AppError::Validation(format!(
                    "SAP Business One refused the call: {message}"
                )));
            }
            return Ok(answer);
        }
        Err(AppError::Validation(
            "SAP Business One refused the session".into(),
        ))
    }

    /// Every record of `kind`.
    pub async fn pull(&mut self, kind: ErpKind) -> Result<Vec<ErpRecord>, AppError> {
        let (resource, select, filter) = resource_of(kind);
        let mut url = format!("{}/{resource}?$select={select}", self.base_url);
        if let Some(filter) = filter {
            url.push_str("&$filter=");
            url.push_str(&filter.replace(' ', "%20").replace('\'', "%27"));
        }
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let answer = self.send("GET", url.clone(), None).await?;
            let page: Value = serde_json::from_str(&answer.body)
                .map_err(|_| AppError::internal("the Service Layer answered no JSON"))?;
            out.extend(
                page["value"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| map_record(kind, r)),
            );
            match page["odata.nextLink"]
                .as_str()
                .or(page["@odata.nextLink"].as_str())
            {
                Some(next) if next.starts_with("http") => url = next.to_owned(),
                Some(next) => url = format!("{}/{}", self.base_url, next.trim_start_matches('/')),
                None => return Ok(out),
            }
        }
        Err(AppError::Validation(
            "SAP Business One paged too many times".into(),
        ))
    }

    /// Creates or patches the business partner of an Attome account; its
    /// card code.
    pub async fn push_customer(
        &mut self,
        fields: &Map<String, Value>,
        card_code: Option<&str>,
    ) -> Result<String, AppError> {
        let mut values = partner_values(fields);
        match card_code {
            Some(code) => {
                self.send(
                    "PATCH",
                    format!("{}/BusinessPartners({})", self.base_url, odata_key(code)),
                    Some(values),
                )
                .await?;
                Ok(code.to_owned())
            }
            None => {
                values["CardType"] = json!("cCustomer");
                let answer = self
                    .send(
                        "POST",
                        format!("{}/BusinessPartners", self.base_url),
                        Some(values),
                    )
                    .await?;
                let created: Value = serde_json::from_str(&answer.body)
                    .map_err(|_| AppError::internal("the Service Layer answered no JSON"))?;
                created["CardCode"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| AppError::internal("the Service Layer gave no CardCode"))
            }
        }
    }
}

/// The resource, `$select` and `$filter` a kind reads.
pub fn resource_of(kind: ErpKind) -> (&'static str, &'static str, Option<&'static str>) {
    match kind {
        ErpKind::Customer => (
            "BusinessPartners",
            "CardCode,CardName,Phone1,EmailAddress,Website",
            Some("CardType eq 'cCustomer'"),
        ),
        ErpKind::Product => ("Items", "ItemCode,ItemName,SalesItem", None),
        ErpKind::Order => ("Orders", "DocEntry,DocNum,DocDate,DocCurrency", None),
        ErpKind::Invoice => (
            "Invoices",
            "DocEntry,DocNum,DocTotal,DocDate,DocDueDate",
            None,
        ),
    }
}

/// A Service Layer row as an Attome record (`None` without its key).
pub fn map_record(kind: ErpKind, row: &Value) -> Option<ErpRecord> {
    let mut f = Map::new();
    let key = match kind {
        ErpKind::Customer => {
            put(&mut f, "name", text(&row["CardName"]));
            put(&mut f, "phone", text(&row["Phone1"]));
            put(&mut f, "website", text(&row["Website"]));
            put(&mut f, "email_domain", email_domain(&row["EmailAddress"]));
            row["CardCode"].as_str()?.to_owned()
        }
        ErpKind::Product => {
            put(&mut f, "name", text(&row["ItemName"]));
            put(&mut f, "sku", text(&row["ItemCode"]));
            if let Some(flag) = row["SalesItem"].as_str() {
                f.insert("is_orderable".into(), Value::Bool(flag == "tYES"));
            }
            row["ItemCode"].as_str()?.to_owned()
        }
        ErpKind::Order => {
            put(
                &mut f,
                "name",
                row["DocNum"].as_i64().map(|n| json!(n.to_string())),
            );
            put(&mut f, "ordered_on", date(&row["DocDate"]));
            put(&mut f, "currency", text(&row["DocCurrency"]));
            row["DocEntry"].as_i64()?.to_string()
        }
        ErpKind::Invoice => {
            put(
                &mut f,
                "invoice_number",
                row["DocNum"].as_i64().map(|n| json!(n.to_string())),
            );
            if let Some(total) = row["DocTotal"].as_f64() {
                f.insert("amount".into(), json!(total));
            }
            put(&mut f, "issued_date", date(&row["DocDate"]));
            put(&mut f, "due_date", date(&row["DocDueDate"]));
            let entry = row["DocEntry"].as_i64()?.to_string();
            f.insert(
                "external_system_id".into(),
                json!(format!("sap_b1:{entry}")),
            );
            entry
        }
    };
    Some(ErpRecord {
        kind,
        external_id: format!("sap_b1:{key}"),
        fields: f,
    })
}

/// An account's fields as business-partner values.
pub fn partner_values(fields: &Map<String, Value>) -> Value {
    let mut values = Map::new();
    for (attome, sap) in [
        ("name", "CardName"),
        ("phone", "Phone1"),
        ("website", "Website"),
    ] {
        if let Some(v) = fields.get(attome).and_then(text) {
            values.insert(sap.to_owned(), v);
        }
    }
    Value::Object(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fixture {
        answers: Mutex<Vec<Response>>,
        seen: Mutex<Vec<Request>>,
    }

    /// A canned answer: status, body and headers.
    type Answer<'a> = (u16, Value, Vec<(&'a str, &'a str)>);

    impl Fixture {
        fn new(answers: Vec<Answer<'_>>) -> Self {
            Fixture {
                answers: Mutex::new(
                    answers
                        .into_iter()
                        .rev()
                        .map(|(status, body, headers)| Response {
                            status,
                            headers: headers
                                .into_iter()
                                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                                .collect(),
                            body: body.to_string(),
                        })
                        .collect(),
                ),
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
            self.seen.lock().unwrap().push(request);
            let answer = self.answers.lock().unwrap().pop();
            Box::pin(async move { answer.ok_or_else(|| AppError::internal("no more answers")) })
        }
    }

    fn login() -> (u16, Value, Vec<(&'static str, &'static str)>) {
        (
            200,
            json!({ "SessionId": "abc", "Version": "1000190", "SessionTimeout": 30 }),
            vec![
                ("Set-Cookie", "B1SESSION=abc; HttpOnly; Secure"),
                ("Set-Cookie", "ROUTEID=.node1; path=/b1s"),
            ],
        )
    }

    #[tokio::test]
    async fn erp_connectors_sap_b1_pulls_pages_and_signs_in_again() {
        let fixture = Fixture::new(vec![
            login(),
            (
                200,
                json!({ "value": [
                { "CardCode": "C20000", "CardName": "Al Noor Trading", "Phone1": "011 444 5555",
                  "EmailAddress": "ap@alnoor.sa", "Website": null }
            ], "odata.nextLink": "BusinessPartners?$skip=20" }),
                vec![],
            ),
            (
                401,
                json!({ "error": { "message": { "value": "Invalid session" } } }),
                vec![],
            ),
            login(),
            (
                200,
                json!({ "value": [{ "CardCode": "C20001", "CardName": "Gulf Steel" }] }),
                vec![],
            ),
        ]);
        let mut sap = SapB1Client::new(
            "https://b1.example.sa:50000/b1s/v1",
            "SBO_PROD",
            "manager",
            Secret::new("pw"),
            &fixture,
        );
        let customers = sap.pull(ErpKind::Customer).await.unwrap();
        assert_eq!(customers.len(), 2);
        assert_eq!(customers[0].external_id, "sap_b1:C20000");
        assert_eq!(customers[0].fields["email_domain"], "alnoor.sa");
        assert!(!customers[0].fields.contains_key("website"));
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.len(), 5, "login, page, expired, login again, page");
        assert!(
            seen[1]
                .headers
                .contains(&("Cookie".into(), "B1SESSION=abc; ROUTEID=.node1".into()))
        );
        assert!(
            seen[1]
                .url
                .contains("$filter=CardType%20eq%20%27cCustomer%27")
        );
        assert_eq!(
            seen[4].url,
            "https://b1.example.sa:50000/b1s/v1/BusinessPartners?$skip=20"
        );
        assert!(!seen[0].body.as_deref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn erp_connectors_sap_b1_maps_items_orders_invoices_and_pushes_customers() {
        let item = map_record(
            ErpKind::Product,
            &json!({ "ItemCode": "A100", "ItemName": "Steel bar", "SalesItem": "tYES" }),
        )
        .unwrap();
        assert_eq!(item.fields["sku"], "A100");
        assert_eq!(item.fields["is_orderable"], true);
        let invoice = map_record(ErpKind::Invoice, &json!({ "DocEntry": 7, "DocNum": 1042, "DocTotal": 2300.5, "DocDate": "2026-10-01T00:00:00Z", "DocDueDate": "2026-10-31" })).unwrap();
        assert_eq!(invoice.fields["invoice_number"], "1042");
        assert_eq!(invoice.fields["issued_date"], "2026-10-01");
        assert_eq!(invoice.external_id, "sap_b1:7");

        let fixture = Fixture::new(vec![
            login(),
            (
                201,
                json!({ "CardCode": "C30000", "CardName": "New Co" }),
                vec![],
            ),
            (204, json!(null), vec![]),
        ]);
        let mut sap = SapB1Client::new(
            "https://b1.example.sa/b1s/v1/",
            "SBO",
            "manager",
            Secret::new("pw"),
            &fixture,
        );
        let mut fields = Map::new();
        fields.insert("name".into(), json!("New Co"));
        assert_eq!(sap.push_customer(&fields, None).await.unwrap(), "C30000");
        assert_eq!(
            sap.push_customer(&fields, Some("C3'0")).await.unwrap(),
            "C3'0"
        );
        let seen = fixture.seen.lock().unwrap();
        assert!(
            seen[1]
                .body
                .as_deref()
                .unwrap()
                .contains("\"CardType\":\"cCustomer\"")
        );
        assert_eq!(seen[2].method, "PATCH");
        assert!(seen[2].url.ends_with("BusinessPartners('C3''0')"));
    }
}
