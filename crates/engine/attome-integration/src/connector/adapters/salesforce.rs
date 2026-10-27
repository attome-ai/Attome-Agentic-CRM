//! A24-T1: Salesforce as a migration source.
//!
//! - The model comes from REST describe: `GET /sobjects` lists the objects
//!   (queryable, not hidden; or the configured ones), and
//!   `GET /sobjects/{name}/describe` gives each one's fields and types.
//! - Records come from a Bulk API 2.0 query job: `POST /jobs/query` with a
//!   SOQL query over the object's fields, ordered by `SystemModstamp` and
//!   filtered after `since`; the job is polled until `JobComplete`, then
//!   its CSV results are read a page at a time by the `Sforce-Locator` the
//!   source gives. The cursor is `job id:locator`, so a read resumes on the
//!   same job.
//! - Files are the record's `ContentDocumentLink`s, each read from its
//!   latest `ContentVersion`'s `VersionData`.
//!
//! The access token is a [`Secret`]; when the source refuses it (`401`) and
//! a refresh token is configured, it is refreshed once through the OAuth
//! token endpoint.

use attome_types::AppError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value};

use super::migration_source::{
    MAX_ENTITIES, RateLimit, RecordPage, SourceConnector, SourceEntity, SourceField, SourceFile,
    SourceFuture, SourceModel, SourceRecord, csv_rows, header, plain_name, send_with_backoff,
};
use crate::connector::sdk::{Request, Response, Secret, Transport};

/// The REST API version read.
pub const API_VERSION: &str = "v61.0";
/// Rows one results page asks for.
pub const PAGE_ROWS: u32 = 10_000;
/// Times a query job is polled before giving up.
pub const MAX_POLLS: u32 = 120;
/// Seconds between polls of a running job.
pub const POLL_SECS: u64 = 2;

/// Refreshing the access token.
#[derive(Clone)]
pub struct Refresh {
    /// `https://login.salesforce.com/services/oauth2/token` or the org's.
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Secret,
    pub refresh_token: Secret,
}

/// A Salesforce org read as a migration source.
pub struct SalesforceSource<'a> {
    /// `https://<org>.my.salesforce.com`.
    pub instance_url: String,
    access_token: Secret,
    refresh: Option<Refresh>,
    /// The objects to read; empty: every queryable object the org shows.
    pub objects: Vec<String>,
    transport: &'a dyn Transport,
    limit: RateLimit,
}

impl std::fmt::Debug for SalesforceSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SalesforceSource")
            .field("instance_url", &self.instance_url)
            .field("objects", &self.objects)
            .finish_non_exhaustive()
    }
}

/// The Attome type of a Salesforce field (`describe` `type`, and
/// `extraTypeInfo` for rich text and images). `None`: not migrated (the
/// record id, compound address and location fields). Pure.
pub fn attome_type(sf_type: &str, extra: Option<&str>) -> Option<&'static str> {
    Some(match sf_type {
        "string" | "email" | "phone" | "url" | "encryptedstring" | "combobox" => "text",
        "textarea" if extra == Some("richtextarea") => "rich_text",
        "textarea" if extra == Some("imageurl") => "image",
        "textarea" => "text",
        "int" | "double" | "percent" | "long" => "number",
        "currency" => "currency",
        "date" => "date",
        "datetime" => "date_time",
        "time" => "time",
        "boolean" => "bool",
        "picklist" | "multipicklist" => "choice",
        "reference" => "lookup",
        "base64" => "file",
        _ => return None,
    })
}

/// A field of a `describe` answer. Pure.
pub fn field_of(f: &Value) -> Option<SourceField> {
    let name = f["name"].as_str()?;
    let sf_type = f["type"].as_str()?;
    let attome = attome_type(sf_type, f["extraTypeInfo"].as_str())?;
    Some(SourceField {
        name: name.to_owned(),
        label: f["label"].as_str().unwrap_or(name).to_owned(),
        source_type: sf_type.to_owned(),
        attome_type: attome,
        // Required: not nillable, no default and must be given on create.
        required: f["nillable"] == false
            && f["defaultedOnCreate"] == false
            && f["createable"] == true,
        lookup_target: f["referenceTo"][0].as_str().map(str::to_owned),
        choices: f["picklistValues"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| v["active"] != false)
            .filter_map(|v| v["value"].as_str().map(str::to_owned))
            .collect(),
        multi: sf_type == "multipicklist",
    })
}

/// The SOQL query of a Bulk API job over `fields` of `object`, changed after
/// `since`, oldest first. Pure; the names are checked plain beforehand.
pub fn soql(object: &str, fields: &[String], since: Option<DateTime<Utc>>) -> String {
    let mut select: Vec<&str> = vec!["Id", "SystemModstamp"];
    select.extend(
        fields
            .iter()
            .map(String::as_str)
            .filter(|f| *f != "Id" && *f != "SystemModstamp"),
    );
    let mut q = format!("SELECT {} FROM {object}", select.join(", "));
    if let Some(since) = since {
        q.push_str(&format!(
            " WHERE SystemModstamp > {}",
            since.to_rfc3339_opts(SecondsFormat::Secs, true)
        ));
    }
    q.push_str(" ORDER BY SystemModstamp ASC");
    q
}

/// The records of a CSV results page. Pure.
pub fn records_of_csv(text: &str) -> Vec<SourceRecord> {
    let mut rows = csv_rows(text).into_iter();
    let Some(head) = rows.next() else {
        return Vec::new();
    };
    rows.filter(|r| r.len() == head.len())
        .filter_map(|r| {
            let mut fields = Map::new();
            let mut id = None;
            let mut modified = None;
            for (name, value) in head.iter().zip(r) {
                match name.as_str() {
                    "Id" => id = Some(value),
                    "SystemModstamp" => modified = Some(value),
                    _ => {
                        let v = if value.is_empty() {
                            Value::Null
                        } else {
                            Value::String(value)
                        };
                        fields.insert(name.clone(), v);
                    }
                }
            }
            Some(SourceRecord {
                id: id.filter(|i| !i.is_empty())?,
                modified_at: modified.filter(|m| !m.is_empty()),
                fields,
            })
        })
        .collect()
}

/// Whether `id` is a Salesforce record id (15 or 18 letters and digits).
pub fn record_id(id: &str) -> bool {
    (id.len() == 15 || id.len() == 18) && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// `text` as a URL query value.
fn encode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

impl<'a> SalesforceSource<'a> {
    pub fn new(
        instance_url: &str,
        access_token: Secret,
        refresh: Option<Refresh>,
        transport: &'a dyn Transport,
    ) -> Self {
        SalesforceSource {
            instance_url: instance_url.trim_end_matches('/').to_owned(),
            access_token,
            refresh,
            objects: Vec::new(),
            transport,
            limit: RateLimit::default(),
        }
    }

    fn api(&self, path: &str) -> String {
        format!("{}/services/data/{API_VERSION}{path}", self.instance_url)
    }

    async fn refresh_token(&mut self) -> Result<bool, AppError> {
        let Some(refresh) = self.refresh.clone() else {
            return Ok(false);
        };
        let body = format!(
            "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
            encode(&refresh.client_id),
            encode(refresh.client_secret.wire_value()),
            encode(refresh.refresh_token.wire_value()),
        );
        let answer = send_with_backoff(
            self.transport,
            Request {
                method: "POST".into(),
                url: refresh.token_url.clone(),
                headers: vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                body: Some(body),
            },
            &mut self.limit,
        )
        .await?;
        if answer.status >= 400 {
            return Err(AppError::Validation(
                "Salesforce refused to refresh the access token".into(),
            ));
        }
        let token: Value = serde_json::from_str(&answer.body)
            .map_err(|_| AppError::internal("Salesforce answered the token call with no JSON"))?;
        let access = token["access_token"]
            .as_str()
            .ok_or_else(|| AppError::internal("Salesforce gave no access token"))?;
        self.access_token = Secret::new(access);
        Ok(true)
    }

    /// One call, signed; a refused token is refreshed once.
    async fn call(
        &mut self,
        method: &str,
        url: String,
        body: Option<Value>,
        accept: &str,
    ) -> Result<Response, AppError> {
        for attempt in 0..2 {
            let mut headers = vec![
                (
                    "Authorization".to_owned(),
                    format!("Bearer {}", self.access_token.wire_value()),
                ),
                ("Accept".to_owned(), accept.to_owned()),
            ];
            if body.is_some() {
                headers.push(("Content-Type".into(), "application/json".into()));
            }
            let answer = send_with_backoff(
                self.transport,
                Request {
                    method: method.into(),
                    url: url.clone(),
                    headers,
                    body: body.as_ref().map(Value::to_string),
                },
                &mut self.limit,
            )
            .await?;
            if answer.status == 401 && attempt == 0 && self.refresh_token().await? {
                continue;
            }
            if answer.status >= 400 {
                let message = serde_json::from_str::<Value>(&answer.body)
                    .ok()
                    .and_then(|v| v[0]["message"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("status {}", answer.status));
                return Err(AppError::Validation(format!(
                    "Salesforce refused the call: {message}"
                )));
            }
            return Ok(answer);
        }
        Err(AppError::Validation(
            "Salesforce refused the access token".into(),
        ))
    }

    async fn json(
        &mut self,
        method: &str,
        url: String,
        body: Option<Value>,
    ) -> Result<Value, AppError> {
        let answer = self.call(method, url, body, "application/json").await?;
        serde_json::from_str(&answer.body)
            .map_err(|_| AppError::internal("Salesforce answered with no JSON"))
    }

    async fn describe(&mut self, object: &str) -> Result<SourceEntity, AppError> {
        if !plain_name(object) {
            return Err(AppError::Validation(format!(
                "{object:?} is not a Salesforce object name"
            )));
        }
        let d = self
            .json(
                "GET",
                self.api(&format!("/sobjects/{object}/describe")),
                None,
            )
            .await?;
        Ok(SourceEntity {
            name: object.to_owned(),
            label: d["label"].as_str().unwrap_or(object).to_owned(),
            custom: d["custom"] == true,
            fields: d["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(field_of)
                .collect(),
        })
    }

    async fn model(&mut self) -> Result<SourceModel, AppError> {
        let names: Vec<String> = if self.objects.is_empty() {
            let list = self.json("GET", self.api("/sobjects"), None).await?;
            list["sobjects"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|o| o["queryable"] == true && o["deprecatedAndHidden"] != true)
                .filter(|o| o["layoutable"] == true || o["custom"] == true)
                .filter_map(|o| o["name"].as_str().map(str::to_owned))
                .take(MAX_ENTITIES)
                .collect()
        } else {
            self.objects.clone()
        };
        let mut entities = Vec::with_capacity(names.len());
        for name in names {
            entities.push(self.describe(&name).await?);
        }
        Ok(SourceModel { entities })
    }

    /// Starts the query job of a first page and waits for it.
    async fn start_job(
        &mut self,
        object: &str,
        since: Option<DateTime<Utc>>,
    ) -> Result<String, AppError> {
        let entity = self.describe(object).await?;
        let fields: Vec<String> = entity
            .fields
            .iter()
            .filter(|f| f.attome_type != "file")
            .map(|f| f.name.clone())
            .collect();
        let job = self
            .json(
                "POST",
                self.api("/jobs/query"),
                Some(serde_json::json!({
                    "operation": "query",
                    "query": soql(object, &fields, since),
                })),
            )
            .await?;
        let id = job["id"]
            .as_str()
            .filter(|i| plain_name(i))
            .ok_or_else(|| AppError::internal("Salesforce gave the query job no id"))?
            .to_owned();
        for poll in 0..MAX_POLLS {
            let state = self
                .json("GET", self.api(&format!("/jobs/query/{id}")), None)
                .await?;
            match state["state"].as_str() {
                Some("JobComplete") => return Ok(id),
                Some("Failed" | "Aborted") => {
                    return Err(AppError::Validation(format!(
                        "the Salesforce query job stopped: {}",
                        state["errorMessage"].as_str().unwrap_or("no reason given")
                    )));
                }
                _ if poll + 1 < MAX_POLLS => {
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_SECS)).await;
                }
                _ => {}
            }
        }
        Err(AppError::Validation(
            "the Salesforce query job did not finish in time; read again to resume".into(),
        ))
    }

    async fn page(
        &mut self,
        object: &str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
    ) -> Result<RecordPage, AppError> {
        let (job, locator) = match cursor {
            Some(c) => {
                let (job, locator) = c.split_once(':').unwrap_or((c, ""));
                if !plain_name(job) || !locator.chars().all(|ch| ch.is_ascii_alphanumeric()) {
                    return Err(AppError::InvalidCursor);
                }
                (job.to_owned(), locator.to_owned())
            }
            None => (self.start_job(object, since).await?, String::new()),
        };
        let mut url = self.api(&format!("/jobs/query/{job}/results?maxRecords={PAGE_ROWS}"));
        if !locator.is_empty() {
            url.push_str(&format!("&locator={locator}"));
        }
        let answer = self.call("GET", url, None, "text/csv").await?;
        let next = header(&answer, "sforce-locator")
            .map(str::trim)
            .filter(|l| !l.is_empty() && *l != "null")
            .map(|l| format!("{job}:{l}"));
        Ok(RecordPage {
            records: records_of_csv(&answer.body),
            next,
        })
    }

    async fn files(&mut self, record: &str) -> Result<Vec<SourceFile>, AppError> {
        if !record_id(record) {
            return Err(AppError::Validation(format!(
                "{record:?} is not a Salesforce record id"
            )));
        }
        let q = format!(
            "SELECT ContentDocumentId, ContentDocument.Title, ContentDocument.FileExtension, \
             ContentDocument.ContentSize, ContentDocument.LatestPublishedVersionId \
             FROM ContentDocumentLink WHERE LinkedEntityId = '{record}'"
        );
        let answer = self
            .json("GET", self.api(&format!("/query?q={}", encode(&q))), None)
            .await?;
        Ok(answer["records"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| {
                let doc = &r["ContentDocument"];
                let version = doc["LatestPublishedVersionId"].as_str()?;
                let title = doc["Title"].as_str().unwrap_or("file");
                let name = match doc["FileExtension"].as_str() {
                    Some(ext) if !ext.is_empty() => format!("{title}.{ext}"),
                    _ => title.to_owned(),
                };
                Some(SourceFile {
                    id: r["ContentDocumentId"]
                        .as_str()
                        .unwrap_or(version)
                        .to_owned(),
                    name,
                    content_type: None,
                    size: doc["ContentSize"].as_i64(),
                    url: self.api(&format!("/sobjects/ContentVersion/{version}/VersionData")),
                })
            })
            .collect())
    }
}

impl SourceConnector for SalesforceSource<'_> {
    fn describe_model<'a>(&'a mut self) -> SourceFuture<'a, SourceModel> {
        Box::pin(self.model())
    }

    fn read_records<'a>(
        &'a mut self,
        entity: &'a str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&'a str>,
    ) -> SourceFuture<'a, RecordPage> {
        Box::pin(self.page(entity, since, cursor))
    }

    fn read_files<'a>(
        &'a mut self,
        _entity: &'a str,
        record_id: &'a str,
    ) -> SourceFuture<'a, Vec<SourceFile>> {
        Box::pin(self.files(record_id))
    }

    fn rate_limit(&self) -> RateLimit {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::super::migration_source::fixture::Recorded;
    use super::*;

    const ORG: &str = "https://acme.my.salesforce.com/services/data/v61.0";

    const DESCRIBE: &str = r#"{
      "name": "Account", "label": "Account", "custom": false,
      "fields": [
        {"name": "Id", "label": "Account ID", "type": "id", "nillable": false},
        {"name": "Name", "label": "Account Name", "type": "string", "nillable": false,
         "defaultedOnCreate": false, "createable": true},
        {"name": "Industry", "label": "Industry", "type": "picklist", "nillable": true,
         "picklistValues": [{"value": "Banking", "active": true}, {"value": "Old", "active": false}]},
        {"name": "AnnualRevenue", "label": "Annual Revenue", "type": "currency", "nillable": true},
        {"name": "ParentId", "label": "Parent Account", "type": "reference", "nillable": true,
         "referenceTo": ["Account"]},
        {"name": "Description", "label": "Description", "type": "textarea",
         "extraTypeInfo": "richtextarea", "nillable": true},
        {"name": "BillingAddress", "label": "Billing Address", "type": "address", "nillable": true}
      ]
    }"#;

    #[tokio::test]
    async fn sources_salesforce_reads_the_model_from_describe() {
        let source = Recorded::new(vec![
            (
                "GET",
                "https://acme.my.salesforce.com/services/data/v61.0/sobjects/Account/describe",
                200,
                DESCRIBE,
                vec![],
            ),
            (
                "GET",
                "https://acme.my.salesforce.com/services/data/v61.0/sobjects",
                200,
                r#"{"sobjects": [
                    {"name": "Account", "queryable": true, "layoutable": true},
                    {"name": "AccountHistory", "queryable": true, "layoutable": false},
                    {"name": "Legacy__c", "queryable": true, "custom": true, "deprecatedAndHidden": true}
                ]}"#,
                vec![],
            ),
        ]);
        let mut sf = SalesforceSource::new(
            "https://acme.my.salesforce.com/",
            Secret::new("token"),
            None,
            &source,
        );
        let model = sf.describe_model().await.unwrap();
        assert_eq!(model.entities.len(), 1);
        let account = &model.entities[0];
        let types: Vec<(&str, &str)> = account
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.attome_type))
            .collect();
        assert_eq!(
            types,
            [
                ("Name", "text"),
                ("Industry", "choice"),
                ("AnnualRevenue", "currency"),
                ("ParentId", "lookup"),
                ("Description", "rich_text"),
            ]
        );
        assert!(account.fields[0].required);
        assert_eq!(account.fields[1].choices, ["Banking"]);
        assert_eq!(account.fields[3].lookup_target.as_deref(), Some("Account"));
        let seen = source.seen.lock().unwrap();
        assert_eq!(
            seen[0].headers[0],
            ("Authorization".into(), "Bearer token".into())
        );
    }

    #[tokio::test]
    async fn sources_salesforce_reads_records_by_bulk_query_and_resumes() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{ORG}/sobjects/Account/describe"),
                200,
                DESCRIBE,
                vec![],
            ),
            (
                "POST",
                &format!("{ORG}/jobs/query"),
                200,
                r#"{"id": "750R0000000zLfMIAU"}"#,
                vec![],
            ),
            (
                "GET",
                &format!("{ORG}/jobs/query/750R0000000zLfMIAU/results"),
                200,
                "\"Id\",\"SystemModstamp\",\"Name\",\"Industry\"\n\
                 \"001A\",\"2026-01-02T10:00:00.000Z\",\"Acme, Inc\",\"Banking\"\n",
                vec![("Sforce-Locator", "MTAwMDA")],
            ),
            (
                "GET",
                &format!("{ORG}/jobs/query/750R0000000zLfMIAU"),
                200,
                r#"{"state": "JobComplete"}"#,
                vec![],
            ),
            (
                "GET",
                &format!(
                    "{ORG}/jobs/query/750R0000000zLfMIAU/results?maxRecords=10000&locator=MTAwMDA"
                ),
                200,
                "\"Id\",\"SystemModstamp\",\"Name\",\"Industry\"\n\"001B\",\"2026-01-03T10:00:00.000Z\",\"Beta\",\"\"\n",
                vec![("Sforce-Locator", "null")],
            ),
        ]);
        let mut sf = SalesforceSource::new(
            "https://acme.my.salesforce.com",
            Secret::new("token"),
            None,
            &source,
        );
        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = sf.read_records("Account", Some(since), None).await.unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].id, "001A");
        assert_eq!(first.records[0].fields["Name"], "Acme, Inc");
        assert_eq!(first.next.as_deref(), Some("750R0000000zLfMIAU:MTAwMDA"));
        {
            let seen = source.seen.lock().unwrap();
            let job = seen.iter().find(|r| r.method == "POST").unwrap();
            let query: Value = serde_json::from_str(job.body.as_deref().unwrap()).unwrap();
            assert_eq!(
                query["query"],
                "SELECT Id, SystemModstamp, Name, Industry, AnnualRevenue, ParentId, Description \
                 FROM Account WHERE SystemModstamp > 2026-01-01T00:00:00Z ORDER BY SystemModstamp ASC"
            );
        }
        let second = sf
            .read_records("Account", Some(since), first.next.as_deref())
            .await
            .unwrap();
        assert_eq!(second.records[0].fields["Industry"], Value::Null);
        assert_eq!(second.next, None);
        assert!(matches!(
            sf.read_records("Account", None, Some("bad job:x")).await,
            Err(AppError::InvalidCursor)
        ));
    }

    #[tokio::test]
    async fn sources_salesforce_lists_files_and_refreshes_a_refused_token() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{ORG}/query"),
                401,
                r#"[{"message": "Session expired"}]"#,
                vec![],
            ),
            (
                "POST",
                "https://login.salesforce.com/services/oauth2/token",
                200,
                r#"{"access_token": "fresh"}"#,
                vec![],
            ),
            (
                "GET",
                &format!("{ORG}/query"),
                200,
                r#"{"records": [{"ContentDocumentId": "069A", "ContentDocument": {
                    "Title": "Contract", "FileExtension": "pdf", "ContentSize": 2048,
                    "LatestPublishedVersionId": "068A"}}]}"#,
                vec![],
            ),
        ]);
        let mut sf = SalesforceSource::new(
            "https://acme.my.salesforce.com",
            Secret::new("stale"),
            Some(Refresh {
                token_url: "https://login.salesforce.com/services/oauth2/token".into(),
                client_id: "cid".into(),
                client_secret: Secret::new("cs"),
                refresh_token: Secret::new("rt"),
            }),
            &source,
        );
        let files = sf
            .read_files("Account", "001000000000001AAA")
            .await
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "Contract.pdf");
        assert_eq!(files[0].size, Some(2048));
        assert_eq!(
            files[0].url,
            format!("{ORG}/sobjects/ContentVersion/068A/VersionData")
        );
        let seen = source.seen.lock().unwrap();
        assert_eq!(seen[2].headers[0].1, "Bearer fresh");
        drop(seen);
        assert!(sf.read_files("Account", "001' OR Id != '").await.is_err());
    }
}
