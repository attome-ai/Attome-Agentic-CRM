//! A24-T1: Dynamics 365 (Dataverse) as a migration source, over the Web API
//! (`/api/data/v9.2`).
//!
//! - The model comes from the Web API's metadata: `EntityDefinitions` lists
//!   the tables (valid for search, or the configured ones), each table's
//!   `Attributes` give its columns and types, and the choice columns'
//!   option sets come from the `PicklistAttributeMetadata` cast.
//! - Records are OData pages of the table's entity set ordered by
//!   `modifiedon` and filtered after `since`, at most
//!   [`PAGE_SIZE`] rows each (`Prefer: odata.maxpagesize`); the cursor is the
//!   page's `@odata.nextLink`, accepted back only on this organisation's
//!   Web API.
//! - Files are the record's notes that carry a document (`annotations`),
//!   each read from its `documentbody`.
//!
//! The access token is a [`Secret`]; when the source refuses it (`401`) and
//! client credentials are configured, a new one is taken once from the
//! token endpoint.

use attome_types::AppError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value};

use super::migration_source::{
    MAX_ENTITIES, MAX_USERS, RateLimit, RecordPage, SourceConnector, SourceEntity, SourceField,
    SourceFile, SourceFuture, SourceModel, SourceRecord, SourceUser, plain_name, send_with_backoff,
};
use crate::connector::sdk::{Request, Response, Secret, Transport};

/// The Web API version read.
pub const API_VERSION: &str = "v9.2";
/// Rows one page asks for.
pub const PAGE_SIZE: u32 = 5_000;

/// Taking a new access token with the app's client credentials.
#[derive(Clone, Debug)]
pub struct ClientCredentials {
    /// `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`.
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Secret,
}

/// A Dataverse organisation read as a migration source.
pub struct DynamicsSource<'a> {
    /// `https://<org>.crm.dynamics.com`.
    pub org_url: String,
    access_token: Secret,
    credentials: Option<ClientCredentials>,
    /// The tables to read, by logical name; empty: every table valid for
    /// search.
    pub tables: Vec<String>,
    transport: &'a dyn Transport,
    limit: RateLimit,
}

impl std::fmt::Debug for DynamicsSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicsSource")
            .field("org_url", &self.org_url)
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

/// The Attome type of a Dataverse column (`AttributeType`, and
/// `AttributeTypeName` for the virtual multi-select choice, files and
/// images). `None`: not migrated (the row id, calculated parts of other
/// columns, partition ids). Pure.
pub fn attome_type(attribute_type: &str, type_name: Option<&str>) -> Option<&'static str> {
    Some(match (attribute_type, type_name) {
        ("Virtual", Some("MultiSelectPicklistType")) => "choice",
        ("Virtual", Some("FileType")) => "file",
        ("Virtual", Some("ImageType")) => "image",
        ("String" | "Memo" | "EntityName", _) => "text",
        ("Integer" | "BigInt" | "Decimal" | "Double", _) => "number",
        ("Money", _) => "currency",
        ("DateTime", _) => "date_time",
        ("Boolean", _) => "bool",
        ("Picklist" | "State" | "Status", _) => "choice",
        ("Lookup" | "Customer" | "Owner", _) => "lookup",
        _ => return None,
    })
}

/// A column of an `Attributes` answer. Pure.
pub fn field_of(a: &Value) -> Option<SourceField> {
    let name = a["LogicalName"].as_str()?;
    if a["IsValidForRead"] == false || a["AttributeOf"].is_string() {
        return None;
    }
    let attribute_type = a["AttributeType"].as_str()?;
    let type_name = a["AttributeTypeName"]["Value"].as_str();
    let attome = attome_type(attribute_type, type_name)?;
    Some(SourceField {
        name: name.to_owned(),
        label: label(&a["DisplayName"]).unwrap_or_else(|| name.to_owned()),
        source_type: type_name.unwrap_or(attribute_type).to_owned(),
        attome_type: attome.to_owned(),
        required: matches!(
            a["RequiredLevel"]["Value"].as_str(),
            Some("ApplicationRequired" | "SystemRequired")
        ),
        lookup_target: a["Targets"][0].as_str().map(str::to_owned),
        choices: Vec::new(),
        multi: type_name == Some("MultiSelectPicklistType"),
    })
}

/// A metadata label's user-language text.
fn label(l: &Value) -> Option<String> {
    l["UserLocalizedLabel"]["Label"]
        .as_str()
        .or(l["LocalizedLabels"][0]["Label"].as_str())
        .map(str::to_owned)
}

/// The OData query of one table's first page. Pure; the names are checked
/// plain beforehand.
pub fn first_page_query(
    entity_set: &str,
    columns: &[String],
    since: Option<DateTime<Utc>>,
) -> String {
    let mut q = format!("{entity_set}?$select={}", columns.join(","));
    if let Some(since) = since {
        q.push_str(&format!(
            "&$filter=modifiedon%20gt%20{}",
            since.to_rfc3339_opts(SecondsFormat::Secs, true)
        ));
    }
    q.push_str("&$orderby=modifiedon%20asc");
    q
}

/// The records of an OData page, by the table's id column. Pure.
pub fn records_of_page(page: &Value, id_column: &str) -> Vec<SourceRecord> {
    page["value"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let row = row.as_object()?;
            let id = row.get(id_column)?.as_str()?.to_owned();
            let fields: Map<String, Value> = row
                .iter()
                .filter(|(k, _)| !k.starts_with('@') && k.as_str() != id_column)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Some(SourceRecord {
                id,
                modified_at: row
                    .get("modifiedon")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                fields,
            })
        })
        .collect()
}

/// Whether `id` is a GUID.
pub fn guid(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

fn encode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

impl<'a> DynamicsSource<'a> {
    pub fn new(
        org_url: &str,
        access_token: Secret,
        credentials: Option<ClientCredentials>,
        transport: &'a dyn Transport,
    ) -> Self {
        DynamicsSource {
            org_url: org_url.trim_end_matches('/').to_owned(),
            access_token,
            credentials,
            tables: Vec::new(),
            transport,
            limit: RateLimit::default(),
        }
    }

    fn api(&self, path: &str) -> String {
        format!("{}/api/data/{API_VERSION}/{path}", self.org_url)
    }

    async fn new_token(&mut self) -> Result<bool, AppError> {
        let Some(c) = self.credentials.clone() else {
            return Ok(false);
        };
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
            encode(&c.client_id),
            encode(c.client_secret.wire_value()),
            encode(&format!("{}/.default", self.org_url)),
        );
        let answer = send_with_backoff(
            self.transport,
            Request {
                method: "POST".into(),
                url: c.token_url.clone(),
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
                "Microsoft Entra ID refused the client credentials".into(),
            ));
        }
        let token: Value = serde_json::from_str(&answer.body)
            .map_err(|_| AppError::internal("the token endpoint answered with no JSON"))?;
        let access = token["access_token"]
            .as_str()
            .ok_or_else(|| AppError::internal("the token endpoint gave no access token"))?;
        self.access_token = Secret::new(access);
        Ok(true)
    }

    /// One GET, signed; a refused token is renewed once.
    async fn get(&mut self, url: String) -> Result<Value, AppError> {
        for attempt in 0..2 {
            let answer: Response = send_with_backoff(
                self.transport,
                Request {
                    method: "GET".into(),
                    url: url.clone(),
                    headers: vec![
                        (
                            "Authorization".into(),
                            format!("Bearer {}", self.access_token.wire_value()),
                        ),
                        ("Accept".into(), "application/json".into()),
                        ("OData-MaxVersion".into(), "4.0".into()),
                        ("OData-Version".into(), "4.0".into()),
                        ("Prefer".into(), format!("odata.maxpagesize={PAGE_SIZE}")),
                    ],
                    body: None,
                },
                &mut self.limit,
            )
            .await?;
            if answer.status == 401 && attempt == 0 && self.new_token().await? {
                continue;
            }
            if answer.status >= 400 {
                let message = serde_json::from_str::<Value>(&answer.body)
                    .ok()
                    .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("status {}", answer.status));
                return Err(AppError::Validation(format!(
                    "Dynamics 365 refused the call: {message}"
                )));
            }
            return serde_json::from_str(&answer.body)
                .map_err(|_| AppError::internal("Dynamics 365 answered with no JSON"));
        }
        Err(AppError::Validation(
            "Dynamics 365 refused the access token".into(),
        ))
    }

    /// One table's definition: (entity set, id column, label, custom).
    async fn definition(
        &mut self,
        table: &str,
    ) -> Result<(String, String, String, bool), AppError> {
        if !plain_name(table) {
            return Err(AppError::Validation(format!(
                "{table:?} is not a Dataverse table name"
            )));
        }
        let d = self
            .get(self.api(&format!(
                "EntityDefinitions(LogicalName='{table}')?$select=LogicalName,EntitySetName,PrimaryIdAttribute,DisplayName,IsCustomEntity"
            )))
            .await?;
        let set = d["EntitySetName"].as_str().filter(|s| plain_name(s));
        let id = d["PrimaryIdAttribute"].as_str().filter(|s| plain_name(s));
        match (set, id) {
            (Some(set), Some(id)) => Ok((
                set.to_owned(),
                id.to_owned(),
                label(&d["DisplayName"]).unwrap_or_else(|| table.to_owned()),
                d["IsCustomEntity"] == true,
            )),
            _ => Err(AppError::internal(format!(
                "Dynamics 365 gave {table} no entity set"
            ))),
        }
    }

    async fn describe(&mut self, table: &str) -> Result<SourceEntity, AppError> {
        let (_, _, table_label, custom) = self.definition(table).await?;
        let attrs = self
            .get(self.api(&format!(
                "EntityDefinitions(LogicalName='{table}')/Attributes?$select=LogicalName,AttributeType,AttributeTypeName,DisplayName,RequiredLevel,IsValidForRead,AttributeOf"
            )))
            .await?;
        let mut fields: Vec<SourceField> = attrs["value"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(field_of)
            .collect();
        // Lookup targets are on the lookup cast only.
        if fields.iter().any(|f| f.attome_type == "lookup") {
            let lookups = self
                .get(self.api(&format!(
                    "EntityDefinitions(LogicalName='{table}')/Attributes/Microsoft.Dynamics.CRM.LookupAttributeMetadata?$select=LogicalName,Targets"
                )))
                .await?;
            for l in lookups["value"].as_array().into_iter().flatten() {
                if let Some(f) = fields
                    .iter_mut()
                    .find(|f| l["LogicalName"] == f.name.as_str())
                {
                    f.lookup_target = l["Targets"][0].as_str().map(str::to_owned);
                }
            }
        }
        if fields.iter().any(|f| f.attome_type == "choice" && !f.multi) {
            let picklists = self
                .get(self.api(&format!(
                    "EntityDefinitions(LogicalName='{table}')/Attributes/Microsoft.Dynamics.CRM.PicklistAttributeMetadata?$select=LogicalName&$expand=OptionSet($select=Options)"
                )))
                .await?;
            for p in picklists["value"].as_array().into_iter().flatten() {
                if let Some(f) = fields
                    .iter_mut()
                    .find(|f| p["LogicalName"] == f.name.as_str())
                {
                    f.choices = p["OptionSet"]["Options"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|o| o["Value"].as_i64().map(|v| v.to_string()))
                        .collect();
                }
            }
        }
        Ok(SourceEntity {
            name: table.to_owned(),
            label: table_label,
            custom,
            fields,
        })
    }

    async fn model(&mut self) -> Result<SourceModel, AppError> {
        let names: Vec<String> = if self.tables.is_empty() {
            let list = self
                .get(self.api(
                    "EntityDefinitions?$select=LogicalName&$filter=IsValidForAdvancedFind%20eq%20true",
                ))
                .await?;
            list["value"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e["LogicalName"].as_str().map(str::to_owned))
                .take(MAX_ENTITIES)
                .collect()
        } else {
            self.tables.clone()
        };
        let mut entities = Vec::with_capacity(names.len());
        for name in names {
            entities.push(self.describe(&name).await?);
        }
        Ok(SourceModel {
            entities,
            users: Vec::new(),
        })
    }

    async fn page(
        &mut self,
        table: &str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
    ) -> Result<RecordPage, AppError> {
        let (set, id_column, _, _) = self.definition(table).await?;
        let url = match cursor {
            // Only a next link of this table on this organisation's Web API.
            Some(c) if c.starts_with(&self.api(&format!("{set}?"))) => c.to_owned(),
            Some(_) => return Err(AppError::InvalidCursor),
            None => {
                let entity = self.describe(table).await?;
                let mut columns: Vec<String> = vec![id_column.clone(), "modifiedon".into()];
                columns.extend(
                    entity
                        .fields
                        .iter()
                        .filter(|f| !matches!(f.attome_type.as_str(), "file" | "image"))
                        .filter(|f| f.name != id_column && f.name != "modifiedon")
                        .map(|f| {
                            // A lookup is read through its value column.
                            if f.attome_type == "lookup" {
                                format!("_{}_value", f.name)
                            } else {
                                f.name.clone()
                            }
                        }),
                );
                self.api(&first_page_query(&set, &columns, since))
            }
        };
        let page = self.get(url).await?;
        Ok(RecordPage {
            records: records_of_page(&page, &id_column),
            next: page["@odata.nextLink"].as_str().map(str::to_owned),
        })
    }

    async fn files(&mut self, record: &str) -> Result<Vec<SourceFile>, AppError> {
        if !guid(record) {
            return Err(AppError::Validation(format!(
                "{record:?} is not a Dataverse row id"
            )));
        }
        let notes = self
            .get(self.api(&format!(
                "annotations?$select=annotationid,filename,mimetype,filesize&$filter=_objectid_value%20eq%20{record}%20and%20isdocument%20eq%20true"
            )))
            .await?;
        Ok(notes["value"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| {
                let id = n["annotationid"].as_str().filter(|i| guid(i))?;
                Some(SourceFile {
                    id: id.to_owned(),
                    name: n["filename"].as_str().unwrap_or("file").to_owned(),
                    content_type: n["mimetype"].as_str().map(str::to_owned),
                    size: n["filesize"].as_i64(),
                    url: self.api(&format!("annotations({id})/documentbody")),
                })
            })
            .collect())
    }
}

impl DynamicsSource<'_> {
    async fn users(&mut self) -> Result<Vec<SourceUser>, AppError> {
        let mut url =
            self.api("systemusers?$select=systemuserid,fullname,internalemailaddress,isdisabled");
        let mut out = Vec::new();
        loop {
            let page = self.get(url).await?;
            out.extend(
                page["value"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|u| {
                        Some(SourceUser {
                            id: u["systemuserid"].as_str()?.to_owned(),
                            name: u["fullname"].as_str().unwrap_or_default().to_owned(),
                            email: u["internalemailaddress"].as_str().map(str::to_owned),
                            active: u["isdisabled"] != true,
                        })
                    }),
            );
            match page["@odata.nextLink"].as_str() {
                Some(next)
                    if out.len() < MAX_USERS && next.starts_with(&self.api("systemusers")) =>
                {
                    url = next.to_owned();
                }
                _ => return Ok(out),
            }
        }
    }
}

impl SourceConnector for DynamicsSource<'_> {
    fn read_users<'a>(&'a mut self) -> SourceFuture<'a, Vec<SourceUser>> {
        Box::pin(self.users())
    }

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

    const API: &str = "https://acme.crm4.dynamics.com/api/data/v9.2";

    fn definition() -> String {
        r#"{"LogicalName": "account", "EntitySetName": "accounts", "PrimaryIdAttribute": "accountid",
            "IsCustomEntity": false, "DisplayName": {"UserLocalizedLabel": {"Label": "Account"}}}"#
            .to_owned()
    }

    const ATTRIBUTES: &str = r#"{"value": [
        {"LogicalName": "accountid", "AttributeType": "Uniqueidentifier", "IsValidForRead": true},
        {"LogicalName": "name", "AttributeType": "String", "IsValidForRead": true,
         "RequiredLevel": {"Value": "ApplicationRequired"},
         "DisplayName": {"UserLocalizedLabel": {"Label": "Account Name"}}},
        {"LogicalName": "revenue", "AttributeType": "Money", "IsValidForRead": true},
        {"LogicalName": "revenue_base", "AttributeType": "Money", "IsValidForRead": true,
         "AttributeOf": "revenue"},
        {"LogicalName": "industrycode", "AttributeType": "Picklist", "IsValidForRead": true},
        {"LogicalName": "parentaccountid", "AttributeType": "Lookup", "IsValidForRead": true},
        {"LogicalName": "modifiedon", "AttributeType": "DateTime", "IsValidForRead": true},
        {"LogicalName": "new_tags", "AttributeType": "Virtual", "IsValidForRead": true,
         "AttributeTypeName": {"Value": "MultiSelectPicklistType"}}
    ]}"#;

    fn describe_answers() -> Vec<(String, u16, String)> {
        vec![
            (format!("{API}/EntityDefinitions(LogicalName='account')?"), 200, definition()),
            (
                format!("{API}/EntityDefinitions(LogicalName='account')/Attributes?"),
                200,
                ATTRIBUTES.to_owned(),
            ),
            (
                format!("{API}/EntityDefinitions(LogicalName='account')/Attributes/Microsoft.Dynamics.CRM.LookupAttributeMetadata"),
                200,
                r#"{"value": [{"LogicalName": "parentaccountid", "Targets": ["account"]}]}"#.to_owned(),
            ),
            (
                format!("{API}/EntityDefinitions(LogicalName='account')/Attributes/Microsoft.Dynamics.CRM.PicklistAttributeMetadata"),
                200,
                r#"{"value": [{"LogicalName": "industrycode", "OptionSet": {"Options": [{"Value": 1}, {"Value": 2}]}}]}"#.to_owned(),
            ),
        ]
    }

    fn recorded(answers: Vec<(String, u16, String)>) -> Recorded {
        Recorded::new(
            answers
                .iter()
                .map(|(p, s, b)| ("GET", p.as_str(), *s, b.as_str(), vec![]))
                .collect(),
        )
    }

    #[tokio::test]
    async fn sources_dynamics_reads_the_model_from_metadata() {
        let source = recorded(describe_answers());
        let mut d = DynamicsSource::new(
            "https://acme.crm4.dynamics.com",
            Secret::new("t"),
            None,
            &source,
        );
        d.tables = vec!["account".into()];
        let model = d.describe_model().await.unwrap();
        let account = &model.entities[0];
        assert_eq!(account.label, "Account");
        let types: Vec<(&str, &str)> = account
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.attome_type.as_str()))
            .collect();
        assert_eq!(
            types,
            [
                ("name", "text"),
                ("revenue", "currency"),
                ("industrycode", "choice"),
                ("parentaccountid", "lookup"),
                ("modifiedon", "date_time"),
                ("new_tags", "choice"),
            ]
        );
        assert!(account.fields[0].required);
        assert_eq!(account.fields[0].label, "Account Name");
        assert_eq!(account.fields[2].choices, ["1", "2"]);
        assert_eq!(account.fields[3].lookup_target.as_deref(), Some("account"));
        assert!(account.fields[5].multi);
    }

    #[tokio::test]
    async fn sources_dynamics_pages_records_by_next_link() {
        let next = format!("{API}/accounts?$select=accountid&$skiptoken=abc");
        let mut answers = vec![(
            format!("{API}/EntityDefinitions(LogicalName='account')?"),
            200,
            definition(),
        )];
        answers.extend(describe_answers());
        answers.push((
            format!("{API}/accounts?$select=accountid,modifiedon,name,revenue,industrycode,_parentaccountid_value,new_tags&$filter=modifiedon%20gt%202026-01-01T00:00:00Z&$orderby=modifiedon%20asc"),
            200,
            format!(
                r#"{{"value": [{{"@odata.etag": "W/1", "accountid": "6f9c7f5e-0000-0000-0000-000000000001",
                    "modifiedon": "2026-01-02T00:00:00Z", "name": "Acme"}}],
                    "@odata.nextLink": "{next}"}}"#
            ),
        ));
        answers.push((
            format!("{API}/EntityDefinitions(LogicalName='account')?"),
            200,
            definition(),
        ));
        answers.push((
            next.clone(),
            200,
            r#"{"value": [{"accountid": "6f9c7f5e-0000-0000-0000-000000000002", "name": "Beta"}]}"#
                .to_owned(),
        ));
        answers.push((
            format!("{API}/EntityDefinitions(LogicalName='account')?"),
            200,
            definition(),
        ));
        let source = recorded(answers);
        let mut d = DynamicsSource::new(
            "https://acme.crm4.dynamics.com/",
            Secret::new("t"),
            None,
            &source,
        );
        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = d.read_records("account", Some(since), None).await.unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].id, "6f9c7f5e-0000-0000-0000-000000000001");
        assert_eq!(
            first.records[0].modified_at.as_deref(),
            Some("2026-01-02T00:00:00Z")
        );
        assert!(!first.records[0].fields.contains_key("@odata.etag"));
        assert_eq!(first.next.as_deref(), Some(next.as_str()));
        let second = d
            .read_records("account", Some(since), first.next.as_deref())
            .await
            .unwrap();
        assert_eq!(second.records[0].fields["name"], "Beta");
        assert_eq!(second.next, None);
        // A cursor that leaves the organisation's Web API is refused.
        assert!(matches!(
            d.read_records("account", None, Some("https://evil.example/accounts?x"))
                .await,
            Err(AppError::InvalidCursor)
        ));
    }

    #[tokio::test]
    async fn sources_dynamics_lists_note_files_and_renews_a_refused_token() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{API}/annotations?"),
                401,
                r#"{"error": {"message": "expired"}}"#,
                vec![],
            ),
            (
                "POST",
                "https://login.microsoftonline.com/t/oauth2/v2.0/token",
                200,
                r#"{"access_token": "new"}"#,
                vec![],
            ),
            (
                "GET",
                &format!("{API}/annotations?"),
                200,
                r#"{"value": [{"annotationid": "6f9c7f5e-0000-0000-0000-0000000000aa",
                   "filename": "quote.pdf", "mimetype": "application/pdf", "filesize": 512}]}"#,
                vec![],
            ),
        ]);
        let mut d = DynamicsSource::new(
            "https://acme.crm4.dynamics.com",
            Secret::new("old"),
            Some(ClientCredentials {
                token_url: "https://login.microsoftonline.com/t/oauth2/v2.0/token".into(),
                client_id: "app".into(),
                client_secret: Secret::new("s"),
            }),
            &source,
        );
        let files = d
            .read_files("account", "6f9c7f5e-0000-0000-0000-000000000001")
            .await
            .unwrap();
        assert_eq!(files[0].name, "quote.pdf");
        assert_eq!(files[0].content_type.as_deref(), Some("application/pdf"));
        assert_eq!(
            files[0].url,
            format!("{API}/annotations(6f9c7f5e-0000-0000-0000-0000000000aa)/documentbody")
        );
        assert_eq!(source.seen.lock().unwrap()[2].headers[0].1, "Bearer new");
        assert!(d.read_files("account", "1 or 1=1").await.is_err());
    }
}
