//! A24-T2: Zoho CRM as a migration source, over the v6 API.
//!
//! - The model is the API-supported modules (`GET /settings/modules`, or the
//!   configured ones) and each one's fields (`GET /settings/fields`).
//! - Records are pages of the module ordered by `Modified_Time`, changed
//!   after `since` (`If-Modified-Since`), [`PAGE`] at a time by Zoho's
//!   `page_token`.
//! - Files are the record's attachments.
//!
//! The access token is a [`Secret`]; on `401` with a refresh token
//! configured it is refreshed once through Zoho's accounts server.

use attome_types::AppError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;

use super::migration_source::{
    MAX_ENTITIES, MAX_USERS, RateLimit, RecordPage, SourceConnector, SourceEntity, SourceField,
    SourceFile, SourceFuture, SourceModel, SourceRecord, SourceUser, plain_name, send_with_backoff,
};
use crate::connector::sdk::{Request, Response, Secret, Transport};

/// Records one page asks for (the API's most).
pub const PAGE: u32 = 200;

/// Refreshing the access token.
#[derive(Clone, Debug)]
pub struct ZohoRefresh {
    /// `https://accounts.zoho.com/oauth/v2/token` (or the data centre's).
    pub token_url: String,
    pub client_id: String,
    pub client_secret: Secret,
    pub refresh_token: Secret,
}

/// A Zoho CRM organisation read as a migration source.
pub struct ZohoSource<'a> {
    /// `https://www.zohoapis.com/crm/v6` (or the data centre's).
    pub api_url: String,
    token: Secret,
    refresh: Option<ZohoRefresh>,
    /// The modules to read, by API name; empty: every API-supported module.
    pub modules: Vec<String>,
    transport: &'a dyn Transport,
    limit: RateLimit,
}

impl std::fmt::Debug for ZohoSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZohoSource")
            .field("api_url", &self.api_url)
            .field("modules", &self.modules)
            .finish_non_exhaustive()
    }
}

/// The Attome type of a Zoho field's `data_type`. `None`: not migrated
/// (formulas, rollups, subforms). Pure.
pub fn attome_type(data_type: &str) -> Option<&'static str> {
    Some(match data_type {
        "text" | "textarea" | "email" | "phone" | "website" | "autonumber" => "text",
        "integer" | "double" | "bigint" | "decimal" | "percent" => "number",
        "currency" => "currency",
        "date" => "date",
        "datetime" => "date_time",
        "boolean" => "bool",
        "picklist" | "multiselectpicklist" => "choice",
        "lookup" | "ownerlookup" | "userlookup" => "lookup",
        "fileupload" => "file",
        "imageupload" | "profileimage" => "image",
        _ => return None,
    })
}

/// A field of a fields answer. Pure.
pub fn field_of(f: &Value) -> Option<SourceField> {
    let name = f["api_name"].as_str()?;
    let data_type = f["data_type"].as_str()?;
    let attome = attome_type(data_type)?;
    let lookup_target = match data_type {
        "lookup" => f["lookup"]["module"]["api_name"]
            .as_str()
            .map(str::to_owned),
        "ownerlookup" | "userlookup" => Some("users".to_owned()),
        _ => None,
    };
    Some(SourceField {
        name: name.to_owned(),
        label: f["field_label"].as_str().unwrap_or(name).to_owned(),
        source_type: data_type.to_owned(),
        attome_type: attome.to_owned(),
        required: f["system_mandatory"] == true,
        lookup_target,
        choices: f["pick_list_values"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["actual_value"].as_str().map(str::to_owned))
            .filter(|v| v != "-None-")
            .collect(),
        multi: data_type == "multiselectpicklist",
    })
}

/// The records of a page. Pure.
pub fn records_of(page: &Value) -> Vec<SourceRecord> {
    page["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let row = r.as_object()?;
            let id = match row.get("id")? {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return None,
            };
            Some(SourceRecord {
                id,
                modified_at: row
                    .get("Modified_Time")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                fields: row
                    .iter()
                    .filter(|(k, _)| k.as_str() != "id" && !k.starts_with('$'))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            })
        })
        .collect()
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_digit())
}

fn encode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

impl<'a> ZohoSource<'a> {
    pub fn new(
        api_url: &str,
        token: Secret,
        refresh: Option<ZohoRefresh>,
        transport: &'a dyn Transport,
    ) -> Self {
        ZohoSource {
            api_url: api_url.trim_end_matches('/').to_owned(),
            token,
            refresh,
            modules: Vec::new(),
            transport,
            limit: RateLimit::default(),
        }
    }

    async fn refresh_token(&mut self) -> Result<bool, AppError> {
        let Some(r) = self.refresh.clone() else {
            return Ok(false);
        };
        let answer = send_with_backoff(
            self.transport,
            Request {
                method: "POST".into(),
                url: format!(
                    "{}?refresh_token={}&client_id={}&client_secret={}&grant_type=refresh_token",
                    r.token_url,
                    encode(r.refresh_token.wire_value()),
                    encode(&r.client_id),
                    encode(r.client_secret.wire_value()),
                ),
                headers: vec![],
                body: None,
            },
            &mut self.limit,
        )
        .await?;
        let token: Value = serde_json::from_str(&answer.body).unwrap_or(Value::Null);
        match token["access_token"].as_str() {
            Some(access) if answer.status < 400 => {
                self.token = Secret::new(access);
                Ok(true)
            }
            _ => Err(AppError::Validation(
                "Zoho refused to refresh the access token".into(),
            )),
        }
    }

    /// One GET, signed; a refused token is refreshed once. A `204` (no
    /// records) is an empty object.
    async fn get(&mut self, path: &str, since: Option<DateTime<Utc>>) -> Result<Value, AppError> {
        for attempt in 0..2 {
            let mut headers = vec![(
                "Authorization".to_owned(),
                format!("Zoho-oauthtoken {}", self.token.wire_value()),
            )];
            if let Some(since) = since {
                headers.push((
                    "If-Modified-Since".into(),
                    since.to_rfc3339_opts(SecondsFormat::Secs, true),
                ));
            }
            let answer: Response = send_with_backoff(
                self.transport,
                Request {
                    method: "GET".into(),
                    url: format!("{}{path}", self.api_url),
                    headers,
                    body: None,
                },
                &mut self.limit,
            )
            .await?;
            if answer.status == 401 && attempt == 0 && self.refresh_token().await? {
                continue;
            }
            if answer.status == 204 || answer.status == 304 {
                return Ok(Value::Object(serde_json::Map::new()));
            }
            if answer.status >= 400 {
                let message = serde_json::from_str::<Value>(&answer.body)
                    .ok()
                    .and_then(|v| v["message"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("status {}", answer.status));
                return Err(AppError::Validation(format!(
                    "Zoho CRM refused the call: {message}"
                )));
            }
            return serde_json::from_str(&answer.body)
                .map_err(|_| AppError::internal("Zoho CRM answered with no JSON"));
        }
        Err(AppError::Validation(
            "Zoho CRM refused the access token".into(),
        ))
    }

    async fn describe(
        &mut self,
        module: &str,
        label: &str,
        custom: bool,
    ) -> Result<SourceEntity, AppError> {
        if !plain_name(module) {
            return Err(AppError::Validation(format!(
                "{module:?} is not a Zoho module"
            )));
        }
        let fields = self
            .get(&format!("/settings/fields?module={module}"), None)
            .await?;
        Ok(SourceEntity {
            name: module.to_owned(),
            label: label.to_owned(),
            custom,
            fields: fields["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(field_of)
                .collect(),
        })
    }

    async fn model(&mut self) -> Result<SourceModel, AppError> {
        let modules: Vec<(String, String, bool)> = if self.modules.is_empty() {
            let list = self.get("/settings/modules", None).await?;
            list["modules"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|m| m["api_supported"] == true)
                .filter_map(|m| {
                    let name = m["api_name"].as_str()?.to_owned();
                    let label = m["plural_label"].as_str().unwrap_or(&name).to_owned();
                    Some((name, label, m["generated_type"] == "custom"))
                })
                .take(MAX_ENTITIES)
                .collect()
        } else {
            self.modules
                .iter()
                .map(|m| (m.clone(), m.clone(), false))
                .collect()
        };
        let mut entities = Vec::with_capacity(modules.len());
        for (name, label, custom) in modules {
            entities.push(self.describe(&name, &label, custom).await?);
        }
        Ok(SourceModel {
            entities,
            users: Vec::new(),
        })
    }

    async fn page(
        &mut self,
        module: &str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
    ) -> Result<RecordPage, AppError> {
        if let Some(c) = cursor
            && !c
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            return Err(AppError::InvalidCursor);
        }
        let entity = self.describe(module, module, false).await?;
        let fields: Vec<&str> = entity
            .fields
            .iter()
            .filter(|f| !matches!(f.attome_type.as_str(), "file" | "image"))
            .map(|f| f.name.as_str())
            .collect();
        let mut path = format!(
            "/{module}?fields={}&sort_by=Modified_Time&sort_order=asc&per_page={PAGE}",
            fields.join(",")
        );
        if let Some(token) = cursor {
            path.push_str(&format!("&page_token={token}"));
        }
        let page = self.get(&path, since).await?;
        let next = (page["info"]["more_records"] == true)
            .then(|| page["info"]["next_page_token"].as_str().map(str::to_owned))
            .flatten();
        Ok(RecordPage {
            records: records_of(&page),
            next,
        })
    }

    async fn files(&mut self, module: &str, record: &str) -> Result<Vec<SourceFile>, AppError> {
        if !plain_name(module) || !digits(record) {
            return Err(AppError::Validation("not a Zoho record".into()));
        }
        let list = self
            .get(
                &format!("/{module}/{record}/Attachments?fields=id,File_Name,Size"),
                None,
            )
            .await?;
        Ok(list["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                let id = a["id"].as_str().filter(|i| digits(i))?;
                Some(SourceFile {
                    id: id.to_owned(),
                    name: a["File_Name"].as_str().unwrap_or("file").to_owned(),
                    content_type: None,
                    size: a["Size"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .or(a["Size"].as_i64()),
                    url: format!("{}/{module}/{record}/Attachments/{id}", self.api_url),
                })
            })
            .collect())
    }
}

impl ZohoSource<'_> {
    async fn users(&mut self) -> Result<Vec<SourceUser>, AppError> {
        let mut out = Vec::new();
        for page in 1..=50 {
            let body = self
                .get(
                    &format!("/users?type=AllUsers&per_page=200&page={page}"),
                    None,
                )
                .await?;
            out.extend(
                body["users"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|u| {
                        let id = match &u["id"] {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            _ => return None,
                        };
                        Some(SourceUser {
                            id,
                            name: u["full_name"].as_str().unwrap_or_default().to_owned(),
                            email: u["email"].as_str().map(str::to_owned),
                            active: u["status"].as_str() != Some("disabled"),
                        })
                    }),
            );
            if body["info"]["more_records"] != true || out.len() >= MAX_USERS {
                break;
            }
        }
        Ok(out)
    }
}

impl SourceConnector for ZohoSource<'_> {
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
        entity: &'a str,
        record_id: &'a str,
    ) -> SourceFuture<'a, Vec<SourceFile>> {
        Box::pin(self.files(entity, record_id))
    }

    fn rate_limit(&self) -> RateLimit {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::super::migration_source::fixture::Recorded;
    use super::*;

    const API: &str = "https://www.zohoapis.sa/crm/v6";

    const FIELDS: &str = r#"{"fields": [
        {"api_name": "Account_Name", "field_label": "Account Name", "data_type": "text", "system_mandatory": true},
        {"api_name": "Annual_Revenue", "field_label": "Annual Revenue", "data_type": "currency"},
        {"api_name": "Industry", "field_label": "Industry", "data_type": "picklist",
         "pick_list_values": [{"actual_value": "-None-"}, {"actual_value": "Banking"}]},
        {"api_name": "Parent_Account", "field_label": "Parent", "data_type": "lookup",
         "lookup": {"module": {"api_name": "Accounts"}}},
        {"api_name": "Owner", "field_label": "Owner", "data_type": "ownerlookup"},
        {"api_name": "Score", "field_label": "Score", "data_type": "formula"}
    ]}"#;

    #[tokio::test]
    async fn sources_more_zoho_reads_modules_fields_and_pages() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{API}/settings/modules"),
                200,
                r#"{"modules": [
                    {"api_name": "Accounts", "plural_label": "Accounts", "api_supported": true, "generated_type": "default"},
                    {"api_name": "Visits", "plural_label": "Visits", "api_supported": false}
                ]}"#,
                vec![],
            ),
            (
                "GET",
                &format!("{API}/settings/fields?module=Accounts"),
                200,
                FIELDS,
                vec![],
            ),
            (
                "GET",
                &format!("{API}/settings/fields?module=Accounts"),
                200,
                FIELDS,
                vec![],
            ),
            (
                "GET",
                &format!(
                    "{API}/Accounts?fields=Account_Name,Annual_Revenue,Industry,Parent_Account,Owner"
                ),
                200,
                r#"{"data": [{"id": "4150868000000224005", "Account_Name": "Acme",
                    "Modified_Time": "2026-01-02T10:00:00+03:00", "$approved": true}],
                    "info": {"more_records": true, "next_page_token": "c8582e7f0e1a"}}"#,
                vec![],
            ),
            (
                "GET",
                &format!("{API}/settings/fields?module=Accounts"),
                200,
                FIELDS,
                vec![],
            ),
            ("GET", &format!("{API}/Accounts?"), 204, "", vec![]),
        ]);
        let mut z = ZohoSource::new(API, Secret::new("tok"), None, &source);
        let model = z.describe_model().await.unwrap();
        assert_eq!(model.entities.len(), 1);
        let types: Vec<(&str, &str)> = model.entities[0]
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.attome_type.as_str()))
            .collect();
        assert_eq!(
            types,
            [
                ("Account_Name", "text"),
                ("Annual_Revenue", "currency"),
                ("Industry", "choice"),
                ("Parent_Account", "lookup"),
                ("Owner", "lookup"),
            ]
        );
        assert!(model.entities[0].fields[0].required);
        assert_eq!(model.entities[0].fields[2].choices, ["Banking"]);
        assert_eq!(
            model.entities[0].fields[4].lookup_target.as_deref(),
            Some("users")
        );

        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = z.read_records("Accounts", Some(since), None).await.unwrap();
        assert_eq!(first.records[0].id, "4150868000000224005");
        assert!(!first.records[0].fields.contains_key("$approved"));
        assert_eq!(first.next.as_deref(), Some("c8582e7f0e1a"));
        {
            let seen = source.seen.lock().unwrap();
            let page = &seen[3];
            assert!(
                page.headers
                    .contains(&("If-Modified-Since".into(), "2026-01-01T00:00:00Z".into()))
            );
            assert_eq!(page.headers[0].1, "Zoho-oauthtoken tok");
        }
        let second = z
            .read_records("Accounts", Some(since), first.next.as_deref())
            .await
            .unwrap();
        assert!(second.records.is_empty());
        assert_eq!(second.next, None);
        assert!(matches!(
            z.read_records("Accounts", None, Some("a&b=c")).await,
            Err(AppError::InvalidCursor)
        ));
    }

    #[tokio::test]
    async fn sources_more_zoho_lists_attachments_and_refreshes_a_refused_token() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{API}/Accounts/4150868000000224005/Attachments"),
                401,
                "{}",
                vec![],
            ),
            (
                "POST",
                "https://accounts.zoho.sa/oauth/v2/token",
                200,
                r#"{"access_token": "fresh"}"#,
                vec![],
            ),
            (
                "GET",
                &format!("{API}/Accounts/4150868000000224005/Attachments"),
                200,
                r#"{"data": [{"id": "4150868000000301001", "File_Name": "contract.pdf", "Size": "2048"}]}"#,
                vec![],
            ),
        ]);
        let mut z = ZohoSource::new(
            API,
            Secret::new("stale"),
            Some(ZohoRefresh {
                token_url: "https://accounts.zoho.sa/oauth/v2/token".into(),
                client_id: "cid".into(),
                client_secret: Secret::new("cs"),
                refresh_token: Secret::new("rt"),
            }),
            &source,
        );
        let files = z
            .read_files("Accounts", "4150868000000224005")
            .await
            .unwrap();
        assert_eq!(files[0].name, "contract.pdf");
        assert_eq!(files[0].size, Some(2048));
        assert_eq!(
            source.seen.lock().unwrap()[2].headers[0].1,
            "Zoho-oauthtoken fresh"
        );
        assert!(z.read_files("Accounts", "1; drop").await.is_err());
    }
}
