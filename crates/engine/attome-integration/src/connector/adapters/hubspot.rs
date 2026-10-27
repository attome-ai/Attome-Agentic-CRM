//! A24-T2: HubSpot as a migration source, over the CRM v3 API.
//!
//! - The model is each object's properties (`GET /crm/v3/properties/{object}`)
//!   for the standard objects (contacts, companies, deals, tickets) or the
//!   configured ones; hidden and calculated properties are left out.
//! - Records: without `since`, the object's list (`GET /crm/v3/objects/{object}`);
//!   with it, the search route filtered on the object's last-modified
//!   property and sorted by it. Pages of [`PAGE`] by HubSpot's `after`
//!   cursor; the cursor carries which of the two reads it continues.
//! - Files: the attachments of the notes associated with the record.
//!
//! The private-app token is a [`Secret`].

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::migration_source::{
    RateLimit, RecordPage, SourceConnector, SourceEntity, SourceField, SourceFile, SourceFuture,
    SourceModel, SourceRecord, plain_name, send_with_backoff,
};
use crate::connector::sdk::{Request, Secret, Transport};

/// Records one page asks for (the API's most).
pub const PAGE: u32 = 100;
/// The objects read when none are configured.
pub const STANDARD_OBJECTS: [&str; 4] = ["contacts", "companies", "deals", "tickets"];

/// A HubSpot portal read as a migration source.
pub struct HubSpotSource<'a> {
    /// `https://api.hubapi.com`.
    pub base_url: String,
    token: Secret,
    /// The objects to read; empty: [`STANDARD_OBJECTS`].
    pub objects: Vec<String>,
    transport: &'a dyn Transport,
    limit: RateLimit,
}

impl std::fmt::Debug for HubSpotSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubSpotSource")
            .field("base_url", &self.base_url)
            .field("objects", &self.objects)
            .finish_non_exhaustive()
    }
}

/// The Attome type of a HubSpot property (`type`, `fieldType`, and the
/// number display hint). Pure.
pub fn attome_type(kind: &str, field_type: &str, hint: Option<&str>) -> Option<&'static str> {
    Some(match (kind, field_type) {
        ("string", "html") => "rich_text",
        ("string" | "phone_number", _) => "text",
        ("number", _) if hint == Some("currency") => "currency",
        ("number", _) => "number",
        ("date", _) => "date",
        ("datetime", _) => "date_time",
        ("bool", _) => "bool",
        ("enumeration", _) => "choice",
        _ => return None,
    })
}

/// A property of a properties answer; `None` for hidden, calculated or
/// unmapped ones. Pure.
pub fn field_of(p: &Value) -> Option<SourceField> {
    if p["hidden"] == true || p["calculated"] == true {
        return None;
    }
    let name = p["name"].as_str()?;
    let kind = p["type"].as_str()?;
    let field_type = p["fieldType"].as_str().unwrap_or("");
    let mut attome = attome_type(kind, field_type, p["numberDisplayHint"].as_str())?;
    // The owner is a lookup to the portal's users.
    let lookup_target = p["referencedObjectType"].as_str().map(|t| t.to_lowercase());
    if lookup_target.is_some() {
        attome = "lookup";
    }
    Some(SourceField {
        name: name.to_owned(),
        label: p["label"].as_str().unwrap_or(name).to_owned(),
        source_type: format!("{kind}/{field_type}"),
        attome_type: attome,
        required: false,
        lookup_target,
        choices: if attome == "choice" {
            p["options"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|o| o["hidden"] != true)
                .filter_map(|o| o["value"].as_str().map(str::to_owned))
                .collect()
        } else {
            Vec::new()
        },
        multi: kind == "enumeration" && field_type == "checkbox",
    })
}

/// The property that holds when an object's record last changed.
pub fn modified_property(object: &str) -> &'static str {
    if object == "contacts" {
        "lastmodifieddate"
    } else {
        "hs_lastmodifieddate"
    }
}

/// The records of a list or search answer. Pure.
pub fn records_of(page: &Value) -> Vec<SourceRecord> {
    page["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some(SourceRecord {
                id: r["id"].as_str()?.to_owned(),
                modified_at: r["updatedAt"].as_str().map(str::to_owned),
                fields: r["properties"].as_object().cloned().unwrap_or_default(),
            })
        })
        .collect()
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_digit())
}

impl<'a> HubSpotSource<'a> {
    pub fn new(base_url: &str, token: Secret, transport: &'a dyn Transport) -> Self {
        HubSpotSource {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
            objects: Vec::new(),
            transport,
            limit: RateLimit::default(),
        }
    }

    async fn call(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, AppError> {
        let mut headers = vec![(
            "Authorization".to_owned(),
            format!("Bearer {}", self.token.wire_value()),
        )];
        if body.is_some() {
            headers.push(("Content-Type".into(), "application/json".into()));
        }
        let answer = send_with_backoff(
            self.transport,
            Request {
                method: method.into(),
                url: format!("{}{path}", self.base_url),
                headers,
                body: body.as_ref().map(Value::to_string),
            },
            &mut self.limit,
        )
        .await?;
        if answer.status >= 400 {
            let message = serde_json::from_str::<Value>(&answer.body)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("status {}", answer.status));
            return Err(AppError::Validation(format!(
                "HubSpot refused the call: {message}"
            )));
        }
        serde_json::from_str(&answer.body)
            .map_err(|_| AppError::internal("HubSpot answered with no JSON"))
    }

    async fn describe(&mut self, object: &str) -> Result<SourceEntity, AppError> {
        if !plain_name(object) {
            return Err(AppError::Validation(format!(
                "{object:?} is not a HubSpot object"
            )));
        }
        let props = self
            .call("GET", &format!("/crm/v3/properties/{object}"), None)
            .await?;
        Ok(SourceEntity {
            name: object.to_owned(),
            label: object.to_owned(),
            custom: !STANDARD_OBJECTS.contains(&object),
            fields: props["results"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(field_of)
                .collect(),
        })
    }

    async fn model(&mut self) -> Result<SourceModel, AppError> {
        let objects: Vec<String> = if self.objects.is_empty() {
            STANDARD_OBJECTS.iter().map(|o| (*o).to_owned()).collect()
        } else {
            self.objects.clone()
        };
        let mut entities = Vec::with_capacity(objects.len());
        for object in objects {
            entities.push(self.describe(&object).await?);
        }
        Ok(SourceModel { entities })
    }

    async fn page(
        &mut self,
        object: &str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
    ) -> Result<RecordPage, AppError> {
        // `l:<after>` continues a list, `s:<after>` a search.
        let (search, after) = match cursor {
            Some(c) => match c.split_once(':') {
                Some(("l", a)) if digits(a) => (false, Some(a.to_owned())),
                Some(("s", a)) if digits(a) => (true, Some(a.to_owned())),
                _ => return Err(AppError::InvalidCursor),
            },
            None => (since.is_some(), None),
        };
        let entity = self.describe(object).await?;
        let properties: Vec<&str> = entity.fields.iter().map(|f| f.name.as_str()).collect();
        let page = if search {
            let modified = modified_property(object);
            let mut body = json!({
                "sorts": [{ "propertyName": modified, "direction": "ASCENDING" }],
                "properties": properties,
                "limit": PAGE,
            });
            if let Some(since) = since {
                body["filterGroups"] = json!([{ "filters": [{
                    "propertyName": modified, "operator": "GT",
                    "value": since.timestamp_millis().to_string(),
                }] }]);
            }
            if let Some(after) = &after {
                body["after"] = Value::String(after.clone());
            }
            self.call(
                "POST",
                &format!("/crm/v3/objects/{object}/search"),
                Some(body),
            )
            .await?
        } else {
            let mut path = format!(
                "/crm/v3/objects/{object}?limit={PAGE}&properties={}",
                properties.join(",")
            );
            if let Some(after) = &after {
                path.push_str(&format!("&after={after}"));
            }
            self.call("GET", &path, None).await?
        };
        let next = page["paging"]["next"]["after"]
            .as_str()
            .filter(|a| digits(a))
            .map(|a| format!("{}:{a}", if search { "s" } else { "l" }));
        Ok(RecordPage {
            records: records_of(&page),
            next,
        })
    }

    async fn files(&mut self, object: &str, record: &str) -> Result<Vec<SourceFile>, AppError> {
        if !plain_name(object) || !digits(record) {
            return Err(AppError::Validation("not a HubSpot record".into()));
        }
        let links = self
            .call(
                "GET",
                &format!("/crm/v4/objects/{object}/{record}/associations/notes?limit=500"),
                None,
            )
            .await?;
        let notes: Vec<Value> = links["results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|l| {
                l["toObjectId"]
                    .as_i64()
                    .or_else(|| l["toObjectId"].as_str()?.parse().ok())
            })
            .map(|id| json!({ "id": id.to_string() }))
            .collect();
        if notes.is_empty() {
            return Ok(Vec::new());
        }
        let read = self
            .call(
                "POST",
                "/crm/v3/objects/notes/batch/read",
                Some(json!({ "properties": ["hs_attachment_ids"], "inputs": notes })),
            )
            .await?;
        let mut out = Vec::new();
        for note in read["results"].as_array().into_iter().flatten() {
            let ids = note["properties"]["hs_attachment_ids"]
                .as_str()
                .unwrap_or("");
            for id in ids.split(';').map(str::trim).filter(|i| digits(i)) {
                out.push(SourceFile {
                    id: id.to_owned(),
                    name: id.to_owned(),
                    content_type: None,
                    size: None,
                    url: format!("{}/files/v3/files/{id}/signed-url", self.base_url),
                });
            }
        }
        Ok(out)
    }
}

impl SourceConnector for HubSpotSource<'_> {
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

/// The fields of a record as one map, for tests and callers that do not
/// need the record's id apart.
pub fn flatten(record: &SourceRecord) -> Map<String, Value> {
    let mut all = record.fields.clone();
    all.insert("id".into(), Value::String(record.id.clone()));
    all
}

#[cfg(test)]
mod tests {
    use super::super::migration_source::fixture::Recorded;
    use super::*;

    const API: &str = "https://api.hubapi.com";

    const PROPERTIES: &str = r#"{"results": [
        {"name": "firstname", "label": "First Name", "type": "string", "fieldType": "text"},
        {"name": "notes_html", "label": "Notes", "type": "string", "fieldType": "html"},
        {"name": "annualrevenue", "label": "Revenue", "type": "number", "fieldType": "number",
         "numberDisplayHint": "currency"},
        {"name": "lifecyclestage", "label": "Stage", "type": "enumeration", "fieldType": "select",
         "options": [{"value": "lead"}, {"value": "customer"}, {"value": "old", "hidden": true}]},
        {"name": "interests", "label": "Interests", "type": "enumeration", "fieldType": "checkbox",
         "options": [{"value": "a"}]},
        {"name": "hubspot_owner_id", "label": "Owner", "type": "enumeration", "fieldType": "select",
         "referencedObjectType": "OWNER"},
        {"name": "hs_calculated", "label": "Calc", "type": "number", "fieldType": "calculation_equation",
         "calculated": true},
        {"name": "hs_internal", "label": "Hidden", "type": "string", "fieldType": "text", "hidden": true}
    ]}"#;

    #[tokio::test]
    async fn sources_more_hubspot_reads_properties_and_pages() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{API}/crm/v3/properties/contacts"),
                200,
                PROPERTIES,
                vec![],
            ),
            (
                "GET",
                &format!("{API}/crm/v3/properties/contacts"),
                200,
                PROPERTIES,
                vec![],
            ),
            (
                "POST",
                &format!("{API}/crm/v3/objects/contacts/search"),
                200,
                r#"{"results": [{"id": "51", "updatedAt": "2026-01-02T00:00:00Z",
                    "properties": {"firstname": "Lina"}}], "paging": {"next": {"after": "100"}}}"#,
                vec![("X-HubSpot-RateLimit-Remaining", "99")],
            ),
            (
                "GET",
                &format!("{API}/crm/v3/properties/contacts"),
                200,
                PROPERTIES,
                vec![],
            ),
            (
                "POST",
                &format!("{API}/crm/v3/objects/contacts/search"),
                200,
                r#"{"results": [{"id": "52", "properties": {"firstname": "Omar"}}]}"#,
                vec![],
            ),
        ]);
        let mut hs = HubSpotSource::new(API, Secret::new("pat"), &source);
        hs.objects = vec!["contacts".into()];
        let model = hs.describe_model().await.unwrap();
        let types: Vec<(&str, &str)> = model.entities[0]
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.attome_type))
            .collect();
        assert_eq!(
            types,
            [
                ("firstname", "text"),
                ("notes_html", "rich_text"),
                ("annualrevenue", "currency"),
                ("lifecyclestage", "choice"),
                ("interests", "choice"),
                ("hubspot_owner_id", "lookup"),
            ]
        );
        assert_eq!(model.entities[0].fields[3].choices, ["lead", "customer"]);
        assert!(model.entities[0].fields[4].multi);

        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = hs
            .read_records("contacts", Some(since), None)
            .await
            .unwrap();
        assert_eq!(flatten(&first.records[0])["firstname"], "Lina");
        assert_eq!(first.next.as_deref(), Some("s:100"));
        {
            let seen = source.seen.lock().unwrap();
            let search: Value = serde_json::from_str(seen[2].body.as_deref().unwrap()).unwrap();
            assert_eq!(
                search["filterGroups"][0]["filters"][0]["propertyName"],
                "lastmodifieddate"
            );
            assert_eq!(
                search["filterGroups"][0]["filters"][0]["value"],
                "1767225600000"
            );
        }
        let second = hs
            .read_records("contacts", Some(since), first.next.as_deref())
            .await
            .unwrap();
        assert_eq!(second.records[0].id, "52");
        assert_eq!(second.next, None);
        assert!(matches!(
            hs.read_records("contacts", None, Some("x:1")).await,
            Err(AppError::InvalidCursor)
        ));
    }

    #[tokio::test]
    async fn sources_more_hubspot_lists_note_attachments() {
        let source = Recorded::new(vec![
            (
                "GET",
                &format!("{API}/crm/v4/objects/companies/77/associations/notes"),
                200,
                r#"{"results": [{"toObjectId": 901}]}"#,
                vec![],
            ),
            (
                "POST",
                &format!("{API}/crm/v3/objects/notes/batch/read"),
                200,
                r#"{"results": [{"id": "901", "properties": {"hs_attachment_ids": "11;12"}}]}"#,
                vec![],
            ),
        ]);
        let mut hs = HubSpotSource::new(API, Secret::new("pat"), &source);
        let files = hs.read_files("companies", "77").await.unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[1].url, format!("{API}/files/v3/files/12/signed-url"));
        assert!(hs.read_files("companies", "77 OR 1").await.is_err());
    }
}
