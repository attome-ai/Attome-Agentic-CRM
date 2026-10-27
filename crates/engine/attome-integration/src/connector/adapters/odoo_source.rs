//! A24-T2: Odoo as a migration source, over the same JSON-RPC session as
//! the ERP connector ([`super::odoo::OdooClient`]).
//!
//! - The model is each model's `fields_get` (stored fields only), for the
//!   configured models or [`DEFAULT_MODELS`].
//! - Records are `search_read` pages ordered by `write_date, id`, changed
//!   after `since`, [`PAGE`] at a time; the cursor is the next offset.
//! - Files are the record's `ir.attachment`s, read from `/web/content/{id}`.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::migration_source::{
    RateLimit, RecordPage, SourceConnector, SourceEntity, SourceField, SourceFile, SourceFuture,
    SourceModel, SourceRecord,
};
use super::odoo::OdooClient;

/// Records one page reads.
pub const PAGE: u64 = 500;
/// The models read when none are configured.
pub const DEFAULT_MODELS: [&str; 5] = [
    "res.partner",
    "crm.lead",
    "sale.order",
    "product.product",
    "project.task",
];

/// An Odoo database read as a migration source.
#[derive(Debug)]
pub struct OdooSource<'a> {
    client: OdooClient<'a>,
    /// The models to read; empty: [`DEFAULT_MODELS`].
    pub models: Vec<String>,
}

/// The Attome type of an Odoo field type. `None`: not migrated (one-to-many
/// and many-to-many lists, properties, references). Pure.
pub fn attome_type(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "char" | "text" => "text",
        "html" => "rich_text",
        "integer" | "float" => "number",
        "monetary" => "currency",
        "date" => "date",
        "datetime" => "date_time",
        "boolean" => "bool",
        "selection" => "choice",
        "many2one" => "lookup",
        "binary" | "image" => "file",
        _ => return None,
    })
}

/// The fields of a `fields_get` answer, in name order. Pure.
pub fn fields_of(answer: &Value) -> Vec<SourceField> {
    let Some(fields) = answer.as_object() else {
        return Vec::new();
    };
    fields
        .iter()
        .filter(|(_, f)| f["store"] != false)
        .filter_map(|(name, f)| {
            let kind = f["type"].as_str()?;
            let attome = attome_type(kind)?;
            Some(SourceField {
                name: name.clone(),
                label: f["string"].as_str().unwrap_or(name).to_owned(),
                source_type: kind.to_owned(),
                attome_type: if kind == "image" { "image" } else { attome },
                required: f["required"] == true,
                lookup_target: f["relation"].as_str().map(str::to_owned),
                choices: f["selection"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|pair| pair[0].as_str().map(str::to_owned))
                    .collect(),
                multi: false,
            })
        })
        .collect()
}

/// One record: a many-to-one `[id, "name"]` becomes its id, and `false`
/// (Odoo's empty) becomes `null` except on a yes/no field. Pure.
pub fn record_of(row: &Value, bools: &[&str]) -> Option<SourceRecord> {
    let row = row.as_object()?;
    let id = row.get("id")?.as_i64()?;
    let fields: Map<String, Value> = row
        .iter()
        .filter(|(k, _)| k.as_str() != "id")
        .map(|(k, v)| {
            let v = match v {
                Value::Array(pair)
                    if pair.len() == 2 && pair[0].is_i64() && pair[1].is_string() =>
                {
                    pair[0].clone()
                }
                Value::Bool(false) if !bools.contains(&k.as_str()) => Value::Null,
                other => other.clone(),
            };
            (k.clone(), v)
        })
        .collect();
    Some(SourceRecord {
        id: id.to_string(),
        modified_at: row
            .get("write_date")
            .and_then(Value::as_str)
            .map(str::to_owned),
        fields,
    })
}

/// Whether `model` is an Odoo model name (`res.partner`).
fn model_name(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 128
        && model
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_')
}

impl<'a> OdooSource<'a> {
    pub fn new(client: OdooClient<'a>) -> Self {
        OdooSource {
            client,
            models: Vec::new(),
        }
    }

    async fn describe(&mut self, model: &str) -> Result<SourceEntity, AppError> {
        if !model_name(model) {
            return Err(AppError::Validation(format!(
                "{model:?} is not an Odoo model"
            )));
        }
        let answer = self
            .client
            .execute(
                model,
                "fields_get",
                json!([]),
                json!({ "attributes": ["string", "type", "required", "relation", "selection", "store"] }),
            )
            .await?;
        Ok(SourceEntity {
            name: model.to_owned(),
            label: model.to_owned(),
            custom: model.starts_with("x_"),
            fields: fields_of(&answer),
        })
    }

    async fn model(&mut self) -> Result<SourceModel, AppError> {
        let models: Vec<String> = if self.models.is_empty() {
            DEFAULT_MODELS.iter().map(|m| (*m).to_owned()).collect()
        } else {
            self.models.clone()
        };
        let mut entities = Vec::with_capacity(models.len());
        for model in models {
            entities.push(self.describe(&model).await?);
        }
        Ok(SourceModel { entities })
    }

    async fn page(
        &mut self,
        model: &str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
    ) -> Result<RecordPage, AppError> {
        let offset: u64 = match cursor {
            Some(c) => c.parse().map_err(|_| AppError::InvalidCursor)?,
            None => 0,
        };
        let entity = self.describe(model).await?;
        let mut names: Vec<&str> = vec!["id", "write_date"];
        names.extend(
            entity
                .fields
                .iter()
                .filter(|f| !matches!(f.attome_type, "file" | "image"))
                .map(|f| f.name.as_str())
                .filter(|n| *n != "id" && *n != "write_date"),
        );
        let bools: Vec<&str> = entity
            .fields
            .iter()
            .filter(|f| f.attome_type == "bool")
            .map(|f| f.name.as_str())
            .collect();
        let domain = match since {
            Some(since) => json!([[
                "write_date",
                ">",
                since.format("%Y-%m-%d %H:%M:%S").to_string()
            ]]),
            None => json!([]),
        };
        let rows = self
            .client
            .execute(
                model,
                "search_read",
                json!([domain]),
                json!({ "fields": names, "offset": offset, "limit": PAGE, "order": "write_date asc, id asc" }),
            )
            .await?;
        let rows = rows.as_array().cloned().unwrap_or_default();
        let full = rows.len() as u64 == PAGE;
        Ok(RecordPage {
            records: rows.iter().filter_map(|r| record_of(r, &bools)).collect(),
            next: full.then(|| (offset + PAGE).to_string()),
        })
    }

    async fn files(&mut self, model: &str, record: &str) -> Result<Vec<SourceFile>, AppError> {
        let id: i64 = record
            .parse()
            .map_err(|_| AppError::Validation("not an Odoo record id".into()))?;
        if !model_name(model) {
            return Err(AppError::Validation(format!(
                "{model:?} is not an Odoo model"
            )));
        }
        let rows = self
            .client
            .execute(
                "ir.attachment",
                "search_read",
                json!([[["res_model", "=", model], ["res_id", "=", id]]]),
                json!({ "fields": ["name", "mimetype", "file_size"] }),
            )
            .await?;
        Ok(rows
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                let id = a["id"].as_i64()?;
                Some(SourceFile {
                    id: id.to_string(),
                    name: a["name"].as_str().unwrap_or("file").to_owned(),
                    content_type: a["mimetype"].as_str().map(str::to_owned),
                    size: a["file_size"].as_i64(),
                    url: format!("{}/web/content/{id}", self.client.url),
                })
            })
            .collect())
    }
}

impl SourceConnector for OdooSource<'_> {
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
        RateLimit::default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::migration_source::fixture::Recorded;
    use super::*;
    use crate::connector::sdk::Secret;

    const URL: &str = "https://acme.odoo.com/jsonrpc";

    fn rpc(result: Value) -> String {
        json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    fn fields() -> String {
        rpc(json!({
            "name": {"string": "Name", "type": "char", "required": true, "store": true},
            "is_company": {"string": "Is a Company", "type": "boolean", "store": true},
            "parent_id": {"string": "Related Company", "type": "many2one", "relation": "res.partner", "store": true},
            "type": {"string": "Address Type", "type": "selection",
                     "selection": [["contact", "Contact"], ["invoice", "Invoice Address"]], "store": true},
            "child_ids": {"string": "Contacts", "type": "one2many", "relation": "res.partner", "store": true},
            "display_name": {"string": "Display Name", "type": "char", "store": false},
            "image_1920": {"string": "Image", "type": "image", "store": true}
        }))
    }

    #[tokio::test]
    async fn sources_more_odoo_reads_fields_and_pages_by_offset() {
        let source = Recorded::new(vec![
            ("POST", URL, 200, &rpc(json!(2)), vec![]),
            ("POST", URL, 200, &fields(), vec![]),
            ("POST", URL, 200, &fields(), vec![]),
            (
                "POST",
                URL,
                200,
                &rpc(json!([
                    {"id": 7, "write_date": "2026-01-02 10:00:00", "name": "Acme",
                     "is_company": false, "parent_id": [3, "Holding"], "type": false}
                ])),
                vec![],
            ),
        ]);
        let client = OdooClient::new(
            "https://acme.odoo.com",
            "acme",
            "admin",
            Secret::new("key"),
            &source,
        );
        let mut odoo = OdooSource::new(client);
        odoo.models = vec!["res.partner".into()];
        let model = odoo.describe_model().await.unwrap();
        let fields = &model.entities[0].fields;
        let mut types: Vec<(&str, &str)> = fields
            .iter()
            .map(|f| (f.name.as_str(), f.attome_type))
            .collect();
        types.sort_unstable();
        assert_eq!(
            types,
            [
                ("image_1920", "image"),
                ("is_company", "bool"),
                ("name", "text"),
                ("parent_id", "lookup"),
                ("type", "choice"),
            ]
        );
        let by_name = |n: &str| fields.iter().find(|f| f.name == n).unwrap();
        assert!(by_name("name").required);
        assert_eq!(by_name("type").choices, ["contact", "invoice"]);
        assert_eq!(
            by_name("parent_id").lookup_target.as_deref(),
            Some("res.partner")
        );

        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let page = odoo
            .read_records("res.partner", Some(since), None)
            .await
            .unwrap();
        let acme = &page.records[0];
        assert_eq!(acme.id, "7");
        assert_eq!(acme.fields["parent_id"], 3);
        assert_eq!(acme.fields["is_company"], false);
        assert_eq!(acme.fields["type"], Value::Null);
        assert_eq!(page.next, None);
        let seen = source.seen.lock().unwrap();
        let call: Value = serde_json::from_str(seen[3].body.as_deref().unwrap()).unwrap();
        assert_eq!(
            call["params"]["args"][5][0][0],
            json!(["write_date", ">", "2026-01-01 00:00:00"])
        );
        drop(seen);
        assert!(matches!(
            odoo.read_records("res.partner", None, Some("ten")).await,
            Err(AppError::InvalidCursor)
        ));
    }

    #[tokio::test]
    async fn sources_more_odoo_lists_attachments() {
        let source = Recorded::new(vec![
            ("POST", URL, 200, &rpc(json!(2)), vec![]),
            (
                "POST",
                URL,
                200,
                &rpc(
                    json!([{"id": 41, "name": "quote.pdf", "mimetype": "application/pdf", "file_size": 900}]),
                ),
                vec![],
            ),
        ]);
        let client = OdooClient::new(
            "https://acme.odoo.com/",
            "acme",
            "admin",
            Secret::new("key"),
            &source,
        );
        let mut odoo = OdooSource::new(client);
        let files = odoo.read_files("res.partner", "7").await.unwrap();
        assert_eq!(files[0].url, "https://acme.odoo.com/web/content/41");
        assert_eq!(files[0].size, Some(900));
        assert!(odoo.read_files("res.partner", "7 or 1").await.is_err());
        assert!(odoo.read_files("res.partner;drop", "7").await.is_err());
    }
}
