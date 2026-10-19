//! K3-T1: a document template renders through the one template language
//! (Z13, `attome_html::tmpl`) before PDF conversion: `{{ field | filter }}`
//! outputs with region formats (`currency('SAR')`, `hijri`, `date`,
//! `number`, `digits`), `{% if %}` and `{% for line in invoice_line limit 100
//! %}` over related records, and `{% dir %}` for right-to-left blocks.
//!
//! Every value comes from the requesting user's own reads, never a wider
//! one: the record through `crate::merge::build_context` (record- and
//! field-level security, so a field the user cannot read is absent and
//! renders empty), and each related list through the stored-query engine's
//! entity list (`execute_stored_query`) under the same `SecurityContext`,
//! so only the child records and fields that user may read are there.
//!
//! A related list is the child entity's logical name (`invoice_line`), for
//! every entity with a lookup to this one that the template names; at most
//! [`MAX_CHILD_ROWS`] rows each, oldest first. `zatca_qr` is the ZATCA
//! simplified-invoice QR (seller name, VAT number, time, total with VAT, VAT
//! total as base64 TLV, drawn as an SVG `data:` URI for an `<img src>`), when
//! the template names it and the record has `grand_total` and `vat_total`.
//! `brand_app_name`, `brand_logo_url` and `brand_primary` are the deployment
//! brand, as before.

use attome_core::{AttrInfo, EngineState, Filter};
use attome_html::tmpl::{Output, RenderContext, Template};
use attome_rules::{Context as RulesContext, Schema, Type, Value as RulesValue};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// Most rows one related list carries into a document.
pub const MAX_CHILD_ROWS: i64 = 200;
/// The brand fields every document may use.
const BRAND_FIELDS: [&str; 3] = ["brand_app_name", "brand_logo_url", "brand_primary"];
/// The field a template names for the ZATCA QR.
pub const ZATCA_QR_FIELD: &str = "zatca_qr";

/// Whether `source` names `word` as a whole identifier.
pub fn mentions(source: &str, word: &str) -> bool {
    let bytes = source.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    source.match_indices(word).any(|(at, _)| {
        let before = at.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(at + word.len()).copied();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

/// The ZATCA simplified-invoice QR payload: five TLV fields (tag, length,
/// UTF-8 value), base64. `None` when a value is longer than one TLV field
/// can carry (255 bytes).
pub fn zatca_tlv(
    seller_name: &str,
    vat_number: &str,
    timestamp: DateTime<Utc>,
    total_with_vat: f64,
    vat_total: f64,
) -> Option<String> {
    let fields = [
        seller_name.to_owned(),
        vat_number.to_owned(),
        timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        format!("{total_with_vat:.2}"),
        format!("{vat_total:.2}"),
    ];
    let mut bytes = Vec::new();
    for (tag, value) in (1u8..).zip(fields.iter()) {
        let len = u8::try_from(value.len()).ok()?;
        bytes.push(tag);
        bytes.push(len);
        bytes.extend_from_slice(value.as_bytes());
    }
    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// `payload` drawn as a QR code, as an SVG `data:` URI for `<img src>`.
pub fn qr_data_uri(payload: &str) -> Result<String, AppError> {
    let code = qrcode::QrCode::new(payload.as_bytes())
        .map_err(|e| AppError::Validation(format!("the QR payload cannot be drawn: {e}")))?;
    let svg = code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(160, 160)
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())
    ))
}

/// One related list: the child entity, the lookup that points at the
/// record, and the child's fields.
#[derive(Debug, Clone)]
struct ChildList {
    entity: String,
    lookup: String,
    attrs: Vec<AttrInfo>,
}

/// The fields of `attrs` a template can read, in order, with their types.
fn record_fields(attrs: &[AttrInfo]) -> Vec<(String, Type)> {
    attrs
        .iter()
        .filter_map(|attr| {
            attome_records::rule_engine::rules_type_of(attr)
                .map(|ty| (attr.logicalname.clone(), ty))
        })
        .collect()
}

/// One child row as a template record: every readable field in schema
/// order, null where the row lacks it (not readable, or empty).
fn record_value(attrs: &[AttrInfo], row: &serde_json::Map<String, Value>) -> RulesValue {
    RulesValue::Record(
        attrs
            .iter()
            .filter(|attr| attome_records::rule_engine::rules_type_of(attr).is_some())
            .map(|attr| {
                (
                    attr.logicalname.clone(),
                    attome_records::rule_engine::rules_value_of_attr(
                        attr,
                        row.get(&attr.logicalname),
                    ),
                )
            })
            .collect(),
    )
}

/// The schema and values a document template renders against.
#[derive(Debug)]
pub struct DocumentInput {
    pub schema: Schema,
    pub values: RulesContext,
    /// The record's own `language` (`ar`, `en`...), when it has one: an
    /// invoice is written in its customer's language.
    pub language: Option<String>,
}

/// The pure half of [`build_input`]: the record's fields, the brand, the
/// related lists already read and the QR, as one schema and context.
fn assemble(
    now: DateTime<Utc>,
    attrs: &[AttrInfo],
    data: &serde_json::Map<String, Value>,
    children: &[(ChildList, Vec<serde_json::Map<String, Value>>)],
    zatca_qr: Option<String>,
) -> DocumentInput {
    let mut schema = attome_records::rule_engine::schema_for_entity(attrs);
    let mut values = attome_records::rule_engine::context_for_record(now, attrs, data);
    let own: Vec<&str> = attrs.iter().map(|a| a.logicalname.as_str()).collect();
    for brand in BRAND_FIELDS {
        if own.contains(&brand) {
            continue;
        }
        schema = schema.with_field(brand, Type::Text);
        values = values.with_field(
            brand,
            data.get(brand)
                .and_then(Value::as_str)
                .map_or(RulesValue::Null, |s| RulesValue::Text(s.to_owned())),
        );
    }
    for (child, rows) in children {
        let fields = record_fields(&child.attrs);
        schema = schema.with_field(
            child.entity.clone(),
            Type::List(Box::new(Type::Record(fields))),
        );
        values = values.with_field(
            child.entity.clone(),
            RulesValue::List(
                rows.iter()
                    .map(|row| record_value(&child.attrs, row))
                    .collect(),
            ),
        );
    }
    if !own.contains(&ZATCA_QR_FIELD) {
        schema = schema.with_field(ZATCA_QR_FIELD, Type::Text);
        values = values.with_field(
            ZATCA_QR_FIELD,
            zatca_qr.map_or(RulesValue::Null, RulesValue::Text),
        );
    }
    let language = data
        .get("language")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.len() <= 16)
        .map(str::to_owned);
    DocumentInput {
        schema,
        values,
        language,
    }
}

/// The entities with a lookup to `entity_id` that `source` names, with that
/// lookup; an entity named like one of the record's own fields is left out.
fn child_lists(
    state: &EngineState,
    entity_id: Uuid,
    source: &str,
    own: &[AttrInfo],
) -> Vec<ChildList> {
    let registry = state.entities.load();
    registry
        .iter()
        .filter(|meta| mentions(source, &meta.logicalname))
        .filter(|meta| !own.iter().any(|a| a.logicalname == meta.logicalname))
        .filter_map(|meta| {
            let lookup = meta
                .attrs
                .iter()
                .find(|a| a.lookup_entity_ref == Some(entity_id))?;
            Some(ChildList {
                entity: meta.logicalname.clone(),
                lookup: lookup.logicalname.clone(),
                attrs: meta.attrs.clone(),
            })
        })
        .collect()
}

/// The child rows `security` may read, oldest first, at most
/// [`MAX_CHILD_ROWS`].
async fn read_children(
    state: &EngineState,
    security: &SecurityContext,
    child: &ChildList,
    record_id: Uuid,
) -> Result<Vec<serde_json::Map<String, Value>>, AppError> {
    let filter: Filter = serde_json::from_value(serde_json::json!({
        "field": child.lookup,
        "op": "eq",
        "value": record_id.to_string(),
    }))
    .map_err(AppError::internal)?;
    let request = attome_records::query_exec::ExecuteQueryRequest::for_entity_list(
        child.entity.clone(),
        vec![filter],
        "created_at".to_owned(),
        "asc".to_owned(),
        MAX_CHILD_ROWS,
        None,
        None,
    );
    let page = attome_records::query_exec::execute_stored_query(state, security, request)
        .await?
        .into_cursor_page();
    Ok(page
        .items
        .into_iter()
        .filter_map(|row| match row {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .collect())
}

/// The ZATCA QR for the record, from the seller settings and the record's
/// totals, or `None` when any of them is missing.
fn zatca_qr_for(state: &EngineState, data: &serde_json::Map<String, Value>) -> Option<String> {
    let setting = |key: &str| {
        attome_core::setting_registry().get(key).and_then(|d| {
            let (value, _) = state.settings.load().resolve(d, None, None);
            value
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        })
    };
    let seller = setting("billing.seller_name")?;
    let vat_number = setting("billing.seller_vat_number")?;
    let number = |key: &str| {
        data.get(key).and_then(|v| match v {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        })
    };
    let total = number("grand_total")?;
    let vat = number("vat_total")?;
    let at = data
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map_or_else(Utc::now, |d| d.with_timezone(&Utc));
    let payload = zatca_tlv(&seller, &vat_number, at, total, vat)?;
    qr_data_uri(&payload).ok()
}

/// Reads everything `source` needs for one record as `security`.
pub async fn build_input(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    record_id: Uuid,
    source: &str,
) -> Result<DocumentInput, AppError> {
    let merge = crate::merge::build_context(state, security, entity, record_id).await?;
    let (entity_id, _, attrs, _) =
        attome_records::entity_crud::resolve_entity(state, entity).await?;
    let mut children = Vec::new();
    for child in child_lists(state, entity_id, source, &attrs) {
        let rows = read_children(state, security, &child, record_id).await?;
        children.push((child, rows));
    }
    let qr = if mentions(source, ZATCA_QR_FIELD) {
        zatca_qr_for(state, &merge.data)
    } else {
        None
    };
    Ok(assemble(Utc::now(), &attrs, &merge.data, &children, qr))
}

/// Compiles and renders `source` as HTML for `locale` (`ar-SA`, `en`...).
pub fn render_document(
    source: &str,
    input: DocumentInput,
    locale: &str,
) -> Result<String, AppError> {
    let template = Template::compile(source, &input.schema)
        .map_err(|e| AppError::Validation(format!("{}: {e}", e.code())))?;
    template
        .render(&RenderContext::new(
            input.values,
            locale.to_owned(),
            Output::Html,
        ))
        .map_err(|e| AppError::Validation(format!("{}: {e}", e.code())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(name: &str, field_type_int: i32) -> AttrInfo {
        serde_json::from_value(serde_json::json!({
            "logicalname": name,
            "field_type_int": field_type_int,
            "is_sensitive": false,
            "is_sortable": false,
            "is_filterable": false,
        }))
        .unwrap_or_else(|e| panic!("AttrInfo: {e}"))
    }

    fn map(value: Value) -> serde_json::Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => serde_json::Map::new(),
        }
    }

    /// An invoice with two lines; `secret_note` is not in the data, as a
    /// field the reader may not see is not.
    fn invoice() -> DocumentInput {
        let attrs = vec![
            attr("number", 0),
            attr("customer", 0),
            attr("grand_total", 2),
            attr("secret_note", 0),
        ];
        let data = map(serde_json::json!({
            "number": "INV-7",
            "customer": "شركة الأمل",
            "grand_total": 1150.5,
            "brand_app_name": "Attome",
        }));
        let line = ChildList {
            entity: "invoice_line".into(),
            lookup: "invoice_ref".into(),
            attrs: vec![attr("description", 0), attr("amount", 2)],
        };
        let rows = vec![
            map(serde_json::json!({"description": "استشارة", "amount": 1000})),
            map(serde_json::json!({"description": "Travel <b>", "amount": 150.5})),
        ];
        assemble(Utc::now(), &attrs, &data, &[(line, rows)], None)
    }

    const SOURCE: &str = "<h1>{{ brand_app_name }} {{ number }}</h1>\
<p>{{ customer }}</p>\
{% for line in invoice_line limit 50 %}<li>{{ line.description }}: {{ line.amount | number(2) }}</li>{% end %}\
<p>{{ grand_total | currency('SAR') }}</p><p>[{{ secret_note }}]</p>";

    #[test]
    fn a_document_renders_its_record_lines_and_brand_in_english() {
        let html = render_document(SOURCE, invoice(), "en").unwrap_or_else(|e| panic!("{e}"));
        assert!(html.contains("<h1>Attome INV-7</h1>"), "{html}");
        assert!(html.contains("<li>استشارة: 1,000.00</li>"), "{html}");
        // Values are escaped in HTML output.
        assert!(html.contains("Travel &lt;b&gt;"), "{html}");
        assert!(html.contains("1,150.50"), "{html}");
        // A field the reader may not see renders empty.
        assert!(html.contains("<p>[]</p>"), "{html}");
    }

    #[test]
    fn a_document_renders_arabic_region_formats() {
        let html = render_document(SOURCE, invoice(), "ar-SA").unwrap_or_else(|e| panic!("{e}"));
        assert!(html.contains("شركة الأمل"), "{html}");
        let english = render_document(SOURCE, invoice(), "en").unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(
            html, english,
            "the Arabic render formats numbers and money for ar-SA"
        );
    }

    #[test]
    fn a_template_naming_an_unknown_field_is_refused_with_its_place() {
        let err = render_document("{{ no_such_field }}", invoice(), "en")
            .err()
            .unwrap_or_else(|| panic!("an unknown field must not compile"));
        assert!(err.to_string().contains("line 1"), "{err}");
    }

    #[test]
    fn related_lists_are_found_by_name_only() {
        assert!(mentions(
            "{% for l in invoice_line limit 5 %}",
            "invoice_line"
        ));
        assert!(!mentions("{{ invoice_lines }}", "invoice_line"));
        assert!(!mentions("{{ my_invoice_line }}", "invoice_line"));
    }

    #[test]
    fn the_zatca_payload_is_five_tlv_fields() {
        let at = DateTime::parse_from_rfc3339("2026-10-19T09:30:00Z")
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|e| panic!("{e}"));
        let payload = zatca_tlv("Attome", "310122393500003", at, 1150.5, 150.07)
            .unwrap_or_else(|| panic!("a payload"));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut fields = Vec::new();
        let mut rest = bytes.as_slice();
        while let [tag, len, tail @ ..] = rest {
            let (value, after) = tail.split_at(usize::from(*len));
            fields.push((*tag, String::from_utf8(value.to_vec()).unwrap_or_default()));
            rest = after;
        }
        assert_eq!(
            fields,
            vec![
                (1, "Attome".to_owned()),
                (2, "310122393500003".to_owned()),
                (3, "2026-10-19T09:30:00Z".to_owned()),
                (4, "1150.50".to_owned()),
                (5, "150.07".to_owned()),
            ]
        );
        assert!(zatca_tlv(&"x".repeat(300), "1", at, 1.0, 0.0).is_none());
        let uri = qr_data_uri("hello").unwrap_or_else(|e| panic!("{e}"));
        assert!(uri.starts_with("data:image/svg+xml;base64,"), "{uri}");
    }
}
