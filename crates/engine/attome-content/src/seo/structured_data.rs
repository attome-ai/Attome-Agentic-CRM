//! Structured data (roadmap E13-T4): a page's schema.org JSON-LD, built
//! from the page and the records it shows, using schema.org property names
//! only, and checked before it is served.

use serde_json::{Value, json};

use crate::model::PageDetail;

/// The schema.org types a page can describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaKind {
    Organization,
    BreadcrumbList,
    Article,
    FaqPage,
    Event,
    Product,
    JobPosting,
    LocalBusiness,
}

impl SchemaKind {
    /// The schema.org `@type`.
    pub fn type_name(self) -> &'static str {
        match self {
            Self::Organization => "Organization",
            Self::BreadcrumbList => "BreadcrumbList",
            Self::Article => "Article",
            Self::FaqPage => "FAQPage",
            Self::Event => "Event",
            Self::Product => "Product",
            Self::JobPosting => "JobPosting",
            Self::LocalBusiness => "LocalBusiness",
        }
    }

    fn from_type(name: &str) -> Option<Self> {
        [
            Self::Organization,
            Self::BreadcrumbList,
            Self::Article,
            Self::FaqPage,
            Self::Event,
            Self::Product,
            Self::JobPosting,
            Self::LocalBusiness,
        ]
        .into_iter()
        .find(|k| k.type_name() == name)
    }

    /// The properties a valid document of this kind must carry.
    pub fn required(self) -> &'static [&'static str] {
        match self {
            Self::Article => &["headline", "datePublished"],
            Self::Event => &["name", "startDate", "location"],
            Self::Product => &["name"],
            Self::JobPosting => &["title", "datePosted", "hiringOrganization"],
            Self::FaqPage => &["mainEntity"],
            Self::BreadcrumbList => &["itemListElement"],
            Self::Organization | Self::LocalBusiness => &["name"],
        }
    }
}

const CONTEXT: &str = "https://schema.org";

/// Copies the schema.org properties named in `keys` from `record` (a
/// record's values) into `out`, skipping empty ones.
fn copy(out: &mut serde_json::Map<String, Value>, record: &Value, keys: &[(&str, &str)]) {
    for (from, to) in keys {
        if let Some(v) = record
            .get(*from)
            .filter(|v| !v.is_null() && *v != &json!(""))
        {
            out.insert((*to).to_owned(), v.clone());
        }
    }
}

/// The JSON-LD for `page` of `kind`, from the records the page shows
/// (`records`, each a record's values). Pure.
pub fn json_ld(page: &PageDetail, kind: SchemaKind, records: &[Value]) -> Value {
    let first = records.first().cloned().unwrap_or(Value::Null);
    let mut doc = serde_json::Map::new();
    doc.insert("@context".into(), json!(CONTEXT));
    doc.insert("@type".into(), json!(kind.type_name()));
    match kind {
        SchemaKind::Article => {
            doc.insert("headline".into(), json!(page.title));
            if let Some(at) = page.published_at {
                doc.insert("datePublished".into(), json!(at.to_rfc3339()));
            }
            doc.insert("dateModified".into(), json!(page.updated_at.to_rfc3339()));
            copy(
                &mut doc,
                &first,
                &[("author", "author"), ("image", "image")],
            );
        }
        SchemaKind::FaqPage => {
            let items: Vec<Value> = records
                .iter()
                .filter_map(|r| {
                    let q = r.get("question")?.as_str()?;
                    let a = r.get("answer")?.as_str()?;
                    Some(json!({
                        "@type": "Question",
                        "name": q,
                        "acceptedAnswer": { "@type": "Answer", "text": a }
                    }))
                })
                .collect();
            doc.insert("mainEntity".into(), json!(items));
        }
        SchemaKind::Event => {
            copy(
                &mut doc,
                &first,
                &[
                    ("name", "name"),
                    ("starts_at", "startDate"),
                    ("ends_at", "endDate"),
                    ("description", "description"),
                ],
            );
            if let Some(venue) = first
                .get("venue")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            {
                doc.insert(
                    "location".into(),
                    json!({ "@type": "Place", "name": venue }),
                );
            } else if let Some(url) = first
                .get("online_url")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            {
                doc.insert(
                    "location".into(),
                    json!({ "@type": "VirtualLocation", "url": url }),
                );
                doc.insert(
                    "eventAttendanceMode".into(),
                    json!("https://schema.org/OnlineEventAttendanceMode"),
                );
            }
        }
        SchemaKind::Product => {
            copy(
                &mut doc,
                &first,
                &[
                    ("name", "name"),
                    ("description", "description"),
                    ("sku", "sku"),
                ],
            );
            if let Some(price) = first.get("price").filter(|p| !p.is_null()) {
                doc.insert(
                    "offers".into(),
                    json!({
                        "@type": "Offer",
                        "price": price,
                        "priceCurrency": first.get("currency").cloned().unwrap_or(json!("SAR")),
                    }),
                );
            }
        }
        SchemaKind::JobPosting => {
            copy(
                &mut doc,
                &first,
                &[
                    ("title", "title"),
                    ("description", "description"),
                    ("posted_on", "datePosted"),
                    ("valid_through", "validThrough"),
                    ("employment_type", "employmentType"),
                ],
            );
            if let Some(org) = first.get("organization").and_then(Value::as_str) {
                doc.insert(
                    "hiringOrganization".into(),
                    json!({ "@type": "Organization", "name": org }),
                );
            }
        }
        SchemaKind::BreadcrumbList => {
            let mut items = Vec::new();
            let mut path = String::new();
            for (i, segment) in page
                .url_path
                .split('/')
                .filter(|s| !s.is_empty())
                .enumerate()
            {
                path.push('/');
                path.push_str(segment);
                items.push(json!({
                    "@type": "ListItem",
                    "position": i + 1,
                    "name": segment.replace('-', " "),
                    "item": path,
                }));
            }
            doc.insert("itemListElement".into(), json!(items));
        }
        SchemaKind::Organization | SchemaKind::LocalBusiness => {
            copy(
                &mut doc,
                &first,
                &[
                    ("name", "name"),
                    ("website", "url"),
                    ("logo", "logo"),
                    ("phone", "telephone"),
                    ("email", "email"),
                ],
            );
            if kind == SchemaKind::LocalBusiness
                && let Some(street) = first.get("street").and_then(Value::as_str)
            {
                doc.insert(
                    "address".into(),
                    json!({
                        "@type": "PostalAddress",
                        "streetAddress": street,
                        "addressLocality": first.get("city").cloned().unwrap_or(Value::Null),
                        "addressCountry": first.get("country").cloned().unwrap_or(Value::Null),
                    }),
                );
            }
        }
    }
    Value::Object(doc)
}

/// Checks a JSON-LD document: the schema.org context, a known `@type` and
/// that type's required properties. Pure.
pub fn validate_json_ld(v: &Value) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if v.get("@context").and_then(Value::as_str) != Some(CONTEXT) {
        problems.push(format!("@context must be {CONTEXT}"));
    }
    match v
        .get("@type")
        .and_then(Value::as_str)
        .and_then(SchemaKind::from_type)
    {
        None => problems.push("@type is not a supported schema.org type".to_owned()),
        Some(kind) => {
            for property in kind.required() {
                let present = v.get(*property).is_some_and(|p| match p {
                    Value::Null => false,
                    Value::String(s) => !s.trim().is_empty(),
                    Value::Array(a) => !a.is_empty(),
                    _ => true,
                });
                if !present {
                    problems.push(format!("{} needs {property}", kind.type_name()));
                }
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_ld_event_has_required_fields() {
        let page = crate::seo::settings::tests::page(json!([]));
        let doc = json_ld(
            &page,
            SchemaKind::Event,
            &[
                json!({"name": "Expo", "starts_at": "2026-11-02T09:00:00+03:00", "venue": "Riyadh Front"}),
            ],
        );
        assert_eq!(doc["@type"], "Event");
        assert_eq!(doc["location"]["name"], "Riyadh Front");
        assert_eq!(validate_json_ld(&doc), Ok(()));
    }

    #[test]
    fn validate_rejects_missing_headline() {
        let doc = json!({ "@context": "https://schema.org", "@type": "Article", "datePublished": "2026-10-20" });
        let problems = validate_json_ld(&doc).unwrap_err();
        assert!(
            problems.iter().any(|p| p.contains("headline")),
            "{problems:?}"
        );
        assert!(validate_json_ld(&json!({"@type": "Thing"})).is_err());
    }

    #[test]
    fn breadcrumbs_follow_the_path() {
        let mut page = crate::seo::settings::tests::page(json!([]));
        page.url_path = "/products/smart-meters".into();
        let doc = json_ld(&page, SchemaKind::BreadcrumbList, &[]);
        assert_eq!(doc["itemListElement"][1]["item"], "/products/smart-meters");
        assert_eq!(doc["itemListElement"][1]["position"], 2);
    }
}
