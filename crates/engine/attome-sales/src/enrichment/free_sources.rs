//! D24-T5: three free enrichment sources as L9 providers
//! ([`EnrichmentSource`]), each answering `account` values that the L9
//! runner turns into proposals with the source's name and the time it was
//! fetched (the provenance). Each call is bounded to [`FETCH_TIMEOUT`].
//!
//! - `registry` ([`RegistrySource`]): the Saudi commercial register (AJ4's
//!   Wathq client) by the account's `cr_number`: legal names, the CR
//!   number, phone, website, head-office address and founding year
//!   (`wathq::account_patch`), and the industry code: the first activity's
//!   ISIC Rev.4 class (the first four digits of the register's code) as
//!   `isic_code_ref`, when the crm pack's ISIC list (D24-T3) holds it. The
//!   register's status has no account field to land in.
//! - `national_address` ([`NationalAddressSource`]): SPL's National Address
//!   (AJ5) for the account's `hq_address`, by its short address when it
//!   holds one, else as free text; the standardised address is proposed as
//!   `hq_address`.
//! - `website` ([`WebsiteSource`]): the account's own website root only,
//!   fetched through the crawler's SSRF-safe fetch and only where its
//!   `robots.txt` allows `/`: `og:image` becomes `logo_url`, and a
//!   schema.org `Organization` in JSON-LD gives `telephone` (`phone`),
//!   `address` (`hq_address`) and `sameAs` (`social_links`). No model call.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_integration::connector::adapters::national_address::{
    self, Language, NationalAddressClient,
};
use attome_integration::connector::adapters::wathq::{self, WathqClient};
use attome_integration::enrich::{EnrichmentSource, SourcedValue};
use attome_types::AppError;
use serde_json::{Value, json};

/// How long one provider call may take.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a website's home page read.
const MAX_PAGE_BYTES: usize = 1024 * 1024;

const USER_AGENT: &str = "AttomeEnrichment/1.0 (+https://attome.ai)";

type Lookup<'a> = Pin<Box<dyn Future<Output = Result<Vec<SourcedValue>, AppError>> + Send + 'a>>;

fn sourced(field: &str, value: Value) -> SourcedValue {
    SourcedValue {
        field: field.to_owned(),
        value,
    }
}

fn text<'a>(record: &'a Value, field: &str) -> Option<&'a str> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

async fn bounded<T>(
    what: &str,
    call: impl Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    tokio::time::timeout(FETCH_TIMEOUT, call)
        .await
        .map_err(|_| AppError::Validation(format!("{what} did not answer within 10 seconds")))?
}

// ── registry ─────────────────────────────────────────────────────────────

/// The commercial register (AJ4) by `cr_number`.
pub struct RegistrySource<'c> {
    pub client: WathqClient<'c>,
    /// Where the ISIC list is read; `None` proposes no industry code.
    pub db: Option<&'c attome_db::DbPool>,
}

/// The ISIC Rev.4 class a register activity code falls in: its first four
/// digits (the register extends the class with two of its own). Pure.
pub fn isic_class(code: &str) -> Option<&str> {
    let code = code.trim();
    if code.len() >= 4 && code.bytes().all(|b| b.is_ascii_digit()) {
        code.get(..4)
    } else {
        None
    }
}

/// The `isic_code` record for the first activity's class, when the ISIC
/// list is installed and holds it.
async fn isic_ref(
    db: &attome_db::DbPool,
    found: &wathq::Registration,
) -> Result<Option<uuid::Uuid>, AppError> {
    let Some(class) = found.activities.iter().find_map(|a| isic_class(&a.code)) else {
        return Ok(None);
    };
    let installed: Option<String> = sqlx::query_scalar("SELECT to_regclass('isic_code')::text")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if installed.is_none() {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT id FROM isic_code WHERE code = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT 1",
    )
    .bind(class)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

impl std::fmt::Debug for RegistrySource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrySource").finish_non_exhaustive()
    }
}

/// The account values a registration gives. Pure.
pub fn registry_values(found: &wathq::Registration) -> Vec<SourcedValue> {
    wathq::account_patch(found, None)
        .into_iter()
        .map(|(field, value)| SourcedValue { field, value })
        .collect()
}

impl EnrichmentSource for RegistrySource<'_> {
    fn name(&self) -> &str {
        "registry"
    }

    fn lookup<'a>(&'a self, _entity: &'a str, record: &'a Value) -> Lookup<'a> {
        Box::pin(async move {
            let Some(cr) = text(record, "cr_number").and_then(wathq::cr_number) else {
                return Ok(Vec::new());
            };
            let found = bounded("the commercial register", self.client.full_info(&cr)).await?;
            let Some(found) = found else {
                return Ok(Vec::new());
            };
            let mut values = registry_values(&found);
            if let Some(db) = self.db
                && let Some(id) = isic_ref(db, &found).await?
            {
                values.push(sourced("isic_code_ref", json!(id)));
            }
            Ok(values)
        })
    }
}

// ── national address ─────────────────────────────────────────────────────

/// SPL's National Address (AJ5) for `hq_address`.
pub struct NationalAddressSource<'c> {
    pub client: NationalAddressClient<'c>,
    pub language: Language,
}

impl std::fmt::Debug for NationalAddressSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NationalAddressSource")
            .finish_non_exhaustive()
    }
}

/// A standardised address as one line: building number and street,
/// district, city and postal code, then the additional number. Pure.
pub fn address_line(found: &national_address::Standardised) -> Option<String> {
    let join = |parts: &[&Option<String>]| -> Option<String> {
        let words: Vec<&str> = parts
            .iter()
            .filter_map(|p| p.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        (!words.is_empty()).then(|| words.join(" "))
    };
    let pieces: Vec<String> = [
        join(&[&found.building_number, &found.street]),
        join(&[&found.district]),
        join(&[&found.city, &found.postal_code]),
        found
            .additional_number
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|n| format!("+{}", n.trim())),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!pieces.is_empty()).then(|| pieces.join(", "))
}

impl EnrichmentSource for NationalAddressSource<'_> {
    fn name(&self) -> &str {
        "national_address"
    }

    fn lookup<'a>(&'a self, _entity: &'a str, record: &'a Value) -> Lookup<'a> {
        Box::pin(async move {
            let Some(address) = text(record, "hq_address") else {
                return Ok(Vec::new());
            };
            let short = address
                .split(|c: char| !c.is_ascii_alphanumeric())
                .find_map(national_address::short_address);
            let found = match short {
                Some(code) => {
                    bounded(
                        "the National Address",
                        self.client.by_short_address(&code, self.language),
                    )
                    .await?
                }
                None => bounded(
                    "the National Address",
                    self.client.by_free_text(address, self.language),
                )
                .await?
                .into_iter()
                .next(),
            };
            Ok(found
                .as_ref()
                .and_then(address_line)
                .map(|line| vec![sourced("hq_address", json!(line))])
                .unwrap_or_default())
        })
    }
}

// ── website ──────────────────────────────────────────────────────────────

/// The account's own website, read from its home page's metadata.
#[derive(Debug)]
pub struct WebsiteSource {
    pub client: attome_server::ssrf_guard::GuardedClient,
}

impl WebsiteSource {
    /// A source over a guarded client with [`FETCH_TIMEOUT`].
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {
            client: attome_server::ssrf_guard::GuardedClient::new(FETCH_TIMEOUT.as_secs())
                .map_err(AppError::internal)?,
        })
    }
}

/// The site's root (`https://host/`) from what an account's `website`
/// holds (`example.sa`, `www.example.sa/about`, a full URL). Pure.
pub fn site_root(website: &str) -> Option<reqwest::Url> {
    let website = website.trim();
    let with_scheme = if website.contains("://") {
        website.to_owned()
    } else {
        format!("https://{website}")
    };
    let mut url = reqwest::Url::parse(&with_scheme).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Some(url)
}

/// The value of `attr` in the first tag (lowercased text `lower`, original
/// `html`) whose `key` attribute is `name`. Pure.
fn meta_content(html: &str, key: &str, name: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("<meta") {
        let start = from + at;
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        let tag = &html[start..end];
        let tag_lower = &lower[start..end];
        if attribute(tag_lower, tag, key).is_some_and(|v| v.eq_ignore_ascii_case(name)) {
            return attribute(tag_lower, tag, "content").filter(|v| !v.trim().is_empty());
        }
        from = end;
    }
    None
}

/// An attribute's value in one tag, quoted with `"` or `'`. Pure.
fn attribute(tag_lower: &str, tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let mut from = 0;
    while let Some(at) = tag_lower[from..].find(&needle) {
        let at = from + at;
        let before_ok = at == 0
            || tag_lower[..at]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace);
        let value_start = at + needle.len();
        if before_ok {
            let quote = tag[value_start..].chars().next()?;
            if quote == '"' || quote == '\'' {
                let rest = &tag[value_start + 1..];
                let close = rest.find(quote)?;
                return Some(rest[..close].to_owned());
            }
        }
        from = value_start;
    }
    None
}

/// The JSON-LD documents in a page. Pure.
fn json_ld(html: &str) -> Vec<Value> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = lower[from..].find("application/ld+json") {
        let at = from + at;
        let Some(open_end) = lower[at..].find('>').map(|e| at + e + 1) else {
            break;
        };
        let Some(close) = lower[open_end..].find("</script").map(|e| open_end + e) else {
            break;
        };
        if let Ok(doc) = serde_json::from_str::<Value>(html[open_end..close].trim()) {
            match doc {
                Value::Array(items) => out.extend(items),
                Value::Object(ref map) if map.contains_key("@graph") => {
                    out.extend(map["@graph"].as_array().cloned().unwrap_or_default());
                }
                other => out.push(other),
            }
        }
        from = close;
    }
    out
}

fn is_organization(doc: &Value) -> bool {
    let is_org = |t: &str| {
        matches!(
            t,
            "Organization"
                | "Corporation"
                | "LocalBusiness"
                | "Store"
                | "NGO"
                | "GovernmentOrganization"
        )
    };
    match doc.get("@type") {
        Some(Value::String(t)) => is_org(t),
        Some(Value::Array(types)) => types.iter().filter_map(Value::as_str).any(is_org),
        _ => false,
    }
}

/// A schema.org address as one line. Pure.
fn postal_line(address: &Value) -> Option<String> {
    match address {
        Value::String(s) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Value::Object(map) => {
            let parts: Vec<&str> = [
                "streetAddress",
                "addressLocality",
                "addressRegion",
                "postalCode",
                "addressCountry",
            ]
            .iter()
            .filter_map(|k| map.get(*k).and_then(Value::as_str))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        _ => None,
    }
}

/// The account values a home page's metadata gives: `og:image` as
/// `logo_url`, and from a JSON-LD organisation `telephone`, `address` and
/// `sameAs`. Pure.
pub fn website_values(html: &str) -> Vec<SourcedValue> {
    let mut out = Vec::new();
    if let Some(logo) = meta_content(html, "property", "og:image") {
        out.push(sourced("logo_url", json!(logo.trim())));
    }
    if let Some(org) = json_ld(html).into_iter().find(is_organization) {
        if out.is_empty()
            && let Some(logo) = org.get("logo").and_then(|l| {
                l.as_str()
                    .map(str::to_owned)
                    .or_else(|| l.get("url").and_then(Value::as_str).map(str::to_owned))
            })
        {
            out.push(sourced("logo_url", json!(logo)));
        }
        if let Some(phone) = org.get("telephone").and_then(Value::as_str) {
            out.push(sourced("phone", json!(phone.trim())));
        }
        if let Some(line) = org.get("address").and_then(postal_line) {
            out.push(sourced("hq_address", json!(line)));
        }
        let links: Vec<&str> = match org.get("sameAs") {
            Some(Value::String(s)) => vec![s.as_str()],
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !links.is_empty() {
            out.push(sourced("social_links", json!(links.join("\n"))));
        }
    }
    out
}

impl EnrichmentSource for WebsiteSource {
    fn name(&self) -> &str {
        "website"
    }

    fn lookup<'a>(&'a self, _entity: &'a str, record: &'a Value) -> Lookup<'a> {
        Box::pin(async move {
            let Some(root) = text(record, "website").and_then(site_root) else {
                return Ok(Vec::new());
            };
            // The site's own rules first: a site that keeps robots off its
            // home page is not read.
            let mut robots_url = root.clone();
            robots_url.set_path("/robots.txt");
            let robots = match bounded("the website", async {
                Ok(attome_webcrawl::safety::fetch_safely(
                    &self.client,
                    &robots_url,
                    64 * 1024,
                    USER_AGENT,
                )
                .await
                .ok())
            })
            .await?
            {
                Some(page) => attome_webcrawl::safety::RobotsRules::parse(&page.body),
                None => attome_webcrawl::safety::RobotsRules::default(),
            };
            if !robots.allows("/") {
                return Ok(Vec::new());
            }
            let page = bounded("the website", async {
                attome_webcrawl::safety::fetch_safely(
                    &self.client,
                    &root,
                    MAX_PAGE_BYTES,
                    USER_AGENT,
                )
                .await
                .map_err(|e| AppError::Validation(format!("the website: {e}")))
            })
            .await?;
            Ok(website_values(&page.body))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = r#"<!doctype html><html><head>
<meta name="description" content="Fresh dates since 1975">
<meta property="og:image" content="https://cdn.alnakheel.sa/logo.png">
<script type="application/ld+json">
{"@context": "https://schema.org", "@type": "Organization", "name": "Al Nakheel Foods",
 "telephone": "+966 11 234 5678",
 "address": {"@type": "PostalAddress", "streetAddress": "King Fahd Road", "addressLocality": "Riyadh",
             "postalCode": "12271", "addressCountry": "SA"},
 "sameAs": ["https://x.com/alnakheel", "https://www.linkedin.com/company/alnakheel"]}
</script></head><body></body></html>"#;

    fn value<'a>(values: &'a [SourcedValue], field: &str) -> Option<&'a Value> {
        values.iter().find(|v| v.field == field).map(|v| &v.value)
    }

    #[test]
    fn website_jsonld_is_mapped() {
        let values = website_values(HOME);
        assert_eq!(
            value(&values, "logo_url"),
            Some(&json!("https://cdn.alnakheel.sa/logo.png"))
        );
        assert_eq!(value(&values, "phone"), Some(&json!("+966 11 234 5678")));
        assert_eq!(
            value(&values, "hq_address"),
            Some(&json!("King Fahd Road, Riyadh, 12271, SA"))
        );
        assert_eq!(
            value(&values, "social_links"),
            Some(&json!(
                "https://x.com/alnakheel\nhttps://www.linkedin.com/company/alnakheel"
            ))
        );
        assert!(website_values("<html><body>nothing</body></html>").is_empty());
    }

    #[test]
    fn a_website_field_names_its_root() {
        assert_eq!(
            site_root("www.example.sa/about?x=1").map(|u| u.to_string()),
            Some("https://www.example.sa/".to_owned())
        );
        assert_eq!(site_root("ftp://example.sa"), None);
    }

    #[test]
    fn a_register_activity_falls_in_its_isic_class() {
        assert_eq!(isic_class("464101"), Some("4641"));
        assert_eq!(isic_class(" 0111 "), Some("0111"));
        assert_eq!(isic_class("46A1"), None);
        assert_eq!(isic_class("464"), None);
    }

    #[test]
    fn a_standardised_address_reads_as_one_line() {
        let found = national_address::Standardised {
            building_number: Some("8228".into()),
            street: Some("Imam Saud".into()),
            district: Some("Al Nakheel".into()),
            city: Some("Riyadh".into()),
            postal_code: Some("12382".into()),
            additional_number: Some("2121".into()),
            short_address: Some("RRRD2929".into()),
            region: None,
            latitude: None,
            longitude: None,
        };
        assert_eq!(
            address_line(&found).as_deref(),
            Some("8228 Imam Saud, Al Nakheel, Riyadh 12382, +2121")
        );
    }
}
