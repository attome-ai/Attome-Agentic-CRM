//! AB11-T7: the status page hosted apart from the deployment, so customers
//! can read it while the deployment itself is down.
//!
//! Every minute (with the status watch, [`publish_if_changed`]) the public
//! status is rendered from the public snapshot only
//! ([`crate::public_status::visible_to`] with no internal detail: public
//! components, public incidents with their published updates, public
//! maintenance) as three files ([`render`]): `index.html` (English),
//! `ar/index.html` (Arabic, right to left) and `status.json`, with every
//! date in Gregorian and Hijri (Umm al-Qura). When the content changed
//! since the last publication (`ops_status_publication`, migration 0362,
//! keyed by its SHA-256 without the render time):
//!
//! - with `ops.status.bucket` set, the three files go to that bucket with
//!   `Cache-Control: max-age=60`, through the bucket's own credentials read
//!   from `ops.status.bucket_credentials_file` (a JSON file on the server
//!   with `access_key` and `secret_key`, kept out of the database);
//! - with `ops.status.webhook_url` set, `status.json` is POSTed there
//!   through the outbound guard (no private or metadata address), with a
//!   10-second timeout and up to three tries.
//!
//! A target that fails is logged and tried again the next minute: the
//! content is recorded as published only when every configured target took
//! it. Nothing here runs inside a database transaction.

use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::public_status::StatusSnapshot;

/// The setting naming the bucket the page goes to.
pub const BUCKET_SETTING: &str = "ops.status.bucket";
/// The setting naming the file that holds the bucket's credentials.
pub const CREDENTIALS_SETTING: &str = "ops.status.bucket_credentials_file";
/// The setting naming the status tool's webhook.
pub const WEBHOOK_SETTING: &str = "ops.status.webhook_url";

/// How long the hosted copy may be cached.
pub const CACHE_CONTROL: &str = "max-age=60";
/// How long one webhook call may take.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
/// Webhook tries per publication.
const WEBHOOK_TRIES: u32 = 3;

/// The publication target the bucket and webhook share.
const TARGET: &str = "hosted";

/// One published update of a public incident.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PublicUpdate {
    pub incident_id: Uuid,
    pub stage: String,
    pub body_en: String,
    pub body_ar: Option<String>,
    pub published_at: DateTime<Utc>,
}

/// The three files of the hosted page.
#[derive(Debug, Clone)]
pub struct StaticPage {
    pub index_en: String,
    pub index_ar: String,
    pub status_json: Value,
}

impl StaticPage {
    /// The page's content without the render time, for change detection.
    /// Pure.
    pub fn fingerprint(&self) -> String {
        let mut content = self.status_json.clone();
        if let Some(object) = content.as_object_mut() {
            object.remove("generated_at");
        }
        hex::encode(Sha256::digest(content.to_string().as_bytes()))
    }
}

const HIJRI_MONTHS_EN: [&str; 12] = [
    "Muharram",
    "Safar",
    "Rabi al-Awwal",
    "Rabi al-Thani",
    "Jumada al-Ula",
    "Jumada al-Akhirah",
    "Rajab",
    "Shaban",
    "Ramadan",
    "Shawwal",
    "Dhu al-Qadah",
    "Dhu al-Hijjah",
];
const HIJRI_MONTHS_AR: [&str; 12] = [
    "محرم",
    "صفر",
    "ربيع الأول",
    "ربيع الآخر",
    "جمادى الأولى",
    "جمادى الآخرة",
    "رجب",
    "شعبان",
    "رمضان",
    "شوال",
    "ذو القعدة",
    "ذو الحجة",
];
const GREGORIAN_MONTHS_AR: [&str; 12] = [
    "يناير",
    "فبراير",
    "مارس",
    "أبريل",
    "مايو",
    "يونيو",
    "يوليو",
    "أغسطس",
    "سبتمبر",
    "أكتوبر",
    "نوفمبر",
    "ديسمبر",
];

/// A moment in Gregorian and Hijri, in English or Arabic, UTC. Pure.
pub fn dual_date(at: DateTime<Utc>, arabic: bool) -> String {
    let day: NaiveDate = at.date_naive();
    let time = at.format("%H:%M UTC");
    let hijri = attome_calendar::hijri::to_hijri(day).ok();
    let month = day.month0() as usize;
    if arabic {
        let gregorian = format!(
            "{} {} {}",
            day.day(),
            GREGORIAN_MONTHS_AR[month],
            day.year()
        );
        match hijri {
            Some(h) => format!(
                "{gregorian} م ({} {} {} هـ) {time}",
                h.day,
                HIJRI_MONTHS_AR[usize::from(h.month.clamp(1, 12) - 1)],
                h.year
            ),
            None => format!("{gregorian} م {time}"),
        }
    } else {
        let gregorian = day.format("%-d %B %Y");
        match hijri {
            Some(h) => format!(
                "{gregorian} ({} {} {} AH) {time}",
                h.day,
                HIJRI_MONTHS_EN[usize::from(h.month.clamp(1, 12) - 1)],
                h.year
            ),
            None => format!("{gregorian} {time}"),
        }
    }
}

/// `text` safe inside HTML text and attribute values. Pure.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn state_label(state: &str, arabic: bool) -> &'static str {
    match (state, arabic) {
        ("operational", false) => "Operational",
        ("degraded", false) => "Degraded",
        ("down", false) => "Down",
        ("operational", true) => "يعمل",
        ("degraded", true) => "أداء منخفض",
        ("down", true) => "متوقف",
        (_, false) => "Unknown",
        (_, true) => "غير معروف",
    }
}

fn stage_label(stage: &str, arabic: bool) -> &'static str {
    match (stage, arabic) {
        ("investigating", false) => "Investigating",
        ("identified", false) => "Identified",
        ("monitoring", false) => "Monitoring",
        ("resolved", false) => "Resolved",
        ("investigating", true) => "قيد التحقق",
        ("identified", true) => "تم تحديد السبب",
        ("monitoring", true) => "تحت المراقبة",
        ("resolved", true) => "تم الحل",
        (_, false) => "Update",
        (_, true) => "تحديث",
    }
}

fn pick<'a>(en: &'a str, ar: Option<&'a str>, arabic: bool) -> &'a str {
    match ar {
        Some(ar) if arabic && !ar.trim().is_empty() => ar,
        _ => en,
    }
}

fn html(snapshot: &StatusSnapshot, updates: &[PublicUpdate], arabic: bool) -> String {
    let (lang, dir, title, components_h, incidents_h, maintenance_h, none_open, updated) = if arabic
    {
        (
            "ar",
            "rtl",
            "حالة الخدمة",
            "المكونات",
            "الحوادث",
            "الصيانة المجدولة",
            "لا توجد حوادث مفتوحة.",
            "آخر تحديث",
        )
    } else {
        (
            "en",
            "ltr",
            "Service status",
            "Components",
            "Incidents",
            "Scheduled maintenance",
            "No open incidents.",
            "Last updated",
        )
    };
    let mut body = String::new();
    body.push_str(&format!(
        "<h2>{components_h}</h2>\n<ul class=\"components\">\n"
    ));
    for c in &snapshot.components {
        let name = if arabic { &c.name_ar } else { &c.name_en };
        body.push_str(&format!(
            "<li class=\"{state}\"><span>{name}</span> <strong>{label}</strong></li>\n",
            state = escape(&c.state),
            name = escape(name),
            label = state_label(&c.state, arabic),
        ));
    }
    body.push_str("</ul>\n");
    body.push_str(&format!("<h2>{incidents_h}</h2>\n"));
    if snapshot.incidents.is_empty() {
        body.push_str(&format!("<p>{none_open}</p>\n"));
    }
    for incident in &snapshot.incidents {
        body.push_str(&format!(
            "<article class=\"incident {impact}\">\n<h3>{title}</h3>\n<p>{since}</p>\n",
            impact = escape(&incident.impact),
            title = escape(pick(
                &incident.title_en,
                incident.title_ar.as_deref(),
                arabic
            )),
            since = escape(&dual_date(incident.started_at, arabic)),
        ));
        for update in updates.iter().filter(|u| u.incident_id == incident.id) {
            body.push_str(&format!(
                "<p><strong>{stage}</strong> ({at}): {text}</p>\n",
                stage = stage_label(&update.stage, arabic),
                at = escape(&dual_date(update.published_at, arabic)),
                text = escape(pick(&update.body_en, update.body_ar.as_deref(), arabic)),
            ));
        }
        body.push_str("</article>\n");
    }
    if !snapshot.maintenance.is_empty() {
        body.push_str(&format!("<h2>{maintenance_h}</h2>\n<ul>\n"));
        for m in &snapshot.maintenance {
            body.push_str(&format!(
                "<li>{title}: {from} – {to}</li>\n",
                title = escape(pick(&m.title_en, m.title_ar.as_deref(), arabic)),
                from = escape(&dual_date(m.starts_at, arabic)),
                to = escape(&dual_date(m.ends_at, arabic)),
            ));
        }
        body.push_str("</ul>\n");
    }
    let other = if arabic {
        "<a href=\"../index.html\" hreflang=\"en\">English</a>"
    } else {
        "<a href=\"ar/index.html\" hreflang=\"ar\">العربية</a>"
    };
    format!(
        "<!doctype html>\n<html lang=\"{lang}\" dir=\"{dir}\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n<style>\nbody{{font-family:system-ui,sans-serif;max-width:46rem;\
         margin:0 auto;padding:1rem;line-height:1.5}}\n.components{{list-style:none;padding:0}}\n\
         .components li{{display:flex;justify-content:space-between;padding:.5rem 0;\
         border-block-end:1px solid #ddd}}\n.operational strong{{color:#1a7f37}}\n\
         .degraded strong{{color:#9a6700}}\n.down strong{{color:#cf222e}}\n\
         .incident{{border-inline-start:4px solid #9a6700;padding-inline-start:.75rem;\
         margin-block:1rem}}\n</style>\n</head>\n<body>\n<header><h1>{title}</h1>\
         <nav>{other}</nav></header>\n<main>\n{body}</main>\n<footer><p>{updated}: {at}</p>\
         </footer>\n</body>\n</html>\n",
        at = escape(&dual_date(snapshot.computed_at, arabic)),
    )
}

/// The three files from `snapshot`, which must already be the public view
/// (`visible_to(.., false)`); `updates` are the published updates of its
/// incidents, oldest first. Pure.
pub fn render(snapshot: &StatusSnapshot, updates: &[PublicUpdate]) -> StaticPage {
    let incidents: Vec<Value> = snapshot
        .incidents
        .iter()
        .map(|i| {
            json!({
                "id": i.id,
                "title_en": i.title_en,
                "title_ar": i.title_ar,
                "state": i.state,
                "impact": i.impact,
                "components": i.components,
                "started_at": i.started_at,
                "updates": updates
                    .iter()
                    .filter(|u| u.incident_id == i.id)
                    .map(|u| json!({
                        "stage": u.stage,
                        "body_en": u.body_en,
                        "body_ar": u.body_ar,
                        "published_at": u.published_at,
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let status_json = json!({
        "components": snapshot.components.iter().map(|c| json!({
            "key": c.key, "name_en": c.name_en, "name_ar": c.name_ar, "state": c.state,
        })).collect::<Vec<_>>(),
        "incidents": incidents,
        "maintenance": snapshot.maintenance.iter().map(|m| json!({
            "id": m.id, "title_en": m.title_en, "title_ar": m.title_ar,
            "components": m.components, "starts_at": m.starts_at, "ends_at": m.ends_at,
        })).collect::<Vec<_>>(),
        "generated_at": snapshot.computed_at,
    });
    StaticPage {
        index_en: html(snapshot, updates, false),
        index_ar: html(snapshot, updates, true),
        status_json,
    }
}

/// `ops.status.bucket`.
#[derive(Debug, Clone, Deserialize)]
struct BucketTarget {
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    region: String,
    bucket: String,
    /// A folder inside the bucket, without slashes at either end.
    #[serde(default)]
    prefix: String,
}

/// The credentials file's content.
#[derive(Deserialize)]
struct BucketCredentials {
    access_key: String,
    secret_key: String,
}

fn setting(state: &EngineState, key: &str) -> Option<Value> {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
}

fn text_setting(state: &EngineState, key: &str) -> Option<String> {
    setting(state, key)
        .and_then(|v| v.as_str().map(str::trim).map(str::to_owned))
        .filter(|s| !s.is_empty())
}

async fn public_updates(
    state: &EngineState,
    snapshot: &StatusSnapshot,
) -> Result<Vec<PublicUpdate>, AppError> {
    let ids: Vec<Uuid> = snapshot.incidents.iter().map(|i| i.id).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT incident_id, stage, body_en, body_ar, published_at FROM ops_incident_update \
          WHERE incident_id = ANY($1) ORDER BY published_at, id",
    )
    .bind(&ids)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn upload(state: &EngineState, page: &StaticPage) -> Result<(), AppError> {
    let Some(target) = setting(state, BUCKET_SETTING).filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let target: BucketTarget = serde_json::from_value(target)
        .map_err(|_| AppError::Validation(format!("{BUCKET_SETTING} is not a bucket")))?;
    let file = text_setting(state, CREDENTIALS_SETTING)
        .ok_or_else(|| AppError::Validation(format!("{CREDENTIALS_SETTING} is not set")))?;
    let raw = tokio::fs::read(&file)
        .await
        .map_err(|_| AppError::Validation(format!("{CREDENTIALS_SETTING} cannot be read")))?;
    let credentials: BucketCredentials = serde_json::from_slice(&raw).map_err(|_| {
        AppError::Validation(format!(
            "{CREDENTIALS_SETTING} must hold access_key and secret_key"
        ))
    })?;
    let client = attome_storage::create_storage_client_for(
        attome_config::S3Target {
            endpoint: &target.endpoint,
            public_endpoint: "",
            region: &target.region,
            bucket: &target.bucket,
            access_key: &credentials.access_key,
            secret_key: &credentials.secret_key,
            verify_ssl: true,
        },
        "ops-status-page",
    )
    .await
    .map_err(AppError::internal)?;
    let prefix = target.prefix.trim_matches('/');
    let path = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        }
    };
    for (name, body, content_type) in [
        (
            "index.html",
            page.index_en.clone(),
            "text/html; charset=utf-8",
        ),
        (
            "ar/index.html",
            page.index_ar.clone(),
            "text/html; charset=utf-8",
        ),
        (
            "status.json",
            page.status_json.to_string(),
            "application/json",
        ),
    ] {
        let mut attributes = object_store::Attributes::new();
        attributes.insert(object_store::Attribute::CacheControl, CACHE_CONTROL.into());
        attributes.insert(object_store::Attribute::ContentType, content_type.into());
        let options = object_store::PutOptions {
            attributes,
            ..Default::default()
        };
        object_store::ObjectStore::put_opts(
            client.store(),
            &object_store::path::Path::from(path(name)),
            body.into(),
            options,
        )
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

async fn post_webhook(state: &EngineState, page: &StaticPage) -> Result<(), AppError> {
    let Some(url) = text_setting(state, WEBHOOK_SETTING) else {
        return Ok(());
    };
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("ops-status-webhook").no_redirects(),
        |b| b.timeout(WEBHOOK_TIMEOUT),
    )
    .map_err(AppError::internal)?;
    let mut last = String::new();
    for attempt in 1..=WEBHOOK_TRIES {
        match client.post(&url).json(&page.status_json).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last = format!("HTTP {}", response.status().as_u16()),
            Err(error) => last = error.without_url().to_string(),
        }
        if attempt < WEBHOOK_TRIES {
            tokio::time::sleep(Duration::from_secs(u64::from(attempt))).await;
        }
    }
    Err(AppError::internal(format!(
        "the status webhook did not take the status: {last}"
    )))
}

/// Publishes the hosted page when its content changed since the last
/// publication and a bucket or a webhook is configured; whether it
/// published.
pub async fn publish_if_changed(state: &EngineState) -> Result<bool, AppError> {
    let bucket = setting(state, BUCKET_SETTING).is_some_and(|v| !v.is_null());
    let webhook = text_setting(state, WEBHOOK_SETTING).is_some();
    if !bucket && !webhook {
        return Ok(false);
    }
    let snapshot = crate::public_status::public_snapshot(state).await?;
    let updates = public_updates(state, &snapshot).await?;
    let page = render(&snapshot, &updates);
    let fingerprint = page.fingerprint();
    let last: Option<String> =
        sqlx::query_scalar("SELECT fingerprint FROM ops_status_publication WHERE target = $1")
            .bind(TARGET)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if last.as_deref() == Some(fingerprint.as_str()) {
        return Ok(false);
    }
    upload(state, &page).await?;
    post_webhook(state, &page).await?;
    sqlx::query(
        "INSERT INTO ops_status_publication (target, fingerprint, published_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (target) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, \
             published_at = EXCLUDED.published_at",
    )
    .bind(TARGET)
    .bind(&fingerprint)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_status::{IncidentSummary, visible_to};

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn incident(audience: &str, title: &str) -> IncidentSummary {
        IncidentSummary {
            id: Uuid::now_v7(),
            title_en: title.to_owned(),
            title_ar: Some(format!("{title} بالعربية")),
            audience: audience.to_owned(),
            state: "investigating".to_owned(),
            impact: "major".to_owned(),
            components: vec!["records".to_owned()],
            started_at: at("2026-11-01T10:00:00Z"),
        }
    }

    fn snapshot(incidents: Vec<IncidentSummary>) -> StatusSnapshot {
        StatusSnapshot {
            components: Vec::new(),
            incidents,
            maintenance: Vec::new(),
            computed_at: at("2026-11-01T10:05:00Z"),
        }
    }

    #[test]
    fn static_page_has_no_internal_incidents() {
        let public = incident("public", "Payments are slow");
        let internal = incident("internal", "Primary database failover <drill>");
        let public_id = public.id;
        let shown = visible_to(snapshot(vec![public, internal]), false);
        let updates = vec![PublicUpdate {
            incident_id: public_id,
            stage: "identified".to_owned(),
            body_en: "A card network is <slow>.".to_owned(),
            body_ar: None,
            published_at: at("2026-11-01T10:03:00Z"),
        }];
        let page = render(&shown, &updates);
        for text in [
            &page.index_en,
            &page.index_ar,
            &page.status_json.to_string(),
        ] {
            assert!(!text.contains("failover"), "{text}");
        }
        assert!(page.index_en.contains("Payments are slow"));
        assert!(page.index_en.contains("A card network is &lt;slow&gt;."));
        assert_eq!(
            page.status_json["incidents"][0]["updates"][0]["stage"],
            "identified"
        );
    }

    #[test]
    fn arabic_page_is_rtl_with_hijri_date() {
        let page = render(&snapshot(vec![incident("public", "Outage")]), &[]);
        assert!(page.index_ar.contains("<html lang=\"ar\" dir=\"rtl\">"));
        assert!(page.index_ar.contains("Outage بالعربية"));
        let hijri = attome_calendar::hijri::to_hijri(NaiveDate::from_ymd_opt(2026, 11, 1).unwrap())
            .unwrap();
        let expected = format!(
            "{} {} {} هـ",
            hijri.day,
            HIJRI_MONTHS_AR[usize::from(hijri.month - 1)],
            hijri.year
        );
        assert!(page.index_ar.contains(&expected), "{}", page.index_ar);
        assert!(page.index_en.contains("<html lang=\"en\" dir=\"ltr\">"));
        assert!(page.index_en.contains(" AH)"));
    }

    #[test]
    fn the_fingerprint_ignores_the_render_time() {
        let mut later = snapshot(vec![incident("public", "Outage")]);
        let first = render(&later, &[]);
        later.computed_at = at("2026-11-01T11:00:00Z");
        assert_eq!(first.fingerprint(), render(&later, &[]).fingerprint());
    }
}
