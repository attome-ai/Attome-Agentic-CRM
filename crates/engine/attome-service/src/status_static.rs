//! H8-T2: the status page as one static HTML file, for a bucket or a
//! separate host that stays up when the platform does not.
//!
//! [`render_html`] turns the public page (`GET /api/v1/status`, the same
//! [`StatusPage`]) into a self-contained page in English and Arabic (each
//! half in its own language and direction, styled with logical properties
//! only, no scripts). Every value from the records is escaped.
//!
//! Two ways out:
//! - **On change.** The `status_page_notify` job already reads the change
//!   feed; when a batch touched any `status_*` record it renders the page
//!   again and writes `status-page/index.html` and `status-page/status.json`
//!   to the deployment's object store ([`publish`]), where a bucket policy
//!   or a static host can serve them. A failed write is logged, never
//!   failing the notices.
//! - **Elsewhere.** `attome status-page --url <server> --out <dir>` reads a
//!   server's public page and writes the same two files to a directory, for
//!   a host the server cannot write to.

use attome_core::EngineState;
use attome_html::escape_html;
use attome_types::AppError;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};

use crate::status_page::{StatusEvent, StatusPage};

/// Where [`publish`] writes in the object store.
pub const PREFIX: &str = "status-page";

/// The page's words, English and Arabic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ar,
}

/// One label in a language. Pure.
pub fn label(key: &str, lang: Lang) -> &'static str {
    let (en, ar) = match key {
        "title" => ("System status", "حالة الأنظمة"),
        "operational" => ("Operational", "يعمل"),
        "maintenance" => ("Under maintenance", "تحت الصيانة"),
        "degraded" => ("Degraded performance", "أداء منخفض"),
        "partial_outage" => ("Partial outage", "انقطاع جزئي"),
        "major_outage" => ("Major outage", "انقطاع كبير"),
        "incidents" => ("Current incidents", "الحوادث الحالية"),
        "scheduled" => ("Maintenance", "الصيانة"),
        "resolved" => ("Resolved this week", "تم حلها هذا الأسبوع"),
        "none" => ("Nothing to report.", "لا شيء للإبلاغ عنه."),
        "updated" => ("Updated", "آخر تحديث"),
        "components" => ("Components", "المكونات"),
        _ => ("", ""),
    };
    match lang {
        Lang::En => en,
        Lang::Ar => ar,
    }
}

fn pick<'a>(lang: Lang, en: &'a str, ar: Option<&'a str>) -> &'a str {
    match (lang, ar) {
        (Lang::Ar, Some(ar)) if !ar.trim().is_empty() => ar,
        _ => en,
    }
}

fn status_label(status: &str, lang: Lang) -> String {
    let known = label(status, lang);
    if known.is_empty() {
        escape_html(status)
    } else {
        known.to_owned()
    }
}

fn events(out: &mut String, heading: &str, list: &[StatusEvent], lang: Lang) {
    out.push_str(&format!("<h2>{heading}</h2>"));
    if list.is_empty() {
        out.push_str(&format!("<p class=\"none\">{}</p>", label("none", lang)));
        return;
    }
    for event in list {
        out.push_str("<article>");
        out.push_str(&format!(
            "<h3>{}</h3>",
            escape_html(pick(lang, &event.title, event.title_ar.as_deref()))
        ));
        if let Some(status) = event.status.as_deref() {
            out.push_str(&format!("<p class=\"state\">{}</p>", escape_html(status)));
        }
        for update in &event.updates {
            out.push_str(&format!(
                "<p><time datetime=\"{at}\">{at}</time> {body}</p>",
                at = update.at.format("%Y-%m-%dT%H:%MZ"),
                body = escape_html(pick(lang, &update.body, update.body_ar.as_deref())),
            ));
        }
        out.push_str("</article>");
    }
}

fn section(page: &StatusPage, lang: Lang) -> String {
    let (code, dir) = match lang {
        Lang::En => ("en", "ltr"),
        Lang::Ar => ("ar", "rtl"),
    };
    let mut out = format!("<section lang=\"{code}\" dir=\"{dir}\">");
    out.push_str(&format!(
        "<h1>{}</h1><p class=\"overall s-{status}\">{label}</p>",
        label("title", lang),
        status = escape_html(&page.overall),
        label = status_label(&page.overall, lang),
    ));
    out.push_str(&format!("<h2>{}</h2>", label("components", lang)));
    for group in &page.groups {
        if let Some(name) = group.name.as_deref() {
            out.push_str(&format!("<h3>{}</h3>", escape_html(name)));
        }
        out.push_str("<ul>");
        for c in &group.components {
            out.push_str(&format!(
                "<li><span>{name}</span><span class=\"s-{status}\">{label}</span></li>",
                name = escape_html(pick(lang, &c.name, c.name_ar.as_deref())),
                status = escape_html(&c.status),
                label = status_label(&c.status, lang),
            ));
        }
        out.push_str("</ul>");
    }
    events(&mut out, label("incidents", lang), &page.incidents, lang);
    events(&mut out, label("scheduled", lang), &page.maintenance, lang);
    events(
        &mut out,
        label("resolved", lang),
        &page.recently_resolved,
        lang,
    );
    out.push_str(&format!(
        "<p class=\"updated\">{} <time datetime=\"{at}\">{at}</time></p></section>",
        label("updated", lang),
        at = page.generated_at.format("%Y-%m-%dT%H:%MZ"),
    ));
    out
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;margin:0;background:#f7f7f8;color:#1d1d1f}\
section{max-inline-size:48rem;margin-inline:auto;padding-block:2rem;padding-inline:1rem}\
ul{list-style:none;padding-inline-start:0}\
li{display:flex;justify-content:space-between;padding-block:.5rem;border-block-end:1px solid #ddd}\
article{padding-block:.5rem;border-inline-start:3px solid #999;padding-inline-start:.75rem;margin-block:.75rem}\
.overall{font-size:1.25rem;font-weight:600}\
.s-operational{color:#1a7f37}.s-maintenance{color:#0969da}.s-degraded{color:#9a6700}\
.s-partial_outage{color:#bc4c00}.s-major_outage{color:#cf222e}\
.none,.updated,.state{color:#57606a}\
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}li{border-color:#30363d}}";

/// The whole page, English then Arabic. Pure.
pub fn render_html(page: &StatusPage) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title} · {title_ar}</title><style>{STYLE}</style></head><body>{en}{ar}</body></html>\n",
        title = label("title", Lang::En),
        title_ar = label("title", Lang::Ar),
        en = section(page, Lang::En),
        ar = section(page, Lang::Ar),
    )
}

/// Renders the page from the records and writes `index.html` and
/// `status.json` under [`PREFIX`] in the object store.
pub async fn publish(state: &EngineState) -> Result<(), AppError> {
    let page = crate::status_page::build(state).await?;
    let html = render_html(&page);
    let json = serde_json::to_vec(&page).map_err(AppError::internal)?;
    let store = state.base.storage.store();
    for (name, bytes) in [("index.html", html.into_bytes()), ("status.json", json)] {
        let path = ObjectPath::parse(format!("{PREFIX}/{name}")).map_err(AppError::internal)?;
        store
            .put(&path, bytes.into())
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

#[cfg(test)]
mod status_page_render {
    use super::*;
    use crate::status_page::{StatusComponent, StatusGroup, StatusUpdate};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn page() -> StatusPage {
        let at = Utc.with_ymd_and_hms(2026, 10, 20, 9, 30, 0).unwrap();
        StatusPage {
            overall: "partial_outage".into(),
            groups: vec![StatusGroup {
                name: Some("Core".into()),
                components: vec![StatusComponent {
                    id: Uuid::nil(),
                    name: "API <v1>".into(),
                    name_ar: Some("الواجهة".into()),
                    status: "partial_outage".into(),
                }],
            }],
            incidents: vec![StatusEvent {
                id: Uuid::nil(),
                title: "Slow sign-in".into(),
                title_ar: None,
                status: Some("investigating".into()),
                impact: None,
                component_id: None,
                starts_at: Some(at),
                ends_at: None,
                updates: vec![StatusUpdate {
                    status: None,
                    body: "We are looking <script>".into(),
                    body_ar: Some("نحن نتحقق".into()),
                    at,
                }],
            }],
            maintenance: vec![],
            recently_resolved: vec![],
            generated_at: at,
        }
    }

    #[test]
    fn renders_both_languages_and_escapes_record_text() {
        let html = render_html(&page());
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<section lang=\"en\" dir=\"ltr\">"));
        assert!(html.contains("<section lang=\"ar\" dir=\"rtl\">"));
        assert!(html.contains("Partial outage"));
        assert!(html.contains("انقطاع جزئي"));
        assert!(html.contains("الواجهة"));
        assert!(html.contains("API &lt;v1&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("نحن نتحقق"));
        assert!(html.contains("2026-10-20T09:30Z"));
    }

    #[test]
    fn uses_logical_properties_only() {
        let html = render_html(&page());
        for physical in [
            "margin-left",
            "margin-right",
            "padding-left",
            "padding-right",
            "text-align:left",
            "border-left",
        ] {
            assert!(!html.contains(physical), "{physical}");
        }
    }

    #[test]
    fn empty_lists_say_nothing_to_report() {
        let html = render_html(&page());
        assert!(html.contains(label("none", Lang::En)));
        assert!(html.contains(label("none", Lang::Ar)));
    }

    #[test]
    fn the_page_survives_its_own_json() {
        let json = serde_json::to_string(&page()).unwrap();
        let back: StatusPage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, page());
    }
}
