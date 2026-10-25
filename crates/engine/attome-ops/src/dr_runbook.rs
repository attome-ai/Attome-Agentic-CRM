//! AB3-T8: this deployment's disaster runbook, generated.
//!
//! `GET /api/v1/ops/dr-runbook?lang=en|ar&format=html|pdf` (`ops.read`)
//! fills one bilingual template (Arabic right to left) from what this
//! deployment is: its profile and recovery targets with their proof
//! (AB3-T1), the people to call (`ops.dr_contacts`), how to declare a
//! disaster (AB3-T7), the recovery commands with this deployment's backup
//! folder, failback, and the checks after recovery.
//!
//! v2 backs up with `pg_dump` into `backup.dir` and restores with
//! `attome restore`, so the commands name that folder (there is no
//! pgBackRest stanza). Nothing secret is written: no password, key or
//! credential value, only paths and command lines. `format=pdf` renders
//! through the docgen render service and falls back to HTML when it does
//! not answer.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{StatusCode, header},
    response::Response,
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::recovery_targets::RecoveryTarget;
use crate::upgrades::OpsRead;

/// The runbook's options.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunbookQuery {
    /// `en` (default) or `ar`.
    #[serde(default)]
    pub lang: Option<String>,
    /// `html` (default) or `pdf`.
    #[serde(default)]
    pub format: Option<String>,
}

/// One person to call, as `ops.dr_contacts` lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub name: String,
    pub role: String,
    pub phone: String,
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct Words {
    lang: &'static str,
    dir: &'static str,
    title: &'static str,
    scope: &'static str,
    profile: &'static str,
    scenario: &'static str,
    rpo: &'static str,
    rto: &'static str,
    proven: &'static str,
    yes: &'static str,
    no: &'static str,
    contacts: &'static str,
    no_contacts: &'static str,
    declare: &'static str,
    declare_text: &'static str,
    recover: &'static str,
    recover_text: &'static str,
    failback: &'static str,
    failback_text: &'static str,
    after: &'static str,
    after_text: &'static str,
}

const EN: Words = Words {
    lang: "en",
    dir: "ltr",
    title: "Disaster recovery runbook",
    scope: "Scope and targets",
    profile: "Deployment profile",
    scenario: "Scenario",
    rpo: "Data loss allowed (RPO, s)",
    rto: "Time to serve again (RTO, s)",
    proven: "Proven by a fresh drill",
    yes: "yes",
    no: "no",
    contacts: "Who to call",
    no_contacts: "No contacts are configured (ops.dr_contacts).",
    declare: "Declare the disaster",
    declare_text: "An operator with ops.dr.declare declares it (POST /api/v1/ops/disasters, or the operations pages). Every action that replaces live data or switches site waits for a second person in the Operations role to approve it.",
    recover: "Recover",
    recover_text: "On the recovery host, with the configuration of this deployment:",
    failback: "Fail back",
    failback_text: "When the primary site is healthy again, take a fresh backup on the recovery site, restore it on the primary the same way, ask for the failback action on the declared disaster, and close the disaster once traffic is back.",
    after: "After recovery",
    after_text: "Check that the server is ready and every check passes, verify the audit chain, and record a restore drill so the targets show as proven again:",
};

const AR: Words = Words {
    lang: "ar",
    dir: "rtl",
    title: "دليل التعافي من الكوارث",
    scope: "النطاق والأهداف",
    profile: "ملف النشر",
    scenario: "السيناريو",
    rpo: "فقد البيانات المسموح (ث)",
    rto: "وقت العودة للخدمة (ث)",
    proven: "مثبت بتمرين حديث",
    yes: "نعم",
    no: "لا",
    contacts: "جهات الاتصال",
    no_contacts: "لم تُضبط جهات اتصال (ops.dr_contacts).",
    declare: "إعلان الكارثة",
    declare_text: "يعلنها مشغّل يملك ops.dr.declare (عبر POST /api/v1/ops/disasters أو صفحات العمليات). كل إجراء يستبدل البيانات الحية أو يحوّل الموقع ينتظر موافقة شخص آخر في دور العمليات.",
    recover: "الاستعادة",
    recover_text: "على مضيف الاستعادة، وبإعدادات هذا النشر:",
    failback: "العودة إلى الموقع الأساسي",
    failback_text: "عندما يعود الموقع الأساسي سليمًا، خذ نسخة احتياطية حديثة على موقع الاستعادة، واستعدها على الأساسي بالطريقة نفسها، واطلب إجراء العودة على الكارثة المعلنة، ثم أغلقها بعد عودة الحركة.",
    after: "بعد الاستعادة",
    after_text: "تأكد أن الخادم جاهز وأن كل الفحوص تنجح، وتحقق من سلسلة التدقيق، وسجّل تمرين استعادة لتظهر الأهداف مثبتة من جديد:",
};

/// The runbook as HTML. Pure.
pub fn render(
    arabic: bool,
    profile: &str,
    targets: &[RecoveryTarget],
    contacts: &[Contact],
    backup_dir: &str,
) -> String {
    let w = if arabic { &AR } else { &EN };
    let mut rows = String::new();
    for t in targets {
        rows.push_str(&format!(
            "<tr><td dir=\"ltr\">{}</td><td dir=\"ltr\">{}</td><td dir=\"ltr\">{}</td><td>{}</td></tr>",
            escape(&t.scenario),
            t.rpo_seconds,
            t.rto_seconds,
            if t.proven { w.yes } else { w.no }
        ));
    }
    let people = if contacts.is_empty() {
        format!("<p>{}</p>", w.no_contacts)
    } else {
        let mut list = String::from("<ul>");
        for c in contacts {
            list.push_str(&format!(
                "<li><strong>{}</strong> · {} · <span dir=\"ltr\">{}</span></li>",
                escape(&c.name),
                escape(&c.role),
                escape(&c.phone)
            ));
        }
        list.push_str("</ul>");
        list
    };
    let dir = escape(backup_dir);
    format!(
        "<!doctype html><html lang=\"{lang}\" dir=\"{d}\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body>\
         <h1>{title}</h1>\
         <h2>{scope}</h2><p>{profile_label}: <strong dir=\"ltr\">{profile}</strong></p>\
         <table><thead><tr><th>{scenario}</th><th>{rpo}</th><th>{rto}</th><th>{proven}</th></tr></thead><tbody>{rows}</tbody></table>\
         <h2>{contacts}</h2>{people}\
         <h2>{declare}</h2><p>{declare_text}</p>\
         <h2>{recover}</h2><p>{recover_text}</p>\
         <pre dir=\"ltr\">attome drill readiness\nattome restore latest    # newest archive in {dir}\nattome restore &lt;archive&gt;    # a named archive from {dir}\nattome serve</pre>\
         <h2>{failback}</h2><p>{failback_text}</p>\
         <h2>{after}</h2><p>{after_text}</p>\
         <pre dir=\"ltr\">attome doctor\nattome verify-audit-chain\nattome drill readiness</pre>\
         </body></html>",
        lang = w.lang,
        d = w.dir,
        title = w.title,
        scope = w.scope,
        profile_label = w.profile,
        profile = escape(profile),
        scenario = w.scenario,
        rpo = w.rpo,
        rto = w.rto,
        proven = w.proven,
        contacts = w.contacts,
        declare = w.declare,
        declare_text = w.declare_text,
        recover = w.recover,
        recover_text = w.recover_text,
        failback = w.failback,
        failback_text = w.failback_text,
        after = w.after,
        after_text = w.after_text,
    )
}

/// The disaster runbook
///
/// AB3-T8: this deployment's runbook, from its profile, recovery targets,
/// contacts and backup folder, in English or Arabic, as HTML or (when the
/// render service answers) PDF. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/dr-runbook",
    tag = "ops",
    operation_id = "get_ops_dr_runbook",
    params(RunbookQuery),
    responses(
        (status = 200, description = "The runbook (text/html, or application/pdf when asked and available)", content_type = "text/html", body = String),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 422, description = "An unknown language or format", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_runbook(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(query): Query<RunbookQuery>,
) -> Result<Response, AppError> {
    let arabic = match query.lang.as_deref().unwrap_or("en") {
        "en" => false,
        "ar" => true,
        _ => return Err(AppError::Validation("lang is en or ar".into())),
    };
    let pdf = match query.format.as_deref().unwrap_or("html") {
        "html" => false,
        "pdf" => true,
        _ => return Err(AppError::Validation("format is html or pdf".into())),
    };
    let config = &state.base.config;
    let profile = config.ops.profile.clone();
    let targets = crate::recovery_targets::list_with_proof(&state.base.db, &profile).await?;
    let contacts: Vec<Contact> = config
        .ops
        .dr_contacts
        .iter()
        .map(|c| Contact {
            name: c.name.clone(),
            role: c.role.clone(),
            phone: c.phone.clone(),
        })
        .collect();
    let backup_dir = config.backup.resolved_dir().display().to_string();
    let html = render(arabic, &profile, &targets, &contacts, &backup_dir);
    if pdf {
        match attome_docgen::render_client::render_pdf(&config.docgen, &html, "A4", None).await {
            Ok(bytes) => {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/pdf")
                    .body(Body::from(bytes))
                    .map_err(AppError::internal);
            }
            Err(error) => {
                tracing::warn!(%error, "dr runbook: the PDF was not rendered; answering HTML");
            }
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .map_err(AppError::internal)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ops/dr-runbook", get(get_runbook))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_runbook))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(scenario: &str, proven: bool) -> RecoveryTarget {
        RecoveryTarget {
            id: uuid::Uuid::nil(),
            profile: "solo".into(),
            scenario: scenario.into(),
            rpo_seconds: 300,
            rto_seconds: 3600,
            evidence_kind: "recovery".into(),
            proven,
            proven_on: None,
            measured_rpo_seconds: None,
            measured_rto_seconds: None,
            row_version: 1,
            updated_by: None,
            updated_at: None,
        }
    }

    #[test]
    fn runbook_contains_stanza_and_contacts() {
        let html = render(
            false,
            "solo",
            &[target("corruption", true), target("ransomware", false)],
            &[Contact {
                name: "Sara <ops>".into(),
                role: "On call".into(),
                phone: "+966 55 000 0000".into(),
            }],
            "/var/lib/attome/backups",
        );
        assert!(html.contains("attome restore latest"));
        assert!(html.contains("/var/lib/attome/backups"));
        assert!(html.contains("Sara &lt;ops&gt;"));
        assert!(html.contains("+966 55 000 0000"));
        assert!(html.contains("corruption"));
        assert!(html.contains("dir=\"ltr\""));
    }

    #[test]
    fn arabic_runbook_is_rtl() {
        let html = render(true, "ha", &[], &[], "C:\\attome\\backups");
        assert!(html.starts_with("<!doctype html><html lang=\"ar\" dir=\"rtl\">"));
        assert!(html.contains("دليل التعافي من الكوارث"));
        assert!(html.contains("ops.dr_contacts"));
    }
}
