//! AB4-T10: the auditor pack. `GET /api/v1/ops/drills/auditor-pack?from=&to=`
//! (`ops.auditor.read`) answers one zip an auditor checks offline:
//!
//! - `evidence/<kind>/<date>-<id>.json`: every signed drill report finished
//!   in the period (at most 400 days), exactly as uploaded;
//! - `keys/drill-public-keys.txt` (key id and key per line) and one
//!   `keys/<key id>.pub` per configured key, for `attome drill verify
//!   --public-key`;
//! - `README.txt`, in English and Arabic, saying how to verify;
//! - the verification guide as `guide-en.pdf` and `guide-ar.pdf` (right to
//!   left), rendered through the docgen render service; when that service
//!   does not answer, `guide-en.html` and `guide-ar.html` instead, and the
//!   README says so.
//!
//! The zip is built off the async runtime (`spawn_blocking`), stored without
//! compression (the files are small and already text). The export is
//! audited (`ops.auditor_pack_exported`, Access) through the security event
//! writer; a GET carries no `x-audit` declaration. Every report is signed
//! (AB4-T6 accepts nothing else), so there are no legacy files to mark.

use std::io::Write;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{StatusCode, header},
    response::Response,
    routing::get,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::evidence;

/// The longest period one pack covers.
pub const MAX_DAYS: i64 = 400;

/// `ops.auditor.read`: who exports the auditor pack.
#[derive(Debug)]
pub struct OpsAuditorRead;

impl PrivilegeKey for OpsAuditorRead {
    const KEY: &'static str = "ops.auditor.read";
}

/// The pack's period, both days included.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PackPeriod {
    /// First day (YYYY-MM-DD, UTC).
    pub from: NaiveDate,
    /// Last day (YYYY-MM-DD, UTC).
    pub to: NaiveDate,
}

/// Checks a period. Pure.
pub fn check_period(period: &PackPeriod) -> Result<(), AppError> {
    if period.to < period.from {
        return Err(AppError::Validation("to is on or after from".into()));
    }
    if (period.to - period.from).num_days() + 1 > MAX_DAYS {
        return Err(AppError::Validation(format!(
            "a pack covers at most {MAX_DAYS} days"
        )));
    }
    Ok(())
}

/// One stored report, as the pack lists it.
#[derive(Debug, Clone)]
pub struct PackedRun {
    pub id: Uuid,
    pub kind: String,
    pub finished_at: DateTime<Utc>,
    pub evidence: serde_json::Value,
}

/// A report's path in the zip. Pure.
pub fn evidence_path(run: &PackedRun) -> String {
    format!(
        "evidence/{}/{}-{}.json",
        run.kind,
        run.finished_at.format("%Y-%m-%d"),
        run.id
    )
}

const README_EN: &str = "Attome recovery drill evidence

Each file under evidence/ is one drill's report (attome-evidence/v1),
signed with Ed25519 by the drill host. To check one offline, with the
attome binary of any version:

  attome drill verify evidence/<kind>/<file>.json --public-key keys/<key id>.pub

'signature ok' means the report is the one the drill produced, unchanged.
The command then prints overall_ok; exit 0 means the drill passed, 2 a bad
signature, 3 a drill that failed. The key id each report names is in its
key_id field; keys/drill-public-keys.txt lists the deployment's keys.
";

const README_AR: &str = "أدلة تمارين الاستعادة في Attome

كل ملف تحت evidence/ تقرير تمرين واحد (attome-evidence/v1) موقّع بمفتاح
Ed25519 لمضيف التمرين. للتحقق منه دون اتصال، بأي إصدار من attome:

  attome drill verify evidence/<kind>/<file>.json --public-key keys/<key id>.pub

تعني 'signature ok' أن التقرير هو ما أنتجه التمرين دون تغيير. ثم يطبع الأمر
overall_ok؛ رمز الخروج 0 نجاح التمرين، و2 توقيع غير صالح، و3 تمرين فشل.
معرّف المفتاح في الحقل key_id من كل تقرير، ويسرد keys/drill-public-keys.txt
مفاتيح هذا النشر.
";

const HTML_NOTE: &str = "
The render service did not answer, so the guide is included as
guide-en.html and guide-ar.html instead of PDF.
لم تستجب خدمة العرض، فأُرفق الدليل بصيغة HTML بدل PDF.
";

/// The verification guide as HTML, in English or Arabic. Pure.
pub fn guide_html(arabic: bool) -> String {
    let (lang, dir, title, body) = if arabic {
        ("ar", "rtl", "دليل التحقق من أدلة التمارين", README_AR)
    } else {
        ("en", "ltr", "Verifying drill evidence", README_EN)
    };
    let escaped = body
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        "<!doctype html><html lang=\"{lang}\" dir=\"{dir}\"><head><meta charset=\"utf-8\">\
         <title>{title}</title></head><body><h1>{title}</h1><pre style=\"white-space:pre-wrap\">{escaped}</pre></body></html>"
    )
}

/// The guide files: PDFs, or the HTML when the render service is away.
#[derive(Debug)]
pub struct Guides {
    pub files: Vec<(String, Vec<u8>)>,
    pub rendered: bool,
}

/// Builds the zip. Pure but for the allocation; run it off the runtime.
pub fn build_zip(runs: &[PackedRun], keys: &[String], guides: &Guides) -> Result<Vec<u8>, String> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut add = |name: &str, bytes: &[u8]| -> Result<(), String> {
        zip.start_file(name, options).map_err(|e| e.to_string())?;
        zip.write_all(bytes).map_err(|e| e.to_string())
    };
    for run in runs {
        let mut bytes = serde_json::to_vec_pretty(&run.evidence).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        add(&evidence_path(run), &bytes)?;
    }
    let mut list = String::new();
    for key in keys {
        let id = evidence::verifying_key(key)
            .map(|k| evidence::key_id(&k))
            .unwrap_or_else(|_| "invalid".to_owned());
        list.push_str(&format!("{id} {}\n", key.trim()));
        if id != "invalid" {
            add(
                &format!("keys/{id}.pub"),
                format!("{}\n", key.trim()).as_bytes(),
            )?;
        }
    }
    add("keys/drill-public-keys.txt", list.as_bytes())?;
    let mut readme = format!("{README_EN}\n{README_AR}");
    if !guides.rendered {
        readme.push_str(HTML_NOTE);
    }
    add("README.txt", readme.as_bytes())?;
    for (name, bytes) in &guides.files {
        add(name, bytes)?;
    }
    zip.finish()
        .map(std::io::Cursor::into_inner)
        .map_err(|e| e.to_string())
}

async fn guides(state: &EngineState) -> Guides {
    let docgen = &state.base.config.docgen;
    let en = guide_html(false);
    let ar = guide_html(true);
    let rendered = match (
        attome_docgen::render_client::render_pdf(docgen, &en, "A4", None).await,
        attome_docgen::render_client::render_pdf(docgen, &ar, "A4", None).await,
    ) {
        (Ok(en_pdf), Ok(ar_pdf)) => Some((en_pdf, ar_pdf)),
        (Err(error), _) | (_, Err(error)) => {
            tracing::warn!(%error, "auditor pack: the guide was not rendered; HTML included");
            None
        }
    };
    match rendered {
        Some((en_pdf, ar_pdf)) => Guides {
            files: vec![
                ("guide-en.pdf".into(), en_pdf),
                ("guide-ar.pdf".into(), ar_pdf),
            ],
            rendered: true,
        },
        None => Guides {
            files: vec![
                ("guide-en.html".into(), en.into_bytes()),
                ("guide-ar.html".into(), ar.into_bytes()),
            ],
            rendered: false,
        },
    }
}

/// Export the auditor pack
///
/// AB4-T10: a zip of every signed drill report finished in the period (at
/// most 400 days), the drill public keys, and how to verify them offline in
/// English and Arabic. Needs `ops.auditor.read`. The export is audited.
#[utoipa::path(
    get,
    path = "/api/v1/ops/drills/auditor-pack",
    tag = "ops",
    operation_id = "export_ops_auditor_pack",
    params(PackPeriod),
    responses(
        (status = 200, description = "The pack", content_type = "application/zip", body = Vec<u8>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.auditor.read", body = ErrorResponse),
        (status = 422, description = "A period that ends before it starts or is longer than 400 days", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_pack(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsAuditorRead>>,
    Query(period): Query<PackPeriod>,
) -> Result<Response, AppError> {
    check_period(&period)?;
    let rows: Vec<(Uuid, String, DateTime<Utc>, serde_json::Value)> = sqlx::query_as(
        "SELECT id, kind, finished_at, evidence FROM ops_drill_run \
          WHERE finished_at >= $1::date AND finished_at < $2::date + 1 \
          ORDER BY finished_at, id",
    )
    .bind(period.from)
    .bind(period.to)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let runs: Vec<PackedRun> = rows
        .into_iter()
        .map(|(id, kind, finished_at, evidence)| PackedRun {
            id,
            kind,
            finished_at,
            evidence,
        })
        .collect();
    let count = runs.len();
    let keys = state.base.config.ops.drill_public_keys.clone();
    let guides = guides(&state).await;
    let bytes = tokio::task::spawn_blocking(move || build_zip(&runs, &keys, &guides))
        .await
        .map_err(AppError::internal)?
        .map_err(AppError::internal)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Export,
            ctx.user_id,
            "ops_drill_run",
            None,
        )
        .named("ops.auditor_pack_exported")
        .comment(format!(
            "auditor pack {} to {}: {count} drill reports",
            period.from, period.to
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"attome-auditor-pack-{}-{}.zip\"",
                period.from, period.to
            ),
        )
        .body(Body::from(bytes))
        .map_err(AppError::internal)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ops/drills/auditor-pack", get(export_pack))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(export_pack))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn period_over_400_days_is_422() {
        let period = |from: &str, to: &str| PackPeriod {
            from: day(from),
            to: day(to),
        };
        assert!(check_period(&period("2026-01-01", "2026-01-01")).is_ok());
        assert!(check_period(&period("2025-01-01", "2026-02-04")).is_ok());
        assert!(check_period(&period("2025-01-01", "2026-02-05")).is_err());
        assert!(check_period(&period("2026-02-01", "2026-01-01")).is_err());
    }

    #[test]
    fn pack_contains_evidence_and_keys() {
        let key = evidence::SigningKey::from_bytes(&[4u8; 32]);
        let public = evidence::public_key_base64(&key);
        let id = evidence::key_id(&key.verifying_key());
        let run = PackedRun {
            id: Uuid::nil(),
            kind: "restore".into(),
            finished_at: DateTime::parse_from_rfc3339("2026-10-01T03:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            evidence: serde_json::json!({ "key_id": id, "signature": "x" }),
        };
        let guides = Guides {
            files: vec![("guide-en.html".into(), guide_html(false).into_bytes())],
            rendered: false,
        };
        let bytes = build_zip(std::slice::from_ref(&run), &[public.clone()], &guides).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut names: Vec<String> = archive.file_names().map(str::to_owned).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "README.txt".to_owned(),
                "evidence/restore/2026-10-01-00000000-0000-0000-0000-000000000000.json".to_owned(),
                "guide-en.html".to_owned(),
                format!("keys/{id}.pub"),
                "keys/drill-public-keys.txt".to_owned(),
            ]
        );
        let mut list = String::new();
        archive
            .by_name("keys/drill-public-keys.txt")
            .unwrap()
            .read_to_string(&mut list)
            .unwrap();
        assert_eq!(list, format!("{id} {public}\n"));
        let mut readme = String::new();
        archive
            .by_name("README.txt")
            .unwrap()
            .read_to_string(&mut readme)
            .unwrap();
        assert!(readme.contains("attome drill verify"));
        assert!(readme.contains("HTML"));
        assert!(guide_html(true).contains("dir=\"rtl\""));
    }
}
