//! AD6-T2: documentation for every published metadata version, in English
//! and Arabic.
//!
//! A publish that records a new version (`attome_model::switch::record`)
//! enqueues [`PUBLISH_DOCS`] in its own transaction, so the documentation
//! job exists exactly when the version does. The job ([`generate`]) reads the
//! deployment's live metadata (entities with their fields, flows, rules) and
//! the metadata changes made between the previous version and this one,
//! renders one Markdown document per language ([`render`]; Arabic names from
//! `metadata_label`, falling back to the English name) and stores both in
//! `metadata_version_doc` (migration 0285) with the version. A retry
//! rewrites the same rows. `GET /api/v1/admin/metadata/versions/{version}/docs`
//! answers it.
//!
//! Metadata only: no record value is read. Each list is capped at
//! [`MAX_ITEMS`] so a very large model still renders a bounded document.

use attome_core::{EngineState, FieldType};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// The registered job type that writes a version's documentation.
pub const PUBLISH_DOCS: attome_jobs::JobType =
    attome_jobs::JobType::new("metadata_publish_docs", 1);

/// The languages every version is documented in.
pub const LANGS: [&str; 2] = ["en", "ar"];

/// The most entities, flows, rules and changes one document lists.
pub const MAX_ITEMS: i64 = 500;

/// What the documentation job carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishDocsPayload {
    pub version: i64,
}

/// The job that documents `version`, for a publish to enqueue in its
/// transaction.
pub fn publish_docs_job(version: i64) -> attome_core::jobs::EngineJob {
    attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
        name: PUBLISH_DOCS.name.to_owned(),
        version: PUBLISH_DOCS.version,
        payload: json!(PublishDocsPayload { version }),
        next: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocField {
    pub logicalname: String,
    pub name: String,
    pub name_ar: Option<String>,
    pub field_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocEntity {
    pub logicalname: String,
    pub name: String,
    pub name_ar: Option<String>,
    pub fields: Vec<DocField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocRule {
    pub entity: String,
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocChange {
    pub logicalname: String,
    pub change_kind: String,
    pub at: DateTime<Utc>,
}

/// Everything one version's documentation says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocInput {
    pub version: i64,
    pub published_at: DateTime<Utc>,
    /// The version before, when there is one.
    pub previous: Option<i64>,
    pub entities: Vec<DocEntity>,
    pub flows: Vec<String>,
    pub rules: Vec<DocRule>,
    pub changes: Vec<DocChange>,
}

/// The words of a document, per language.
struct Words {
    title: &'static str,
    published: &'static str,
    entities: &'static str,
    fields: &'static str,
    flows: &'static str,
    rules: &'static str,
    changes: &'static str,
    first: &'static str,
    none: &'static str,
}

const EN: Words = Words {
    title: "Documentation for version",
    published: "Published",
    entities: "Entities",
    fields: "Fields",
    flows: "Flows",
    rules: "Rules",
    changes: "Changes since version",
    first: "This is the first version.",
    none: "None.",
};

const AR: Words = Words {
    title: "توثيق الإصدار",
    published: "نُشر في",
    entities: "الكيانات",
    fields: "الحقول",
    flows: "التدفقات",
    rules: "القواعد",
    changes: "التغييرات منذ الإصدار",
    first: "هذا هو الإصدار الأول.",
    none: "لا شيء.",
};

/// A Markdown cell: `|` and line breaks would break the table.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// One version's documentation in `lang` (`ar` for Arabic, English
/// otherwise), as Markdown. Pure.
pub fn render(input: &DocInput, lang: &str) -> String {
    let arabic = lang == "ar";
    let w = if arabic { &AR } else { &EN };
    let name = |en: &str, ar: &Option<String>| -> String {
        match (arabic, ar) {
            (true, Some(ar)) if !ar.trim().is_empty() => ar.clone(),
            _ => en.to_owned(),
        }
    };
    let mut out = format!(
        "# {} {}\n\n{}: {}\n\n## {}\n\n",
        w.title,
        input.version,
        w.published,
        input.published_at.format("%Y-%m-%d %H:%M UTC"),
        w.entities
    );
    if input.entities.is_empty() {
        out.push_str(&format!("{}\n\n", w.none));
    }
    for entity in &input.entities {
        out.push_str(&format!(
            "### {} (`{}`)\n\n",
            name(&entity.name, &entity.name_ar),
            entity.logicalname
        ));
        if entity.fields.is_empty() {
            out.push_str(&format!("{}\n\n", w.none));
            continue;
        }
        out.push_str(&format!("{}:\n\n| | | |\n|---|---|---|\n", w.fields));
        for field in &entity.fields {
            out.push_str(&format!(
                "| {} | `{}` | {} |\n",
                cell(&name(&field.name, &field.name_ar)),
                field.logicalname,
                field.field_type
            ));
        }
        out.push('\n');
    }
    out.push_str(&format!("## {}\n\n", w.flows));
    if input.flows.is_empty() {
        out.push_str(&format!("{}\n\n", w.none));
    } else {
        for flow in &input.flows {
            out.push_str(&format!("- {}\n", cell(flow)));
        }
        out.push('\n');
    }
    out.push_str(&format!("## {}\n\n", w.rules));
    if input.rules.is_empty() {
        out.push_str(&format!("{}\n\n", w.none));
    } else {
        for rule in &input.rules {
            out.push_str(&format!(
                "- `{}`: {} ({})\n",
                rule.entity,
                cell(&rule.name),
                rule.kind
            ));
        }
        out.push('\n');
    }
    match input.previous {
        None => out.push_str(&format!("{}\n", w.first)),
        Some(previous) => {
            out.push_str(&format!("## {} {}\n\n", w.changes, previous));
            if input.changes.is_empty() {
                out.push_str(&format!("{}\n", w.none));
            }
            for change in &input.changes {
                out.push_str(&format!(
                    "- {} `{}` {}\n",
                    change.at.format("%Y-%m-%d %H:%M"),
                    change.logicalname,
                    change.change_kind
                ));
            }
        }
    }
    out
}

/// The field type's name for the document.
fn type_name(type_int: Option<i32>) -> String {
    type_int
        .and_then(FieldType::from_int)
        .map_or_else(|| "text".to_owned(), |t| t.as_str().to_owned())
}

/// Reads what `version`'s documentation says from the live metadata.
pub async fn gather(state: &EngineState, version: i64) -> Result<DocInput, AppError> {
    let db = &state.base.db;
    let meta = &state.base.db_migrator;
    let published_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT published_at FROM metadata_published_version WHERE version = $1",
    )
    .bind(version)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let previous: Option<(i64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT version, published_at FROM metadata_published_version \
          WHERE version < $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(version)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let labels: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT object_kind, object_ref, display_name FROM metadata_label \
          WHERE locale LIKE 'ar%' AND object_kind IN ('entity', 'attribute')",
    )
    .fetch_all(meta)
    .await
    .map_err(AppError::internal)?;
    let arabic = |kind: &str, reference: &str| {
        labels
            .iter()
            .find(|(k, r, _)| k == kind && r == reference)
            .map(|(_, _, name)| name.clone())
    };

    let entity_rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, logicalname, name FROM entity_info \
          WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL \
          ORDER BY logicalname LIMIT $1",
    )
    .bind(MAX_ITEMS)
    .fetch_all(meta)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = entity_rows.iter().map(|(id, _, _)| *id).collect();
    let attribute_rows: Vec<(Uuid, String, Option<String>, Option<i32>)> = sqlx::query_as(
        "SELECT entity_ref, logicalname, name, type FROM attribute_info \
          WHERE entity_ref = ANY($1) AND (is_active IS NULL OR is_active = true) \
            AND logicalname IS NOT NULL \
          ORDER BY entity_ref, logicalname",
    )
    .bind(&ids)
    .fetch_all(meta)
    .await
    .map_err(AppError::internal)?;
    let entities = entity_rows
        .into_iter()
        .map(|(id, logicalname, name)| DocEntity {
            name_ar: arabic("entity", &logicalname),
            fields: attribute_rows
                .iter()
                .filter(|(entity, ..)| *entity == id)
                .map(|(_, field, field_name, type_int)| DocField {
                    name: field_name.clone().unwrap_or_else(|| field.clone()),
                    name_ar: arabic("attribute", &format!("{logicalname}.{field}")),
                    logicalname: field.clone(),
                    field_type: type_name(*type_int),
                })
                .collect(),
            name: name.unwrap_or_else(|| logicalname.clone()),
            logicalname,
        })
        .collect();

    let flows: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM workflow_definition WHERE is_active AND NOT is_deleted \
          ORDER BY name LIMIT $1",
    )
    .bind(MAX_ITEMS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rules: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT entity_logicalname, name, kind FROM rule WHERE is_active AND NOT is_deleted \
          ORDER BY entity_logicalname, display_order, name LIMIT $1",
    )
    .bind(MAX_ITEMS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let changes: Vec<(String, String, DateTime<Utc>)> = match previous {
        Some((_, since)) => sqlx::query_as(
            "SELECT logicalname, change_kind, created_at FROM metadata_change_log \
              WHERE created_at > $1 AND created_at <= $2 ORDER BY created_at DESC LIMIT $3",
        )
        .bind(since)
        .bind(published_at)
        .bind(MAX_ITEMS)
        .fetch_all(meta)
        .await
        .map_err(AppError::internal)?,
        None => Vec::new(),
    };
    Ok(DocInput {
        version,
        published_at,
        previous: previous.map(|(v, _)| v),
        entities,
        flows,
        rules: rules
            .into_iter()
            .map(|(entity, name, kind)| DocRule { entity, name, kind })
            .collect(),
        changes: changes
            .into_iter()
            .map(|(logicalname, change_kind, at)| DocChange {
                logicalname,
                change_kind,
                at,
            })
            .collect(),
    })
}

/// The documentation job: renders `version` in every language and stores
/// it, replacing an earlier attempt's.
pub async fn generate(state: &EngineState, version: i64) -> Result<(), AppError> {
    let input = gather(state, version).await?;
    for lang in LANGS {
        sqlx::query(
            "INSERT INTO metadata_version_doc (version, lang, markdown) VALUES ($1, $2, $3) \
             ON CONFLICT (version, lang) DO UPDATE SET markdown = EXCLUDED.markdown, \
                 generated_at = now()",
        )
        .bind(version)
        .bind(lang)
        .bind(render(&input, lang))
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// A version's stored documentation.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct VersionDoc {
    pub version: i64,
    /// `en` or `ar`.
    pub lang: String,
    pub markdown: String,
    pub generated_at: DateTime<Utc>,
}

/// `version`'s documentation in `lang`; `None` until the job has written it.
pub async fn read_doc(
    state: &EngineState,
    version: i64,
    lang: &str,
) -> Result<Option<VersionDoc>, AppError> {
    let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT markdown, generated_at FROM metadata_version_doc WHERE version = $1 AND lang = $2",
    )
    .bind(version)
    .bind(lang)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(markdown, generated_at)| VersionDoc {
        version,
        lang: lang.to_owned(),
        markdown,
        generated_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(previous: Option<i64>) -> DocInput {
        DocInput {
            version: 7,
            published_at: "2026-10-26T09:00:00Z".parse().unwrap(),
            previous,
            entities: vec![DocEntity {
                logicalname: "account".into(),
                name: "Account".into(),
                name_ar: Some("حساب".into()),
                fields: vec![
                    DocField {
                        logicalname: "name".into(),
                        name: "Account | Name".into(),
                        name_ar: None,
                        field_type: "text".into(),
                    },
                    DocField {
                        logicalname: "industry".into(),
                        name: "Industry".into(),
                        name_ar: Some("القطاع".into()),
                        field_type: "choice".into(),
                    },
                ],
            }],
            flows: vec!["Welcome new account".into()],
            rules: vec![DocRule {
                entity: "account".into(),
                name: "Name required".into(),
                kind: "validation".into(),
            }],
            changes: vec![DocChange {
                logicalname: "account".into(),
                change_kind: "attribute_added".into(),
                at: "2026-10-26T08:30:00Z".parse().unwrap(),
            }],
        }
    }

    #[test]
    fn builder_docs_lists_entities_flows_rules_and_changes() {
        let doc = render(&input(Some(6)), "en");
        assert!(doc.starts_with("# Documentation for version 7\n"), "{doc}");
        assert!(doc.contains("### Account (`account`)"), "{doc}");
        assert!(
            doc.contains("| Account \\| Name | `name` | text |"),
            "a pipe is escaped: {doc}"
        );
        assert!(doc.contains("- Welcome new account"), "{doc}");
        assert!(
            doc.contains("- `account`: Name required (validation)"),
            "{doc}"
        );
        assert!(doc.contains("## Changes since version 6"), "{doc}");
        assert!(doc.contains("`account` attribute_added"), "{doc}");
    }

    #[test]
    fn builder_docs_arabic_uses_arabic_names_with_english_fallback() {
        let doc = render(&input(None), "ar");
        assert!(doc.starts_with("# توثيق الإصدار 7"), "{doc}");
        assert!(doc.contains("### حساب (`account`)"), "{doc}");
        assert!(doc.contains("| القطاع | `industry` | choice |"), "{doc}");
        assert!(
            doc.contains("| Account \\| Name | `name` | text |"),
            "no Arabic name: English {doc}"
        );
        assert!(doc.contains("هذا هو الإصدار الأول."), "{doc}");
    }

    #[test]
    fn builder_docs_job_carries_its_version() {
        let job = publish_docs_job(12);
        let attome_core::jobs::EngineJob::Registered(registered) = job else {
            panic!("a registered job");
        };
        assert_eq!(registered.name, PUBLISH_DOCS.name);
        assert_eq!(
            registered.payload::<PublishDocsPayload>().unwrap(),
            PublishDocsPayload { version: 12 }
        );
        assert_eq!(type_name(Some(5)), "date");
        assert_eq!(type_name(None), "text");
    }
}
