//! Seeds a sensible default `category` (D-372 UI grouping follow-up) for
//! every entity that doesn't have one yet, derived from the
//! `xrm_{module}_{entity}` logicalname convention (D-222). Never overwrites
//! an admin-set category — a one-time default, not a managed taxonomy the
//! platform re-asserts every boot.

use attome_db::DbPool;
use attome_types::AppError;

/// `(module prefix, friendly category label)` — checked in order, first
/// match wins. A logicalname whose module segment isn't listed here (or has
/// no `xrm_{module}_...` shape at all) falls through to [`FALLBACK_CATEGORY`].
const MODULE_CATEGORIES: &[(&str, &str)] = &[
    ("core", "Core Platform"),
    ("audit", "Audit & Compliance"),
    ("workflow", "Workflow"),
    ("notification", "Notifications"),
    ("project", "Project Management"),
    ("s2s", "System-to-System Integration"),
    ("knowledge", "Knowledge Base"),
    ("content", "Content Management"),
    ("webcrawl", "Web Crawling"),
    ("search", "Search"),
    ("action", "Actions"),
];

/// Entities whose logicalname has no `xrm_{module}_{entity}` shape at all —
/// a single word after `xrm_` (module and entity collapse to one segment),
/// or no `xrm_` prefix whatsoever. Named explicitly rather than guessed,
/// since a naive split would either miss these or miscategorize them under
/// a module named after the entity itself.
const EXPLICIT_CATEGORIES: &[(&str, &str)] = &[
    ("note", "Core Platform"),
    ("communication", "Core Platform"),
    ("attome_document", "Document Management"),
    ("dashboard", "Reporting"),
];

const FALLBACK_CATEGORY: &str = "Other";

fn category_for(logicalname: &str) -> &'static str {
    for (name, category) in EXPLICIT_CATEGORIES {
        if *name == logicalname {
            return category;
        }
    }
    let Some(rest) = logicalname.strip_prefix("xrm_") else {
        return FALLBACK_CATEGORY;
    };
    let Some(module) = rest.split('_').next() else {
        return FALLBACK_CATEGORY;
    };
    MODULE_CATEGORIES
        .iter()
        .find(|(prefix, _)| *prefix == module)
        .map_or(FALLBACK_CATEGORY, |(_, category)| category)
}

/// Backfills `entity_info.category` for every entity that doesn't
/// have one yet (`category IS NULL`). Idempotent and safe every boot — a
/// no-op once every entity has a category, whether from this backfill or a
/// later admin edit (this never runs against a row that already has one).
///
/// A single row's UPDATE failing is logged and skipped rather than failing
/// the whole boot — this is cosmetic UI grouping, not a correctness or
/// security concern, unlike `backfill_readonly_grants`'s access grants.
pub async fn backfill_entity_category(db: &DbPool) -> Result<(), AppError> {
    let logicalnames: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
         WHERE category IS NULL AND (is_active IS NULL OR is_active = true) \
           AND logicalname IS NOT NULL AND logicalname <> ''",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for logicalname in logicalnames {
        let category = category_for(&logicalname);
        if let Err(e) = sqlx::query(
            "UPDATE entity_info SET category = $1 \
             WHERE logicalname = $2 AND category IS NULL",
        )
        .bind(category)
        .bind(&logicalname)
        .execute(db)
        .await
        {
            tracing::error!(
                error = %e, logicalname = %logicalname,
                "entity category backfill failed for this entity",
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_module_prefixes() {
        assert_eq!(category_for("audit_header"), "Audit & Compliance");
        assert_eq!(category_for("project_team"), "Project Management");
        assert_eq!(category_for("user_account"), "Core Platform");
        assert_eq!(category_for("knowledge_data_source"), "Knowledge Base");
    }

    #[test]
    fn maps_explicit_single_segment_exceptions() {
        assert_eq!(category_for("note"), "Core Platform");
        assert_eq!(category_for("attome_document"), "Document Management");
        assert_eq!(category_for("dashboard"), "Reporting");
    }

    #[test]
    fn falls_back_for_unknown_module_or_shape() {
        assert_eq!(category_for("unknownmodule_thing"), "Other");
        assert_eq!(category_for("not_even_xrm_prefixed"), "Other");
        assert_eq!(category_for("xrm_"), "Other");
    }
}
