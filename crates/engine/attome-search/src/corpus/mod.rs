//! The record corpus — what a record's indexable text *is*.
//!
//! **Without this, nothing is ever indexed.** `drain_once` takes a
//! [`ProjectFn`](crate::drain::ProjectFn) and the whole engine — legs, fusion,
//! ranking, routes, harnesses — sat behind a projector nobody had written. The
//! symptom was not a failure anywhere: search worked, returned nothing, and
//! every test passed because every test seeds the index directly.
//!
//! ## Field security is enforced here, not filtered later
//!
//! S3 says a field-secured attribute is **never indexed**. That has to happen
//! at projection, because there is no later point at which it can: once a
//! value is inside a `tsvector` it is matchable, and matchability is the
//! disclosure — a user who can confirm a salary by typing it and seeing which
//! record comes back has read the field, whatever the read path says. So
//! `is_sensitive` attributes are dropped before any text is assembled, and
//! `sensitive_attributes_are_never_projected` asserts it against a value that
//! would otherwise be unmissable.
//!
//! ## Only text is indexed
//!
//! Numbers, dates, booleans, lookups and file keys are skipped. A date
//! stringified into a `tsvector` matches lexically at random ("2026" matching
//! every record modified that year), and a lookup column holds a UUID whose
//! *display* value lives in another table — indexing the raw id would let
//! nobody find anything and would make every record match every other record's
//! id. Both belong to a later, deliberate design, not to a default that
//! silently degrades relevance for everyone.
//!
//! ## Exact keys are the record id, and nothing else, for now
//!
//! `AttrInfo` carries no uniqueness flag, so there is no metadata-driven way to
//! know which attribute is an identifier. The alternative — guessing from names
//! that end in `code`/`number`/`ref` — produces a different index per
//! deployment and mis-keys silently, which is worse than a narrow one. The
//! record id is the one identifier the platform actually guarantees. When
//! uniqueness reaches the metadata, this is the single place to widen.

pub mod knowledge;
pub mod memory;

/// Polymorphic child entities (basic-units plan B-R1, U1): a note,
/// communication, tag or follow is readable only by someone who can also read
/// the record it is attached to. The search index checks a hit against the
/// indexed row's *own* entity and id, which cannot express that, so these are
/// never indexed ([`project_record`]) and never matched (`routes`, which drops
/// them from the caller's access map so rows indexed before this change stay
/// unreachable too).
///
/// A copy of `attome_records::entity_crud::POLYMORPHIC_CHILD_ENTITIES`:
/// this crate cannot depend on the entity engine. Change both together.
pub const POLYMORPHIC_CHILD_ENTITIES: &[&str] = &[
    "note",
    "communication",
    "tag_item",
    "follow",
    "reminder",
    // U2 activities (D-600), added to D-593's list 2026-09-23.
    "activity",
];

use attome_core::sql_ident::quote_ident;
use attome_core::{AttrInfo, EntityMetaRegistry};
use attome_types::AppError;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::project::{ProjectedRow, project};

/// `field_type_int` for a text column — see `provision::identifiers::type_to_int`.
const FIELD_TYPE_TEXT: i32 = 3;
/// Single-value choice. Indexed: a choice value is a human-authored label, and
/// "open"/"مغلق" is exactly what someone types into a search box.
const FIELD_TYPE_CHOICE: i32 = 7;
/// Rich text (U9, D-605). Indexed by its *text content*: the stored value is
/// sanitized HTML, and indexing the markup would make every record match
/// "strong" or "href" — [`index_value`] strips it first.
const FIELD_TYPE_RICH_TEXT: i32 = 17;

/// The attributes whose values become indexable text, in metadata order.
///
/// Separated from the read so it can be tested without a database — the rule
/// this encodes (what is indexable, and what is never indexable) is the
/// security-relevant half, and it should not need a Postgres to assert.
pub fn indexable_attributes(attrs: &[AttrInfo]) -> Vec<&AttrInfo> {
    attrs
        .iter()
        .filter(|a| !a.is_sensitive)
        .filter(|a| {
            a.field_type_int == FIELD_TYPE_TEXT
                || a.field_type_int == FIELD_TYPE_CHOICE
                || a.field_type_int == FIELD_TYPE_RICH_TEXT
        })
        .collect()
}

/// The indexable text of one stored value: a rich-text value's visible text
/// (`attome_html::html_to_text` — tags removed, `<script>`/`<style>` content
/// dropped, entities decoded), every other indexable value as stored.
pub fn index_value(attr: &AttrInfo, raw: String) -> String {
    if attr.field_type_int == FIELD_TYPE_RICH_TEXT {
        attome_html::html_to_text(&raw)
    } else {
        raw
    }
}

/// Which attribute supplies the title, if any.
///
/// The entity's declared `primary_name_attribute` first — it is the platform's
/// own answer to "what displays this record", already used for lookup
/// tombstones, and search disagreeing with the rest of the UI about a record's
/// name would be its own bug. Falls back to the first indexable attribute so an
/// entity that never declared one is still findable rather than silently
/// title-less.
pub fn title_attribute<'a>(
    meta_primary: Option<&str>,
    indexable: &[&'a AttrInfo],
) -> Option<&'a AttrInfo> {
    if let Some(name) = meta_primary
        && let Some(found) = indexable.iter().find(|a| a.logicalname == name)
    {
        return Some(found);
    }
    indexable.first().copied()
}

/// Reads one record and projects it.
///
/// `Ok(None)` means "gone or not indexable", which the drain treats exactly
/// like a delete — a record that was deleted, soft-deleted, or whose entity was
/// dropped between the event and the drain must not leave a stale index row
/// behind (G2).
pub async fn project_record(
    db: &PgPool,
    registry: &EntityMetaRegistry,
    entity_logicalname: &str,
    record_id: Uuid,
) -> Result<Option<(ProjectedRow, Option<Uuid>, Option<Uuid>)>, AppError> {
    // U1: not indexable (see `POLYMORPHIC_CHILD_ENTITIES`). `None` removes
    // whatever an earlier drain indexed for this record.
    if POLYMORPHIC_CHILD_ENTITIES.contains(&entity_logicalname) {
        return Ok(None);
    }
    let Some(meta) = registry.get(entity_logicalname) else {
        // An entity the registry does not know is not indexable. Returning an
        // error would stall the drain on one bad event forever; returning None
        // removes whatever is indexed and moves on.
        return Ok(None);
    };

    let indexable = indexable_attributes(&meta.attrs);
    let title_attr = title_attribute(meta.primary_name_attribute.as_deref(), &indexable);

    // Identifiers are quoted through the shared helper and come from validated
    // metadata — the registry, never request data. `quote_ident` is the same
    // helper every other dynamic-identifier path uses.
    let table = quote_ident(entity_logicalname);
    let mut columns: Vec<String> = vec!["organization_ref".into(), "owner_ref".into()];
    columns.extend(indexable.iter().map(|a| quote_ident(&a.logicalname)));

    // The live predicate. A soft-deleted record must leave the index, and this
    // is the read that decides — `is_active = false` returns no row, which the
    // caller turns into a delete.
    let sql = format!(
        "SELECT {} FROM {table} WHERE id = $1 AND is_active = true",
        columns.join(", ")
    );

    let Some(row) = sqlx::query(&sql)
        .bind(record_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
    else {
        return Ok(None);
    };

    let organization_ref: Option<Uuid> = row.try_get("organization_ref").unwrap_or(None);
    let owner_ref: Option<Uuid> = row.try_get("owner_ref").unwrap_or(None);

    let value_of = |attr: &AttrInfo| -> Option<String> {
        // `try_get` by name rather than index: the column list and the
        // attribute list are built from the same iteration, but an index-based
        // read would silently shift every value by one if that ever stopped
        // being true — and a record showing another field's text is both wrong
        // and very hard to notice.
        row.try_get::<Option<String>, _>(attr.logicalname.as_str())
            .ok()
            .flatten()
            .map(|v| index_value(attr, v))
            .filter(|v| !v.trim().is_empty())
    };

    let title = title_attr.and_then(value_of).unwrap_or_default();
    let body = indexable
        .iter()
        .filter(|a| Some(a.logicalname.as_str()) != title_attr.map(|t| t.logicalname.as_str()))
        .filter_map(|a| value_of(a))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(Some((
        project(&title, None, &body, vec![record_id.to_string()]),
        organization_ref,
        owner_ref,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{DataClassification, OnTargetDelete};

    fn attr(name: &str, type_int: i32, sensitive: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.into(),
            field_type_int: type_int,
            is_required: false,
            max_length: None,
            is_sensitive: sensitive,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            options: None,
        }
    }

    /// **The S3 assertion.** A secured attribute never reaches the projection,
    /// so its value never reaches a `tsvector`. Matchability *is* the
    /// disclosure: someone who can confirm a salary by typing it and seeing
    /// which record comes back has read the field, whatever the read path says.
    #[test]
    fn sensitive_attributes_are_never_projected() {
        let attrs = vec![
            attr("name", FIELD_TYPE_TEXT, false),
            attr("salary_band", FIELD_TYPE_TEXT, true),
        ];
        let indexable = indexable_attributes(&attrs);
        assert_eq!(indexable.len(), 1);
        assert_eq!(indexable[0].logicalname, "name");
    }

    /// U9: a rich-text field is indexed by its text content, never its
    /// markup.
    #[test]
    fn rich_text_is_indexed_as_its_text_content() {
        let attrs = vec![attr("body", FIELD_TYPE_RICH_TEXT, false)];
        let indexable = indexable_attributes(&attrs);
        assert_eq!(indexable.len(), 1);
        assert_eq!(
            index_value(
                indexable[0],
                "<p>Quarterly <strong>renewal</strong> &amp; pricing</p>".into()
            ),
            "Quarterly renewal & pricing"
        );
        let plain = attr("name", FIELD_TYPE_TEXT, false);
        assert_eq!(index_value(&plain, "<b>kept</b>".into()), "<b>kept</b>");
    }

    /// Non-text types are skipped. A stringified date matches lexically at
    /// random, and a lookup column holds a UUID whose display value is in
    /// another table entirely.
    #[test]
    fn only_text_and_choice_are_indexed() {
        let attrs = vec![
            attr("name", FIELD_TYPE_TEXT, false),
            attr("status", FIELD_TYPE_CHOICE, false),
            attr("amount", 1, false),
            attr("due", 5, false),
            attr("closed", 6, false),
            attr("account", 11, false),
            attr("contract_pdf", 12, false),
        ];
        let names: Vec<&str> = indexable_attributes(&attrs)
            .iter()
            .map(|a| a.logicalname.as_str())
            .collect();
        assert_eq!(names, vec!["name", "status"]);
    }

    /// The declared primary name wins. Search disagreeing with the rest of the
    /// UI about a record's name would be its own bug.
    #[test]
    fn the_declared_primary_name_supplies_the_title() {
        let attrs = vec![
            attr("code", FIELD_TYPE_TEXT, false),
            attr("company_name", FIELD_TYPE_TEXT, false),
        ];
        let indexable = indexable_attributes(&attrs);
        let title = title_attribute(Some("company_name"), &indexable).expect("a title");
        assert_eq!(title.logicalname, "company_name");
    }

    /// An entity with no declared primary name still gets a title rather than
    /// silently indexing every record as untitled.
    #[test]
    fn an_entity_without_a_declared_name_still_gets_a_title() {
        let attrs = vec![attr("label", FIELD_TYPE_TEXT, false)];
        let indexable = indexable_attributes(&attrs);
        assert_eq!(
            title_attribute(None, &indexable).map(|a| a.logicalname.as_str()),
            Some("label")
        );
    }

    /// A primary name that is *secured* must not come back as the title
    /// through the fallback — the fallback picks from the indexable set, which
    /// the secured attribute has already left.
    #[test]
    fn a_secured_primary_name_does_not_slip_back_in_as_the_title() {
        let attrs = vec![
            attr("full_name", FIELD_TYPE_TEXT, true),
            attr("reference", FIELD_TYPE_TEXT, false),
        ];
        let indexable = indexable_attributes(&attrs);
        let title = title_attribute(Some("full_name"), &indexable).expect("a title");
        assert_eq!(
            title.logicalname, "reference",
            "the secured name must not be resurrected as the title"
        );
    }
}
