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
pub mod record_chunks;

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
    // C1-T1: a note's replies, on the note's own parent record.
    "note_reply",
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
        .filter(|a| !a.is_read_gated())
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

/// A25-T2: how an attribute takes part in search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    /// Matched exactly, in its normalised form (a phone, an email, an id),
    /// as well as being text.
    Key,
    /// Full text.
    Text,
    /// Not searched.
    Off,
}

impl SearchMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "key" => Some(Self::Key),
            "text" => Some(Self::Text),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// What kind of key an attribute's name says it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Phone,
    Email,
    Id,
}

fn key_kind(name: &str) -> Option<KeyKind> {
    let n = name.to_ascii_lowercase();
    if n.contains("phone") || n.contains("mobile") {
        Some(KeyKind::Phone)
    } else if n.contains("email") {
        Some(KeyKind::Email)
    } else if n.contains("national_id")
        || n.contains("id_number")
        || n.contains("iqama")
        || n.contains("commercial_registration")
        || n == "cr_number"
        || n == "code"
        || n.ends_with("_code")
        || n.contains("reference")
    {
        Some(KeyKind::Id)
    } else {
        None
    }
}

/// A25-T2: an attribute's mode when no setting names it: a phone, email,
/// identity number, code or reference is a key; every other indexable
/// attribute is text. Pure.
pub fn default_mode(attr: &AttrInfo) -> SearchMode {
    if attr.field_type_int == FIELD_TYPE_TEXT && key_kind(&attr.logicalname).is_some() {
        SearchMode::Key
    } else {
        SearchMode::Text
    }
}

/// A25-T2: the exact keys a key attribute's value gives: a phone in its
/// international form (`default_country` places a local number), an email
/// lowercased, anything else as an identifier. Pure.
pub fn exact_keys_for(attr_name: &str, value: &str, default_country: &str) -> Vec<String> {
    let key = match key_kind(attr_name) {
        Some(KeyKind::Phone) => attome_core::match_normalize::phone_key(value, default_country),
        Some(KeyKind::Email) => attome_core::match_normalize::email_key(value),
        _ => Some(attome_core::match_normalize::id_key(value)),
    };
    key.filter(|k| !k.is_empty()).into_iter().collect()
}

/// A25-T12: the prefix of a transliteration key among a row's exact keys.
pub const TRANSLIT_PREFIX: &str = "tr:";
/// A25-T12: the shortest transliteration skeleton kept. Shorter ones
/// (`Ali` is `al`) would match too many unrelated names.
pub const MIN_TRANSLIT_KEY: usize = 4;
/// A25-T12: the most title words transliterated.
const MAX_TRANSLIT_WORDS: usize = 8;

fn translit_of(text: &str) -> Option<String> {
    let key = attome_core::match_normalize::translit_key(text);
    (key.chars().count() >= MIN_TRANSLIT_KEY).then(|| format!("{TRANSLIT_PREFIX}{key}"))
}

/// A25-T12: the keys that let a title be found from its spelling in the
/// other script (`Abdullah` finds `عبدالله`, `يوسف` finds `Yousef`): the
/// transliteration skeleton (`attome_core::match_normalize::translit_key`)
/// of each word, of each pair of adjacent words (`Abd Allah` is one name)
/// and of the whole title when it is short. Skeletons under
/// [`MIN_TRANSLIT_KEY`] letters are left out. Pure.
pub fn translit_keys(title: &str) -> Vec<String> {
    let words: Vec<&str> = title
        .split_whitespace()
        .filter(|w| w.chars().any(char::is_alphabetic))
        .take(MAX_TRANSLIT_WORDS)
        .collect();
    let mut keys: Vec<String> = Vec::new();
    let mut push = |key: Option<String>| {
        if let Some(key) = key
            && !keys.contains(&key)
        {
            keys.push(key);
        }
    };
    for word in &words {
        push(translit_of(word));
    }
    for pair in words.windows(2) {
        push(translit_of(&pair.join(" ")));
    }
    if (3..=4).contains(&words.len()) {
        push(translit_of(&words.join(" ")));
    }
    keys
}

/// A25-T12: the transliteration key a query is looked up by: the skeleton
/// of the whole query (one name, possibly written as two words), when it is
/// letters only and long enough. Pure.
pub fn translit_query_key(query: &str) -> Option<String> {
    let q = query.trim();
    if q.is_empty() || q.split_whitespace().count() > 2 || q.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    translit_of(q)
}

/// A25-T2: a query's phone form, when it is a phone number written with
/// digits only (spaces, dashes, brackets and a leading `+` allowed), to look
/// up beside the query itself. Pure.
pub fn phone_query_key(query: &str, default_country: &str) -> Option<String> {
    let q = crate::normalize_ar(query);
    let q = q.trim();
    let digits = q.chars().filter(char::is_ascii_digit).count();
    let plain = q
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '-' | '(' | ')' | '+'));
    if !plain || !(7..=16).contains(&digits) {
        return None;
    }
    attome_core::match_normalize::phone_key(q, default_country)
}

/// The search settings an entity's attributes carry (A25-T1), by attribute.
async fn attribute_modes(
    db: &PgPool,
    entity: &str,
) -> Result<std::collections::HashMap<String, SearchMode>, AppError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT attribute_logicalname, mode FROM search_attribute_setting \
          WHERE entity_logicalname = $1",
    )
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(attr, mode)| SearchMode::parse(&mode).map(|m| (attr, m)))
        .collect())
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

/// The document entity whose projection carries its file's text (K1-T4).
pub const DOCUMENT_ENTITY: &str = "attome_document";

/// The extracted text of the file a document names, if any.
async fn document_text(db: &PgPool, document_id: Uuid) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT t.content_text FROM attome_document d \
           JOIN document_text t ON t.file_key = d.file \
          WHERE d.id = $1",
    )
    .bind(document_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
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
    project_record_in(db, registry, entity_logicalname, record_id, "").await
}

/// [`project_record`] with the deployment's default country, which places a
/// local phone number for its exact key (A25-T2).
pub async fn project_record_in(
    db: &PgPool,
    registry: &EntityMetaRegistry,
    entity_logicalname: &str,
    record_id: Uuid,
    default_country: &str,
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

    // A25-T2: each attribute's mode, from its setting or the default; an
    // `off` attribute is not read at all.
    let settings = attribute_modes(db, entity_logicalname).await?;
    let mode_of = |a: &AttrInfo| {
        settings
            .get(&a.logicalname)
            .copied()
            .unwrap_or_else(|| default_mode(a))
    };
    let indexable: Vec<&AttrInfo> = indexable_attributes(&meta.attrs)
        .into_iter()
        .filter(|a| mode_of(a) != SearchMode::Off)
        .collect();
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

    // K1-T4: a document is also found by the text of the file it names
    // (`attome_document::text_extract`), under the document's own
    // permissions, which are the row's.
    let body = if entity_logicalname == DOCUMENT_ENTITY {
        // Cut to the index ceiling here too: the body is also stored verbatim
        // for snippets, and a whole book there helps no one.
        let text = document_text(db, record_id)
            .await?
            .map(|t| crate::project::truncate_for_index(&t).to_owned());
        match text {
            Some(text) if body.is_empty() => text,
            Some(text) => format!("{body}\n{text}"),
            None => body,
        }
    } else {
        body
    };

    let mut keys = vec![record_id.to_string()];
    for attr in indexable.iter().filter(|a| mode_of(a) == SearchMode::Key) {
        if let Some(value) = value_of(attr) {
            keys.extend(exact_keys_for(&attr.logicalname, &value, default_country));
        }
    }
    // A25-T12: the title found from its spelling in the other script.
    keys.extend(translit_keys(&title));
    keys.dedup();

    Ok(Some((
        project(&title, None, &body, keys),
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
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options: None,
        }
    }

    /// **The S3 assertion.** A secured attribute never reaches the projection,
    /// so its value never reaches a `tsvector`. Matchability *is* the
    /// disclosure: someone who can confirm a salary by typing it and seeing
    /// which record comes back has read the field, whatever the read path says.
    #[test]
    fn translit_keys_meet_across_scripts() {
        let arabic = translit_keys("عبدالله الأحمد");
        let query = translit_query_key("Abdullah").expect("a long enough key");
        assert!(arabic.contains(&query), "{arabic:?} lacks {query}");
        // Written as two words, the name still meets.
        assert_eq!(translit_query_key("Abd Allah"), Some(query.clone()));
        assert!(translit_keys("Abd Allah Saleh").contains(&query));
        assert!(translit_keys("محمد").contains(&translit_query_key("Mohammed").unwrap()));
        // Short skeletons, digits and long queries are not looked up.
        assert_eq!(translit_query_key("Ali"), None);
        assert_eq!(translit_query_key("INV 2041"), None);
        assert_eq!(translit_query_key("one two three"), None);
        assert!(translit_keys("Al").is_empty());
        assert!(arabic.iter().all(|k| k.starts_with(TRANSLIT_PREFIX)));
    }

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

    #[test]
    fn phone_attribute_becomes_exact_key() {
        let phone = attr("mobile_phone", FIELD_TYPE_TEXT, false);
        assert_eq!(default_mode(&phone), SearchMode::Key);
        assert_eq!(
            exact_keys_for("mobile_phone", "050 123 4567", "SA"),
            vec!["+966501234567".to_owned()]
        );
        assert_eq!(
            exact_keys_for("email", " Sara@Example.COM ", "SA"),
            vec!["sara@example.com".to_owned()]
        );
        assert_eq!(
            phone_query_key("0501234567", "SA").as_deref(),
            Some("+966501234567")
        );
        assert_eq!(phone_query_key("invoice 0501234567", "SA"), None);
        assert_eq!(
            default_mode(&attr("notes", FIELD_TYPE_TEXT, false)),
            SearchMode::Text
        );
    }

    #[test]
    fn secret_attribute_never_projected_even_when_selected() {
        // A sensitive attribute is dropped before modes apply, so no setting
        // can make it a key or text.
        let attrs = vec![attr("national_id", FIELD_TYPE_TEXT, true)];
        assert!(indexable_attributes(&attrs).is_empty());
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
