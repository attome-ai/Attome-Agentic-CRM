//! Identifier validation and field-type -> PostgreSQL-type mapping shared by
//! every other provisioning submodule.
//!
//! C-16 (M01 §7): the int<->[`FieldType`] and [`FieldType`]->PG-type maps
//! themselves live once, on `attome_core::FieldType`. The thin `&str`
//! wrappers below exist only because every caller in this module
//! (`reconcile.rs`, `table.rs`, `schema_change.rs`) still carries the field
//! type as the wire string (`"choice"`, `"file"`, …), not the enum.

use attome_core::FieldType;
use attome_types::AppError;

pub(super) fn type_to_int(ft: &str) -> i32 {
    FieldType::try_from(ft).unwrap_or(FieldType::Text).to_int()
}

/// The one field-type validator (U9 checklist item 3): the admin attribute
/// handler (`attome-server/src/admin/attribute.rs`) and reconcile used to keep
/// two hand-copied `valid_field_type` lists that had to be edited together;
/// both call this now, and it reads `FieldType::NAMES`.
pub fn valid_field_type(ft: &str) -> bool {
    FieldType::is_valid_name(ft)
}

/// The field-type name the *physical column* is provisioned as (U9):
/// `FieldType::storage` — a `formula`'s declared `result_type`, `text` for
/// `rich_text`, `file` for `image`, and the type itself for everything
/// else. Every DDL path (`provision_column`, `evolve_attribute_schema`)
/// takes this, never the metadata type, so a formula's column is `NUMERIC`,
/// `TIMESTAMPTZ`, ... rather than `TEXT`.
pub fn physical_field_type(field_type: &str, options: Option<&serde_json::Value>) -> &'static str {
    FieldType::try_from(field_type)
        .unwrap_or(FieldType::Text)
        .storage(options)
        .as_str()
}

/// D-078 (F004): `choice` is TEXT (single) / TEXT[] (multi), not INTEGER —
/// `attome_field::ChoiceOptions` validates string labels (`choices: Vec<String>`),
/// so an INTEGER column could never actually hold a value that passed
/// validation. `is_multi` comes from the attribute's `options.multi`,
/// resolved by the caller (`ensure_attribute`) before the column is created.
///
/// `file` follows the same shape for the same reason (D-362): a multi-file
/// field stores a JSON array of object-key strings
/// (`attome_field::validate_multi_file`), which a scalar `TEXT` column cannot
/// hold — so `options.multi` picks `JSONB` instead, mirroring `choice`'s
/// `TEXT[]` branch rather than inventing a second mechanism.
pub(super) fn pg_type_for(field_type: &str, is_multi: bool) -> &'static str {
    FieldType::try_from(field_type)
        .unwrap_or(FieldType::Text)
        .pg_type(is_multi)
}

/// Reads `options.multi` (F004's `ChoiceOptions.multi`) without a full
/// `serde_json` round-trip — `provision.rs` only needs the one bool to pick a
/// column type, not the whole `choices` list.
pub(super) fn options_want_multi_choice(
    field_type: &str,
    options: Option<&serde_json::Value>,
) -> bool {
    field_type == "choice" && options.is_some_and(|o| FieldType::Choice.is_multi_valued(o))
}

/// `attome_field::FileOptions.multi`'s column-type counterpart — see `pg_type_for`.
pub(super) fn options_want_multi_file(
    field_type: &str,
    options: Option<&serde_json::Value>,
) -> bool {
    matches!(field_type, "file" | "image")
        && options.is_some_and(|o| FieldType::File.is_multi_valued(o))
}

/// Whether `field_type`+`options` describes a multi-valued (`TEXT[]`/`JSONB`)
/// physical column rather than a scalar one — the one composed check every
/// caller outside this module needs (`reconcile.rs`'s own `is_multi` local,
/// the schema-change plan machinery, and the admin/bundle callers that
/// enqueue a contract change). See `pg_type_for`'s doc comment for why only
/// `choice`/`file` can be multi at all (D-078/D-362).
pub fn is_multi_valued(field_type: &str, options: Option<&serde_json::Value>) -> bool {
    options_want_multi_choice(field_type, options) || options_want_multi_file(field_type, options)
}

/// Postgres truncates identifiers at 63 bytes (`NAMEDATALEN`-1) with only a
/// NOTICE, not an error. 48 keeps every derived name this module composes
/// except the two-identifier attribute index (checked separately by
/// `attribute_index_name`) safely under that limit:
/// `idx_{name}_active` = len+11 <= 59. The charset is pure ASCII, so
/// bytes == chars and `s.len()` is the byte length Postgres sees.
/// P-provisioning-hardening item (a). Defined once in `attome_db::ident`
/// (CLEANUP-REVIEW 3.4) and re-exported here.
pub use attome_db::ident::MAX_IDENTIFIER_LEN;

/// Identifiers here become part of a raw DDL string (table/column names can't
/// be bind parameters), so this is re-checked here even though callers in
/// attome-server already validate — defense in depth for other/future callers.
/// The single shared validator (`admin.rs` calls this instead of keeping its
/// own copy) — see D-021 for why the two had drifted apart. The charset
/// check itself is `attome_db::ident::valid_identifier` (CLEANUP-REVIEW 3.4).
pub fn valid_identifier(s: &str) -> bool {
    attome_db::ident::valid_identifier(s, MAX_IDENTIFIER_LEN)
}

/// Postgres truncates index names > 63 bytes silently; a truncated name that
/// collides with an existing index makes `CREATE INDEX ... IF NOT EXISTS` a
/// silent no-op — a "filterable"/"sortable" field with no index and no error.
/// So a name that would be too long is never truncated: it keeps a readable
/// prefix and ends in a hash of the whole entity and field pair, which is
/// unique per pair and always fits. P-provisioning-hardening item (a).
pub fn attribute_index_name(entity: &str, field: &str) -> Result<String, AppError> {
    let name = format!("idx_{entity}_{field}_sf");
    if name.len() <= attome_db::ident::PG_MAX_IDENTIFIER_LEN {
        return Ok(name);
    }
    // FNV-1a, 64 bit: stable across builds and platforms, unlike std's hasher.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in entity.bytes().chain([0]).chain(field.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // "idx_" + 39 + "_" + 16 hex + "_sf" = 63.
    let prefix: String = format!("{entity}_{field}").chars().take(39).collect();
    Ok(format!("idx_{prefix}_{hash:016x}_sf"))
}
