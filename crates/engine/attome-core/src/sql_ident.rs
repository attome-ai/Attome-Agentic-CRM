/// Wraps an already-validated identifier (entity/column/index name) for safe
/// interpolation into dynamic DDL/DML strings. Callers MUST validate the
/// identifier (e.g. `attome_metadata::provision::valid_identifier`) before this —
/// this is formatting, not a validation layer. `valid_identifier` remains the
/// primary gate (charset + length, P-provisioning-hardening item a); escaping
/// below is the backstop, not a substitute for it.
///
/// Every entity/column name that reaches SQL as a raw identifier (not a bound
/// value) must go through this, even when it looks safe today — an
/// entity/field logicalname that happens to be a Postgres reserved word
/// (`order`, `user`, `group`, `select`, ...) is only usable unquoted, and
/// `valid_identifier`'s lowercase+digits+underscore charset does nothing to
/// rule those out.
///
/// Doubles any embedded `"` (the standard Postgres identifier-escaping rule,
/// same behavior as libpq's `PQescapeIdentifier`) — P-provisioning-hardening
/// item (b): not currently exploitable, since every identifier reaching this
/// function already passed `valid_identifier`'s charset check upstream, but
/// this was the one point where a future upstream validation bug would have
/// become DDL/SQL injection with no backstop of its own.
///
/// Defined once in `attome_db::ident` (CLEANUP-REVIEW 3.4) and re-exported here
/// so existing `attome_core::sql_ident::quote_ident` callers are unchanged.
pub use attome_db::ident::quote_ident;

/// The full physical system-column set every provisioned entity table has
/// (`attome_metadata::provision::provision_table`'s `CREATE TABLE` shape, D-005).
/// Distinct from `entity_crud`'s smaller internal `SYSTEM_COLS` list, which
/// is the subset stripped from the outgoing `data` payload — `is_active` /
/// `created_by` / `modified_by` / `organization_ref` DO appear in `data` today
/// (pre-existing API contract), so dropping them from a SELECT list would
/// silently change the response shape even though they're "system" columns.
///
/// `owner_ref`/`owner_type` (D-137) are a denormalized, read-only-to-clients
/// pointer at the record's current owner (0=user, 1=team — same
/// `principal_type` convention `record_share` uses). They exist purely
/// to serve "my records"/pipeline-by-owner queries, grid "Owner" columns, and
/// queue (team) ownership without a join into `record_share` — they are
/// NEVER consulted by `rls_predicate`/any access-control decision, which
/// keeps reading `record_share` exclusively (D-133's "one predicate
/// shape" property is unchanged). Written by exactly two call sites:
/// `entity_mutation::create_one` (initial, always the creator) and
/// `attome_security::admin::reassign_owner` (change) — never inferred by
/// scanning `record_share`'s (possibly multiple) action-capability rows.
pub const ALL_SYSTEM_COLS: &[&str] = &[
    "id",
    "created_at",
    "created_by",
    "modified_at",
    "modified_by",
    "organization_ref",
    "is_active",
    "row_version",
    "owner_ref",
    "owner_type",
];

/// The one live-row predicate every read that counts, lists or exports
/// records must agree on (dashboard 10/10 Phase 0 spikes S2 and S8): a
/// provisioned table's `is_active` is nullable and NULL counts as live, the
/// engine's own convention. Append-only entities have no soft-delete
/// lifecycle, so they get no predicate. `alias` is the caller's table alias
/// (a fixed SQL identifier, never request data).
pub fn live_row_predicate(alias: &str, is_append_only: bool) -> Option<String> {
    (!is_append_only).then(|| format!("({alias}.is_active IS NULL OR {alias}.is_active = true)"))
}

/// Builds an explicit, quoted, comma-joined SELECT/RETURNING column list for
/// a generic entity row: every system column plus every attribute the caller
/// may see. Replaces `SELECT *` / `RETURNING *` in the generic CRUD path
/// (external architecture review, 2026-07-21) — the arc-swap metadata
/// registry already knows the exact column set for an entity, so there is no
/// reason to pull every physical column across the wire only to prune most
/// of it in Rust afterward.
///
/// `include_sensitive` is a projection-time field-level-security gate: when
/// `false`, an `is_sensitive` attribute's column is never even requested —
/// the value never leaves Postgres for a caller who shouldn't see it, a
/// stronger property than fetching it and stripping it in
/// `entity_crud::build_response` afterward. Read-only call sites should pass
/// the caller's privilege (e.g. `ctx.is_admin`); mutation call sites whose
/// row also feeds an audit diff must pass `true` unconditionally — the audit
/// event needs every field's before/after value regardless of the HTTP
/// caller's own visibility, and `build_response` remains the place that
/// hides a sensitive value from the *response*, independent of what the SQL
/// fetched.
pub fn select_columns(attrs: &[crate::AttrInfo], include_sensitive: bool) -> String {
    select_columns_filtered(attrs, |_attr| include_sensitive)
}

/// Same projection as `select_columns`, but the include/exclude decision for
/// each `is_sensitive` attribute is made per-attribute by `can_read` instead
/// of one flat bool for the whole row (F013/F135, D-111) — a caller can hold
/// a field-security grant for one sensitive attribute and not another.
/// `attome-core` has no `attome-security` dependency (guidelines §1), so the
/// grant decision itself is computed by the caller (`entity_crud.rs`, which
/// already holds a `SecurityContext`) and passed in as a plain predicate.
pub fn select_columns_filtered(
    attrs: &[crate::AttrInfo],
    can_read: impl Fn(&crate::AttrInfo) -> bool,
) -> String {
    let mut cols: Vec<String> = ALL_SYSTEM_COLS.iter().map(|c| (*c).to_owned()).collect();
    for attr in attrs {
        if attr.is_sensitive && !can_read(attr) {
            continue;
        }
        cols.push(quote_ident(&attr.logicalname));
    }
    cols.join(", ")
}

/// The system columns plus every attribute `keep` admits, sensitive or not.
/// D-589's bulk projection (`attome_security::field_gate::bulk_columns`) uses it,
/// because on a bulk surface a non-sensitive field can be hidden too; the
/// interactive [`select_columns_filtered`] only ever asks about sensitive ones.
pub fn select_columns_where(
    attrs: &[crate::AttrInfo],
    keep: impl Fn(&crate::AttrInfo) -> bool,
) -> String {
    let mut cols: Vec<String> = ALL_SYSTEM_COLS.iter().map(|c| (*c).to_owned()).collect();
    for attr in attrs {
        if keep(attr) {
            cols.push(quote_ident(&attr.logicalname));
        }
    }
    cols.join(", ")
}

#[cfg(test)]
mod tests {
    use super::{ALL_SYSTEM_COLS, live_row_predicate, quote_ident, select_columns};

    #[test]
    fn live_row_predicate_counts_null_as_live_and_skips_append_only() {
        assert_eq!(
            live_row_predicate("t", false).as_deref(),
            Some("(t.is_active IS NULL OR t.is_active = true)")
        );
        assert_eq!(live_row_predicate("t", true), None);
    }
    use crate::AttrInfo;

    #[test]
    fn quotes_plain_identifier() {
        assert_eq!(quote_ident("api_key"), "\"api_key\"");
    }

    #[test]
    fn quotes_reserved_word() {
        assert_eq!(quote_ident("order"), "\"order\"");
    }

    #[test]
    fn doubles_embedded_quote() {
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }

    #[test]
    fn doubles_multiple_quotes() {
        assert_eq!(quote_ident("a\"b\"c"), "\"a\"\"b\"\"c\"");
    }

    fn attr(logicalname: &str, is_sensitive: bool) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int: 3,
            is_required: false,
            max_length: None,
            is_sensitive,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options: None,
        }
    }

    #[test]
    fn select_columns_includes_all_system_cols_and_non_sensitive_attrs() {
        let attrs = vec![attr("name", false), attr("notes", false)];
        let cols = select_columns(&attrs, false);
        for sys in ALL_SYSTEM_COLS {
            assert!(cols.contains(sys), "missing system col {sys} in {cols}");
        }
        assert!(cols.contains("\"name\""));
        assert!(cols.contains("\"notes\""));
    }

    #[test]
    fn select_columns_excludes_sensitive_when_not_included() {
        let attrs = vec![attr("name", false), attr("ssn", true)];
        let cols = select_columns(&attrs, false);
        assert!(cols.contains("\"name\""));
        assert!(!cols.contains("\"ssn\""));
    }

    #[test]
    fn select_columns_includes_sensitive_when_requested() {
        let attrs = vec![attr("name", false), attr("ssn", true)];
        let cols = select_columns(&attrs, true);
        assert!(cols.contains("\"name\""));
        assert!(cols.contains("\"ssn\""));
    }

    /// D-137: owner_ref/owner_type must flow through the generic entity CRUD
    /// SELECT/RETURNING projection unquoted-column-name-wise like every other
    /// system column (organization_ref, row_version, ...) — no entity_crud.rs
    /// response-shape change should have been needed to expose them, which is
    /// only true if they're in this list.
    #[test]
    fn owner_columns_are_system_columns() {
        assert!(ALL_SYSTEM_COLS.contains(&"owner_ref"));
        assert!(ALL_SYSTEM_COLS.contains(&"owner_type"));
        let cols = select_columns(&[], true);
        assert!(cols.contains("owner_ref"));
        assert!(cols.contains("owner_type"));
    }
}
