//! D-589: the one place a field's visibility is decided per surface.
//!
//! Two surface classes:
//!
//! - [`Surface::Interactive`]: record get/list, related lists, hierarchy and
//!   merge preview. D-111 is unchanged there: a non-sensitive field follows
//!   record access, and a sensitive field needs its field-security grant.
//! - [`Surface::Bulk`]: export, `query/execute` and stored queries, reports,
//!   document generation, dashboards, AI context and tools, search aggregates
//!   and graph, webhook payloads, bundle record sets. A non-sensitive field is
//!   returned only if one of the caller's roles lists it, unless the caller
//!   is still [`BulkFields::Legacy`]. A sensitive field still needs its grant.
//!
//! On a bulk surface the entity's system columns (`id` and the other
//! `ALL_SYSTEM_COLS`) and its primary name attribute are always readable to a
//! caller who can read the record, so a result is never a list of anonymous
//! rows.
//!
//! A surface decides with [`readable`] (or [`field_readable`] when it has no
//! [`AttrInfo`] at hand) and projects with [`bulk_columns`]. The guard test in
//! `crates/engine/attome-security/tests/field_gate_guard.rs` fails when a bulk
//! surface decides visibility any other way.

use attome_core::AttrInfo;
use attome_server::security::{BulkFields, SecurityContext};

use crate::context::SecurityContextExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Interactive,
    Bulk,
}

/// Whether `ctx` may see `attr` of `entity` on `surface`.
pub fn readable(
    ctx: &SecurityContext,
    entity: &str,
    attr: &AttrInfo,
    primary_name: Option<&str>,
    surface: Surface,
) -> bool {
    field_readable(
        ctx,
        entity,
        &attr.logicalname,
        attr.is_sensitive,
        primary_name,
        surface,
    )
}

/// [`readable`] for a caller that knows the field's name and sensitivity but
/// holds no `AttrInfo` (a graph edge, a webhook snapshot).
pub fn field_readable(
    ctx: &SecurityContext,
    entity: &str,
    field: &str,
    is_sensitive: bool,
    primary_name: Option<&str>,
    surface: Surface,
) -> bool {
    if is_sensitive {
        return ctx.has_field_read_grant(entity, field);
    }
    if surface == Surface::Interactive || ctx.is_admin || primary_name == Some(field) {
        return true;
    }
    match &ctx.bulk_fields {
        BulkFields::Legacy => true,
        BulkFields::Listed(fields) => fields.contains(&format!("{entity}.{field}")),
    }
}

/// The SELECT list for a bulk read of `entity`: the system columns plus every
/// attribute [`readable`] admits on [`Surface::Bulk`].
pub fn bulk_columns(
    ctx: &SecurityContext,
    entity: &str,
    attrs: &[AttrInfo],
    primary_name: Option<&str>,
) -> String {
    attome_core::select_columns_where(attrs, |attr| {
        readable(ctx, entity, attr, primary_name, Surface::Bulk)
    })
}

/// True when the caller is on the pre-D-589 behaviour for bulk surfaces.
pub fn is_legacy(ctx: &SecurityContext) -> bool {
    matches!(ctx.bulk_fields, BulkFields::Legacy)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use uuid::Uuid;

    use super::*;

    fn ctx(bulk_fields: BulkFields, sensitive_grants: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: sensitive_grants.iter().map(|s| s.to_string()).collect(),
            field_write_grants: HashSet::new(),
            bulk_fields,
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    fn listed(fields: &[&str]) -> BulkFields {
        BulkFields::Listed(fields.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn interactive_is_d111_unchanged() {
        let c = ctx(listed(&[]), &[]);
        assert!(field_readable(
            &c,
            "account",
            "phone",
            false,
            None,
            Surface::Interactive
        ));
        assert!(!field_readable(
            &c,
            "account",
            "salary",
            true,
            None,
            Surface::Interactive
        ));
    }

    #[test]
    fn a_listed_caller_sees_only_listed_fields_and_the_primary_name_in_bulk() {
        let c = ctx(listed(&["account.phone"]), &[]);
        assert!(field_readable(
            &c,
            "account",
            "phone",
            false,
            Some("name"),
            Surface::Bulk
        ));
        assert!(field_readable(
            &c,
            "account",
            "name",
            false,
            Some("name"),
            Surface::Bulk
        ));
        assert!(!field_readable(
            &c,
            "account",
            "revenue",
            false,
            Some("name"),
            Surface::Bulk
        ));
        // Listing is per entity.
        assert!(!field_readable(
            &c,
            "contact",
            "phone",
            false,
            None,
            Surface::Bulk
        ));
    }

    #[test]
    fn a_legacy_caller_keeps_todays_bulk_behaviour() {
        let c = ctx(BulkFields::Legacy, &[]);
        assert!(field_readable(
            &c,
            "account",
            "revenue",
            false,
            None,
            Surface::Bulk
        ));
        assert!(!field_readable(
            &c,
            "account",
            "salary",
            true,
            None,
            Surface::Bulk
        ));
    }

    #[test]
    fn a_sensitive_field_always_needs_its_grant_even_when_listed() {
        let c = ctx(listed(&["account.salary"]), &[]);
        assert!(!field_readable(
            &c,
            "account",
            "salary",
            true,
            None,
            Surface::Bulk
        ));
        let c = ctx(listed(&[]), &["account.salary"]);
        assert!(field_readable(
            &c,
            "account",
            "salary",
            true,
            None,
            Surface::Bulk
        ));
    }
}
