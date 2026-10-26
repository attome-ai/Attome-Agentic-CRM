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
use attome_core::field_mask::{ColumnAccess, MaskFormat};
use attome_server::security::{BulkFields, SecurityContext};

use crate::context::SecurityContextExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Interactive,
    Bulk,
}

/// Q15-T1: the format `ctx` may see `entity.field` masked in, when it may see
/// it only masked. An administrator sees every field in full; a format this
/// code does not know masks fully rather than not at all.
pub fn field_mask(ctx: &SecurityContext, entity: &str, field: &str) -> Option<MaskFormat> {
    if ctx.is_admin {
        return None;
    }
    ctx.field_masks
        .get(&format!("{entity}.{field}"))
        .map(|format| MaskFormat::parse(format).unwrap_or(MaskFormat::Full))
}

/// Q15-T1: how a surface projects `attr`: in full when [`readable`], masked
/// when the caller holds only a masked grant and the surface is interactive,
/// otherwise not at all. A bulk surface never shows a masked field: it is
/// not readable there, masked or not.
pub fn projection(
    ctx: &SecurityContext,
    entity: &str,
    attr: &AttrInfo,
    primary_name: Option<&str>,
    surface: Surface,
) -> ColumnAccess {
    if readable(ctx, entity, attr, primary_name, surface) {
        ColumnAccess::Full
    } else if surface == Surface::Interactive
        && attr.is_sensitive
        && let Some(format) = field_mask(ctx, entity, &attr.logicalname)
    {
        ColumnAccess::Masked(format)
    } else {
        ColumnAccess::Hidden
    }
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
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    fn sensitive_attr(name: &str) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: 1,
            is_required: false,
            max_length: None,
            is_sensitive: true,
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

    /// Q15-T1: a masked grant shows the field masked on an interactive read,
    /// never on a bulk one; a grant in full, or an administrator, sees it in
    /// full; nothing granted hides it.
    #[test]
    fn field_mask_projection_by_surface_and_grant() {
        let card = sensitive_attr("card_number");
        let mut masked = ctx(BulkFields::Legacy, &[]);
        masked
            .field_masks
            .insert("account.card_number".into(), "last4".into());
        assert_eq!(
            projection(&masked, "account", &card, None, Surface::Interactive),
            ColumnAccess::Masked(MaskFormat::Last4)
        );
        assert_eq!(
            projection(&masked, "account", &card, None, Surface::Bulk),
            ColumnAccess::Hidden
        );
        assert!(!masked.has_field_write_grant("account", "card_number"));

        let full = ctx(BulkFields::Legacy, &["account.card_number"]);
        assert_eq!(
            projection(&full, "account", &card, None, Surface::Interactive),
            ColumnAccess::Full
        );
        let admin = SecurityContext {
            is_admin: true,
            ..ctx(BulkFields::Legacy, &[])
        };
        assert_eq!(field_mask(&admin, "account", "card_number"), None);
        assert_eq!(
            projection(
                &ctx(BulkFields::Legacy, &[]),
                "account",
                &card,
                None,
                Surface::Interactive
            ),
            ColumnAccess::Hidden
        );
    }

    #[test]
    fn field_mask_unknown_format_masks_fully() {
        let mut c = ctx(BulkFields::Legacy, &[]);
        c.field_masks.insert("account.iban".into(), "half".into());
        assert_eq!(field_mask(&c, "account", "iban"), Some(MaskFormat::Full));
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
