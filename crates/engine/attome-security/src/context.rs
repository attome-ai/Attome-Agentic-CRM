//! Ergonomic authorization checks on top of `attome_server::security::SecurityContext`.
//!
//! `SecurityContext` itself lives in attome-server (it's inserted as an
//! `Extension<T>` by attome-server's `authz` middleware, and attome-server cannot
//! name a type from attome-security — dependency direction, guidelines §1). This
//! extension trait adds the methods handlers actually call, without a second
//! near-identical struct or a conversion at the boundary.

use attome_server::security::SecurityContext;
use attome_types::AppError;

/// Privilege key granting unconditional access to every gated route/action.
pub const ADMIN_PRIVILEGE_KEY: &str = attome_server::security::ADMIN_PRIVILEGE_KEY;
/// Grants access to the sidebar manager and its mutation API.
pub const SIDEBAR_MANAGE_PRIVILEGE_KEY: &str = "sidebar.manage";

/// Type-level marker for [`SIDEBAR_MANAGE_PRIVILEGE_KEY`], so a sidebar-admin
/// handler can name `Authorized<Privilege<SidebarManage>>` and have the
/// extractor perform the check that used to be an easily-omitted
/// `ctx.require_key(SIDEBAR_MANAGE_PRIVILEGE_KEY)?` line in the body.
#[derive(Debug)]
pub struct SidebarManage;

impl attome_server::authz::PrivilegeKey for SidebarManage {
    const KEY: &'static str = SIDEBAR_MANAGE_PRIVILEGE_KEY;
}

/// Compile-time action verbs for `Authorized<RecordScoped<A>>`.
///
/// These are the second half of the entity privilege key `require` builds —
/// `"{entity}.{action}"` — with the entity coming from the route's `{entity}`
/// path segment. Naming one in a handler's signature moves that handler's
/// `ctx.require(&entity_name, "read")?` line into the extractor, where it
/// cannot be omitted.
///
/// They live here rather than in attome-server for the same reason
/// [`SidebarManage`] does: attome-server owns the *mechanism*
/// (`attome_server::authz::RecordActionKind`) and this platform owns the
/// vocabulary. Combined markers exist for the two handlers that genuinely
/// need more than one verb — a conjunction, not a choice.
pub mod record_action {
    use attome_server::authz::RecordActionKind;

    /// Reads through the generic entity API.
    #[derive(Debug)]
    pub struct Read;
    impl RecordActionKind for Read {
        const ACTIONS: &'static [&'static str] = &["read"];
    }

    /// Inserts a new record.
    #[derive(Debug)]
    pub struct Create;
    impl RecordActionKind for Create {
        const ACTIONS: &'static [&'static str] = &["create"];
    }

    /// Mutates an existing record. Also the verb for restore, and for the
    /// file-attachment routes that write a record's file field — both reuse
    /// `update` rather than inventing a permission verb per rare action.
    #[derive(Debug)]
    pub struct Update;
    impl RecordActionKind for Update {
        const ACTIONS: &'static [&'static str] = &["update"];
    }

    /// Soft-deletes a record.
    #[derive(Debug)]
    pub struct Delete;
    impl RecordActionKind for Delete {
        const ACTIONS: &'static [&'static str] = &["delete"];
    }

    /// Submits work through the batch/staged-import surface. Held *in
    /// addition* to the verb for the operation being batched, which is why
    /// `bulk::enqueue` keeps a body-dependent `require` alongside this.
    #[derive(Debug)]
    pub struct Bulk;
    impl RecordActionKind for Bulk {
        const ACTIONS: &'static [&'static str] = &["bulk"];
    }

    /// Q14-T1: shares a record (beside the record access the share gives).
    #[derive(Debug)]
    pub struct Share;
    impl RecordActionKind for Share {
        const ACTIONS: &'static [&'static str] = &["share"];
    }

    /// Upsert: it decides insert-or-update from the payload's match key, so
    /// the caller must be entitled to both outcomes before either is chosen.
    #[derive(Debug)]
    pub struct CreateAndUpdate;
    impl RecordActionKind for CreateAndUpdate {
        const ACTIONS: &'static [&'static str] = &["create", "update"];
    }

    /// Merge: the canonical record is updated and the duplicate is deleted,
    /// in one request.
    #[derive(Debug)]
    pub struct UpdateAndDelete;
    impl RecordActionKind for UpdateAndDelete {
        const ACTIONS: &'static [&'static str] = &["update", "delete"];
    }
}

pub trait SecurityContextExt {
    /// Coarse admin-or-nothing check — what P1.1 enforces everywhere today
    /// (no per-entity privileges are seeded yet).
    fn require_admin(&self) -> Result<(), AppError>;

    /// Per-entity/action check for future callers once per-entity grants
    /// exist (Phase 2.8 / F132+). Admin always satisfies it. Defined now so
    /// call sites don't need a second signature migration later.
    fn require(&self, entity: &str, action: &str) -> Result<(), AppError>;

    /// Q10-T11: the decision [`Self::require`] makes, without counting it as
    /// a use of the privilege. Screens (the menu, a form's buttons) ask this
    /// so they show exactly what the API would admit.
    fn allows(&self, entity: &str, action: &str) -> bool;

    /// Flat-key check — for callers holding a bare privilege key rather than
    /// an (entity, action) pair, e.g. `sql_query.required_privilege`
    /// (P1.1e per-query gating). Admin always satisfies it.
    fn require_key(&self, key: &str) -> Result<(), AppError>;

    /// F013/F135 (D-111): true iff `is_admin`, or a `field_security_profile`
    /// reachable through one of this user's roles grants `can_read` for
    /// `(entity, field)`. Callers gate an `is_sensitive` attribute's inclusion
    /// in a response with this per field — not a Result-returning `require*`,
    /// since omitting one sensitive field from a row isn't a rejected request.
    fn has_field_read_grant(&self, entity: &str, field: &str) -> bool;

    /// P-field-write-security (D-141): true iff `is_admin`, or a
    /// `field_security_profile` reachable through one of this user's
    /// roles grants `can_update` for `(entity, field)`. Independent of
    /// `has_field_read_grant` — a caller can hold either grant for a pair
    /// without the other. Only meaningful for `is_sensitive` attributes; the
    /// caller (`entity_mutation`'s payload validation, `merge_records`'
    /// dependent-redirect check) is responsible for checking `is_sensitive`
    /// first, same convention `has_field_read_grant`'s call sites already
    /// follow — a non-sensitive field is never gated by either set.
    fn has_field_write_grant(&self, entity: &str, field: &str) -> bool;
}

impl SecurityContextExt for SecurityContext {
    fn require_admin(&self) -> Result<(), AppError> {
        if self.is_admin {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    fn require(&self, entity: &str, action: &str) -> Result<(), AppError> {
        if self.is_admin {
            return Ok(());
        }
        if self.allows(entity, action) {
            // Q10-T9: counted for the unused-privilege proposals.
            attome_server::privilege_usage::record(self.user_id, &format!("{entity}.{action}"));
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    fn allows(&self, entity: &str, action: &str) -> bool {
        self.is_admin || self.privileges.contains(&format!("{entity}.{action}"))
    }

    fn require_key(&self, key: &str) -> Result<(), AppError> {
        if self.is_admin {
            Ok(())
        } else if self.privileges.contains(key) {
            attome_server::privilege_usage::record(self.user_id, key);
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    fn has_field_read_grant(&self, entity: &str, field: &str) -> bool {
        self.is_admin || self.field_grants.contains(&format!("{entity}.{field}"))
    }

    fn has_field_write_grant(&self, entity: &str, field: &str) -> bool {
        self.is_admin
            || self
                .field_write_grants
                .contains(&format!("{entity}.{field}"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use attome_server::security::SecurityContext;
    use uuid::Uuid;

    use super::*;

    fn ctx(is_admin: bool, field_write_grants: HashSet<String>) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants,
            bulk_fields: Default::default(),
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

    /// P-audit-item-17: `require_admin`/`require`/`require_key` are the actual
    /// functions every "unauthorized action" rejection in the workspace routes
    /// through (`attome-workflow`'s `admin.rs`/`instance_admin.rs`, among others)
    /// — until now only their sibling `has_field_*_grant` methods had test
    /// coverage in this module, not the `Result`-returning checks themselves.
    #[test]
    fn admin_has_write_grant_regardless_of_profile() {
        let c = ctx(true, HashSet::new());
        assert!(c.has_field_write_grant("employee", "salary"));
    }

    #[test]
    fn non_admin_require_admin_is_forbidden() {
        let c = ctx(false, HashSet::new());
        assert!(matches!(c.require_admin(), Err(AppError::Forbidden)));
    }

    #[test]
    fn admin_require_admin_succeeds() {
        let c = ctx(true, HashSet::new());
        assert!(c.require_admin().is_ok());
    }

    #[test]
    fn non_admin_without_the_matching_privilege_is_forbidden() {
        let c = ctx(false, HashSet::new());
        assert!(matches!(
            c.require("workflow_definition", "publish"),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn non_admin_with_the_matching_privilege_succeeds() {
        let mut c = ctx(false, HashSet::new());
        c.privileges
            .insert("workflow_definition.publish".to_owned());
        assert!(c.require("workflow_definition", "publish").is_ok());
        // A privilege for a different action on the same entity does not
        // implicitly grant this one.
        assert!(matches!(
            c.require("workflow_definition", "delete"),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn admin_satisfies_require_and_require_key_without_any_privilege() {
        let c = ctx(true, HashSet::new());
        assert!(c.require("workflow_definition", "publish").is_ok());
        assert!(c.require_key("sidebar.manage").is_ok());
    }

    #[test]
    fn non_admin_without_the_matching_flat_key_is_forbidden() {
        let c = ctx(false, HashSet::new());
        assert!(matches!(
            c.require_key(SIDEBAR_MANAGE_PRIVILEGE_KEY),
            Err(AppError::Forbidden)
        ));
    }

    #[test]
    fn non_admin_with_the_matching_flat_key_succeeds() {
        let mut c = ctx(false, HashSet::new());
        c.privileges.insert(SIDEBAR_MANAGE_PRIVILEGE_KEY.to_owned());
        assert!(c.require_key(SIDEBAR_MANAGE_PRIVILEGE_KEY).is_ok());
    }

    #[test]
    fn non_admin_with_no_grant_is_denied() {
        let c = ctx(false, HashSet::new());
        assert!(!c.has_field_write_grant("employee", "salary"));
    }

    #[test]
    fn non_admin_with_explicit_grant_is_allowed_for_that_pair_only() {
        let c = ctx(false, HashSet::from(["employee.salary".to_owned()]));
        assert!(c.has_field_write_grant("employee", "salary"));
        assert!(!c.has_field_write_grant("employee", "ssn"));
        assert!(!c.has_field_write_grant("contact", "salary"));
    }

    /// Read and write grants are independent axes — holding one says
    /// nothing about the other (P-field-write-security, D-141).
    #[test]
    fn read_grant_alone_does_not_imply_write_grant() {
        let c = SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: HashSet::from(["employee.salary".to_owned()]),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
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
        };
        assert!(c.has_field_read_grant("employee", "salary"));
        assert!(!c.has_field_write_grant("employee", "salary"));
    }

    /// Locks attome-server's `RecordScoped<A>` policy to `require`.
    ///
    /// The extractor must live in attome-server (it owns the `AuthorizedContext`
    /// extension) and attome-server cannot name a trait from attome-security
    /// (guidelines §1), so `RecordScoped<A>::authorize` re-implements the three
    /// lines of `require` above. Duplicated logic that is allowed to drift is
    /// worse than no extractor at all — a handler converted to
    /// `Authorized<RecordScoped<Read>>` has *deleted* its own `require` line
    /// and is relying entirely on the copy. This asserts the two agree across
    /// the cases that distinguish them: admin short-circuit, exact key match,
    /// wrong action, wrong entity.
    ///
    /// The paired assertion for `Admin`/`require_admin` is
    /// `admin_policy_agrees_with_require_admin` below.
    #[test]
    fn record_scoped_policy_matches_require() {
        use attome_server::authz::{AuthorizationPolicy, PolicyScope, RecordScoped};

        use crate::record_action::{Read, Update};

        let admin = ctx(true, HashSet::new());
        let bare = ctx(false, HashSet::new());
        let mut with_read = ctx(false, HashSet::new());
        with_read.privileges.insert("account.read".to_owned());
        let mut with_update = ctx(false, HashSet::new());
        with_update.privileges.insert("account.update".to_owned());

        let cases: [(&str, &SecurityContext, &str); 5] = [
            ("admin", &admin, "account"),
            ("no privileges", &bare, "account"),
            ("holds account.read", &with_read, "account"),
            ("holds account.update", &with_update, "account"),
            ("holds account.read, other entity", &with_read, "contact"),
        ];

        for (label, c, entity) in cases {
            let scope = PolicyScope {
                path_param: Some(entity),
            };

            assert_eq!(
                RecordScoped::<Read>::authorize(c, scope).is_ok(),
                c.require(entity, "read").is_ok(),
                "RecordScoped<Read> and require({entity}, \"read\") disagree for {label}"
            );
            assert_eq!(
                RecordScoped::<Update>::authorize(c, scope).is_ok(),
                c.require(entity, "update").is_ok(),
                "RecordScoped<Update> and require({entity}, \"update\") disagree for {label}"
            );
        }
    }

    /// A multi-verb marker must be exactly the conjunction of its verbs — the
    /// property `merge_records` and `upsert_record` rely on now that they no
    /// longer make the two `require` calls themselves.
    #[test]
    fn combined_record_actions_are_the_conjunction_of_their_verbs() {
        use attome_server::authz::{AuthorizationPolicy, PolicyScope, RecordScoped};

        use crate::record_action::{CreateAndUpdate, UpdateAndDelete};

        let scope = PolicyScope {
            path_param: Some("account"),
        };
        let with = |keys: &[&str]| {
            let mut c = ctx(false, HashSet::new());
            for k in keys {
                c.privileges.insert((*k).to_owned());
            }
            c
        };

        for keys in [
            &[][..],
            &["account.create"],
            &["account.update"],
            &["account.delete"],
            &["account.create", "account.update"],
            &["account.update", "account.delete"],
            &["account.create", "account.update", "account.delete"],
        ] {
            let c = with(keys);
            assert_eq!(
                RecordScoped::<CreateAndUpdate>::authorize(&c, scope).is_ok(),
                c.require("account", "create").is_ok() && c.require("account", "update").is_ok(),
                "CreateAndUpdate disagrees with create AND update for {keys:?}"
            );
            assert_eq!(
                RecordScoped::<UpdateAndDelete>::authorize(&c, scope).is_ok(),
                c.require("account", "update").is_ok() && c.require("account", "delete").is_ok(),
                "UpdateAndDelete disagrees with update AND delete for {keys:?}"
            );
        }
    }

    /// The `Admin` half of the same duplication, pinned for the same reason.
    #[test]
    fn admin_policy_agrees_with_require_admin() {
        use attome_server::authz::{Admin, AuthorizationPolicy, PolicyScope};

        let scope = PolicyScope { path_param: None };
        for is_admin in [true, false] {
            let c = ctx(is_admin, HashSet::new());
            assert_eq!(
                Admin::authorize(&c, scope).is_ok(),
                c.require_admin().is_ok(),
                "Admin policy and require_admin disagree for is_admin={is_admin}"
            );
        }
    }
}
