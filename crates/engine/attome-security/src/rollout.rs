//! The fleet console's rollout credential on a customer server (D-792,
//! `document/general/FLEET-CONSOLE-DESIGN.md` §5).
//!
//! One narrow platform privilege, `metadata.rollout`, held through one
//! platform role, **Rollout operator**, by one password-less user,
//! `attome-rollout`, that one S2S client per customer is bound to. Routes
//! that accept it name [`MetadataRollout`] in their handler signature
//! (`Authorized<Privilege<MetadataRollout>>`); `Privilege<K>` also admits
//! `system.admin`, so administrators keep every one of those routes.
//!
//! What accepts it (and nothing else in the API does):
//!
//! - `POST /api/v1/admin/metadata/changesets/{plan,apply}` and
//!   `GET …/changesets/ledger[/{apply_id}]`;
//! - the release-report reads and item decisions under
//!   `/api/v1/admin/metadata/release-report{s,-items}/…`;
//! - `GET /api/v1/admin/metadata/rollout/status`;
//! - `GET /api/v1/admin/approvals/{id}` for a request the caller itself
//!   submitted (never another's, and no decide route).
//!
//! Declarations, not provisioning: the privilege and the role are platform
//! definitions in `platform-bundles/attome-security.json` (compiled to
//! `changesets/platform/0023-attome-security.json`), applied at boot like every
//! other platform privilege. The user and the S2S client are created per
//! customer through the admin API (`deploy/ONBOARD-rollout-credential.md`).

use attome_server::authz::PrivilegeKey;

/// `privilege.key` of the rollout privilege.
pub const METADATA_ROLLOUT_PRIVILEGE_KEY: &str = "metadata.rollout";

/// `role.name` of the platform role that holds only
/// [`METADATA_ROLLOUT_PRIVILEGE_KEY`].
pub const ROLLOUT_OPERATOR_ROLE: &str = "Rollout operator";

/// The conventional `user_name` of the user a rollout S2S client is bound
/// to (onboarding runbook). Nothing keys behaviour on the name.
pub const ROLLOUT_USER_NAME: &str = "attome-rollout";

/// `Authorized<Privilege<MetadataRollout>>`: `metadata.rollout` or
/// `system.admin`.
#[derive(Debug)]
pub struct MetadataRollout;

impl PrivilegeKey for MetadataRollout {
    const KEY: &'static str = METADATA_ROLLOUT_PRIVILEGE_KEY;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn bundle() -> Value {
        serde_json::from_str(include_str!("../seed/security.json"))
            .expect("platform-bundles/attome-security.json parses")
    }

    #[test]
    fn the_platform_bundle_declares_the_privilege() {
        let bundle = bundle();
        let declared = bundle["privileges"]
            .as_array()
            .expect("privileges")
            .iter()
            .any(|p| p["key"] == METADATA_ROLLOUT_PRIVILEGE_KEY);
        assert!(declared, "metadata.rollout must be a platform privilege");
        assert_eq!(MetadataRollout::KEY, METADATA_ROLLOUT_PRIVILEGE_KEY);
    }

    #[test]
    fn the_rollout_operator_role_holds_only_the_rollout_privilege() {
        let bundle = bundle();
        let role = bundle["roles"]
            .as_array()
            .expect("roles")
            .iter()
            .find(|r| r["name"] == ROLLOUT_OPERATOR_ROLE)
            .expect("the Rollout operator role is declared");
        let keys: Vec<&str> = role["privileges"]
            .as_array()
            .expect("role privileges")
            .iter()
            .filter_map(|g| g["privilege"].as_str())
            .collect();
        assert_eq!(keys, vec![METADATA_ROLLOUT_PRIVILEGE_KEY]);
        assert!(
            role["entity_access"]
                .as_array()
                .is_none_or(|a| a.is_empty()),
            "no entity access"
        );
        assert!(
            role["field_security_profiles"]
                .as_array()
                .is_none_or(|a| a.is_empty()),
            "no field-security profile"
        );
        // Record scope None: the role reads no records even if a grant is
        // ever added to it by mistake.
        assert_eq!(role["access_level"], 0);
    }

    #[test]
    fn the_key_is_not_an_entity_privilege() {
        // `{entity}.{verb}` keys are what an S2S entity ceiling narrows
        // (D-766); this key must never look like one.
        let (prefix, verb) = METADATA_ROLLOUT_PRIVILEGE_KEY
            .split_once('.')
            .expect("dotted key");
        assert_eq!(prefix, "metadata");
        assert!(!["read", "create", "update", "delete", "bulk"].contains(&verb));
    }
}
