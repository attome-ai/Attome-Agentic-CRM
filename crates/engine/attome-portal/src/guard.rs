//! Generic-CRUD guards for the portal entities (D-576 items 2 and 8).
//!
//! The portal entities are ordinary metadata entities so admins can see them,
//! rename them and add their own fields. A few fields, though, decide who can
//! log in where, and only this crate's admin routes may write them:
//!
//! - `webportal`: `keyword` (the URL prefix), `portal_type`, `is_enabled`,
//!   `owning_team_ref` and `mfa_policy`.
//! - `webportal_user`: `webportal_ref` (which portal the account belongs
//!   to), `email` (the login name) and `status`.
//!
//! These run as `EngineModel::record_validators`, which the generic engine
//! applies to every create and update **in every mutation mode**: interactive,
//! bulk, import and bundle alike. `EngineModel::engine_managed_fields` would
//! only cover the interactive mode. The admin routes write with their own SQL
//! and never pass through these validators.
//!
//! Each entity has protected fields that are also `is_required` (`keyword` and
//! `portal_type`; `webportal_ref`, `email` and `status`), so a generic *create*
//! can never succeed: it either omits a required field or sends a refused one.
//! Generic reads, renames, custom-field edits and deletes stay available.

use attome_core::EntityMetaRegistry;
use serde_json::{Map, Value};

pub const WEBPORTAL_PROTECTED: &[&str] = &[
    "keyword",
    "portal_type",
    "is_enabled",
    "owning_team_ref",
    "mfa_policy",
];
pub const WEBPORTAL_USER_PROTECTED: &[&str] = &["webportal_ref", "email", "username", "status"];

fn refuse_protected(
    entity: &str,
    protected: &[&str],
    obj: &Map<String, Value>,
) -> Result<(), String> {
    match protected.iter().find(|f| obj.contains_key(**f)) {
        Some(field) => Err(format!(
            "'{field}' on {entity} is managed by the web portal admin API (/api/v1/admin/webportals)"
        )),
        None => Ok(()),
    }
}

pub fn validate_webportal_record(
    obj: &Map<String, Value>,
    _registry: &EntityMetaRegistry,
) -> Result<(), String> {
    refuse_protected("webportal", WEBPORTAL_PROTECTED, obj)
}

pub fn validate_webportal_user_record(
    obj: &Map<String, Value>,
    _registry: &EntityMetaRegistry,
) -> Result<(), String> {
    refuse_protected("webportal_user", WEBPORTAL_USER_PROTECTED, obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn protected_fields_are_refused_even_when_null() {
        for field in WEBPORTAL_PROTECTED {
            let obj = body(json!({ "name": "x", *field: null }));
            assert!(refuse_protected("webportal", WEBPORTAL_PROTECTED, &obj).is_err());
        }
        for field in WEBPORTAL_USER_PROTECTED {
            let obj = body(json!({ *field: "x" }));
            assert!(refuse_protected("webportal_user", WEBPORTAL_USER_PROTECTED, &obj).is_err());
        }
    }

    #[test]
    fn profile_and_custom_fields_pass() {
        let portal =
            body(json!({ "name": "Customers", "description": "d", "custom_colour": "blue" }));
        assert!(refuse_protected("webportal", WEBPORTAL_PROTECTED, &portal).is_ok());
        let user = body(json!({ "name": "Ada", "contact_ref": null }));
        assert!(refuse_protected("webportal_user", WEBPORTAL_USER_PROTECTED, &user).is_ok());
    }
}
