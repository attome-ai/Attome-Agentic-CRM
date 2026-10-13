//! The stable changeset refusal messages (design §7).
//!
//! `AppError` has no variant carrying a caller-chosen code, so in this lane
//! each refusal is a `409 conflict` whose message **starts with** the stable
//! code (`changeset_required: …`). A dedicated `AppError` variant with its own
//! wire codes is a attome-types + OpenAPI + SDK change for the integrator; when
//! it lands, only this file's callers change.

pub const CHANGESET_REQUIRED: &str = "changeset_required: this metadata write must be recorded in \
     an open changeset; open one with POST /api/v1/admin/changesets or name one with the \
     X-Attome-Changeset header";

pub const CHANGESET_AMBIGUOUS: &str = "changeset_ambiguous: you have more than one open \
     changeset; name the one to record into with the X-Attome-Changeset header";

pub const CHANGESET_NOT_OPEN: &str =
    "changeset_not_open: the changeset does not exist or is closed or abandoned";

pub const CHANGESET_EMPTY: &str =
    "changeset_empty: a changeset with no operations cannot be closed; abandon it instead";

pub const CHANGESET_NOT_EMPTY: &str = "changeset_not_empty: a changeset with operations cannot \
     be abandoned; undo the change with a further change in it, then close it";

pub const CHANGESET_NAME_TAKEN: &str = "changeset_name_taken: an open changeset with this layer, \
     scope and name already exists";

pub const LAYER_MISMATCH: &str = "layer_mismatch: this object is owned by another layer; change \
     it in a changeset of the layer that owns it";

// ── Business keys (D-787 rule 7, D-791 rule 7; Phase 2 design §3.8, §13) ──

pub const BUSINESS_KEY_MISSING: &str = "business_key_missing: this entity declares no business \
     key, so its records cannot be matched or recorded by key; declare one with PATCH \
     /api/v1/admin/entities/{entity_id} (business_key) first";

pub const BUSINESS_KEY_REQUIRED_FOR_REFERENCE_DATA: &str = "business_key_missing: a reference-data entity (is_reference_data) needs a declared \
     business key";

pub const BUSINESS_KEY_MISMATCH: &str = "business_key_mismatch: the operation's target.key must \
     name exactly the entity's declared business key fields";

pub const BUSINESS_KEY_DUPLICATES: &str = "business_key_duplicates: live records share a value \
     of this business key, so its unique index cannot build; resolve the duplicates first";

pub const FIELD_IN_BUSINESS_KEY: &str = "field_in_business_key: the field is part of the entity's \
     business key; declare a key without it first";

pub const LOOKUP_TARGET_HAS_NO_BUSINESS_KEY: &str = "lookup_target_has_no_business_key: a \
     lookup of this reference record names an entity without a business key, so the recorded \
     change could not find its target on another deployment; declare a key on the target \
     entity first";

/// The stable code a refusal message starts with.
pub fn code_of(message: &str) -> &str {
    message.split_once(':').map_or(message, |(code, _)| code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_message_starts_with_its_stable_code() {
        for (message, code) in [
            (CHANGESET_REQUIRED, "changeset_required"),
            (CHANGESET_AMBIGUOUS, "changeset_ambiguous"),
            (CHANGESET_NOT_OPEN, "changeset_not_open"),
            (CHANGESET_EMPTY, "changeset_empty"),
            (CHANGESET_NOT_EMPTY, "changeset_not_empty"),
            (CHANGESET_NAME_TAKEN, "changeset_name_taken"),
            (LAYER_MISMATCH, "layer_mismatch"),
            (BUSINESS_KEY_MISSING, "business_key_missing"),
            (
                BUSINESS_KEY_REQUIRED_FOR_REFERENCE_DATA,
                "business_key_missing",
            ),
            (BUSINESS_KEY_MISMATCH, "business_key_mismatch"),
            (BUSINESS_KEY_DUPLICATES, "business_key_duplicates"),
            (FIELD_IN_BUSINESS_KEY, "field_in_business_key"),
            (
                LOOKUP_TARGET_HAS_NO_BUSINESS_KEY,
                "lookup_target_has_no_business_key",
            ),
        ] {
            assert_eq!(code_of(message), code);
        }
    }
}
