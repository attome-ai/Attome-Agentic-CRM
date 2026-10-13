//! Deterministic ids for bundle-created objects (D-374 amendment).
//!
//! `derived_id` is used only for a `PlanAction::Create` step's new row — it
//! is never compared against an already-live object (that match is, as
//! always, by logical key: `plan.rs`'s diff, not this module). The result is
//! that the *same bundle* produces the *same* entity/attribute/etc. ids on
//! every fresh deployment it is applied to, useful for cross-deployment
//! correlation, without reintroducing the identity model D-374 rejected — an
//! update to an object that already exists under some other id is untouched
//! by this, exactly as before.
//!
//! `component`/`key` are the same strings `plan.rs`/`apply.rs`'s
//! `build_steps` already compute for every `PlanEntry`/`PlannedStep`
//! (`COMPONENT_ENTITY` + `e.logicalname`, `COMPONENT_ATTRIBUTE` +
//! `"{entity}.{attr}"`, etc.) — callers should reuse those exact strings
//! rather than reconstructing key formatting here.

use uuid::Uuid;

/// A fixed, arbitrary namespace UUID for this platform's bundle-derived ids.
/// Minted once; must never change — changing it would silently reassign
/// every previously-derived id the next time a fresh deployment applies the
/// same bundle.
const BUNDLE_ID_NAMESPACE: Uuid = uuid::uuid!("6f6e9b8e-9e1e-4b7a-9b1a-8e2c9f0d7a4c");

/// `UUIDv5(BUNDLE_ID_NAMESPACE, "{component}:{key}")` — deterministic, so the
/// same `(component, key)` always yields the same id.
pub fn derived_id(component: &str, key: &str) -> Uuid {
    Uuid::new_v5(
        &BUNDLE_ID_NAMESPACE,
        format!("{component}:{key}").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::derived_id;

    #[test]
    fn deterministic_across_calls() {
        assert_eq!(
            derived_id("entity", "ai_agent"),
            derived_id("entity", "ai_agent")
        );
    }

    #[test]
    fn distinct_keys_yield_distinct_ids() {
        let ids = [
            derived_id("entity", "ai_agent"),
            derived_id("entity", "ai_model"),
            derived_id("attribute", "ai_agent.name"),
            derived_id("query", "ai_agent/Active Agents"),
        ];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "collision between derived ids {i} and {j}");
            }
        }
    }

    #[test]
    fn same_key_different_component_differs() {
        assert_ne!(
            derived_id("entity", "shared_key"),
            derived_id("attribute", "shared_key")
        );
    }
}
