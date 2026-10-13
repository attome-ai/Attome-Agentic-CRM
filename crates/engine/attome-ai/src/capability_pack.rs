//! Capability packs (C6, D-556) — a named, versioned set of action ids an
//! agent policy references.
//!
//! **A pack is configuration, never an authorization mechanism.** It
//! contributes term 5 of the conjunction (the allow-list) and nothing else:
//!
//! ```text
//! OK   capability pack -> allowed_action_ids -> agent policy -> visible_to() -> gate() -> dispatch()
//! BAD  capability pack -> 'authorized' -> execute()
//! ```
//!
//! Resolution happens **once, at session start** (`resolve`, called from
//! `agent::start_session`), producing the same `allowed_action_ids` snapshot a
//! hand-picked list produces. Nothing at dispatch time reads this module, and
//! nothing here returns a decision — it returns ids, for the same snapshot
//! every other source feeds. An implementation that needs to consult a pack
//! during dispatch has drifted into a second authorization path (I-5).
//!
//! The pack entity itself is ordinary metadata (`ai_capability_pack`,
//! shipped by `platform-bundles/attome-ai-capability-pack.json`), which is why
//! this reads it through `entity_crud::read_record`: the caller's own read
//! privilege is the authorization for resolving a reference, exactly as it is
//! for the policy that names it.

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::agent::json_string_list;

/// The metadata entity a pack is a row of.
pub const CAPABILITY_PACK_ENTITY: &str = "ai_capability_pack";

/// The pack's action-id list field — a JSON array of registered action ids,
/// stored as text like the policy's own JSON list fields.
pub const ACTION_IDS_FIELD: &str = "action_ids";

/// One pack that contributed to a session's allowed-action set, with the
/// `row_version` it held at the moment the session started.
///
/// The id alone is not enough: packs are versioned, so "which capabilities did
/// this session hold" must be answerable later without depending on what the
/// pack says now (D-556 §2). This is the same `{ref, row_version}` pair
/// `PolicySnapshot::policy_ref`/`policy_row_version` already carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CapabilityPackRef {
    pub id: Uuid,
    pub row_version: i64,
}

/// What resolving a policy's referenced packs produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedPacks {
    /// The union of every referenced pack's action ids, in reference order,
    /// with duplicates collapsed. `None` when the policy references no pack
    /// — "no pack contributes". `Some(vec![])` means packs were referenced
    /// and together grant nothing, which is still a grant of nothing.
    pub action_ids: Option<Vec<String>>,
    /// id + `row_version` provenance, in the same order. `None` exactly when
    /// `action_ids` is `None`.
    pub refs: Option<Vec<CapabilityPackRef>>,
}

/// Resolves a policy's `capability_pack_refs` into action ids and provenance.
///
/// * No references at all (`None` or `[]`) resolves to
///   `ResolvedPacks::default()` — no contribution, no provenance. A pack can
///   only ever add ids, so "no packs" is simply "nothing to add", never a
///   widening.
/// * A reference that does not resolve to a pack the caller can read, or one
///   that names an action the registry does not know, **refuses** the start
///   rather than being dropped. Silently ignoring a broken grant is how a
///   policy that looks like it grants something grants nothing, and silently
///   ignoring an unknown id would let a mistyped pack pass review.
pub async fn resolve(
    state: &EngineState,
    ctx: &SecurityContext,
    pack_refs: Option<&[Uuid]>,
) -> Result<ResolvedPacks, AppError> {
    let Some(pack_refs) = pack_refs.filter(|refs| !refs.is_empty()) else {
        return Ok(ResolvedPacks::default());
    };

    let mut action_ids: Vec<String> = Vec::new();
    let mut refs: Vec<CapabilityPackRef> = Vec::with_capacity(pack_refs.len());

    for pack_id in pack_refs {
        let record = match attome_records::entity_crud::read_record(
            state,
            ctx,
            CAPABILITY_PACK_ENTITY,
            *pack_id,
        )
        .await
        {
            Ok(record) => record,
            Err(AppError::NotFound | AppError::Forbidden) => {
                return Err(AppError::Validation(format!(
                    "this agent's policy references capability pack {pack_id}, which does not resolve to an active pack the caller can read; fix or clear capability_pack_refs before a session can start"
                )));
            }
            Err(e) => return Err(e),
        };

        let subject = format!("capability pack {pack_id} is not usable");
        let ids = json_string_list(record.data(), ACTION_IDS_FIELD, &subject)?;
        // A pack with no action_ids grants nothing. None and [] mean the same
        // thing *for a pack* — there is no third "unrestricted" reading, unlike
        // a policy's allow-list — so they are handled explicitly rather than
        // collapsed with unwrap_or_default(), which is the I-16 mistake this
        // module must never make.
        if let Some(ids) = ids {
            for id in ids {
                if crate::engine::REGISTRY.resolve(&id).is_none() {
                    return Err(AppError::Validation(format!(
                        "capability pack {pack_id} names an unknown action {id:?}; a pack is a closed set of registered actions"
                    )));
                }
                if !action_ids.contains(&id) {
                    action_ids.push(id);
                }
            }
        }

        refs.push(CapabilityPackRef {
            id: *pack_id,
            row_version: record.row_version(),
        });
    }

    Ok(ResolvedPacks {
        action_ids: Some(action_ids),
        refs: Some(refs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pack_ref_round_trips_through_json() {
        let reference = CapabilityPackRef {
            id: Uuid::now_v7(),
            row_version: 3,
        };
        let json = serde_json::to_value(vec![&reference]).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!([{ "id": reference.id, "row_version": 3 }])
        );
        let back: Vec<CapabilityPackRef> = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, vec![reference]);
    }
}
