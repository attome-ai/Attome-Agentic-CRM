//! A26-T2: stored derived entities kept current from the change feed.
//!
//! A derived entity's condition reads only its anchor's own fields
//! (V2-D1628 (1)), so every condition is incremental: a record's membership
//! changes only when the record itself changes. Each tick reads a batch of
//! change events ([`CONSUMER`]'s cursor: read, process, then advance, so a
//! crash re-reads the batch; re-checking a record is idempotent), and for
//! each stored definition re-checks the changed anchors
//! ([`derived_entity::reconcile`]): members enter and leave, each with a
//! history row in `derived_entity_history`.
//!
//! **Surge guard.** A change that would move more than
//! [`derived_entity::SURGE_LIMIT`] members is not applied: the definition is
//! paused, the anchors are held in `derived_entity_pending`, and every
//! administrator is notified. While paused, later changes are held too.
//! `POST /api/v1/admin/derived-entities/{name}/resume` applies them all and
//! lifts the pause. With own-field conditions one event moves at most one
//! member, so a feed batch stays under the limit; the guard is for the bulk
//! paths that reuse [`derived_entity::reconcile`] (A26-T3's refresh).

use std::collections::{BTreeSet, HashMap};

use attome_core::EngineState;
use attome_metadata::provision::derived_entity::{self, DerivedEntity, DerivedMode, Reconciled};
use attome_types::AppError;
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-metadata/derived-maintain";
/// The registered job.
pub const JOB: &str = "derived_maintain";
/// Events read per tick.
const BATCH: i64 = 1_000;
/// The notification category of a surge pause.
const NOTIFY_CATEGORY: &str = "derived_entity";

/// The changed records of each anchor entity, each once, in event order.
/// Pure.
pub fn changed_by_entity<'a>(
    events: impl IntoIterator<Item = (&'a str, Uuid)>,
) -> HashMap<&'a str, Vec<Uuid>> {
    let mut seen = BTreeSet::new();
    let mut out: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for (entity, id) in events {
        if seen.insert((entity, id)) {
            out.entry(entity).or_default().push(id);
        }
    }
    out
}

/// One tick: reads a batch of events, keeps every stored derived entity's
/// membership right and advances the cursor. How many events were read.
pub async fn tick(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last_event) = events.last() else {
        return Ok(0);
    };
    let stored: Vec<DerivedEntity> = derived_entity::list(&state.base.db)
        .await?
        .into_iter()
        .filter(|d| d.mode == DerivedMode::Stored)
        .collect();
    if !stored.is_empty() {
        let changed = changed_by_entity(
            events
                .iter()
                .map(|e| (e.entity_logicalname.as_str(), e.record_id)),
        );
        let paused = derived_entity::paused(&state.base.db).await?;
        let registry = std::sync::Arc::clone(&state.entities.load());
        for def in &stored {
            let Some(ids) = changed.get(def.anchor.as_str()) else {
                continue;
            };
            let Some(anchor) = registry.get(&def.anchor) else {
                tracing::warn!(derived = %def.name, anchor = %def.anchor,
                    "derived entity's anchor is not a live entity; membership not kept");
                continue;
            };
            if paused.contains(&def.name) {
                derived_entity::hold(&state.base.db, &def.name, ids).await?;
                continue;
            }
            match derived_entity::reconcile(
                &state.base.db,
                def,
                anchor,
                ids,
                "the record changed",
                Some(derived_entity::SURGE_LIMIT),
            )
            .await?
            {
                Reconciled::Applied(change) => {
                    if !change.is_empty() {
                        tracing::debug!(derived = %def.name, entered = change.enter.len(),
                            left = change.leave.len(), "derived entity membership changed");
                    }
                }
                Reconciled::Surge(moving) => surge(state, def, ids, moving).await?,
            }
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, CONSUMER, last_event).await?;
    Ok(events.len())
}

/// Pauses `def`, holds `ids` and tells every administrator, once.
pub async fn surge(
    state: &EngineState,
    def: &DerivedEntity,
    ids: &[Uuid],
    moving: usize,
) -> Result<(), AppError> {
    let reason = format!(
        "one change would move {moving} members (more than {})",
        derived_entity::SURGE_LIMIT
    );
    if !derived_entity::pause(&state.base.db, &def.name, ids, &reason).await? {
        return Ok(());
    }
    tracing::warn!(derived = %def.name, moving, "derived entity paused by the surge guard");
    let admins = crate::exit::administrators(state).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for user in &admins {
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(*user),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(format!("Derived entity {} paused", def.name)),
            body_html: None,
            body_text: Some(format!(
                "Keeping the derived entity {} current stopped because {reason}. \
                 Nothing has moved yet. Check the change, then resume it \
                 (POST /api/v1/admin/derived-entities/{}/resume) to apply it.",
                def.name, def.name
            )),
            route: None,
            variables: HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch_in_tx(
            &mut tx,
            &state.base.config.notification,
            request,
            Some(NOTIFY_CATEGORY),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_incremental_groups_changes_by_anchor_once() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let grouped = changed_by_entity([("deal", a), ("deal", a), ("account", b), ("deal", b)]);
        assert_eq!(grouped["deal"], vec![a, b]);
        assert_eq!(grouped["account"], vec![b]);
    }
}
