//! Solution 7 Phase 2 (D-787 rule 7, D-791 rule 7; `SOLUTION-7-PHASE-2-DESIGN.md`
//! §1 "Write a reference record", §3.8) — the ambient recording of a generic
//! record write.
//!
//! A write to an `is_reference_data` entity through the generic entity API
//! (`/api/v1/{entity}`: create, update, upsert, bulk) is recorded as one
//! `upsert_record` operation **when a changeset is in play**: the request
//! named one (`X-Attome-Changeset`), the caller has one open, or the server
//! runs in `required` mode. In `auto` mode without an open changeset the
//! write is a customer edit and is not recorded (the release-report lane's
//! record baseline is what tells it apart from ours at the next apply).
//!
//! The entity-mutation primitives (`attome_records::entity_mutation`) sit
//! far below the HTTP handler and take no request context, and they are
//! shared by every record writer (workflow nodes, bulk, staged import,
//! bundle record sets). Rather than thread a [`Recording`] through every one
//! of those signatures, the generic handler wraps its work in [`scope`] and
//! the primitives read [`current`] — the same `tokio::task_local!` shape
//! `attome_server::current_request_meta` uses. Outside a scope (a job, a
//! workflow node, the changeset applier, a test) nothing is recorded.

use std::future::Future;
use std::sync::Arc;

use super::recorder::{Recording, Resolved};

tokio::task_local! {
    static REFERENCE_RECORDING: Arc<Recording>;
}

/// Runs `f` with `recording` as the ambient recording of generic record
/// writes. The generic entity handlers wrap their mutation in this.
pub async fn scope<F: Future>(recording: Arc<Recording>, f: F) -> F::Output {
    REFERENCE_RECORDING.scope(recording, f).await
}

/// The ambient recording, or `None` outside a [`scope`].
pub fn current() -> Option<Arc<Recording>> {
    REFERENCE_RECORDING.try_with(Arc::clone).ok()
}

/// Whether a resolved recording puts a changeset in play for a generic
/// record write (design §1): an explicit or open changeset does; an automatic
/// one (`auto` mode with nothing open, or a break-glass window) does not.
pub fn changeset_in_play(resolved: &Resolved) -> bool {
    resolved.automatic.is_none() && resolved.changeset_id.is_some()
}

#[cfg(test)]
mod tests {
    use super::super::model::{Layer, Origin};
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn nothing_is_ambient_outside_a_scope() {
        assert!(current().is_none());
    }

    #[tokio::test]
    async fn the_scope_carries_the_recording() {
        let recording = Arc::new(Recording::Applying {
            layer: Layer::Project,
        });
        let seen = scope(recording, async { current().map(|r| r.stamp().ok()) }).await;
        assert_eq!(seen, Some(Some(Layer::Project)));
        assert!(current().is_none(), "the scope ends with its future");
    }

    #[test]
    fn only_an_explicit_or_open_changeset_is_in_play() {
        let open = Resolved {
            changeset_id: Some(Uuid::now_v7()),
            layer: Layer::Project,
            automatic: None,
        };
        assert!(changeset_in_play(&open));
        let auto = Resolved {
            changeset_id: None,
            layer: Layer::Project,
            automatic: Some(Origin::Auto),
        };
        assert!(!changeset_in_play(&auto));
        let break_glass = Resolved {
            automatic: Some(Origin::BreakGlass),
            ..auto
        };
        assert!(!changeset_in_play(&break_glass));
        // An automatic changeset already inserted by an earlier write of the
        // same request is still automatic.
        let auto_inserted = Resolved {
            changeset_id: Some(Uuid::now_v7()),
            ..auto
        };
        assert!(!changeset_in_play(&auto_inserted));
    }
}
