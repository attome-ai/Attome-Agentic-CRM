//! D-602 (basic-units U4) — the entity engine's answer to "can this
//! reminder's recipient still read its record?", handed to the notification
//! poller (`attome_notification::reminders::ReminderRecordAccess`).
//!
//! Lives here because this crate depends on both `attome-notification` and
//! `attome-records`, and neither may depend on the other for this. The
//! decision itself is B-R1's parent-record check
//! (`entity_crud::referenced_record_visible`), evaluated for the recipient's
//! own security context, never the caller's or a system one.

use attome_core::EngineState;
use attome_notification::reminders::{AccessFuture, ReminderRecordAccess};
use attome_records::entity_crud::referenced_record_visible;
use uuid::Uuid;

/// The production [`ReminderRecordAccess`].
#[derive(Debug)]
pub struct EngineReminderAccess;

impl ReminderRecordAccess for EngineReminderAccess {
    fn recipient_can_read<'a>(
        &'a self,
        state: &'a EngineState,
        user_id: Uuid,
        entity_name: &'a str,
        record_id: Uuid,
    ) -> AccessFuture<'a> {
        Box::pin(async move {
            // `resolve_strict`: a reminder must not be delivered on a stale
            // cached grant any more than a request would be served on one.
            let ctx = state.base.security.resolve_strict(user_id).await?;
            referenced_record_visible(state, &ctx, entity_name, record_id).await
        })
    }
}
