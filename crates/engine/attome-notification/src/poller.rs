//! Background scanner driving the Notification Engine's dispatch queue
//! (F163) and escalation timer (F172) — a polling loop over durable
//! Postgres state (`notification_dispatch`), not itself an apalis
//! `EngineJob`. The scanner only re-derives "what's pending/due now" from
//! Postgres on every tick and re-enqueues the actual per-dispatch work as a
//! real `EngineJob::FanOutNotification` (`dispatch.rs`'s
//! `recipient::enqueue_fanout_in_tx`), so it holds no state a crash could
//! lose — a bare `tokio::spawn` loop is the correct guidelines §10 shape for
//! that (rebuildable, disposable-on-restart supervision), not a workaround
//! for enum ownership: `EngineJob` already carries notification-specific
//! variants (`FanOutNotification`, `PruneNotificationRecipientPartitions`,
//! `BackfillRecipientForNewUser`) added straightforwardly in this one
//! workspace. `dispatch::claim_pending_batch`'s `FOR UPDATE SKIP LOCKED`
//! makes this safe to run on every app node simultaneously (guidelines'
//! multi-server rule).
//!
//! D-421 / M10 (Approval & Governance) added `approval_timeouts::
//! run_due_approval_timeouts` to this same tick — reusing this scanner
//! (rather than a new `EngineJob` variant or a second `tokio::spawn` loop)
//! is that module plan's own explicit instruction, and it fits the same
//! shape this file already documents above: `approval_request` is
//! durable Postgres state, `attome_approval::list_due_step_timeouts` only
//! re-derives what's due on every tick, and any real per-request work it
//! finds still goes through `apply_step_timeout`'s row-level advisory lock,
//! same multi-node safety as this scanner's other two calls.
//!
//! D-602 (basic-units U4) added `reminders::run_due_reminders` to the same
//! tick, per `user-calendar.md` R7: record reminders are one more call here,
//! not a new loop. Its `FOR UPDATE SKIP LOCKED` claim gives the same
//! every-node safety. It runs first, so the dispatch rows it creates are
//! finished by `run_pending_batch` on the same tick.

use std::sync::Arc;
use std::time::Duration;

use attome_core::EngineState;

use crate::reminders::ReminderRecordAccess;

const BATCH_LIMIT: i64 = 25;

/// Spawns the detached scanner loop. Called once from
/// `EngineSystemBuilder::build()`, same shape as
/// `attome_api::spawn_chainer_lag_refresh`/`spawn_partition_bloat_refresh`.
/// `reminder_access` answers whether a reminder's recipient can still read
/// its record (see `crate::reminders`).
pub fn spawn(
    state: EngineState,
    interval: Duration,
    reminder_access: Arc<dyn ReminderRecordAccess>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            crate::reminders::run_on_tick(&state, &reminder_access, BATCH_LIMIT).await;
            crate::dispatch::run_pending_batch(&state, BATCH_LIMIT).await;
            crate::dispatch::run_due_escalations(&state, BATCH_LIMIT).await;
            crate::approval_timeouts::run_due_approval_timeouts(&state, BATCH_LIMIT).await;
        }
    });
}
