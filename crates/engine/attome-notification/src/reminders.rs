//! Record reminders (basic-units plan U4, D-602): delivery of due
//! `reminder` rows on the notification poller's tick.
//!
//! `reminder` is a platform entity (`platform-bundles/xrm-reminder.json`):
//! a user asks to be reminded about a record at `remind_at`. Who may create
//! one for whom is the entity engine's rule (`SELF_ADDRESSED_ENTITIES`: the
//! creator is the recipient unless an admin sets it), and who may read it is
//! B-R1's parent-record rule (`POLYMORPHIC_CHILD_ENTITIES`).
//!
//! **Delivery is one more call on the existing poller tick** — no new loop,
//! queue or sweep job, the mechanism `user-calendar.md` R7 fixes for event
//! reminders. For each due reminder, one short transaction:
//!
//! 1. locks the row with `FOR UPDATE SKIP LOCKED` and re-checks it is still
//!    pending and due, and still names the recipient and record it was
//!    checked for;
//! 2. creates the notification dispatch **inside that transaction**
//!    (`dispatch::create_dispatch_in_tx`, preference category
//!    [`REMINDER_CATEGORY`]) — or, when the recipient can no longer read the
//!    record, creates nothing;
//! 3. marks the reminder `sent` (or `dismissed`, with `status_reason`);
//! 4. commits.
//!
//! A rollback leaves no notification and the reminder still pending, so the
//! next tick retries. A commit leaves exactly one dispatch and a reminder that
//! is no longer pending. Two pollers racing the same row: one holds the lock,
//! the other skips it, and after the commit the status re-check refuses it.
//! That makes the state change and the dispatch creation atomic and
//! exactly-once; delivery *after* commit keeps the notification layer's own
//! at-least-once behaviour (in-app rows are written in the same transaction;
//! email is an enqueued job).
//!
//! The recipient's read access is decided **before** the lock, on the pool,
//! so no second pool connection is taken while the transaction holds one
//! (M01-core C-12). The lock step's identity re-check closes the window: a
//! reminder edited in between is left for the next tick.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

use crate::dispatch::{DispatchRequest, create_dispatch_in_tx};

/// The preference category every reminder dispatch carries (B-R5): a user
/// can mute reminder email without muting anything else.
pub const REMINDER_CATEGORY: &str = "reminder";

/// The platform entity this module delivers.
pub const REMINDER_ENTITY: &str = "reminder";

/// `status_reason` values a dismissed reminder carries.
pub const REASON_RECORD_NOT_VISIBLE: &str = "record_not_visible";
pub const REASON_RECIPIENT_INACTIVE: &str = "recipient_inactive";
pub const REASON_INVALID_REFERENCE: &str = "invalid_record_reference";

/// Future type of [`ReminderRecordAccess::recipient_can_read`].
pub type AccessFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, AppError>> + Send + 'a>>;

/// Whether a reminder's recipient can still read the record it is about.
///
/// A trait because the answer is the entity engine's (B-R1 parent check,
/// `attome_records::entity_crud::referenced_record_visible`), which this
/// crate cannot depend on without dragging it into every crate that depends
/// on notifications. `attome-api`, which depends on both, supplies it to the
/// poller. `Ok(false)` drops the reminder; `Err` leaves it for the next tick.
pub trait ReminderRecordAccess: Send + Sync + 'static {
    fn recipient_can_read<'a>(
        &'a self,
        state: &'a EngineState,
        user_id: Uuid,
        entity_name: &'a str,
        record_id: Uuid,
    ) -> AccessFuture<'a>;
}

/// What one sweep did. `skipped` counts rows another poller claimed, rows
/// that changed under the check, and rows whose check failed (retried).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReminderSweep {
    pub delivered: usize,
    pub dismissed: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct DueReminder {
    id: Uuid,
    user_ref: Option<Uuid>,
    entity_name: Option<String>,
    record_id: Option<String>,
    note: Option<String>,
}

enum Outcome {
    Deliver {
        user: Uuid,
        entity: String,
        record: Uuid,
    },
    Dismiss(&'static str),
    Retry,
}

/// A status of NULL counts as pending: the entity leaves `status` optional so
/// a create need not name it.
const PENDING_PREDICATE: &str =
    "is_active = TRUE AND COALESCE(status, 'pending') = 'pending' AND remind_at <= NOW()";

/// `entity_name` is used to build the notification's route, so it must be a
/// plain logical name.
fn valid_logical_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The in-app route of a record form, mirroring the host app's
/// `logicalToUrlPath`: logical names carry no module prefix (V2-D483), so
/// every entity has the one `xrm/entity/{logicalname}` shape.
fn record_route(entity_name: &str, record_id: Uuid) -> String {
    format!("/xrm/entity/{entity_name}/form?id={record_id}")
}

#[cfg(test)]
mod record_route_tests {
    use super::record_route;
    use uuid::Uuid;

    #[test]
    fn maps_every_prefix_to_a_routable_path() {
        let id = Uuid::nil();
        assert_eq!(
            record_route("note", id),
            format!("/xrm/entity/note/form?id={id}")
        );
        assert_eq!(
            record_route("trd_symbol", id),
            format!("/xrm/entity/trd_symbol/form?id={id}")
        );
        assert_eq!(
            record_route("account", id),
            format!("/xrm/entity/account/form?id={id}")
        );
        assert_eq!(
            record_route("entity_x", id),
            format!("/xrm/entity/entity_x/form?id={id}")
        );
    }
}

async fn decide(
    state: &EngineState,
    access: &dyn ReminderRecordAccess,
    due: &DueReminder,
) -> Result<Outcome, AppError> {
    let Some(user) = due.user_ref else {
        return Ok(Outcome::Dismiss(REASON_RECIPIENT_INACTIVE));
    };
    let (Some(entity), Some(record)) = (due.entity_name.as_deref(), due.record_id.as_deref())
    else {
        return Ok(Outcome::Dismiss(REASON_INVALID_REFERENCE));
    };
    let Ok(record) = Uuid::parse_str(record.trim()) else {
        return Ok(Outcome::Dismiss(REASON_INVALID_REFERENCE));
    };
    if !valid_logical_name(entity) {
        return Ok(Outcome::Dismiss(REASON_INVALID_REFERENCE));
    }
    let active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(user)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if active != Some(true) {
        return Ok(Outcome::Dismiss(REASON_RECIPIENT_INACTIVE));
    }
    match access.recipient_can_read(state, user, entity, record).await {
        Ok(true) => Ok(Outcome::Deliver {
            user,
            entity: entity.to_owned(),
            record,
        }),
        Ok(false) => Ok(Outcome::Dismiss(REASON_RECORD_NOT_VISIBLE)),
        Err(e) => {
            tracing::warn!(
                reminder_id = %due.id,
                error = %e,
                "reminder: recipient access check failed; retrying next tick"
            );
            Ok(Outcome::Retry)
        }
    }
}

/// Claims, delivers or dismisses one reminder in one transaction. `Ok(false)`
/// when the row was not ours to act on (locked by another poller, no longer
/// pending, or changed since `decide` looked at it).
async fn settle(
    state: &EngineState,
    due: &DueReminder,
    outcome: &Outcome,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: Option<DueReminder> = sqlx::query_as(&format!(
        "SELECT id, user_ref, entity_name, record_id, note FROM reminder \
         WHERE id = $1 AND {PENDING_PREDICATE} FOR UPDATE SKIP LOCKED"
    ))
    .bind(due.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if locked.as_ref() != Some(due) {
        // Dropping `tx` rolls back and releases the lock.
        return Ok(false);
    }

    let (status, reason) = match outcome {
        Outcome::Deliver {
            user,
            entity,
            record,
        } => {
            let body = due
                .note
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| "You asked to be reminded about this record.".to_owned());
            let req = DispatchRequest {
                template_key: None,
                locale: "en".to_owned(),
                recipient_user_ref: Some(*user),
                is_global: false,
                organization_ref: None,
                // The platform default channels, minus the recipient's own
                // mutes for `reminder` (B-R5).
                channels: None,
                subject: Some("Reminder".to_owned()),
                body_html: None,
                body_text: Some(body),
                route: Some(record_route(entity, *record)),
                variables: Default::default(),
                priority: "normal".to_owned(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            create_dispatch_in_tx(
                &mut tx,
                &state.base.config.notification,
                req,
                Some(REMINDER_CATEGORY),
            )
            .await?;
            ("sent", None)
        }
        Outcome::Dismiss(reason) => ("dismissed", Some(*reason)),
        // `run_due_reminders` never settles a retry; nothing to write.
        Outcome::Retry => return Ok(false),
    };

    let updated = sqlx::query(
        "UPDATE reminder SET status = $2, status_reason = $3, modified_at = NOW(), \
         row_version = row_version + 1 WHERE id = $1",
    )
    .bind(due.id)
    .bind(status)
    .bind(reason)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::internal(
            "reminder disappeared while it was locked for delivery",
        ));
    }
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// One sweep over at most `limit` due reminders. Called from
/// `crate::poller`'s tick; also callable directly (tests).
pub async fn run_due_reminders(
    state: &EngineState,
    access: &dyn ReminderRecordAccess,
    limit: i64,
) -> Result<ReminderSweep, AppError> {
    let due: Vec<DueReminder> = match sqlx::query_as(&format!(
        "SELECT id, user_ref, entity_name, record_id, note FROM reminder \
         WHERE {PENDING_PREDICATE} ORDER BY remind_at, id LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(&state.base.db)
    .await
    {
        Ok(rows) => rows,
        // The entity is provisioned by a platform bundle at boot; before
        // that (or on a database that never ran it) there is nothing to do.
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42P01") => {
            return Ok(ReminderSweep::default());
        }
        Err(e) => return Err(AppError::internal(e)),
    };

    let mut sweep = ReminderSweep::default();
    for reminder in &due {
        let outcome = decide(state, access, reminder).await?;
        if matches!(outcome, Outcome::Retry) {
            sweep.skipped += 1;
            continue;
        }
        match settle(state, reminder, &outcome).await {
            Ok(true) => match outcome {
                Outcome::Deliver { .. } => sweep.delivered += 1,
                Outcome::Dismiss(reason) => {
                    tracing::info!(reminder_id = %reminder.id, reason, "reminder dismissed");
                    sweep.dismissed += 1;
                }
                Outcome::Retry => sweep.skipped += 1,
            },
            Ok(false) => sweep.skipped += 1,
            Err(e) => {
                tracing::warn!(
                    reminder_id = %reminder.id,
                    error = %e,
                    "reminder: delivery transaction failed; retrying next tick"
                );
                sweep.skipped += 1;
            }
        }
    }
    Ok(sweep)
}

/// The poller's entry point: logs rather than returns, like its siblings.
pub(crate) async fn run_on_tick(
    state: &EngineState,
    access: &Arc<dyn ReminderRecordAccess>,
    limit: i64,
) {
    if let Err(e) = run_due_reminders(state, access.as_ref(), limit).await {
        tracing::error!(error = %e, "reminder sweep failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_route_maps_the_logical_name_to_its_url_path() {
        let id = Uuid::nil();
        assert_eq!(
            record_route("service_ticket", id),
            format!("/xrm/entity/service_ticket/form?id={id}")
        );
        assert_eq!(
            record_route("account", id),
            format!("/xrm/entity/account/form?id={id}")
        );
    }

    #[test]
    fn only_plain_logical_names_build_a_route() {
        assert!(valid_logical_name("note"));
        assert!(valid_logical_name("account2"));
        assert!(!valid_logical_name(""));
        assert!(!valid_logical_name("../admin"));
        assert!(!valid_logical_name("Account"));
        assert!(!valid_logical_name("a?b=c"));
    }
}
