//! F8-T9: abandoned carts, handed to marketing journeys.
//!
//! With [`ENABLED_SETTING`] on (off by default), the [`JOB`] runs every 15
//! minutes and looks at open portal carts (`commerce_cart`) that hold at
//! least one line, last changed between [`IDLE_SETTING`] minutes (60 by
//! default) and 7 days ago, whose portal user's contact has a phone, mobile
//! or email, and that have not been looked at since they last changed. For
//! each, in batches of [`BATCH`]:
//!
//! - without the contact's active `marketing` consent the cart is marked
//!   `no_consent` and nothing is sent;
//! - with it, the cart is marked `emitted` (and `abandoned_cart_notified_at`)
//!   and a `cart.abandoned` event on the contact is written to the change
//!   feed in the same transaction, which an E8 journey with the entry
//!   source `{"type": "event", "event_name": "cart.abandoned"}` takes.
//!
//! The mark (migration 0376) keeps a second sweep from emitting again;
//! changing the cart clears it. Nothing is sent from here: the journey sends.

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_types::AppError;
use uuid::Uuid;

/// The job's name.
pub const JOB: &str = "commerce_abandoned_cart";
/// Whether the sweep runs (off by default).
pub const ENABLED_SETTING: &str = "commerce.abandoned_cart.enabled";
/// Minutes a cart sits unchanged before it counts as abandoned.
pub const IDLE_SETTING: &str = "commerce.abandoned_cart.idle_minutes";
/// The change-feed event.
pub const EVENT: &str = "cart.abandoned";
/// The consent purpose checked.
pub const PURPOSE: &str = "marketing";
/// Carts per batch.
pub const BATCH: i64 = 500;

/// What a sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    pub emitted: usize,
    pub no_consent: usize,
}

fn idle_minutes(state: &EngineState) -> i64 {
    crate::commerce::setting(state, IDLE_SETTING)
        .as_i64()
        .unwrap_or(60)
        .clamp(15, 7 * 24 * 60)
}

/// One sweep; see the module documentation.
pub async fn sweep(state: &EngineState) -> Result<Swept, AppError> {
    let mut swept = Swept::default();
    if !crate::commerce::setting(state, ENABLED_SETTING)
        .as_bool()
        .unwrap_or(false)
    {
        return Ok(swept);
    }
    let idle = idle_minutes(state);
    let db = &state.base.db;
    loop {
        let carts: Vec<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT c.id, u.contact_ref FROM commerce_cart c \
               JOIN webportal_user u ON u.id = c.portal_user_id \
               JOIN contact k ON k.id = u.contact_ref \
              WHERE c.status = 'open' AND c.abandoned_cart_outcome IS NULL \
                AND c.updated_at <= now() - make_interval(mins => $1::int) \
                AND c.updated_at >= now() - interval '7 days' \
                AND EXISTS (SELECT 1 FROM commerce_cart_line l WHERE l.cart_id = c.id) \
                AND (k.is_active IS NULL OR k.is_active = true) \
                AND (NULLIF(k.mobile_phone, '') IS NOT NULL OR NULLIF(k.phone, '') IS NOT NULL \
                     OR NULLIF(k.email, '') IS NOT NULL) \
              ORDER BY c.updated_at, c.id LIMIT $2",
        )
        .bind(i32::try_from(idle).unwrap_or(60))
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if carts.is_empty() {
            break;
        }
        for (cart, contact) in carts {
            let consented = attome_notification::consent_gate::has_active_consent(
                db,
                "contact",
                &contact.to_string(),
                PURPOSE,
            )
            .await?;
            let mut tx = attome_db::tx::begin(db).await?;
            let marked = sqlx::query(
                "UPDATE commerce_cart SET abandoned_cart_outcome = $2, \
                        abandoned_cart_notified_at = CASE WHEN $2 = 'emitted' THEN now() END \
                  WHERE id = $1 AND abandoned_cart_outcome IS NULL",
            )
            .bind(cart)
            .bind(if consented { "emitted" } else { "no_consent" })
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if marked.rows_affected() == 1 {
                if consented {
                    emit_named(&mut *tx, "contact", contact, ChangeOperation::Update, EVENT)
                        .await?;
                    swept.emitted += 1;
                } else {
                    swept.no_consent += 1;
                }
            }
            attome_db::tx::commit(tx).await?;
        }
    }
    Ok(swept)
}
