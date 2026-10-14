//! C-18 — one shared shape for the small, admin-authored metadata
//! snapshots that used to each hand-roll an identical `struct { by_k:
//! HashMap }` / `from_entries` / `load(db)` / `*_VERSION_CHANNEL` quartet:
//! `state_registry::StateModelRegistry`, `relationship_registry::
//! RelationshipRegistry` and `rule_registry::RuleRegistry` (the form
//! registry went with `form`, D-788/D-790). On the `attome-server` side, each also had
//! its own ~33-line subscriber block with its own always-on Redis
//! connection — see `attome-server/src/system.rs`'s `EngineSystemBuilder::build()`,
//! which now opens one shared subscriber connection and registers each
//! type's [`spawn_doorbell_reload`] on it instead.
//!
//! **Why this closes a real gap, not just a duplication one.** Before this,
//! each of the four had a Redis pub/sub doorbell and nothing else — a
//! dropped `PUBLISH` (or a message sent before this node's subscription was
//! live) left a node stale until the table's next unrelated write, with no
//! self-heal. That was a real invalidation-tier gap relative to `entities`
//! (doorbell + change-log catch-up) and `settings`/`labels` (watermark
//! poll). [`spawn_doorbell_reload`] gives every `SnapshotSource` both
//! halves: the doorbell for prompt invalidation, and a periodic
//! unconditional full reload as the catch-up. Deliberately no watermark
//! table for this tier — these four tables have no per-row change-log to
//! track a cursor against, and a full reload of a small admin-authored
//! table is cheap enough that always re-running it on tick is simpler and
//! no more expensive than adding one, same reasoning `setting_store`/
//! `label_store`'s own module docs already give for their whole-table
//! reread (this is one notch simpler still: no watermark comparison at
//! all, just reload on every tick).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_cache::MetadataCache;
use attome_db::DbPool;
use attome_types::AppError;

/// Boxed, `Send` future — the same local alias `services::NotificationService`
/// already uses in this crate, so `SnapshotSource` stays a plain, non-`dyn`
/// trait without pulling in the `async-trait` crate for four call sites.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A small, admin-authored metadata table snapshot kept warm by one shared
/// [`spawn_doorbell_reload`] registration per implementing type. Only the
/// channel and the underlying query differ between
/// `StateModelRegistry`/`RelationshipRegistry`/`RuleRegistry`.
pub trait SnapshotSource: Sized + Send + Sync + Clone + 'static {
    /// Redis pub/sub channel this snapshot's admin writer best-effort
    /// publishes to after a commit. Payload is unused — a doorbell, not an
    /// instruction, same posture every one of these channels always had.
    const CHANNEL: &'static str;

    /// Builds a full snapshot from Postgres — the type's own pre-existing
    /// `load(db)` free function, unchanged (kept `pub` in its own module for
    /// the handful of callers — admin write paths — that want a synchronous
    /// local refresh right after their own commit, not a spawned reload).
    fn load(db: &DbPool) -> BoxFuture<'_, Result<Self, AppError>>;
}

async fn reload<T: SnapshotSource>(db: &DbPool, cache: &MetadataCache<T>) {
    match T::load(db).await {
        Ok(fresh) => cache.swap(fresh),
        Err(e) => tracing::warn!(
            error = %e,
            channel = T::CHANNEL,
            "snapshot reload failed — keeping the previous snapshot until the next \
             doorbell message or catch-up tick",
        ),
    }
}

/// Registers the doorbell half on `subscriber` (already connected, and
/// `.subscribe()`d to `T::CHANNEL` by the caller — see
/// `attome-server/src/system.rs`'s `EngineSystemBuilder::build()`, which shares
/// ONE subscriber connection across every channel rather than opening one
/// per registry) and spawns the periodic catch-up tick as the other half.
/// Both halves reload unconditionally (no watermark, see this module's own
/// doc comment) — a dropped or missed doorbell message now self-heals by
/// the next tick instead of waiting for the table's next write.
///
/// `interval` is the caller's choice deliberately: production wants
/// something in the tens-of-seconds range (matching `settings`/`labels`'
/// own poll cadence); a test proving the self-heal path wants seconds, not
/// minutes.
///
/// Registers exactly one `on_message` handler per call — `fred`'s
/// `EventInterface::on_message` spawns its own broadcast listener per
/// registration, so this composes cleanly with every other type's own call
/// on the same shared `subscriber`, each independently filtering on its own
/// `T::CHANNEL`.
pub fn spawn_doorbell_reload<T: SnapshotSource>(
    subscriber: &attome_cache::Subscriber,
    db: DbPool,
    cache: MetadataCache<T>,
    interval: Duration,
) {
    {
        let db = db.clone();
        let cache = cache.clone();
        subscriber.on_message(move |msg| {
            if msg.channel == T::CHANNEL {
                let db = db.clone();
                let cache = cache.clone();
                tokio::spawn(async move { reload::<T>(&db, &cache).await });
            }
        });
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate first tick — the caller already pre-warmed
        loop {
            ticker.tick().await;
            reload::<T>(&db, &cache).await;
        }
    });
}
