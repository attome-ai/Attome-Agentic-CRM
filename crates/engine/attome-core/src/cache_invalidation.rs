//! Z3-T5: precise cross-node cache invalidation from the entity change feed.
//!
//! Each node keeps an [`InvalidationBus`] holding its dependency-aware
//! caches ([`InvalidateDeps`], e.g. a `TieredCache` read with
//! `get_or_load_depending`). Once a second the bus reads every finished
//! change event after its position ([`change_feed::read_after`], the same
//! `commit_xid < pg_snapshot_xmin(...)` gate as a cursor consumer) and drops
//! the entries depending on each written record and its entity. That poll is
//! the guarantee and works without Redis: the feed is in Postgres, so every
//! node sees every write within about a second.
//!
//! The doorbell is the speed-up: after a generic record write commits, the
//! writer publishes on [`CACHE_INVALIDATE_CHANNEL`] ([`ring_after_commit`])
//! and every node polls at once instead of at its next tick. The message
//! carries nothing; the poll reads exactly what changed. A lost message costs
//! at most one tick.
//!
//! The position is this node's own, in memory: a node starts at the feed's
//! horizon and flushes the registered caches' L1, so nothing it holds can
//! predate the position. No consumer cursor row is written (nodes come and
//! go, and the feed's pruning must not wait on one that left).
//!
//! Cache contract (guidelines §5): the bus holds handles only, no state that
//! must agree across nodes; a failed read is logged and retried with backoff
//! up to 30 s, during which entries live at most their TTL.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, PoisonError, RwLock};
use std::time::Duration;

use attome_cache::depends::{Dependency, InvalidateDeps};
use attome_db::DbPool;
use attome_types::AppError;
use tokio::sync::{Mutex, Notify};

use crate::change_feed::{self, CursorPosition};

/// The doorbell channel. Payload unused.
pub const CACHE_INVALIDATE_CHANNEL: &str = "attome-cache:invalidate";

/// How often a node reads the feed without a doorbell.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Events read per statement.
const BATCH: i64 = 500;

/// The longest wait between reads after repeated failures.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// One node's invalidation bus. See the module doc.
#[derive(Default)]
pub struct InvalidationBus {
    caches: RwLock<Vec<Arc<dyn InvalidateDeps>>>,
    position: Mutex<Option<CursorPosition>>,
    poke: Notify,
}

impl std::fmt::Debug for InvalidationBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvalidationBus")
            .field("caches", &self.caches().len())
            .finish_non_exhaustive()
    }
}

static BUS: LazyLock<Arc<InvalidationBus>> = LazyLock::new(Arc::default);

/// This process's bus, which the server starts and caches register with.
pub fn bus() -> &'static Arc<InvalidationBus> {
    &BUS
}

impl InvalidationBus {
    /// Adds a cache. A cache registered after the bus started keeps only
    /// entries loaded after that, so it needs no flush.
    pub fn register(&self, cache: Arc<dyn InvalidateDeps>) {
        self.caches
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cache);
    }

    fn caches(&self) -> Vec<Arc<dyn InvalidateDeps>> {
        self.caches
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Asks for a read now (the doorbell). Several rings before the next
    /// read make one read.
    pub fn ring(&self) {
        self.poke.notify_one();
    }

    /// Reads every finished event after this node's position and drops the
    /// entries they make stale; answers how many events it read. The first
    /// call only takes the feed's horizon as the position and flushes the
    /// registered caches.
    pub async fn poll_once(&self, db: &DbPool) -> Result<usize, AppError> {
        let mut position = self.position.lock().await;
        let Some(mut at) = *position else {
            let start = {
                let mut conn = db.acquire().await.map_err(AppError::internal)?;
                change_feed::horizon(&mut conn).await?
            };
            for cache in self.caches() {
                cache.flush_local().await;
            }
            *position = Some(start);
            return Ok(0);
        };
        let mut read = 0;
        loop {
            // The connection goes back to the pool before any invalidation
            // work (which may reach Redis).
            let (events, next) = {
                let mut conn = db.acquire().await.map_err(AppError::internal)?;
                change_feed::read_after(&mut conn, at, BATCH).await?
            };
            let count = events.len();
            let mut stale: HashSet<Dependency> = HashSet::new();
            for event in &events {
                stale.extend(Dependency::of_write(
                    &event.entity_logicalname,
                    event.record_id,
                ));
            }
            if !stale.is_empty() {
                for cache in self.caches() {
                    for dependency in &stale {
                        cache.invalidate_dependency(dependency).await;
                    }
                }
            }
            at = next;
            *position = Some(at);
            read += count;
            if i64::try_from(count).unwrap_or(i64::MAX) < BATCH {
                return Ok(read);
            }
        }
    }

    /// Starts this node's bus: the doorbell on `subscriber` (which the
    /// caller subscribes to [`CACHE_INVALIDATE_CHANNEL`]) and the read
    /// loop, once per `interval` or at once on a ring. Process-lifetime
    /// supervision (guidelines §10).
    pub fn spawn(
        self: &Arc<Self>,
        db: DbPool,
        subscriber: Option<&attome_cache::Subscriber>,
        interval: Duration,
    ) {
        if let Some(subscriber) = subscriber {
            let bus = Arc::clone(self);
            subscriber.on_message(move |message| {
                if message.channel == CACHE_INVALIDATE_CHANNEL {
                    bus.ring();
                }
            });
        }
        let bus = Arc::clone(self);
        tokio::spawn(async move {
            let mut wait = interval;
            loop {
                match bus.poll_once(&db).await {
                    Ok(_) => wait = interval,
                    Err(error) => {
                        wait = (wait * 2).min(MAX_BACKOFF);
                        tracing::error!(
                            event = "cache.invalidation.read_failed",
                            %error,
                            retry_in_secs = wait.as_secs(),
                            "cache invalidation could not read the change feed; cached entries live their TTL until it can"
                        );
                    }
                }
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = bus.poke.notified() => {}
                }
            }
        });
    }
}

/// Rings every node's bus after a write committed. Best effort and off the
/// write path: a lost ring costs one poll interval.
pub fn ring_after_commit(store: &attome_cache::Store) {
    let store = store.clone();
    tokio::spawn(async move {
        if let Err(error) = store.publish(CACHE_INVALIDATE_CHANNEL, "1").await {
            tracing::debug!(%error, "cache invalidation doorbell not sent; the poll catches up");
        }
    });
}
