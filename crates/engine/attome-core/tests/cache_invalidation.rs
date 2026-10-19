//! Z3-T5: a record write drops the cache entries depending on it on another
//! node, through the change feed alone (no Redis), within about a second.
//!
//! Two [`InvalidationBus`]es stand for two nodes over one database. Node B
//! caches a value that depends on an entity; node A writes a record of that
//! entity (its change event, in the write's own transaction, as every
//! entity write path emits it); B's bus drops the entry and the next read
//! loads again. An entry depending on another entity stays.
//!
//! The visibility gate is cluster-wide: another test binary holding a write
//! transaction open delays the event, so the wait is bounded at 3 s as the
//! roadmap asks, with the poll at its production interval.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://...@localhost:5556/attome_test"
//! cargo test -p attome-core --test cache_invalidation
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test writes a change event in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use attome_cache::depends::{Dependency, InvalidateDeps};
use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
use attome_cache::tiered::TieredCache;
use attome_core::cache_invalidation::{InvalidationBus, POLL_INTERVAL};
use attome_core::change_feed::{self, ChangeOperation};
use attome_db::DbPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

static SPEC: CacheSpec = CacheSpec {
    name: "core:invalidation_test",
    crate_name: "core",
    purpose: "invalidation_test",
    source_of_truth: "a test",
    ttl: Duration::from_secs(600),
    jitter_pct: 0,
    l1_capacity: 100,
    partition: Partition::Shared,
    sensitivity: CacheSensitivity::LocalOnly,
    failure: FailureMode::FallBackToSource,
    invalidation: "the change feed (Z3-T5)",
    cold_start: "empty",
    warm_on_start: false,
};

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Reads `id` through `cache`, counting loads.
async fn read(
    cache: &TieredCache<String>,
    id: &str,
    depends_on: &[Dependency],
    loads: &AtomicUsize,
) -> String {
    cache
        .get_or_load_depending(None, id, depends_on, async {
            let n = loads.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(format!("load {n}"))
        })
        .await
        .expect("read")
}

#[tokio::test]
async fn write_invalidates_dependent_entry_on_other_node() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: {}", attome_testkit::skip_remedy());
        return;
    };
    let entity = attome_testkit::unique_logicalname("z3t5");
    let other = attome_testkit::unique_logicalname("z3t5_other");

    // Node A (the writer) and node B (the reader), each with its own bus.
    let node_a = Arc::new(InvalidationBus::default());
    let node_b = Arc::new(InvalidationBus::default());
    let cache = Arc::new(TieredCache::<String>::new(&SPEC, None).expect("cache"));
    node_b.register(Arc::clone(&cache) as Arc<dyn InvalidateDeps>);
    // The first poll takes the horizon, as a starting node does.
    node_a.poll_once(&db).await.expect("start a");
    node_b.poll_once(&db).await.expect("start b");
    node_a.spawn(db.clone(), None, POLL_INTERVAL);
    node_b.spawn(db.clone(), None, POLL_INTERVAL);

    let loads = AtomicUsize::new(0);
    let unrelated = AtomicUsize::new(0);
    let on_entity = [Dependency::Entity(entity.clone())];
    let on_other = [Dependency::Entity(other.clone())];
    assert_eq!(read(&cache, "list", &on_entity, &loads).await, "load 1");
    assert_eq!(
        read(&cache, "list", &on_entity, &loads).await,
        "load 1",
        "cached"
    );
    assert_eq!(read(&cache, "other", &on_other, &unrelated).await, "load 1");

    // Node A writes a record of `entity`.
    let mut tx = db.begin().await.expect("begin");
    change_feed::emit(&mut tx, &entity, Uuid::now_v7(), ChangeOperation::Update)
        .await
        .expect("emit");
    tx.commit().await.expect("commit");
    let written = Instant::now();

    let deadline = written + Duration::from_secs(3);
    loop {
        if read(&cache, "list", &on_entity, &loads).await != "load 1" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "node B still holds the entry 3 s after the write"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("invalidated after {:?}", written.elapsed());
    assert_eq!(
        read(&cache, "other", &on_other, &unrelated).await,
        "load 1",
        "an entry over another entity stays"
    );
}

#[tokio::test]
async fn a_record_dependency_is_dropped_by_a_write_of_that_record_only() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: {}", attome_testkit::skip_remedy());
        return;
    };
    let entity = attome_testkit::unique_logicalname("z3t5_rec");
    let (one, two) = (Uuid::now_v7(), Uuid::now_v7());
    let bus = InvalidationBus::default();
    let cache = Arc::new(TieredCache::<String>::new(&SPEC, None).expect("cache"));
    bus.register(Arc::clone(&cache) as Arc<dyn InvalidateDeps>);
    bus.poll_once(&db).await.expect("start");

    let (loads_one, loads_two) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let dep_one = [Dependency::Record(entity.clone(), one)];
    let dep_two = [Dependency::Record(entity.clone(), two)];
    read(&cache, "one", &dep_one, &loads_one).await;
    read(&cache, "two", &dep_two, &loads_two).await;

    let mut tx = db.begin().await.expect("begin");
    change_feed::emit(&mut tx, &entity, one, ChangeOperation::Update)
        .await
        .expect("emit");
    tx.commit().await.expect("commit");

    let deadline = Instant::now() + Duration::from_secs(20);
    while loads_one.load(Ordering::SeqCst) < 2 {
        bus.poll_once(&db).await.expect("poll");
        read(&cache, "one", &dep_one, &loads_one).await;
        assert!(Instant::now() < deadline, "the write was never read");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    read(&cache, "two", &dep_two, &loads_two).await;
    assert_eq!(
        loads_two.load(Ordering::SeqCst),
        1,
        "another record's entry stays"
    );
}
