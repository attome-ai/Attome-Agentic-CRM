//! Integration tests for privilege resolution + caching.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL`, e.g.
//! `redis://localhost:6379/0`) — skips (loudly) when unset, except under `CI`,
//! per the P1.8 testing-baseline convention. NOT wired into any CI run yet
//! (no `attomedb_test` harness exists — see P1.8); run manually against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! $env:REDIS_URL     = "redis://localhost:6379/0"
//! cargo test -p attome-security --test resolver -- --test-threads=1
//! ```
//!
//! Each test creates its own throwaway `privilege`/`user_account`
//! rows (random UUIDs) rather than truncating shared tables.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::cache::SecurityCache;
use attome_security::db::{
    RecordAction, ensure_privilege, ensure_role_privilege_grant, ensure_user_privilege_grant,
    resolve_all_entity_access_levels, resolve_default_share_entities, resolve_entity_access_level,
    resolve_privileges, users_holding_role,
};
use attome_security::entity_privileges::{
    BULK_ACTION, ENTITY_ACTIONS, EXTRA_ACTIONS, ensure_entity_privileges, rename_entity_privileges,
};
use attome_server::security::AccessLevel;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use fred::prelude::*;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

async fn test_redis() -> RedisPool {
    let url = std::env::var("REDIS_URL").expect(
        "REDIS_URL must be set (e.g. redis://localhost:6379/0) to run attome-security \
         integration tests — see tests/resolver.rs header.",
    );
    let config = RedisConfig::from_url(&url).expect("invalid REDIS_URL");
    let pool = Builder::from_config(config)
        .build_pool(2)
        .expect("failed to build redis pool");
    pool.connect();
    pool.wait_for_connect()
        .await
        .expect("failed to connect to REDIS_URL");
    pool
}

/// Seeds a throwaway user + privilege + direct grant. Returns (user_id, privilege_key).
async fn seed_direct_grant(db: &DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let key = format!("test.direct.{}", Uuid::now_v7());

    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    let privilege_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) VALUES ($1, $2, $3, true, NOW(), 'project')",
    )
    .bind(privilege_id)
    .bind(&key)
    .bind("Test Direct Privilege")
    .execute(db)
    .await
    .expect("insert throwaway privilege");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway direct grant");

    (user_id, key)
}

/// Seeds a throwaway user + role + privilege granted to the role (not the
/// user directly) — D-111's role-mediated grant path, replacing the old
/// core_job-based one.
async fn seed_role(db: &DbPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("test-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");
    role_id
}

async fn link_user_to_role(db: &DbPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("insert throwaway user-role link");
}

/// Seeds a throwaway user + role + privilege granted to the role (not the
/// user directly). Returns (user_id, privilege_key).
async fn seed_role_grant(db: &DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let key = format!("test.role.{}", Uuid::now_v7());

    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    let role_id = seed_role(db).await;
    link_user_to_role(db, user_id, role_id).await;

    let privilege_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) VALUES ($1, $2, $3, true, NOW(), 'project')",
    )
    .bind(privilege_id)
    .bind(&key)
    .bind("Test Role Privilege")
    .execute(db)
    .await
    .expect("insert throwaway privilege");

    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway role grant");

    (user_id, key)
}

#[tokio::test]
async fn resolve_direct_grant() {
    let db = skip_if_no_db!(test_db().await);
    let (user_id, key) = seed_direct_grant(&db).await;

    let privileges = resolve_privileges(&db, user_id).await.expect("resolve");
    assert!(privileges.contains(&key), "direct grant must resolve");
}

#[tokio::test]
async fn resolve_via_role() {
    let db = skip_if_no_db!(test_db().await);
    let (user_id, key) = seed_role_grant(&db).await;

    let privileges = resolve_privileges(&db, user_id).await.expect("resolve");
    assert!(
        privileges.contains(&key),
        "role-mediated grant must resolve"
    );
}

#[tokio::test]
async fn resolve_dedup_across_direct_and_role() {
    let db = skip_if_no_db!(test_db().await);
    let (user_id, direct_key) = seed_direct_grant(&db).await;

    // Grant the SAME privilege to the same user again via a role, and assert
    // the resolver returns it exactly once (HashSet dedup, not two entries).
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;

    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(&direct_key)
        .fetch_one(&db)
        .await
        .expect("fetch privilege id");
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(&db)
    .await
    .expect("insert throwaway role grant");

    let privileges = resolve_privileges(&db, user_id).await.expect("resolve");
    // HashSet<String> can't hold a duplicate by construction — this test
    // documents the intent (both grant paths converge on one key), and
    // guards against a future switch to a Vec that could reintroduce dupes.
    assert_eq!(privileges.iter().filter(|k| *k == &direct_key).count(), 1);
}

#[tokio::test]
async fn cache_hit_serves_stale_value_within_ttl_then_invalidate_requeries() {
    let db = skip_if_no_db!(test_db().await);
    let redis = test_redis().await;
    let (user_id, key) = seed_direct_grant(&db).await;

    // No `cache.roles.coordination` override configured for this test, so —
    // matching `attome_cache::create_role_redis_pool`'s own fallback — the
    // coordination pool is just a second handle to the same Redis instance.
    let cache = SecurityCache::new(db.clone(), redis.clone(), redis);

    let first = cache.resolve(user_id).await.expect("first resolve");
    assert!(first.privileges.contains(&key));

    // Deactivate the grant directly in the DB, bypassing the cache entirely.
    sqlx::query("UPDATE user_account_mm_privilege SET is_active = false WHERE user_ref = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("deactivate grant");

    // Within the 60s TTL, a cache hit must still serve the OLD value —
    // proves the moka/Redis layers are actually consulted before Postgres.
    let second = cache
        .resolve(user_id)
        .await
        .expect("second resolve (cache hit)");
    assert!(
        second.privileges.contains(&key),
        "cache hit should still reflect the pre-deactivation grant within the TTL"
    );

    // Explicit invalidation must force a fresh Postgres read.
    cache.invalidate(user_id).await;
    let third = cache
        .resolve(user_id)
        .await
        .expect("third resolve (post-invalidate)");
    assert!(
        !third.privileges.contains(&key),
        "post-invalidate resolve must reflect the deactivated grant"
    );
}

// ── P-account-state-enforcement (audit finding #2) ────────────────────────────

#[tokio::test]
async fn resolve_privileges_rejects_a_disabled_user() {
    let db = skip_if_no_db!(test_db().await);
    let (user_id, key) = seed_direct_grant(&db).await;

    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the test user");

    let result = resolve_privileges(&db, user_id).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a disabled user's privileges must not resolve, got {result:?} (key was {key})"
    );
}

#[tokio::test]
async fn resolve_privileges_rejects_a_missing_user() {
    let db = skip_if_no_db!(test_db().await);
    let result = resolve_privileges(&db, Uuid::now_v7()).await;
    assert!(matches!(result, Err(AppError::Forbidden)));
}

/// A user whose `is_active` holds the column default still resolves its
/// grants. Migration 0460 (attome-auth hardening 2.4) backfilled the legacy NULL
/// rows this test used to simulate to that default and made NULL impossible.
#[tokio::test]
async fn resolve_privileges_accepts_a_user_on_the_is_active_default() {
    let db = skip_if_no_db!(test_db().await);
    let (user_id, key) = seed_direct_grant(&db).await;
    sqlx::query("UPDATE user_account SET is_active = DEFAULT WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("reset is_active to the column default");

    let privileges = resolve_privileges(&db, user_id).await.expect("resolve");
    assert!(
        privileges.contains(&key),
        "a user on the is_active default must still resolve its grants"
    );
}

/// Closes the residual window the plan documents: even a *warm* cache entry
/// for a user disabled after it was populated must stop granting access once
/// the cache is forced to re-check (the 60s TTL is the Phase-1 bound; Phase 2
/// `auth_epoch` replaces this with sub-second revocation).
#[tokio::test]
async fn disabling_a_user_invalidates_their_warm_cache_entry() {
    let db = skip_if_no_db!(test_db().await);
    let redis = test_redis().await;
    let (user_id, key) = seed_direct_grant(&db).await;
    let cache = SecurityCache::new(db.clone(), redis.clone(), redis);

    let first = cache.resolve(user_id).await.expect("first resolve");
    assert!(first.privileges.contains(&key));

    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("disable the test user");
    cache.invalidate(user_id).await;

    let result = cache.resolve(user_id).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "post-invalidate resolve for a disabled user must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn ensure_entity_privileges_creates_operation_and_bulk_keys_idempotently() {
    let db = skip_if_no_db!(test_db().await);
    let logicalname = format!("test_entity_{}", Uuid::now_v7().simple());

    ensure_entity_privileges(&db, &logicalname, attome_core::changeset::Layer::Project)
        .await
        .expect("seed privileges");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privilege WHERE key LIKE $1")
        .bind(format!("{logicalname}.%"))
        .fetch_one(&db)
        .await
        .expect("count privileges");
    assert_eq!(count, (ENTITY_ACTIONS.len() + EXTRA_ACTIONS.len()) as i64);
    let bulk_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM privilege WHERE key = $1)")
            .bind(format!("{logicalname}.{BULK_ACTION}"))
            .fetch_one(&db)
            .await
            .expect("check bulk privilege");
    assert!(bulk_exists);

    // Idempotent: re-running must not duplicate rows.
    ensure_entity_privileges(&db, &logicalname, attome_core::changeset::Layer::Project)
        .await
        .expect("reseed privileges");
    let count_again: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privilege WHERE key LIKE $1")
        .bind(format!("{logicalname}.%"))
        .fetch_one(&db)
        .await
        .expect("count privileges again");
    assert_eq!(
        count_again,
        (ENTITY_ACTIONS.len() + EXTRA_ACTIONS.len()) as i64
    );
}

#[tokio::test]
async fn rename_entity_privileges_preserves_grant() {
    let db = skip_if_no_db!(test_db().await);
    let old_name = format!("test_entity_{}", Uuid::now_v7().simple());
    let new_name = format!("test_entity_{}", Uuid::now_v7().simple());

    ensure_entity_privileges(&db, &old_name, attome_core::changeset::Layer::Project)
        .await
        .expect("seed privileges");

    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("rename-test-{user_id}"))
        .execute(&db)
        .await
        .expect("insert throwaway user_account");

    let old_key = format!("{old_name}.read");
    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(&old_key)
        .fetch_one(&db)
        .await
        .expect("fetch privilege id");
    ensure_user_privilege_grant(&db, user_id, privilege_id)
        .await
        .expect("grant");

    rename_entity_privileges(&db, &old_name, &new_name)
        .await
        .expect("rename");

    let privileges = resolve_privileges(&db, user_id).await.expect("resolve");
    assert!(
        privileges.contains(&format!("{new_name}.read")),
        "grant must survive under the renamed key"
    );
    assert!(
        !privileges.contains(&old_key),
        "the stale logicalname key must no longer resolve"
    );
}

#[tokio::test]
async fn role_grant_invalidate_forces_fresh_read() {
    let db = skip_if_no_db!(test_db().await);
    let redis = test_redis().await;

    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("role-invalidate-test-{user_id}"))
        .execute(&db)
        .await
        .expect("insert throwaway user_account");
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;

    let cache = SecurityCache::new(db.clone(), redis.clone(), redis);
    let key = format!("test.rolegrant.{}", Uuid::now_v7());

    // Resolve once before the grant exists — populates the cache with no privileges.
    let before = cache.resolve(user_id).await.expect("resolve before grant");
    assert!(!before.privileges.contains(&key));

    // Grant the privilege to the role directly (mirrors admin::create_role_grant).
    let privilege_id = ensure_privilege(
        &db,
        &key,
        &key,
        "test",
        attome_core::changeset::Layer::Project,
    )
    .await
    .expect("ensure privilege");
    ensure_role_privilege_grant(&db, role_id, privilege_id)
        .await
        .expect("grant to role");

    // Within the TTL, the cache must still be stale.
    let still_stale = cache.resolve(user_id).await.expect("resolve still cached");
    assert!(
        !still_stale.privileges.contains(&key),
        "cache hit should not see the new grant yet"
    );

    // Fan out invalidation to every current holder of the role (mirrors admin::create_role_grant).
    for uid in users_holding_role(&db, role_id)
        .await
        .expect("list role holders")
    {
        cache.invalidate(uid).await;
    }

    let after = cache
        .resolve(user_id)
        .await
        .expect("resolve after invalidate");
    assert!(
        after.privileges.contains(&key),
        "post-invalidate resolve must reflect the new role grant"
    );
}

// ── P-authz-revocation-epoch (D-116) ──────────────────────────────────────────

/// Models the exact "pub/sub-loss" shape the epoch mechanism exists for: two
/// independent `SecurityCache`s (each with its own in-process L1, same
/// Postgres + Redis) stand in for two app nodes. Node A handles a revoke and
/// acknowledges it (goal (b)); node B's own L1 is never told to drop its
/// entry (no subscriber wired at this unit level — that's `attome-server`'s
/// job). An ordinary `resolve()` on node B still serves the stale value
/// (documented, correct D-012 behavior) but `resolve_strict` catches the
/// revoke on its very next call via the epoch counter, with no dependence on
/// node B's L1 ever having been purged.
#[tokio::test]
async fn resolve_strict_sees_a_revoke_that_ordinary_resolve_on_another_node_would_still_serve_stale()
 {
    let db = skip_if_no_db!(test_db().await);
    let redis_a = test_redis().await;
    let redis_b = test_redis().await;
    let (user_id, key) = seed_direct_grant(&db).await;

    let node_a = SecurityCache::new(db.clone(), redis_a.clone(), redis_a);
    let node_b = SecurityCache::new(db.clone(), redis_b.clone(), redis_b);

    let warm = node_b.resolve(user_id).await.expect("warm node B's L1");
    assert!(warm.privileges.contains(&key));

    sqlx::query("UPDATE user_account_mm_privilege SET is_active = false WHERE user_ref = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("deactivate grant");
    node_a
        .invalidate_sync(user_id)
        .await
        .expect("node A's acknowledged invalidate must succeed");

    let still_stale = node_b
        .resolve(user_id)
        .await
        .expect("node B ordinary resolve");
    assert!(
        still_stale.privileges.contains(&key),
        "an ordinary resolve must not itself pay the strict epoch check"
    );

    let corrected = node_b
        .resolve_strict(user_id)
        .await
        .expect("node B resolve_strict");
    assert!(
        !corrected.privileges.contains(&key),
        "resolve_strict must see the revoke via the epoch counter even though this node's own L1 was never purged"
    );
}

/// Goal (b): a grant/revoke handler must 500, never 200, when the epoch bump
/// itself couldn't be confirmed — modeled here by pointing the coordination
/// pool at an address nothing listens on (`.connect()` without
/// `.wait_for_connect()` so pool construction itself doesn't panic; the
/// first real command against it runs out our own 300ms fail-closed timeout,
/// same as it would during a real coordination-Redis outage).
#[tokio::test]
async fn invalidate_sync_fails_when_the_coordination_pool_is_unreachable() {
    let db = skip_if_no_db!(test_db().await);
    let redis = test_redis().await;
    let (user_id, _key) = seed_direct_grant(&db).await;

    let dead_config = RedisConfig::from_url("redis://127.0.0.1:1/0").expect("parse dead url");
    let dead_pool = Builder::from_config(dead_config)
        .build_pool(1)
        .expect("build dead pool");
    dead_pool.connect();

    let cache = SecurityCache::new(db.clone(), redis, dead_pool);
    let result = cache.invalidate_sync(user_id).await;
    assert!(
        result.is_err(),
        "invalidate_sync must fail, not silently succeed, when the epoch bump can't be confirmed"
    );
}

// ── Test #21: revocation across nodes and cache failures ──────────────────────
//
// The remaining scenarios in this section close out the cross-node/cache-
// failure checklist against the *unit* (`SecurityCache`) boundary rather than
// full HTTP nodes: `attome_security::strict_authz::strict_authz` — the layer
// that actually protects the admin/schema/sidebar/s2s_admin/license_admin/
// security-admin route bundles in production — is a thin wrapper that calls
// exactly `SecurityCache::resolve_strict` (see `attome-security/src/
// strict_authz.rs`), so proving the fail-closed/converge/isolation/latency
// properties here is equivalent proof for every HTTP request that goes
// through that layer. The "authenticate via node A, retry through node A/B,
// revoke through node C" shape itself — driven through real HTTP requests
// against real `system.admin` grant/role/team endpoints — is covered at
// `crates/engine/attome-server/tests/authz_revocation_cross_node.rs`, which needs
// the full `EngineSystem`/router stack this crate doesn't depend on.
//
// TODO (no existing hook — flagging per audit-system convention, not fixing
// here): there is no metrics counter/gauge for invalidation failures or
// revocation latency anywhere in the codebase (checked `attome-server`'s and
// `attome-server`'s `metrics.rs`) — today the only signal is the `tracing::warn!`
// calls in `cache.rs`. "Measure the actual worst-case revocation time and
// alert if invalidation fails" is only half-satisfiable: this file measures
// the latency (`invalidate_sync_acknowledged_latency_is_bounded` below), but
// there is nothing to assert against for the alerting half until an
// operational metric is added.
//
// Also out of scope here, same as `metadata_cache.rs`'s header note: actually
// stopping/restarting a *live* Redis process (rather than pointing a pool at
// an address nothing listens on) is a manual `docker compose` exercise per
// `/release-and-deploy`, not something faked with test-only hooks that don't
// exist on `SecurityCache` today.

/// "Stop or partition Redis during revocation. Confirm privileged operations
/// fail closed. Restore Redis and confirm caches converge." A dead
/// coordination pool (the exact trick
/// `invalidate_sync_fails_when_the_coordination_pool_is_unreachable` uses)
/// models the partition; a separate, live-pool `SecurityCache` models a node
/// whose coordination-Redis connectivity is healthy (in production, the same
/// node once its connection has been restored — fred pools reconnect
/// automatically) to prove convergence, not just failure.
#[tokio::test]
async fn coordination_redis_partition_fails_closed_then_converges_after_restore() {
    let db = skip_if_no_db!(test_db().await);
    let live_redis = test_redis().await;
    let (user_id, key) = seed_direct_grant(&db).await;

    let cache = SecurityCache::new(db.clone(), live_redis.clone(), live_redis.clone());
    let warm = cache.resolve(user_id).await.expect("warm resolve");
    assert!(warm.privileges.contains(&key));

    let dead_config = RedisConfig::from_url("redis://127.0.0.1:1/0").expect("parse dead url");
    let dead_pool = Builder::from_config(dead_config)
        .build_pool(1)
        .expect("build dead pool");
    dead_pool.connect();
    let partitioned = SecurityCache::new(db.clone(), live_redis.clone(), dead_pool);
    let during_partition = partitioned.resolve_strict(user_id).await;
    assert!(
        during_partition.is_err(),
        "resolve_strict must fail closed while the coordination Redis is unreachable, got {during_partition:?}"
    );

    // A revoke lands from "another node" (its own coordination pool is
    // healthy) while the partition above is in effect.
    sqlx::query("UPDATE user_account_mm_privilege SET is_active = false WHERE user_ref = $1")
        .bind(user_id)
        .execute(&db)
        .await
        .expect("deactivate grant");
    let other_node = SecurityCache::new(db.clone(), live_redis.clone(), live_redis.clone());
    other_node
        .invalidate_sync(user_id)
        .await
        .expect("other node's invalidate_sync (its coordination Redis is reachable)");

    // Once (this node's) coordination-Redis connectivity is healthy again,
    // the very next resolve_strict must see the revoke and self-correct.
    let restored = cache
        .resolve_strict(user_id)
        .await
        .expect("resolve_strict once coordination Redis is reachable again");
    assert!(
        !restored.privileges.contains(&key),
        "post-restore resolve_strict must reflect the revoke that happened during the partition"
    );
}

/// "Confirm unrelated users are unaffected." The epoch counter's key shape
/// (`xrm:authz_epoch:{user_id}`) is per-user by construction, but this proves
/// it: a revoke for one user must not bump another user's epoch or disturb
/// their cached entry.
#[tokio::test]
async fn invalidate_sync_does_not_affect_an_unrelated_users_cache_or_epoch() {
    let db = skip_if_no_db!(test_db().await);
    let redis = test_redis().await;
    let (user_a, key_a) = seed_direct_grant(&db).await;
    let (user_b, key_b) = seed_direct_grant(&db).await;

    let cache = SecurityCache::new(db.clone(), redis.clone(), redis.clone());
    let warm_a = cache.resolve(user_a).await.expect("warm A");
    let warm_b = cache.resolve(user_b).await.expect("warm B");
    assert!(warm_a.privileges.contains(&key_a));
    assert!(warm_b.privileges.contains(&key_b));

    cache
        .invalidate_sync(user_a)
        .await
        .expect("revoke path for user A only");

    let still_b = cache
        .resolve_strict(user_b)
        .await
        .expect("user B resolve_strict after user A's revoke");
    assert!(
        still_b.privileges.contains(&key_b),
        "an unrelated user's privileges must be untouched by another user's revocation"
    );
    assert_eq!(
        still_b.epoch, warm_b.epoch,
        "user B's epoch counter must not be bumped by user A's invalidate_sync"
    );
}

/// "Measure the actual worst-case revocation time" for the synchronous,
/// acknowledged path — the exact call `strict_authz` blocks a privileged
/// request on (epoch INCR + L2 DEL, each individually bounded by
/// `EPOCH_OP_TIMEOUT`/`OP_TIMEOUT` = 300ms/200ms). No alerting hook exists
/// yet to wire this into (see the module TODO above) — this at least gives
/// an operator a number to look at and a regression tripwire.
#[tokio::test]
async fn invalidate_sync_acknowledged_latency_is_bounded() {
    let db = skip_if_no_db!(test_db().await);
    let redis = test_redis().await;
    let (user_id, _key) = seed_direct_grant(&db).await;
    let cache = SecurityCache::new(db.clone(), redis.clone(), redis.clone());
    cache.resolve(user_id).await.expect("warm");

    let started = std::time::Instant::now();
    cache
        .invalidate_sync(user_id)
        .await
        .expect("invalidate_sync");
    let elapsed = started.elapsed();

    eprintln!("invalidate_sync acknowledged latency: {elapsed:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "invalidate_sync took {elapsed:?}, exceeding the 2s local-test bound — \
         investigate before assuming production revocation is fast"
    );
}

/// Regression: `ensure_privilege` used to be SELECT-then-INSERT with no guard
/// between the two statements, so concurrent callers seeding the same key both
/// missed the read and both inserted — the loser got a raw
/// `uq_core_privilege_key` violation surfaced as an opaque `Internal` error
/// out of a helper documented as idempotent. Observed live 2026-08-10 as a
/// `build EngineSystem` failure when two seeds overlapped.
///
/// Fans out N concurrent calls for one fresh key and asserts all of them
/// succeed AND agree on a single id — the second half matters as much as the
/// first, since an `ON CONFLICT DO NOTHING` that forgot its follow-up read
/// would still "succeed" while handing different callers different answers.
#[tokio::test]
async fn ensure_privilege_is_race_safe_under_concurrent_callers() {
    const CALLERS: usize = 12;

    // A dedicated pool: `test_db`'s 5 connections would serialize most of the
    // fan-out, which is exactly the interleaving this test needs to exercise.
    let db = skip_if_no_db!(attome_testkit::migrated_pool(CALLERS as u32).await);

    let key = format!("race_probe_{}.read", Uuid::now_v7().simple());

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..CALLERS {
        let db = db.clone();
        let key = key.clone();
        tasks.spawn(async move {
            ensure_privilege(
                &db,
                &key,
                "Race Probe",
                "concurrency regression fixture",
                attome_core::changeset::Layer::Project,
            )
            .await
        });
    }

    let mut ids = Vec::with_capacity(CALLERS);
    while let Some(joined) = tasks.join_next().await {
        let id = joined
            .expect("ensure_privilege task must not panic")
            .expect("every concurrent ensure_privilege call must succeed, not lose a race");
        ids.push(id);
    }

    assert_eq!(ids.len(), CALLERS);
    let first = ids[0];
    assert!(
        ids.iter().all(|id| *id == first),
        "all concurrent callers must observe one privilege id, got {ids:?}"
    );

    // And exactly one row actually landed.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM privilege WHERE key = $1")
        .bind(&key)
        .fetch_one(&db)
        .await
        .expect("count probe rows");
    assert_eq!(rows, 1, "exactly one privilege row must exist for {key}");
}

// ── resolve_all_entity_access_levels (D-140 follow-up / F-002, TODO-007) ──────
//
// `resolve_all_entity_access_levels` was written by mechanically generalizing
// `resolve_entity_access_level`'s query — joining `entity_info` and
// grouping by entity instead of filtering to one — and carried a
// `TODO(needs a live Postgres)` saying its join condition, `GROUP BY` shape,
// and empty-result case had never been run against a database. These two
// tests are that verification. They matter beyond tidiness: this function
// feeds `polymorphic_audit_predicate`'s per-row access map, so a wrong join
// here is a silent record-level-security defect on the audit list path.

/// Provisions a **real, uniquely-named throwaway** entity through the same
/// `attome_metadata::provision` path the server runs at boot, ensures its
/// `{logicalname}.{action}` privilege keys exist, and returns
/// `(entity_id, logicalname, privilege_id)` for the requested action.
///
/// Two earlier shapes of this helper were both wrong, and the reasons are
/// worth keeping:
///
///  1. **Fabricating a bare `entity_info` row** (the first version)
///     reads as the more hermetic choice and is the opposite: an entity row
///     whose *physical table does not exist* breaks `EngineSystem::build` with
///     `relation "test_ent_…" does not exist`, because boot loads the entity
///     registry. Entity metadata is not throwaway state on its own — it is
///     metadata with a table behind it, and only provisioning creates both.
///  2. **Borrowing an already-seeded entity via `SELECT`** (the second
///     version) then fixed that by never writing metadata at all — but it
///     assumed a *seeded* database. `attome-testkit`'s per-binary clone (D-343)
///     is MIGRATED, never seeded: `entity_info` and
///     `privilege` are both empty in the `attomedb_test` template,
///     so the `SELECT` matched nothing and both tests failed on every
///     migration-only database, everywhere it ran.
///
/// `ensure_entity` resolves both objections at once: it inserts the metadata
/// row *and* calls `provision_table`, so the physical table backing it really
/// exists and the registry can load it. `ensure_entity_privileges` then
/// creates the grantable `{logicalname}.{action}` keys for all four
/// `ENTITY_ACTIONS` — creating a key grants it to nobody, so this widens no
/// access. Nothing needs cleaning up: the whole database is a per-binary
/// clone that is dropped when the binary exits.
async fn provision_entity_with_privilege(db: &DbPool, action: &str) -> (Uuid, String, Uuid) {
    // `unique_logicalname` (not `unique`) — the hyphens `unique` produces are
    // rejected by `valid_identifier`. 18-char prefix + 12 hex fits the
    // 48-char `MAX_IDENTIFIER_LEN` with room to spare.
    let logicalname = attome_testkit::unique_logicalname("test_sec_resolver");

    let entity_id = attome_metadata::provision::ensure_entity(
        db,
        &logicalname,
        "Resolver Test Entity",
        None,
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("provision throwaway entity {logicalname}: {e}"));

    ensure_entity_privileges(db, &logicalname, attome_core::changeset::Layer::Project)
        .await
        .unwrap_or_else(|e| panic!("ensure privileges for {logicalname}: {e}"));

    let key = format!("{logicalname}.{action}");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1 AND is_active = true")
            .bind(&key)
            .fetch_one(db)
            .await
            .unwrap_or_else(|e| {
                panic!("ensure_entity_privileges must have created privilege {key}: {e}")
            });

    (entity_id, logicalname, privilege_id)
}

async fn grant_privilege_to_role(db: &DbPool, role_id: Uuid, privilege_id: Uuid) {
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway role privilege grant");
}

async fn set_role_entity_depth(db: &DbPool, role_id: Uuid, entity_id: Uuid, read_depth: i16) {
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
         (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, $4, $4, $4, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(read_depth)
    .execute(db)
    .await
    .expect("insert throwaway role entity-access depth");
}

async fn seed_bare_user(db: &DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// The bulk resolver must agree, entity for entity, with the single-entity
/// resolver it was generalized from — across an explicit depth, the
/// "privilege held but no depth row" default, a `None` depth, and the
/// cross-role `MAX` that the `GROUP BY logicalname, entity_ref` exists to
/// produce. Agreement with the already-tested function is the strongest
/// available statement that the generalization is faithful; the absolute
/// values are asserted too, so a matching pair of wrong answers still fails.
#[tokio::test]
async fn bulk_entity_access_levels_agree_with_the_single_entity_resolver() {
    let db = skip_if_no_db!(test_db().await);

    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;

    // Every call provisions its own fresh entity, so no two of these can
    // collide and there is nothing to track as "already taken".

    // Explicit Team depth.
    let (team_entity, team_name, team_priv) = provision_entity_with_privilege(&db, "read").await;
    grant_privilege_to_role(&db, role_id, team_priv).await;
    set_role_entity_depth(&db, role_id, team_entity, 1).await;

    // Privilege held, no `role_mm_entity_access` row at all — D-133's
    // zero-behavior-change default of Global, which the query spells as the
    // `COALESCE(..., 3::smallint)` over a LEFT JOIN.
    let (default_entity, default_name, default_priv) =
        provision_entity_with_privilege(&db, "read").await;
    grant_privilege_to_role(&db, role_id, default_priv).await;

    // Explicit None depth — must appear in the map as `None`, which is NOT
    // the same as being absent (absent means "no privilege at all", and
    // `polymorphic_audit_predicate` treats the two differently).
    let (none_entity, none_name, none_priv) = provision_entity_with_privilege(&db, "read").await;
    grant_privilege_to_role(&db, role_id, none_priv).await;
    set_role_entity_depth(&db, role_id, none_entity, 0).await;

    // Same entity reachable through two roles at different depths: the
    // `GROUP BY` + `MAX(depth)` must pick the more permissive one.
    let (max_entity, max_name, max_priv) = provision_entity_with_privilege(&db, "read").await;
    grant_privilege_to_role(&db, role_id, max_priv).await;
    set_role_entity_depth(&db, role_id, max_entity, 0).await;
    let second_role = seed_role(&db).await;
    link_user_to_role(&db, user_id, second_role).await;
    grant_privilege_to_role(&db, second_role, max_priv).await;
    set_role_entity_depth(&db, second_role, max_entity, 2).await;

    // Decoy 1: the privilege exists and is granted, but for `update`, not
    // `read` — a Read resolve must not return it. This is what pins the
    // `p.key = ei.logicalname || $2` suffix half of the join condition. Its
    // own entity, so the `.read` key that also exists on it is never granted.
    let (_update_entity, update_name, update_priv) =
        provision_entity_with_privilege(&db, "update").await;
    grant_privilege_to_role(&db, role_id, update_priv).await;

    // Decoy 2: a `read` privilege on an entity this user is never granted —
    // pins the grant half of the join (the user/role path), not just the key.
    let (_ungranted_entity, ungranted_name, _ungranted_priv) =
        provision_entity_with_privilege(&db, "read").await;

    let map = resolve_all_entity_access_levels(&db, user_id, RecordAction::Read)
        .await
        .expect("bulk entity access-level resolution must succeed");

    let expected = [
        (&team_name, team_entity, AccessLevel::Team),
        (&default_name, default_entity, AccessLevel::Global),
        (&none_name, none_entity, AccessLevel::None),
        (&max_name, max_entity, AccessLevel::BusinessUnit),
    ];
    for (name, entity_id, level) in expected {
        let (got_ref, got_level) = *map
            .get(name.as_str())
            .unwrap_or_else(|| panic!("{name} must be present in the bulk map: {map:?}"));
        assert_eq!(got_ref, entity_id, "{name} resolved the wrong entity_ref");
        assert_eq!(got_level, level, "{name} resolved the wrong access level");

        // …and the single-entity resolver must independently say the same.
        let single = resolve_entity_access_level(&db, user_id, entity_id, name, RecordAction::Read)
            .await
            .expect("single-entity access-level resolution must succeed");
        assert_eq!(
            single, got_level,
            "bulk and single-entity resolvers disagree on {name}"
        );
    }

    assert!(
        !map.contains_key(update_name.as_str()),
        "an entity granted only `.update` must not appear in a Read resolve — \
         the privilege-key join is not suffix-correct: {map:?}"
    );
    assert!(
        !map.contains_key(ungranted_name.as_str()),
        "an entity whose read privilege this user was never granted must not \
         appear: {map:?}"
    );
}

/// The empty-result case the function's TODO called out by name: a user with
/// zero role and zero direct grants. The query must return no rows and the
/// function must hand back an empty map rather than erroring or defaulting to
/// anything permissive — `polymorphic_audit_predicate` turns an absent entry
/// into "exclude the row", so a spurious entry here would be a leak.
#[tokio::test]
async fn bulk_entity_access_levels_is_empty_for_a_user_with_no_grants() {
    let db = skip_if_no_db!(test_db().await);

    let user_id = seed_bare_user(&db).await;
    // An entity with a live read privilege exists in the database, just not
    // granted to this user — so an empty result proves the grant join filters,
    // rather than merely proving the table was empty. On a migration-only
    // database that entity has to be provisioned here; nothing seeds one.
    let (_entity_id, logicalname, _priv_id) = provision_entity_with_privilege(&db, "read").await;

    let map = resolve_all_entity_access_levels(&db, user_id, RecordAction::Read)
        .await
        .expect("bulk resolution must succeed for a user with no grants");

    assert!(
        map.is_empty(),
        "a user with no role and no direct grants must resolve to an empty \
         map (an ungranted entity {logicalname} exists in the database): {map:?}"
    );
}

// ── resolve_default_share_entities (D-357) ───────────────────────────────────
//
// The hoist in `polymorphic_audit_predicate` moved the entity-default-share
// allow-check out of the generated per-row SQL and into this resolver. That
// makes the resolver the enforcement point for a decision that used to be
// made by a subquery whose semantics were pinned by `rls.rs`'s own tests — so
// the four properties that subquery had must now be asserted here, against a
// real `entity_default_share` table:
//
//   1. a user-principal (type 0) allow row matches;
//   2. a team-principal (type 1) allow row matches, via the caller's teams;
//   3. a `deny` (capability 2) row NEVER matches — the range is bounded above
//      at 1, so deny can never satisfy an allow-check (D-133 (4));
//   4. a row belonging to some other principal entirely never matches.
//
// Property 3 is the security-critical one: a bare `capability >= $required`
// here would silently turn every deny row into a grant.

/// A bare `entity_info` row — enough to satisfy
/// `entity_default_share.entity_ref`'s foreign key, which is all the
/// default-share resolver reads.
///
/// Deliberately NOT `provision_entity_with_privilege`: that helper also
/// creates a physical table and four privilege keys, and takes the metadata
/// write lock to do it. This test needs five entities and none of that
/// machinery, and taking the lock five times makes the test lose a race
/// against any sibling suite provisioning an entity of its own ("a metadata
/// write is already in progress"). Direct inserts into a throwaway per-binary
/// database are the sanctioned exemption (guidelines §4, test databases).
async fn insert_bare_entity(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO entity_info (id, logicalname, name, is_active, owner_layer) \
         VALUES ($1, $2, $2, true, 'project')",
    )
    .bind(id)
    .bind(attome_testkit::unique_logicalname("test_defshare"))
    .execute(db)
    .await
    .expect("insert throwaway entity_info");
    id
}

async fn insert_default_share(
    db: &DbPool,
    entity_ref: Uuid,
    principal_type: i16,
    principal_id: Uuid,
    capability: i16,
) {
    sqlx::query(
        "INSERT INTO entity_default_share \
         (id, entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(entity_ref)
    .bind(principal_type)
    .bind(principal_id)
    .bind(capability)
    .execute(db)
    .await
    .expect("insert throwaway entity default share");
}

#[tokio::test]
async fn default_share_entities_resolves_user_and_team_allows_but_never_deny() {
    let db = skip_if_no_db!(test_db().await);

    let user_id = seed_bare_user(&db).await;
    let team_id = Uuid::now_v7();
    let other_user = seed_bare_user(&db).await;

    let user_view = insert_bare_entity(&db).await;
    let user_action = insert_bare_entity(&db).await;
    let team_view = insert_bare_entity(&db).await;
    let denied = insert_bare_entity(&db).await;
    let someone_else = insert_bare_entity(&db).await;

    // 1. user-principal view (0) and action (1) — action satisfies view.
    insert_default_share(&db, user_view, 0, user_id, 0).await;
    insert_default_share(&db, user_action, 0, user_id, 1).await;
    // 2. team-principal view.
    insert_default_share(&db, team_view, 1, team_id, 0).await;
    // 3. a deny row for this very user.
    insert_default_share(&db, denied, 0, user_id, 2).await;
    // 4. an allow row for an unrelated principal.
    insert_default_share(&db, someone_else, 0, other_user, 0).await;

    let got = resolve_default_share_entities(&db, user_id, &[team_id], 0)
        .await
        .expect("default-share resolution must succeed");

    assert!(
        got.contains(&user_view),
        "a user-principal view share must match"
    );
    assert!(
        got.contains(&user_action),
        "an action share must satisfy a view requirement (D-133 (4))"
    );
    assert!(
        got.contains(&team_view),
        "a team-principal share must match"
    );
    assert!(
        !got.contains(&denied),
        "a deny row (capability 2) must NEVER satisfy an allow-check — the \
         range is bounded above at 1, not an open `>= required`"
    );
    assert!(
        !got.contains(&someone_else),
        "another principal's share must not leak into this caller's set"
    );

    // Requiring `action` (1) drops the view-only grant but keeps the action one.
    let action_required = resolve_default_share_entities(&db, user_id, &[team_id], 1)
        .await
        .expect("default-share resolution must succeed for the action capability");
    assert!(
        !action_required.contains(&user_view),
        "a view-only share must not satisfy an action requirement"
    );
    assert!(action_required.contains(&user_action));
}

#[tokio::test]
async fn default_share_entities_is_empty_for_a_caller_with_no_shares() {
    let db = skip_if_no_db!(test_db().await);

    let user_id = seed_bare_user(&db).await;
    let other_user = seed_bare_user(&db).await;
    let entity_id = insert_bare_entity(&db).await;
    // A default share exists in the table, just not for this caller — so an
    // empty result proves the principal filter works rather than that the
    // table was empty.
    insert_default_share(&db, entity_id, 0, other_user, 0).await;

    let got = resolve_default_share_entities(&db, user_id, &[], 0)
        .await
        .expect("default-share resolution must succeed with no teams");

    assert!(
        got.is_empty(),
        "a caller with no shares and no teams must resolve to an empty set \
         (an unrelated share does exist): {got:?}"
    );
}

// ── Q10-T2: create, assign, share, export and bulk levels, and child units ──

/// A role's `role_mm_entity_access` row with the level columns these tests
/// vary spelled out (`None` leaves the assign level NULL).
#[allow(clippy::too_many_arguments)]
async fn set_role_entity_ops(
    db: &DbPool,
    role_id: Uuid,
    entity_id: Uuid,
    read: i16,
    write: i16,
    assign: Option<i16>,
    export: i16,
    read_bu_children: bool,
) {
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
         (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, \
          assign_access_level, export_access_level, read_bu_children, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(read)
    .bind(write)
    .bind(assign)
    .bind(export)
    .bind(read_bu_children)
    .execute(db)
    .await
    .expect("insert throwaway role entity-access row");
}

async fn set_bulk_field_mode(db: &DbPool, role_id: Uuid, mode: i16) {
    sqlx::query("UPDATE role SET bulk_field_mode = $2 WHERE id = $1")
        .bind(role_id)
        .bind(mode)
        .execute(db)
        .await
        .expect("set the role's D-589 bulk field mode");
}

/// Export is its own level and denied unless granted: a role created
/// through the admin API (D-589 `listed`) reads the entity everywhere but
/// exports nothing, with or without an access row. A role still in D-589
/// legacy mode keeps today's reach, its read level.
#[tokio::test]
async fn export_defaults_to_deny() {
    let db = skip_if_no_db!(test_db().await);

    let (entity_id, logicalname, read_priv) = provision_entity_with_privilege(&db, "read").await;

    // Listed role with an access row: read Global, export left at its default.
    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    set_bulk_field_mode(&db, role_id, 1).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, read_priv).await;
    set_role_entity_ops(&db, role_id, entity_id, 3, 3, None, 0, true).await;

    let read =
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Read)
            .await
            .expect("read level");
    let export =
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Export)
            .await
            .expect("export level");
    assert_eq!(read, AccessLevel::Global);
    assert_eq!(export, AccessLevel::None, "export must default to deny");

    // Listed role with no access row at all: D-133's Global default still
    // holds for read, never for export.
    let bare_user = seed_bare_user(&db).await;
    let bare_role = seed_role(&db).await;
    set_bulk_field_mode(&db, bare_role, 1).await;
    link_user_to_role(&db, bare_user, bare_role).await;
    grant_privilege_to_role(&db, bare_role, read_priv).await;
    assert_eq!(
        resolve_entity_access_level(&db, bare_user, entity_id, &logicalname, RecordAction::Read)
            .await
            .expect("read level"),
        AccessLevel::Global
    );
    assert_eq!(
        resolve_entity_access_level(
            &db,
            bare_user,
            entity_id,
            &logicalname,
            RecordAction::Export
        )
        .await
        .expect("export level"),
        AccessLevel::None,
        "a role without an access row must not export"
    );

    // A legacy role (the default for existing roles) exports as far as it reads.
    let legacy_user = seed_bare_user(&db).await;
    let legacy_role = seed_role(&db).await;
    link_user_to_role(&db, legacy_user, legacy_role).await;
    grant_privilege_to_role(&db, legacy_role, read_priv).await;
    set_role_entity_ops(&db, legacy_role, entity_id, 1, 1, None, 0, true).await;
    assert_eq!(
        resolve_entity_access_level(
            &db,
            legacy_user,
            entity_id,
            &logicalname,
            RecordAction::Export
        )
        .await
        .expect("export level"),
        AccessLevel::Team,
        "a D-589 legacy role keeps exporting at its read level"
    );
}

/// A NULL assign level means the write level; a set one wins. Assign is a
/// write, so it counts the role's `update` privilege.
#[tokio::test]
async fn assign_falls_back_to_write_level() {
    let db = skip_if_no_db!(test_db().await);

    let (entity_id, logicalname, update_priv) =
        provision_entity_with_privilege(&db, "update").await;

    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, update_priv).await;
    set_role_entity_ops(&db, role_id, entity_id, 3, 1, None, 0, true).await;

    for action in [
        RecordAction::Assign,
        RecordAction::Share,
        RecordAction::Create,
    ] {
        let level = resolve_entity_access_level(&db, user_id, entity_id, &logicalname, action)
            .await
            .expect("level");
        if action == RecordAction::Assign {
            assert_eq!(level, AccessLevel::Team, "assign must fall back to write");
        } else {
            // Share and create are gated by their own privileges, which this
            // role does not hold.
            assert_eq!(
                level,
                AccessLevel::None,
                "{action:?} needs its own privilege"
            );
        }
    }

    sqlx::query("UPDATE role_mm_entity_access SET assign_access_level = 2 WHERE role_ref = $1")
        .bind(role_id)
        .execute(&db)
        .await
        .expect("set the assign level");
    assert_eq!(
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Assign)
            .await
            .expect("assign level"),
        AccessLevel::BusinessUnit,
        "a set assign level wins over the write level"
    );
    assert_eq!(
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Update)
            .await
            .expect("update level"),
        AccessLevel::Team,
        "the write level itself is unchanged"
    );
}

async fn seed_org(db: &DbPool, parent: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO organization (id, name, organization_ref, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("test-org-{id}"))
    .bind(parent)
    .execute(db)
    .await
    .expect("insert throwaway organization");
    id
}

/// Business-unit read with child units off sees its own unit's records and
/// not the child unit's; update and delete on the same role still reach the
/// child unit, because their flags are on. The predicate runs against real
/// rows, in a temporary table on one connection.
#[tokio::test]
async fn bu_only_excludes_child_unit_records() {
    let db = skip_if_no_db!(test_db().await);

    let parent = seed_org(&db, None).await;
    let child = seed_org(&db, Some(parent)).await;
    let user_id = seed_bare_user(&db).await;
    sqlx::query("UPDATE user_account SET organization_ref = $2 WHERE id = $1")
        .bind(user_id)
        .bind(parent)
        .execute(&db)
        .await
        .expect("set the home unit");

    let (entity_id, logicalname, read_priv) = provision_entity_with_privilege(&db, "read").await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, read_priv).await;
    for action in ["update", "delete"] {
        let id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
            .bind(format!("{logicalname}.{action}"))
            .fetch_one(&db)
            .await
            .expect("the entity's privilege exists");
        grant_privilege_to_role(&db, role_id, id).await;
    }
    set_role_entity_ops(&db, role_id, entity_id, 2, 2, None, 0, false).await;

    let ctx = attome_security::resolve_uncached(&db, user_id)
        .await
        .expect("resolve the context");
    assert!(
        ctx.accessible_org_ids.contains(&child),
        "the walk still reaches the child unit: {:?}",
        ctx.accessible_org_ids
    );
    assert_eq!(ctx.unit_scope.own_org_ids, vec![parent]);
    let level =
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Read)
            .await
            .expect("read level");
    assert_eq!(level, AccessLevel::BusinessUnit);

    let mut conn = db
        .acquire()
        .await
        .expect("one connection for the temp table");
    sqlx::query(
        "CREATE TEMP TABLE q10_rows (id uuid, organization_ref uuid, owner_ref uuid, owner_type smallint)",
    )
    .execute(&mut *conn)
    .await
    .expect("create the temp table");
    let in_parent = Uuid::now_v7();
    let in_child = Uuid::now_v7();
    sqlx::query("INSERT INTO q10_rows (id, organization_ref) VALUES ($1, $2), ($3, $4)")
        .bind(in_parent)
        .bind(parent)
        .bind(in_child)
        .bind(child)
        .execute(&mut *conn)
        .await
        .expect("insert the rows");

    let visible = |capability| {
        attome_security::rls_predicate(&ctx, entity_id, "t", level, capability, 1)
            .expect("a BusinessUnit tier filters")
    };

    let read = visible(attome_security::rls::Capability::View);
    let sql = format!("SELECT t.id FROM q10_rows t WHERE true {}", read.sql);
    let rows: Vec<Uuid> =
        attome_security::bind_rls_predicate(sqlx::query_scalar(&sql), &read.binds)
            .fetch_all(&mut *conn)
            .await
            .expect("run the read predicate");
    assert_eq!(rows, vec![in_parent], "read must not reach the child unit");

    let write = visible(attome_security::rls::Capability::Action);
    let sql = format!(
        "SELECT t.id FROM q10_rows t WHERE true {} ORDER BY t.id",
        write.sql
    );
    let rows: Vec<Uuid> =
        attome_security::bind_rls_predicate(sqlx::query_scalar(&sql), &write.binds)
            .fetch_all(&mut *conn)
            .await
            .expect("run the write predicate");
    assert_eq!(
        rows,
        vec![in_parent, in_child],
        "update and delete keep their child units"
    );
}

// ── Q15-T1: masked field-security grants ──

async fn grant_profile_field(
    db: &DbPool,
    role_id: Uuid,
    field: &str,
    can_update: bool,
    mask: Option<&str>,
) {
    let profile = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO field_security_profile (id, name, owner_layer) VALUES ($1, $2, 'project')",
    )
    .bind(profile)
    .bind(format!("test-profile-{profile}"))
    .execute(db)
    .await
    .expect("insert throwaway profile");
    sqlx::query(
        "INSERT INTO field_security_profile_field \
         (profile_ref, entity_logicalname, field_logicalname, can_read, can_update, mask_format, owner_layer) \
         VALUES ($1, 'q15_account', $2, true, $3, $4, 'project')",
    )
    .bind(profile)
    .bind(field)
    .bind(can_update)
    .bind(mask)
    .execute(db)
    .await
    .expect("insert throwaway profile field");
    sqlx::query(
        "INSERT INTO role_mm_field_security_profile (role_ref, profile_ref, owner_layer) VALUES ($1, $2, 'project')",
    )
    .bind(role_id)
    .bind(profile)
    .execute(db)
    .await
    .expect("assign the profile to the role");
}

/// A masked grant resolves to a mask and to neither a read nor a write
/// grant (even when its row says can_update); a full grant from another
/// profile wins over a mask; of two masks the less revealing one wins.
#[tokio::test]
async fn field_mask_grants_resolve_into_the_context() {
    let db = skip_if_no_db!(test_db().await);
    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;

    grant_profile_field(&db, role_id, "card", true, Some("last4")).await;
    grant_profile_field(&db, role_id, "email", false, Some("email")).await;
    grant_profile_field(&db, role_id, "email", false, Some("full")).await;
    grant_profile_field(&db, role_id, "iban", false, Some("last4")).await;
    grant_profile_field(&db, role_id, "iban", true, None).await;

    let ctx = attome_security::resolve_uncached(&db, user_id)
        .await
        .expect("resolve the context");
    assert_eq!(
        ctx.field_masks.get("q15_account.card").map(String::as_str),
        Some("last4")
    );
    assert!(!ctx.field_grants.contains("q15_account.card"));
    assert!(
        !ctx.field_write_grants.contains("q15_account.card"),
        "a masked field cannot be updated, whatever its row says"
    );
    assert_eq!(
        ctx.field_masks.get("q15_account.email").map(String::as_str),
        Some("full"),
        "the less revealing mask wins"
    );
    assert!(
        !ctx.field_masks.contains_key("q15_account.iban"),
        "a full grant wins"
    );
    assert!(ctx.field_grants.contains("q15_account.iban"));
}

/// The mask PostgreSQL computes in the projection is the mask Rust computes,
/// for every format, so a read path and a mutation path show the same text.
#[tokio::test]
async fn field_mask_sql_matches_the_rust_mask() {
    use attome_core::field_mask::MaskFormat;
    let db = skip_if_no_db!(test_db().await);
    let values = [
        "4111111111111111",
        "123",
        "ahmed@example.com",
        "not-an-email",
        "@example.com",
        "+966501234567",
        "أحمدالسالم",
        "",
    ];
    for name in MaskFormat::ALL {
        let format = MaskFormat::parse(name).unwrap();
        let sql = format!("SELECT {} FROM (VALUES ($1::text)) v(c)", format.sql("c"));
        for value in values {
            let masked: Option<String> = sqlx::query_scalar(&sql)
                .bind(value)
                .fetch_one(&db)
                .await
                .expect("run the mask");
            assert_eq!(
                masked.as_deref(),
                Some(format.apply(value).as_str()),
                "{name} of {value:?}"
            );
        }
        let null: Option<String> = sqlx::query_scalar(&sql)
            .bind(None::<String>)
            .fetch_one(&db)
            .await
            .expect("run the mask");
        assert_eq!(null, None, "{name} keeps NULL");
    }
}

// ── Q10-T4: permission sets ──

/// A set granting `privilege_id`, with its own access row on `entity_id`
/// whose export level is `export`, assigned to `user_id` until `ends_at`.
async fn assign_permission_set(
    db: &DbPool,
    user_id: Uuid,
    entity_id: Uuid,
    privilege_id: Uuid,
    export: i16,
    ends_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Uuid {
    let set_id = Uuid::now_v7();
    sqlx::query("INSERT INTO permission_set (id, name) VALUES ($1, $2)")
        .bind(set_id)
        .bind(format!("test-set-{set_id}"))
        .execute(db)
        .await
        .expect("insert throwaway permission set");
    sqlx::query("INSERT INTO permission_set_privilege (set_ref, privilege_ref) VALUES ($1, $2)")
        .bind(set_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("grant the privilege to the set");
    sqlx::query(
        "INSERT INTO permission_set_entity_access (set_ref, entity_ref, export_access_level) \
         VALUES ($1, $2, $3)",
    )
    .bind(set_id)
    .bind(entity_id)
    .bind(export)
    .execute(db)
    .await
    .expect("insert the set's access row");
    sqlx::query(
        "INSERT INTO permission_set_assignment (set_ref, user_ref, ends_at, reason) \
         VALUES ($1, $2, $3, 'test')",
    )
    .bind(set_id)
    .bind(user_id)
    .bind(ends_at)
    .execute(db)
    .await
    .expect("assign the set");
    set_id
}

/// A role that reads an entity but may not export it gains export from a
/// permission set, which adds to the role like one more role would.
#[tokio::test]
async fn permission_set_adds_export() {
    let db = skip_if_no_db!(test_db().await);
    let (entity_id, logicalname, read_priv) = provision_entity_with_privilege(&db, "read").await;
    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    set_bulk_field_mode(&db, role_id, 1).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, read_priv).await;
    set_role_entity_ops(&db, role_id, entity_id, 3, 3, None, 0, true).await;

    let export = |db: DbPool, name: String| async move {
        resolve_entity_access_level(&db, user_id, entity_id, &name, RecordAction::Export)
            .await
            .expect("export level")
    };
    assert_eq!(
        export(db.clone(), logicalname.clone()).await,
        AccessLevel::None
    );

    assign_permission_set(&db, user_id, entity_id, read_priv, 2, None).await;
    assert_eq!(
        export(db.clone(), logicalname.clone()).await,
        AccessLevel::BusinessUnit,
        "the set adds its export level"
    );
    assert_eq!(
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Read)
            .await
            .expect("read level"),
        AccessLevel::Global,
        "the role's read level is not lowered by the set"
    );

    // A privilege the user holds only through a set counts too.
    let (other_entity, other_name, other_priv) =
        provision_entity_with_privilege(&db, "update").await;
    assign_permission_set(&db, user_id, other_entity, other_priv, 0, None).await;
    let privileges = resolve_privileges(&db, user_id).await.expect("privileges");
    assert!(
        privileges.contains(&format!("{other_name}.update")),
        "{privileges:?}"
    );
}

/// An assignment whose end date has passed gives nothing.
#[tokio::test]
async fn expired_assignment_is_ignored() {
    let db = skip_if_no_db!(test_db().await);
    let (entity_id, logicalname, update_priv) =
        provision_entity_with_privilege(&db, "update").await;
    let user_id = seed_bare_user(&db).await;
    let ended = chrono::Utc::now() - chrono::Duration::hours(1);
    assign_permission_set(&db, user_id, entity_id, update_priv, 3, Some(ended)).await;

    let privileges = resolve_privileges(&db, user_id).await.expect("privileges");
    assert!(
        !privileges.contains(&format!("{logicalname}.update")),
        "an ended assignment grants no privilege: {privileges:?}"
    );
    assert_eq!(
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Update)
            .await
            .expect("update level"),
        AccessLevel::None
    );

    // The same set without an end date does grant.
    let live_user = seed_bare_user(&db).await;
    let future = chrono::Utc::now() + chrono::Duration::days(1);
    assign_permission_set(&db, live_user, entity_id, update_priv, 3, Some(future)).await;
    assert!(
        resolve_privileges(&db, live_user)
            .await
            .expect("privileges")
            .contains(&format!("{logicalname}.update"))
    );
}

/// A set can never carry system administration, even when a row says so.
#[tokio::test]
async fn permission_set_never_grants_system_admin() {
    let db = skip_if_no_db!(test_db().await);
    let (entity_id, _, _) = provision_entity_with_privilege(&db, "read").await;
    // Boot seeds `system.admin`; a migrated test database may not have it.
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \n         VALUES ($1, 'system.admin', 'System Admin', true, NOW(), 'platform') \n         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .execute(&db)
    .await
    .expect("ensure system.admin");
    let admin_priv: Uuid = sqlx::query_scalar(
        "SELECT id FROM privilege WHERE key = 'system.admin' AND is_active = true",
    )
    .fetch_one(&db)
    .await
    .expect("system.admin exists");
    let user_id = seed_bare_user(&db).await;
    assign_permission_set(&db, user_id, entity_id, admin_priv, 0, None).await;
    let privileges = resolve_privileges(&db, user_id).await.expect("privileges");
    assert!(!privileges.contains("system.admin"), "{privileges:?}");
}

// ── Q10-T10: access paths ──

/// The paths behind a level are the resolver's own rows: a direct role at
/// its level and a permission set at its level, whose MAX is the level the
/// resolver returns.
#[tokio::test]
async fn effective_access_lists_role_and_set_paths() {
    use attome_security::explain::{AccessPath, role_paths};
    let db = skip_if_no_db!(test_db().await);
    let (entity_id, logicalname, read_priv) = provision_entity_with_privilege(&db, "read").await;
    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, read_priv).await;
    set_role_entity_ops(&db, role_id, entity_id, 1, 1, None, 0, true).await;
    let set_id = assign_permission_set(&db, user_id, entity_id, read_priv, 0, None).await;

    let paths = role_paths(&db, user_id, entity_id, &logicalname, RecordAction::Read)
        .await
        .expect("paths");
    assert!(
        paths.contains(&AccessPath::Role {
            role_id,
            level: 1,
            bu_children: true
        }),
        "{paths:?}"
    );
    assert!(
        paths.contains(&AccessPath::PermissionSet { set_id, level: 3 }),
        "{paths:?}"
    );
    let level =
        resolve_entity_access_level(&db, user_id, entity_id, &logicalname, RecordAction::Read)
            .await
            .expect("level");
    assert_eq!(level, AccessLevel::Global, "the MAX of the paths");

    let none = seed_bare_user(&db).await;
    assert!(
        role_paths(&db, none, entity_id, &logicalname, RecordAction::Read)
            .await
            .expect("paths")
            .is_empty()
    );
}

// ── Q10-T9: unused-privilege proposals ──

/// A role privilege a holder used recently is left alone; one nobody used
/// in 90 days gets one draft, and a second run makes no second draft.
#[tokio::test]
async fn unused_operation_gets_draft_proposal() {
    let db = skip_if_no_db!(test_db().await);
    let (_, logicalname, read_priv) = provision_entity_with_privilege(&db, "read").await;
    let update_priv: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(format!("{logicalname}.update"))
        .fetch_one(&db)
        .await
        .expect("the update privilege exists");
    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, read_priv).await;
    grant_privilege_to_role(&db, role_id, update_priv).await;

    // Read was used ten days ago; update never was.
    sqlx::query(
        "INSERT INTO privilege_usage_daily (day, user_ref, privilege_key, uses) \
         VALUES (CURRENT_DATE - 10, $1, $2, 3)",
    )
    .bind(user_id)
    .bind(format!("{logicalname}.read"))
    .execute(&db)
    .await
    .expect("record a use");

    let now = chrono::Utc::now();
    attome_security::usage::propose_unused(&db, now)
        .await
        .expect("propose");
    let drafts: Vec<String> = sqlx::query_scalar(
        "SELECT privilege_key FROM privilege_removal_proposal \
         WHERE role_ref = $1 AND status = 'draft' ORDER BY privilege_key",
    )
    .bind(role_id)
    .fetch_all(&db)
    .await
    .expect("drafts");
    assert_eq!(drafts, vec![format!("{logicalname}.update")]);

    attome_security::usage::propose_unused(&db, now)
        .await
        .expect("propose again");
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM privilege_removal_proposal WHERE role_ref = $1")
            .bind(role_id)
            .fetch_one(&db)
            .await
            .expect("count");
    assert_eq!(count, 1, "one draft per role and privilege");
}

// ── Q14-T3: controlled by parent ──

/// A throwaway entity row and its plain table with the columns the record
/// filter reads, plus `extra` columns.
async fn bare_entity_table(db: &DbPool, prefix: &str, extra: &str) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let name = attome_testkit::unique_logicalname(prefix);
    sqlx::query(
        "INSERT INTO entity_info (id, logicalname, name, is_active, owner_layer) \
         VALUES ($1, $2, $2, true, 'project')",
    )
    .bind(id)
    .bind(&name)
    .execute(db)
    .await
    .expect("insert throwaway entity_info");
    sqlx::query(&format!(
        "CREATE TABLE \"{name}\" (id uuid PRIMARY KEY, organization_ref uuid, owner_ref uuid, \
         owner_type smallint{extra})"
    ))
    .execute(db)
    .await
    .expect("create throwaway entity table");
    (id, name)
}

/// A person who can read an account (through a Team-level role and a share
/// of that account) reads the contacts controlled by it, and not the
/// contacts of an account they cannot read, without holding any level of
/// their own on contacts.
#[tokio::test]
async fn controlled_by_parent_reader_of_the_account_reads_its_contacts() {
    use attome_security::parent_access;
    use attome_security::rls::{Capability, rls_predicate};

    let db = skip_if_no_db!(test_db().await);
    let (account, account_name) = bare_entity_table(&db, "q14t3_account", "").await;
    let (contact, contact_name) =
        bare_entity_table(&db, "q14t3_contact", ", account_ref uuid").await;
    let lookup = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attribute_info (id, entity_ref, logicalname, \"type\", lookup_entity_ref, \
         is_active, owner_layer) VALUES ($1, $2, 'account_ref', 11, $3, true, 'project')",
    )
    .bind(lookup)
    .bind(contact)
    .bind(account)
    .execute(&db)
    .await
    .expect("insert the lookup attribute");

    // Read on accounts at Team level; nothing at all on contacts.
    let privilege = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \
         VALUES ($1, $2, 'Read accounts', true, NOW(), 'project')",
    )
    .bind(privilege)
    .bind(format!("{account_name}.read"))
    .execute(&db)
    .await
    .expect("insert the account read privilege");
    let user_id = seed_bare_user(&db).await;
    let role_id = seed_role(&db).await;
    link_user_to_role(&db, user_id, role_id).await;
    grant_privilege_to_role(&db, role_id, privilege).await;
    set_role_entity_depth(&db, role_id, account, 1).await;

    let (shared, unshared) = (Uuid::now_v7(), Uuid::now_v7());
    for id in [shared, unshared] {
        sqlx::query(&format!("INSERT INTO \"{account_name}\" (id) VALUES ($1)"))
            .bind(id)
            .execute(&db)
            .await
            .expect("insert an account");
    }
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 0)",
    )
    .bind(shared)
    .bind(account)
    .bind(user_id)
    .execute(&db)
    .await
    .expect("share one account");
    let (visible, hidden) = (Uuid::now_v7(), Uuid::now_v7());
    for (id, parent) in [(visible, shared), (hidden, unshared)] {
        sqlx::query(&format!(
            "INSERT INTO \"{contact_name}\" (id, account_ref) VALUES ($1, $2)"
        ))
        .bind(id)
        .bind(parent)
        .execute(&db)
        .await
        .expect("insert a contact");
    }

    let links = parent_access::resolve(&db, &[(contact, lookup)])
        .await
        .expect("resolve the parent link");
    assert_eq!(links.len(), 1, "the lookup resolves");
    // A lookup that is not this entity's is left out.
    assert!(
        parent_access::resolve(&db, &[(account, lookup)])
            .await
            .expect("resolve")
            .is_empty()
    );
    parent_access::install(links);

    let level =
        resolve_entity_access_level(&db, user_id, contact, &contact_name, RecordAction::Read)
            .await
            .expect("resolve the level");
    assert_eq!(level, AccessLevel::Team, "the level on the account");

    let ctx = attome_server::security::SecurityContext {
        user_id,
        is_admin: false,
        privileges: Default::default(),
        field_grants: Default::default(),
        field_write_grants: Default::default(),
        field_masks: Default::default(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: Default::default(),
        role_ids: None,
        unit_scope: Default::default(),
        service_principal: false,
    };
    let pred = rls_predicate(&ctx, contact, "c", level, Capability::View, 1)
        .expect("a Team level filters");
    let sql = format!(
        "SELECT c.id FROM \"{contact_name}\" c WHERE TRUE {} ORDER BY c.id",
        pred.sql
    );
    let seen: Vec<Uuid> =
        attome_security::rls_fragment::bind_rls_predicate(sqlx::query_scalar(&sql), &pred.binds)
            .fetch_all(&db)
            .await
            .expect("run the filter");
    parent_access::install([]);
    assert_eq!(
        seen,
        vec![visible],
        "only the contact of the readable account"
    );
}

// ── Q15-T5: the view log ──

/// A full read handed to the view log reaches `field_view_log` on the next
/// flush, with who, what and when.
#[tokio::test]
async fn view_log_read_is_logged_on_flush() {
    use attome_security::view_log::{ViewEntry, flush, record};
    let db = skip_if_no_db!(test_db().await);
    let (user_id, record_id) = (Uuid::now_v7(), Uuid::now_v7());
    let viewed_at = chrono::Utc::now();
    record(
        &db,
        vec![ViewEntry {
            user_id,
            entity: "q15t5_employee".into(),
            record_id,
            attribute: "salary".into(),
            viewed_at,
        }],
    )
    .await
    .expect("buffer the read");
    assert!(flush(&db).await.expect("flush") >= 1);
    let logged: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT user_ref, entity_logicalname, attribute_logicalname FROM field_view_log \
         WHERE record_id = $1",
    )
    .bind(record_id)
    .fetch_all(&db)
    .await
    .expect("read the log");
    assert_eq!(
        logged,
        vec![(user_id, "q15t5_employee".to_owned(), "salary".to_owned())]
    );
}

// ── Q12-T2: delegated administrators ──

/// A delegated administrator (an area privilege, not `system.admin`) is
/// refused on a person who holds `system.admin`, directly or through a role,
/// and allowed on anyone else; a full administrator is allowed on everyone.
#[tokio::test]
async fn delegated_admin_never_acts_on_a_full_admin() {
    use attome_security::delegation::{holds_system_admin, require_not_above};
    let db = skip_if_no_db!(test_db().await);
    // The throwaway database may not hold the seeded privilege.
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer)          VALUES ($1, 'system.admin', 'System administration', true, NOW(), 'platform')          ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .execute(&db)
    .await
    .expect("ensure system.admin");
    let admin_privilege: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(&db)
            .await
            .expect("system.admin is seeded");
    let (direct, through_role, ordinary) = (
        seed_bare_user(&db).await,
        seed_bare_user(&db).await,
        seed_bare_user(&db).await,
    );
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(direct)
    .bind(admin_privilege)
    .execute(&db)
    .await
    .expect("grant system.admin directly");
    let role = seed_role(&db).await;
    grant_privilege_to_role(&db, role, admin_privilege).await;
    link_user_to_role(&db, through_role, role).await;

    for (user, expected) in [(direct, true), (through_role, true), (ordinary, false)] {
        assert_eq!(
            holds_system_admin(&db, user).await.expect("check"),
            expected
        );
    }

    let delegate = attome_server::security::SecurityContext {
        user_id: Uuid::now_v7(),
        is_admin: false,
        privileges: std::collections::HashSet::from(["admin.users".to_owned()]),
        field_grants: Default::default(),
        field_write_grants: Default::default(),
        field_masks: Default::default(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: Default::default(),
        role_ids: None,
        unit_scope: Default::default(),
        service_principal: false,
    };
    for full_admin in [direct, through_role] {
        assert!(matches!(
            require_not_above(&db, &delegate, full_admin).await,
            Err(AppError::Forbidden)
        ));
    }
    assert!(require_not_above(&db, &delegate, ordinary).await.is_ok());
    let admin = attome_server::security::SecurityContext {
        is_admin: true,
        ..delegate
    };
    assert!(require_not_above(&db, &admin, direct).await.is_ok());
}
