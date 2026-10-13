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
    BULK_ACTION, ENTITY_ACTIONS, ensure_entity_privileges, rename_entity_privileges,
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
    assert_eq!(count, ENTITY_ACTIONS.len() as i64 + 1);
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
    assert_eq!(count_again, ENTITY_ACTIONS.len() as i64 + 1);
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
