//! Z3-T6: every cache is declared. Guidelines §5 asks each cache for its
//! source of truth, key, TTL, invalidation, failure and cold-start story;
//! this census holds them in one table and fails when production code builds
//! a cache in a file the table does not name, or when a named file no longer
//! builds one. A new cache adds its row here with those answers, read from
//! its own doc comment.
//!
//! What counts as building a cache: `create_hot_cache(`, `MetadataCache::new(`,
//! `moka::`, `Cache::builder(`, `TieredCache::new(` and a `CacheSpec {`
//! literal, in production code (a file's `#[cfg(test)] mod` and `tests/` are
//! skipped) outside `attome-cache`, which defines them. A `TieredCache`
//! validates its `CacheSpec` when it is built (`TieredCache::new` refuses an
//! invalid one), so the table needs no second check for those.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const NEEDLES: &[&str] = &[
    "create_hot_cache(",
    "MetadataCache::new(",
    "moka::",
    "Cache::builder(",
    "TieredCache::new(",
    "CacheSpec {",
];

/// (file, cache, source of truth, TTL, invalidation, failure, cold start).
type Declared = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const DECLARED_CACHES: &[Declared] = &[
    (
        "crates/engine/attome-audit/src/policy_resolver.rs",
        "attome-audit:policy:{entity}",
        "PostgreSQL audit_config",
        "60 s",
        "the writing node drops its L1 and Redis entry; other nodes wait for the TTL",
        "audit everything on any database or Redis error",
        "empty; the first write per entity loads",
    ),
    (
        "crates/engine/attome-billing/src/tax.rs",
        "billing tax rates",
        "PostgreSQL region_tax_rate",
        "5 min",
        "TaxRateCache::invalidate on the writing node; other nodes wait for the TTL",
        "a failed load is returned and not cached",
        "the first call loads",
    ),
    (
        "crates/engine/attome-core/src/state.rs",
        "EngineState entities, settings, labels, state_models, relationships, rules",
        "PostgreSQL metadata tables and their change logs",
        "none: arc-swap snapshots",
        "change-log doorbells (Redis and Postgres NOTIFY) plus the watermark and settings polls",
        "keep serving the last snapshot; catch-up retries on the next signal",
        "pre-warmed at boot from the Redis snapshot or a full rebuild",
    ),
    (
        "crates/engine/attome-core/src/state.rs",
        "EngineState audit_users ({user_id}:audit)",
        "PostgreSQL user_account",
        "60 s",
        "AUDIT_USER_VERSION_CHANNEL doorbell on a user update or delete",
        "a database error is not cached; the audit row degrades to the id",
        "empty",
    ),
    (
        "crates/engine/attome-core/src/state.rs",
        "EngineState rule_compiled ({rule_id}:{version})",
        "the rules snapshot and the entity schema",
        "none: keyed by version, evicted by capacity",
        "a new rule version is a new key",
        "a miss recompiles; never a wrong answer",
        "empty",
    ),
    (
        "crates/engine/attome-core/src/state.rs",
        "EngineState feature_flags ({flag_key}:{user_id})",
        "the settings snapshot",
        "30 s",
        "invalidate_feature_flags plus FEATURE_FLAG_VERSION_CHANNEL",
        "a miss evaluates from settings",
        "empty",
    ),
    (
        "crates/engine/attome-marketing/src/address_check.rs",
        "marketing:mx:{domain}",
        "the domain's DNS MX records",
        "24 h",
        "none; DNS changes show after the TTL",
        "a Redis error looks the domain up uncached; an unknown answer is not cached",
        "empty",
    ),
    (
        "crates/engine/attome-marketing/src/tracking/collect.rs",
        "tracked sites by site key",
        "PostgreSQL marketing_tracked_site",
        "60 s, at most 10,000 keys",
        "none; an edited site applies within the TTL on every node",
        "a failed read is returned and not cached; an unknown key is cached as absent",
        "empty; the first batch for a site reads it",
    ),
    (
        "crates/engine/attome-portal/src/cache.rs",
        "attome-portal:portal and attome-portal:plan",
        "PostgreSQL portal tables",
        "TTL_SECS",
        "every portal-admin write replaces the Redis access version, so every node misses next; \
         a webportal write drops portal entries through the change feed (Z3-T8: two TieredCaches)",
        "a Redis error or absent version bypasses the cache for that request",
        "empty; a missing version key is created on first read",
    ),
    (
        "crates/engine/attome-records/src/business_rules.rs",
        "br:{rule_id}:{row_version}:{types}:cond",
        "the business-rule rows",
        "24 h",
        "a new row_version is a new key",
        "a miss recompiles",
        "empty",
    ),
    (
        "crates/engine/attome-records/src/query_exec.rs",
        "records:query_repeat:{user_id}:{change position}:{request hash}",
        "the stored query's tables, read with the caller's access",
        "5 s",
        "the entity change feed's newest id is in the key",
        "process-local only; no position runs the query",
        "empty; bounded at 64 MiB",
    ),
    (
        "crates/engine/attome-search/src/access_cache.rs",
        "search access map {user_id}:{epoch}",
        "PostgreSQL role_mm_entity_access and the privilege grants",
        "60 s",
        "a grant change bumps the user's epoch, so the next request uses a new key",
        "a miss resolves from the source",
        "empty",
    ),
    (
        "crates/engine/attome-security/src/cache.rs",
        "security:ctx (SecurityContext)",
        "PostgreSQL roles, grants and memberships",
        "60 s, L1 and Redis",
        "invalidate plus the authz doorbell carrying the user id; the D-116 epoch for strict checks",
        "a Redis error degrades to L1 and the database",
        "empty",
    ),
    (
        "crates/foundation/attome-server/src/state.rs",
        "AppState secrets (SecretRings)",
        "the configuration's key rings",
        "none: an arc-swap snapshot",
        "replaced when the configuration reloads",
        "the last loaded rings stay",
        "built from the configuration at start",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("the workspace root")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target"
                || name == "tests"
                || name == "fuzz"
                || name == "attome-cache"
                || name.starts_with('.')
            {
                continue;
            }
            rust_sources(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

fn production_lines(text: &str) -> Vec<&str> {
    // Every line outside a `#[cfg(test)] mod` block. A file may hold a test
    // module before more production code (query_exec.rs does), so a block is
    // skipped to its closing brace rather than ending the scan.
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let opens_test_mod = lines[i].trim() == "#[cfg(test)]"
            && lines
                .get(i + 1)
                .is_some_and(|next| next.trim_start().starts_with("mod "));
        if !opens_test_mod {
            out.push(lines[i]);
            i += 1;
            continue;
        }
        let mut depth = 0i64;
        let mut opened = false;
        i += 1;
        while i < lines.len() {
            depth += lines[i].matches('{').count() as i64;
            depth -= lines[i].matches('}').count() as i64;
            opened |= lines[i].contains('{');
            i += 1;
            if opened && depth <= 0 {
                break;
            }
        }
    }
    out
}

fn builds_a_cache(text: &str) -> bool {
    production_lines(text).iter().any(|line| {
        let code = line.split("//").next().unwrap_or_default();
        NEEDLES.iter().any(|needle| code.contains(needle))
    })
}

/// Every production file under `crates/` that builds a cache.
fn files_with_caches() -> BTreeSet<String> {
    let root = workspace_root();
    let mut sources = Vec::new();
    rust_sources(&root.join("crates"), &mut sources);
    sources
        .into_iter()
        .filter(|path| {
            path.components().any(|c| c.as_os_str() == "src")
                && std::fs::read_to_string(path).is_ok_and(|text| builds_a_cache(&text))
        })
        .map(|path| {
            path.strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn every_cache_is_declared() {
    let found = files_with_caches();
    let declared: BTreeSet<String> = DECLARED_CACHES
        .iter()
        .map(|row| row.0.to_string())
        .collect();
    let undeclared: Vec<&String> = found.difference(&declared).collect();
    let stale: Vec<&String> = declared.difference(&found).collect();
    assert!(
        undeclared.is_empty(),
        "these files build a cache with no DECLARED_CACHES row: {undeclared:?}. Add one with its \
         source of truth, TTL, invalidation, failure and cold start (guidelines §5)."
    );
    assert!(
        stale.is_empty(),
        "these DECLARED_CACHES files no longer build a cache: {stale:?}. Remove their rows."
    );
}

#[test]
fn every_row_answers_every_question() {
    for row in DECLARED_CACHES {
        let (file, name, source, ttl, invalidation, failure, cold) = *row;
        for (what, answer) in [
            ("cache", name),
            ("source of truth", source),
            ("TTL", ttl),
            ("invalidation", invalidation),
            ("failure", failure),
            ("cold start", cold),
        ] {
            assert!(!answer.trim().is_empty(), "{file}: {what} is empty");
        }
    }
}
