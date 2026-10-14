//! The access-map cache (TODO-020), and the rule that keeps a results cache
//! from becoming a disclosure.
//!
//! ## Why a cache at all
//!
//! Building `access_by_entity` resolves a record-level depth for **every**
//! licensed entity — dozens of rows, one query, per request. That is fine for
//! a list page and unacceptable for typeahead, which fires per keystroke: a
//! user typing a ten-character name would rebuild the whole map ten times, and
//! the map has not changed between the first keystroke and the last.
//!
//! ## Guidelines §5 requires six properties documented. Here they are.
//!
//! | Property | Answer |
//! |---|---|
//! | **Source of truth** | PostgreSQL — `role_mm_entity_access` and the privilege grant tables, via `attome_security::resolve_all_entity_access_levels`. This cache is never authoritative. |
//! | **Key shape** | `"{user_id}:{epoch}"`. The epoch is D-116's per-user revocation counter, already carried on every `SecurityContext`. |
//! | **TTL** | 60 s, matching the authz cache's existing freshness class (D-012). Capacity-bounded at [`ACCESS_MAP_CAPACITY`] entries on attome-cache's `HotCache` (moka), which evicts on both. |
//! | **Invalidation** | By key, not by eviction: a grant change bumps the user's epoch, so the next request computes a *different key* and cannot hit the stale entry. Nothing has to remember to purge anything. |
//! | **Failure behaviour** | Degrade to the source of truth. A cache miss, an eviction, or a cold process is a slower request, never a wrong one. There is no fail-open path here because there is no decision to fail open *about* — the cache stores a resolved answer, and the absence of one means "go and resolve it". |
//! | **Cold start** | Empty. First request per user per epoch pays the resolve, exactly as today. |
//!
//! **Epoch-in-the-key is the whole design.** A TTL-only cache would serve a
//! revoked user their old access map for up to sixty seconds — a real
//! privilege-escalation window, bounded but genuine. Putting the epoch in the
//! key makes the stale entry *unreachable* rather than merely short-lived, and
//! the 60 s TTL exists only to bound memory for users who never come back.
//!
//! ## Search results are cached per caller, never per query
//!
//! A results cache keyed on the query alone would serve one caller's
//! permission-filtered results to another. That is not a subtle bug — it is
//! the single most direct way to turn a search feature into a data breach, and
//! it is an easy mistake because the query string looks like the natural key.
//!
//! [`ResultsCacheKey`] therefore **cannot be constructed without a caller and
//! an epoch**. `a_results_key_cannot_be_built_from_a_query_alone` is the test
//! §8.1 asks for.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use attome_cache::{HotCache, create_hot_cache, get_recorded};
use attome_server::security::{AccessLevel, SecurityContext};
use uuid::Uuid;

/// See the table above.
pub const ACCESS_MAP_TTL: Duration = Duration::from_secs(60);

/// Upper bound on cached maps. One entry per active `(user, epoch)` within the
/// TTL, so this only binds under an unusual burst of distinct callers — and
/// eviction there costs a re-resolve, never a wrong answer.
pub const ACCESS_MAP_CAPACITY: u64 = 10_000;

/// The `hot_cache_lookups_total{cache=...}` label for this cache.
const METRIC_NAME: &str = "search_access_map";

/// One caller's resolved access map at one epoch.
pub type AccessMap = HashMap<String, (Uuid, AccessLevel)>;

/// The cache key. Built from one `SecurityContext` so user id and epoch always
/// come from the same caller.
fn key(ctx: &SecurityContext) -> String {
    format!("{}:{}", ctx.user_id, ctx.epoch)
}

/// Process-local cache of resolved access maps.
///
/// In-process is correct here rather than a shortcut (guidelines §5): the
/// entry is a *read-only snapshot rebuildable from the source of truth*, its
/// key already encodes the invalidation signal, and no node needs to agree
/// with any other about it. Two nodes holding maps computed at the same epoch
/// hold the same map; two at different epochs are each correct for the epoch
/// they answer for.
pub struct AccessMapCache {
    inner: HotCache<Arc<AccessMap>>,
}

impl std::fmt::Debug for AccessMapCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessMapCache").finish_non_exhaustive()
    }
}

impl Default for AccessMapCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AccessMapCache {
    pub fn new() -> Self {
        Self {
            inner: create_hot_cache(ACCESS_MAP_CAPACITY, ACCESS_MAP_TTL.as_secs()),
        }
    }

    /// Returns the cached map for this caller **at this caller's epoch**, if
    /// one is present and fresh.
    ///
    /// Takes the whole `SecurityContext` rather than a user id, so a caller
    /// cannot accidentally look up one user's map with another's epoch — the
    /// two are read from one place.
    pub async fn get(&self, ctx: &SecurityContext) -> Option<Arc<AccessMap>> {
        get_recorded(&self.inner, &key(ctx), METRIC_NAME).await
    }

    /// Stores a freshly resolved map. Expiry and the capacity bound are the
    /// cache's own; nothing here sweeps.
    pub async fn put(&self, ctx: &SecurityContext, map: AccessMap) -> Arc<AccessMap> {
        let shared = Arc::new(map);
        self.inner.insert(key(ctx), Arc::clone(&shared)).await;
        shared
    }
}

/// The key a search-results cache must use.
///
/// **There is deliberately no constructor taking only a query.** A results
/// cache keyed on the query alone serves one caller's permission-filtered
/// results to another — the most direct route from "search feature" to "data
/// breach", and an easy mistake precisely because the query string looks like
/// the obvious key.
///
/// Every field is private and the only constructor requires a
/// `SecurityContext`, so caller and epoch are not something a call site can
/// forget to include.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ResultsCacheKey {
    caller: Uuid,
    /// The same epoch the access map is keyed on. A grant change therefore
    /// invalidates cached *results* too — without it, a user who just lost
    /// access would keep seeing the rows they used to be allowed.
    epoch: i64,
    normalized_query: String,
    audience: &'static str,
    page: i64,
}

impl ResultsCacheKey {
    /// The only way to build one.
    pub fn new(
        ctx: &SecurityContext,
        normalized_query: &str,
        audience: crate::router::Audience,
        page: i64,
    ) -> Self {
        Self {
            caller: ctx.user_id,
            epoch: ctx.epoch,
            normalized_query: normalized_query.to_owned(),
            audience: match audience {
                crate::router::Audience::Human => "human",
                crate::router::Audience::Agent => "agent",
            },
            page,
        }
    }

    pub fn caller(&self) -> Uuid {
        self.caller
    }

    pub fn epoch(&self) -> i64 {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ctx(user_id: Uuid, epoch: i64) -> SecurityContext {
        SecurityContext {
            user_id,
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    fn map_with(entity: &str) -> AccessMap {
        let mut m = HashMap::new();
        m.insert(entity.to_string(), (Uuid::now_v7(), AccessLevel::Team));
        m
    }

    #[tokio::test]
    async fn a_map_is_returned_for_the_same_caller_at_the_same_epoch() {
        let cache = AccessMapCache::new();
        let user = Uuid::now_v7();
        let c = ctx(user, 7);

        assert!(cache.get(&c).await.is_none(), "cold start is empty");
        cache.put(&c, map_with("account")).await;

        let hit = cache.get(&c).await.expect("a fresh entry must be returned");
        assert!(hit.contains_key("account"));
    }

    /// **The invalidation test §8.1 asks for.** A grant change bumps the
    /// caller's epoch, so the next request computes a different key and
    /// *cannot* reach the stale entry — invalidation by unreachability rather
    /// than by anyone remembering to purge.
    #[tokio::test]
    async fn bumping_the_epoch_makes_the_previous_entry_unreachable() {
        let cache = AccessMapCache::new();
        let user = Uuid::now_v7();

        cache.put(&ctx(user, 7), map_with("account")).await;
        assert!(cache.get(&ctx(user, 7)).await.is_some());

        // A grant changed. The epoch moves.
        assert!(
            cache.get(&ctx(user, 8)).await.is_none(),
            "a revoked caller must not be served the access map they had before the revocation — a TTL-only cache would leave a real privilege-escalation window open for its whole TTL"
        );
    }

    /// One caller's map is never served to another, even at the same epoch.
    #[tokio::test]
    async fn one_callers_map_is_never_served_to_another() {
        let cache = AccessMapCache::new();
        cache
            .put(&ctx(Uuid::now_v7(), 1), map_with("account"))
            .await;
        assert!(cache.get(&ctx(Uuid::now_v7(), 1)).await.is_none());
    }

    /// **The test §8.1 explicitly asks to exist: a cache keyed on the query
    /// alone must be impossible to build.**
    ///
    /// This is a compile-shaped assertion written as a test so the reasoning
    /// has somewhere to live. `ResultsCacheKey`'s fields are private and its
    /// only constructor demands a `SecurityContext`, so there is no path from
    /// a query string to a key. If someone adds `ResultsCacheKey::from_query`,
    /// this comment is what they have to argue with.
    #[test]
    fn a_results_key_cannot_be_built_from_a_query_alone() {
        let a = ResultsCacheKey::new(
            &ctx(Uuid::now_v7(), 1),
            "acme",
            crate::router::Audience::Human,
            1,
        );
        let b = ResultsCacheKey::new(
            &ctx(Uuid::now_v7(), 1),
            "acme",
            crate::router::Audience::Human,
            1,
        );
        assert_ne!(
            a, b,
            "two callers issuing the SAME query must produce different cache \
             keys — a query-keyed results cache serves one caller's \
             permission-filtered results to another"
        );
    }

    /// A results key carries the epoch too, so a grant change invalidates
    /// cached results as well as the access map. Without it a user who just
    /// lost access keeps seeing the rows they used to be allowed.
    #[test]
    fn a_results_key_changes_when_the_epoch_does() {
        let user = Uuid::now_v7();
        let before = ResultsCacheKey::new(&ctx(user, 1), "acme", crate::router::Audience::Human, 1);
        let after = ResultsCacheKey::new(&ctx(user, 2), "acme", crate::router::Audience::Human, 1);
        assert_ne!(before, after);
        assert_eq!(before.caller(), after.caller());
    }

    /// Audience and page are part of the key. An agent and a human issuing the
    /// same query get different result sets (different ceiling, floor, and
    /// limit), and serving one the other's would be wrong in both directions.
    #[test]
    fn audience_and_page_are_part_of_the_results_key() {
        let c = ctx(Uuid::now_v7(), 1);
        let human = ResultsCacheKey::new(&c, "acme", crate::router::Audience::Human, 1);
        let agent = ResultsCacheKey::new(&c, "acme", crate::router::Audience::Agent, 1);
        let page_two = ResultsCacheKey::new(&c, "acme", crate::router::Audience::Human, 2);
        assert_ne!(human, agent);
        assert_ne!(human, page_two);
    }

    /// Expired entries are not served, and the cache is bounded. The TTL
    /// bounds memory for callers who never return; the epoch is what bounds
    /// *staleness*. Expiry itself is moka's, so this pins the configuration
    /// rather than sleeping out a minute.
    #[test]
    fn the_cache_is_bounded_by_ttl_and_capacity() {
        let cache = AccessMapCache::new();
        let policy = cache.inner.policy();
        assert_eq!(policy.time_to_live(), Some(ACCESS_MAP_TTL));
        assert_eq!(policy.max_capacity(), Some(ACCESS_MAP_CAPACITY));
    }
}
