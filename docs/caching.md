# Caching

PostgreSQL is the source of truth. A cache only saves work, and every cache in Attome is built the
same way: a `CacheSpec` declaration and a `TieredCache` that reads it (`attome_cache::spec`,
`attome_cache::tiered`). Do not build a cache any other way (a bare `moka` cache, a `HashMap` behind a
lock, a Redis key read by hand). The census test fails when you do.

## Adding a cache

1. Declare it in a `static CacheSpec` next to the code that reads it. The declaration answers
   everything a reviewer asks of a cache:

   | Field | What it says |
   |---|---|
   | `name` | `crate:purpose`, lower case, unique in the process. Every key is `crate:purpose:id`. |
   | `source_of_truth` | The table or computation a value comes from. |
   | `ttl`, `jitter_pct` | How long an entry lives, spread by up to `jitter_pct` percent (at most 50) so entries written together do not expire together. A TTL of zero is refused. |
   | `l1_capacity` | The most entries the in-process tier holds. |
   | `partition` | Whose value an entry is (see [Partitions](#partitions)). |
   | `sensitivity` | Where a value may be kept (see [Sensitivity](#sensitivity)). |
   | `failure` | What a read does when the shared store is down (see [Failure](#failure)). |
   | `invalidation` | What removes a stale entry. |
   | `cold_start` | What an empty cache does, and `warm_on_start` if it is filled at start. |

2. Build it with `TieredCache::new(&SPEC, store)`. `store` is the shared store, or `None` for a cache
   that stays in the process. `new` refuses an invalid declaration.
3. Read it with `get_or_load(id, loader)`, or `get_or_load_for(reader, id, loader)` for a partitioned
   cache. Drop an entry with `invalidate(id)` (`invalidate_for` when partitioned).
4. Add the cache's row to the census, `crates/apps/attome/tests/cache_registry.rs`: the file, the cache,
   its source of truth, TTL, invalidation, failure and cold start, as its declaration states them.

## Tiers

A read tries the in-process tier (L1, moka) first, then the shared store (Redis, or the in-process
store on a single server), then the loader. On the way back it fills the tiers it missed. Concurrent
reads of one key on one node share a single load.

## Partitions

- `Shared`: the same value for every caller. Read with `get_or_load`.
- `PerUser`: keyed by the user id.
- `PerSession`: keyed by the session id.
- `PerPermissionSet`: keyed by the reader's permission fingerprint. This is the only partition that
  may hold rows filtered by permissions, and only rows filtered by privileges and field security. Rows
  filtered by record ownership depend on the user, so they are `PerUser`.

## Sensitivity

- `Plain`: may be stored in Redis as it is.
- `EncryptedInRedis`: sealed with `cache.encryption_key` (AES-256-GCM, tagged with the key id) before
  it reaches Redis. A value that does not open, from a key rotated out or a foreign writer, counts as a
  miss and is logged at `warn`. Over Redis such a cache refuses to start without the key.
- `LocalOnly`: never leaves process memory.

## Failure

- `FallBackToSource`: when the shared store fails, the loader runs. The cache logs a `warn`
  `cache.redis_degraded` at most once a minute.
- `FailClosed`: the read is refused with `503 overloaded`. Use this for security controls, such as
  replay prevention and revocation, which must not pass when they cannot check.

## Invalidation by dependency

A value read through `get_or_load_depending` is recorded under the entities and records it was
computed from (`Dependency::of_write(entity, record_id)` names both). When one of them is written, the
change-feed bus drops the value on every node.

## Warm start and quotas

- `with_warm(loader)` lets a cache fill its L1 at start. A cache whose spec says `warm_on_start`, and
  which its owner registers with `register_warm`, is warmed when the server starts, within a shared time
  budget.
- `with_quota(bytes)` bounds the L1 by the serialized size of its entries rather than their count, so
  one engine's or one extension's cache cannot grow past its share of memory.

## Watching and purging

Every read counts `cache_requests_total{cache, tier, result}`, where `tier` is `l1`, `redis` or
`source` and `result` is `hit`, `miss` or `error`. An entry pushed out by the capacity or the quota
counts `cache_evictions_total{cache}`, and `cache_entries{cache}` is the L1 size.

Administrators see each cache's entries, hit rate and evictions under **Admin > Caches**, or at
`GET /api/v1/admin/caches`. The numbers are for the server that answered; each server counts its own.
`POST /api/v1/admin/caches/{name}/purge` drops one key (`{"key": "..."}`) or the whole cache. The purge
is audited and reaches every server through a PostgreSQL notification sent in the audit's
transaction. A whole-cache purge, or a purge of a partitioned key, clears the in-process tier. A shared
key is also deleted from the shared store. No route ever returns a cached value.

## Aggregate cache

A dashboard data definition can ask to keep its result (AA11-T1):

```json
{ "source": "deal", "measures": [{ "aggregation": "sum", "field": "amount" }],
  "group": { "field": "status" },
  "cache": { "refresh": "on_change", "max_age_seconds": 300 } }
```

The result is stored in PostgreSQL (`aggregate_cache`), keyed by a hash of the definition, the
timezone, the exact statement the caller would run and every value bound to it. The caller's record
filter is part of that statement, so two people share an entry only when they would get the same
answer; people who see only their own, their team's or their unit's records never share. Anyone with
condition grants always runs the statement live. Lookup bucket names are read for each caller and
never stored.

`on_change` (the default) uses an entry while it is younger than `max_age_seconds` (60 to 86,400) and
the entity has not changed since it was computed: the `aggregate_cache_marks` job reads the change
feed every 30 seconds and marks each changed entity, so a change shows within about 30 seconds.
`scheduled` uses an entry until it is `max_age_seconds` old, whatever changed. Entries older than a day
are deleted. A failed cache read or write is logged and the aggregate runs live. Hits and misses
count `aggregate_cache_total{outcome}`.
