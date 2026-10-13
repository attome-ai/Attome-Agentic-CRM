# Solo storage: Redis or in-process memory (A5)

Solo runs on PostgreSQL alone. Everything the platform keeps in Redis is
reconstructable or fails closed on loss (guidelines §5), so a single server can
hold it in process memory. This document is the design; `attome-cache`'s
`MemoryStore` (`src/memory.rs`) is the engine it builds on.

## The handle

`attome_cache::Store` is a small enum:

```rust
pub enum Store {
    Redis(RedisPool),
    Memory(Arc<MemoryStore>),
}
```

Every crate that used a `RedisPool` takes a `&Store` instead. `AppState.redis`
and `AppState.redis_coordination` become `Store`. In Solo both are the same
`Memory` value; with Redis configured they are the two pools they are today.

Nothing outside `attome-cache` matches on the variant. A caller asks the store
for a *named operation* (below), and each operation has a Redis form (today's
Lua script or command) and a memory form (a closure run inside
`MemoryStore::transaction`, which holds the store lock for the whole closure and
so gives the same one-step atomicity a Lua script has).

## Configuration

`cache.backend` in the validated config: `"redis"` (default for Standard and
Cluster) or `"memory"` (default for Solo). `memory` needs no host, port or
password; a Redis block present alongside `memory` is ignored and logged once.
A multi-node deployment configured with `memory` fails at boot: process memory
is not a cross-node source of truth (guidelines §5).

## Operations and their memory equivalents

| Crate | Operation | Redis form | Memory form (one transaction) |
|---|---|---|---|
| attome-cache | `rate_limit::check` | sorted-set script: evict, count, add if under limit | `ZSet::remove_range_by_score`, `len`, `add`, `expire` |
| attome-cache | `token_window` reserve / settle / release | three scripts over a hash and a zset | same steps over `Keyspace` hash and zset |
| attome-cache | `write_coalesce` (lease, note, release) | three scripts | `set_nx` with ttl, `hincr_by`, `del` |
| attome-cache | `sticky_primary` pin | `SET` with ttl, `GET` | `set` with ttl, `get_str` |
| attome-cache | `stream_buffer` | Redis streams | per-stream `VecDeque` in the store (bounded) |
| attome-cache | `persistence` status | `INFO` | fixed `Memory` status |
| attome-s2s | `rate_limit`, `concurrency` | zset script; counter script | as the cache rate limiter; `incr_by` / `incr_by(-1)` with floor |
| attome-server | `api_usage` | hash increment script | `hincr_by` |
| attome-profiler | histogram script | hash increments | `hincr_by` |
| attome-auth | `step_up`, `mfa`, `oidc` | single-use consume scripts | `get` then `del` inside one transaction (replay guard) |
| attome (app) | `failed_login` | counter with ttl | `incr_by` plus `expire` on first hit |
| all | pub/sub (cache invalidation) | Redis channels | `MemoryStore` broadcast channels |

Security controls keep their failure mode: the memory form of replay and
revocation checks cannot fail open, because the check and the write share one
lock. A restart clears the store, exactly as a Redis restart without
persistence does; nonces, windows and pins are all short-lived by design.

## What stays Redis-only

Nothing the product needs. Operator-facing Redis features (`INFO` memory
figures, persistence status) report `memory` / not-applicable in Solo.

## Order of work

1. `Store` and the config switch in `attome-cache`; port the cache primitives
   (rate limit, token window, write coalesce, sticky primary, streams).
2. `AppState` holds `Store`; port attome-server (`api_usage`) and
   attome-profiler.
3. Port attome-s2s, attome-auth (`step_up`, `mfa`, `oidc`) and the app's
   `failed_login`.
4. Solo boot selects `Memory`; `attome init` on a machine with no Redis boots.
5. Each port carries a test that runs the same assertions against both
   variants, so the two forms cannot drift.
