# The data layer

How the platform talks to PostgreSQL: which pool a query uses, how long it may run, what it may
retry, how a statement says where it came from, how reads follow writes, and the tests that hold
those rules.

## Pools

Each pool connects as its own role, so a query can do only what its role allows.

| Pool | Role | Used for |
|---|---|---|
| runtime (`state.base.db`) | `attome_runtime` | every request's reads and writes |
| read-only (`db_readonly`) | `attome_readonly` (`database.readonly`) | `query/execute` and other SELECT-only reads; may point at a replica (`database.readonly.host` / `.port`) |
| read-only primary | `attome_readonly` on the primary | reads that must see the newest commit |
| migrator (`db_migrator`) | `attome_migrator` (`database.migrator`) | provisioning DDL: entity tables, fields, indexes, data-step runs |
| direct | the bootstrap identity | `ensure_schema`, migrations and role-password seeds, at boot only |

Boot checks each pool's identity (`verify_pool_identity`); a pool connected as the wrong role is a
boot error, never a silent fallback. `database.pools.<pool>.max_connections` sizes each one.

## Transactions and statement classes

`attome_db::tx::begin(pool)` opens a transaction and records the wait for a connection per role.
`begin_class(pool, class, config)` also sets the class's timeouts with `SET LOCAL`:

| Class | Statement | Lock | For |
|---|---|---|---|
| `Fast` | 500 ms | 200 ms | interactive reads and small writes |
| `Standard` | 5 s | 1 s | ordinary requests |
| `Report` | 60 s | 1 s | reports and exports |
| `Admin` | 300 s | 5 s | administrative work |

Every class ends a transaction left idle by a stalled caller. A deployment overrides a class under
`database.statement_classes.<class>` with `statement_timeout_ms`, `lock_timeout_ms` and
`idle_in_transaction_timeout_ms` (each above 0). Provisioning DDL runs with no statement timeout
and the field-DDL lock bound (`set_ddl_bounds_in_tx`), so a busy table refuses the change rather
than queueing behind it.

Keep transactions short: no HTTP, Redis, object-store, email or file I/O inside one.

## Retry

`attome_db::tx::with_retry(pool, class, RetryPolicy::SHORT, |tx| ...)` runs its body in a
transaction and again in a fresh one when the body or the commit fails with a serialization
failure (`40001`) or a deadlock (`40P01`): three attempts, 10 ms then 40 ms (plus jitter) apart.
Any other error returns at once. The body must be safe to run twice and do no outside I/O; put
side effects after the call. `db_tx_retries_total` and `db_tx_retry_exhausted_total` count per
`class`.

A record write that loses an optimistic-concurrency race is not retried: a stale `If-Match` is
`409 version_conflict`, for the caller to reload.

## Locks

A lock that serialises one resource is `pg_try_advisory_xact_lock(namespace, hashtext(key))`,
held for the transaction, with the key `"{crate}/{operation}:{resource}"` and the `int4` namespace
of the crate that owns the key. The namespaces are registered in
`crates/apps/attome/tests/advisory_lock_namespaces.rs`; an id is never reused.

## Query tags

A query's text starts with a `/* class */` comment naming its source (`entity.merge`,
`query.execute`, `jobs.queue`), so `pg_stat_statements`, the slow-query log and
`pg_stat_activity` show where it came from. `attome_db::tagged_sql!("class", "...")` tags a
literal at compile time and `attome_db::tag_dynamic("class", &sql)` tags built SQL; the class is
always a `&'static str` in the code. PostgreSQL computes the query id without the comment, so a tag
never splits a statement's statistics.

## Reading your own writes

With a read replica (a read-only role on its own endpoint), a write pins its user to the primary
with the commit's WAL position (`rw_pin::pin_write_with_current_lsn`); the user's reads go to the
primary until the replica's replayed position reaches it (`AppState::read_pool`), or to the primary
for everyone while the replica lags past `database.replica_max_lag_secs`. The pin is kept in the
coordination store: Redis, or the in-process store on one server without Redis.

Without a replica every read is on the primary already, so writes skip the pin and reads skip
the lookup: one server pays nothing for it.

## Censuses

Tests that read the source and fail when a rule is broken:

| Test | Holds |
|---|---|
| `advisory_lock_namespaces` | every lock namespace registered, none reused |
| `list_shape_census` | no list handler answers a bare `Json<Vec<T>>` |
| `contract_shapes` | in `openapi.json`, errors carry `ErrorResponse` and lists are `PaginatedResponse` or `CursorPage` |
| `bounded_state` | in-process channels and caches have a size bound |
| `pooled_session_state_census` | no session-level SQL (`SET`, `LISTEN`, session advisory locks, `PREPARE`) outside reviewed files, so pgbouncer transaction mode is safe |
| `query_budget` (attome-testapp) | statement counts of hot record paths, and a list's count not growing with its page size |
| `audit_coverage_emission` | every mutating route writes the audit event it declares |
