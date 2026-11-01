# Changing a live table

A field added, removed, renamed or retyped on an entity changes a real PostgreSQL table that
people are using. Attome makes every such change through the admin API (never a migration or
hand-written SQL), and runs it so that traffic keeps flowing. This page says how, and what an
operator can see and control while it runs.

## Three classes

Before making a change, a builder can ask how it will run:
`POST /api/v1/admin/entities/{id}/change-plan` with the proposed changes answers each one's
class and an estimate. Nothing is written.

| Class | What runs | Examples |
|---|---|---|
| **instant** | A catalogue-only change, or any change to a table at or under the inline limit | Adding an optional or required field, a choice value, a rename. `required` is enforced by the application, so it never scans the table. |
| **online** | A build that runs beside live traffic | A concurrent index; a `max_length` check added `NOT VALID` and then validated |
| **background** | A durable data-step run that rewrites values in batches | A type change, a backfill, archive-and-drop of a deleted field |

An estimate is the table's planner row count over a measured rate: the median rows per second
of the last 20 finished runs of the same kind (20,000 rows a second until anything has been
measured). An instant change estimates zero.

## Locks

DDL waits for its lock for a short `lock_timeout`, never behind a queue of other sessions. A
statement that cannot get its lock is retried four more times, after 1, 2, 4 and 8 seconds (plus
jitter). A background run that still cannot get it is put back in the queue for later. A
request gets its error. Attome never cancels or terminates another session to get a lock.

## Background runs

A background run works in batches. Each batch is sized from the load: it halves under pressure
(the last batch took over two seconds, the replica lags over ten seconds, or most connections are
busy) and pauses half a second first. In the deployment's quiet hours with no pressure it doubles,
and otherwise it keeps its size. `metadata.quiet_hours` (`"01-05"`, local time, end not included)
and `metadata.backfill_batch_max` (default 50,000) tune it.

`GET /api/v1/admin/data-step-runs/{id}` shows a run's status, rows done, the estimate and the
time left. The field's change screen polls it every five seconds.

| To | Call | What happens |
|---|---|---|
| Pause | `POST /api/v1/admin/data-step-runs/{id}/pause` | The run stops after its current batch and keeps its place. |
| Resume | `POST /api/v1/admin/data-step-runs/{id}/resume` | The run continues from where it stopped. |
| Cancel | `POST /api/v1/admin/data-step-runs/{id}/cancel` | The run stops after its current batch. A type change or delete stays half done until it is abandoned. |
| Abandon | `POST /api/v1/admin/entities/{entity}/fields/{field}/runs/{run}/abandon` | Undoes an unfinished run: drops a retype's shadow column and frees the field. |

## Renames keep the old name for 90 days

When a field is renamed, its old name stays an alias for 90 days. A request that filters,
selects or writes by the old name still works. Its response carries a `Deprecation` header and
a `Link` to the new name, so a client knows to move. After 90 days the alias is pruned and the
old name is unknown.

## A data step in a changeset

A changeset may carry a `data_step` of kind `split` between its expand and contract operations:
`{"op": "data_step", "target": {"entity": "contact"}, "args": {"kind": "split", "source":
"full_name", "targets": [{"field": "first_name", "expression": "word(full_name, 1)"}]}}`.
Applying it queues the same durable split run as `POST /api/v1/admin/entities/{id}/refactor`
(source `apply`, tied to the operation, so applying it again queues nothing); the run's progress is
at `/api/v1/admin/data-step-runs/{id}`. Two more kinds run the same way: `copy` `{"from", "to",
"only_empty"}` copies an attribute into another of the same type (only where the target is empty
unless `only_empty` is `false`), and `set_default` `{"field", "value"}` fills the empty rows of a
field, and `map_values` `{"field", "to", "map", "on_unmapped"}` replaces each stored value the map
names (in `field`, or in `to`), leaving the others as they are and, with `"on_unmapped": "report"`,
counting them on the run. `convert` is refused at plan until it has an executor. To go back, plan a rollback to an
earlier bundle version (`POST /api/v1/admin/metadata/bundles/{name}/rollback`, which shows its plan
first) or preview and switch to an earlier metadata version on the versions screen.

## Old columns go only when every node has moved on

Deleting a field, or finishing a large type change, no longer drops the old column at once. The
column is **retired**: its indexes and constraints go (so the field's own can be made again), its
`NOT NULL` and default are lifted, and it is renamed `__retired_<id>` with its values intact,
recorded in `schema_retired_column` with the metadata version current at the time. A daily job
drops it once `records.contract_period_hours` (168, a week, by default) has passed **and** every
node seen in the last day has switched to that version or a later one (`metadata_node_switch`). A
field that a computed field is built on cannot be retired; change or remove the computed field
first. A drop that fails (the table busy, a dependent object) is logged and tried the next day.

## A builder sees their own change everywhere

After a metadata write, every node catches up from the change log. It is told by a Postgres
`NOTIFY` and, with Redis, by a Redis doorbell, and it checks the change log every few seconds
in case both were missed. The builder who made the change is pinned to it for a minute. Their
next request on a node that has not caught up waits up to two seconds for it. If the node still
hasn't caught up, it answers 503 so the client retries.

## Not yet

Rehearsing a change against a configured copy of the database, and reporting its measured
time, is planned and not built.
