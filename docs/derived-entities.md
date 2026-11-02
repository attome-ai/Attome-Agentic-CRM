# Derived entities

A derived entity is an entity's records that match a condition, under a name of their own: "open
deals over 100,000" over `deal`, "VIP accounts" over `account`. It is read-only: its members
change as the records do, never by writing to it (A26).

## Defining one

`PUT /api/v1/admin/derived-entities/{name}` (the data-model administration area) with:

```json
{ "anchor": "deal", "condition": "amount > 100000 and stage == \"open\"", "mode": "stored" }
```

- `anchor`: the entity whose records it selects.
- `condition`: a rule-language expression over the anchor's **own** fields. Lookups and paths
  (`account.tier`), the clock (`today()`, `now()`) and sensitive fields are refused with 422; they
  come when a compiler for them exists.
- `mode`: `live` (the default) checks the condition at every read, so membership is always
  current. `stored` keeps a membership table that follows record changes within a few seconds and
  reads fast on large entities.

`GET /api/v1/admin/derived-entities` lists them; `DELETE .../{name}` removes one (its view, its
membership table and its definition). The admin screen is **Derived entities**
(`/admin/derived-entities`).

Each one gets a database view, `xrm_dv_<name>`, with SELECT for the read-only role and no writes
for the application role: BI tools can read it like a table.

## Reading members

`GET /api/v1/{name}` and `GET /api/v1/{name}/{id}` read members like any entity's records. They go
through the anchor's own query, so the anchor's record-level security and field gates apply: a
caller needs read on the derived entity **and** on the anchor, and sees only the members they may
read. Every write (`POST`, `PATCH`, `DELETE`, hard delete, restore) answers 405.

`GET /api/v1/derived-entities/{name}/explain/{record_id}` says why a record is or is not a
member: each part of the condition (split at its top-level `and`) with whether it holds and the
record's values of the fields it reads. The caller needs read on the derived entity, the anchor
and the record.

## Before saving: preview

`POST /api/v1/admin/derived-entities/preview` with `{ "anchor", "condition", "name"? }` answers how
many records match now, up to 20 of them, and, against the saved version of `name`, how many would
enter and leave. It writes nothing.

## Stored membership

- **From the change feed.** Every few seconds a consumer re-checks the records that changed and
  moves members in and out, with a row in `derived_entity_history` for each (`enter`/`leave`, the
  reason, the time).
- **Full refresh.** Saving a stored definition fills it from the records it already has, and every
  stored one is refreshed in full nightly, 5,000 records at a time.
- **Surge guard.** A change that would move more than 10,000 members at once is not applied: the
  definition is paused, the changes are held, and every administrator is notified. Check it, then
  `POST /api/v1/admin/derived-entities/{name}/resume` applies them.
- **Over time.** `GET /api/v1/admin/derived-entities/{name}/trend?weeks=12` answers weekly entries,
  exits and members from the history.

## Acting on members

`POST /api/v1/derived-entities/{name}/mass` with `{ "kind": "update" | "delete" | "reassign",
"payload", "reason" }` runs the anchor's mass operation over the current members (up to 100,000,
taken at the start). Each record goes through its normal single-record path; large runs go to the
background, with progress, pause, cancel and undo at `/api/v1/mass/{id}`. It needs bulk on the
derived entity and on the anchor.

## Load

`loadtest/derived/run.ps1` measures how far stored membership lags behind changes at 10 changes a
second over a large anchor; the target is a p95 under 10 seconds.
