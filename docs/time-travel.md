# Time travel

An entity can keep every earlier version of its records, so you can read a record as it stood at
any moment and put an earlier version back. It is off for every entity until an administrator
switches it on; while it is off nothing extra is stored or done.

## Switching it on

`GET /api/v1/admin/time-travel/{entity}` shows the settings and `PUT` the same path saves them
(`If-Match` with the `row_version` read, `"0"` the first time; needs the data-model privilege):

```json
{ "enabled": true, "retention_days": 365 }
```

`retention_days` (1 to 36,500) is how long a version is kept after it was replaced; leave it out to
keep versions for ever. Switching on creates the entity's history table, `<entity>__history`,
partitioned by month, with twelve months of partitions ahead; the partition job keeps that lead and
drops the months older than the retention, except while a legal hold names the entity or one of
its records. Switching off stops keeping new versions and keeps the ones already kept. The entity's
logical name may have at most 45 characters. Each change of these settings is an audited
configuration change.

## What is kept

Before an update or a delete changes a record, the record as it stands, every column, is copied
into the history table in the same transaction: a write that fails keeps nothing. Each version is
valid from the time it was written (its `modified_at`, else `created_at`) until the write that
replaced it. Versions start when time travel is switched on; nothing earlier is reconstructed (for
the field changes recorded before that, use the record's history, `GET /api/v1/{entity}/{id}/history`).

## Reading a record as it was

`GET /api/v1/{entity}/{id}?as_of=2026-10-01T09:00:00Z` answers the version valid at that moment.
The person needs to be able to read the record as it is now; the old version is then shown exactly
as a current read would show it, with the same fields hidden or masked for them. A moment before
the earliest kept version answers 404, and `as_of` on an entity without time travel 422.

## Putting an earlier version back

`POST /api/v1/{entity}/{id}/restore-version` with `If-Match` and

```json
{ "as_of": "2026-10-01T09:00:00Z", "attributes": ["stage", "amount"] }
```

writes the values of that version back through the ordinary update, so validation, business rules
and the audit trail run as for any edit. Only values that differ from the current ones are written.
`attributes` narrows it to those fields; without it every field that can be restored is. Computed
fields, encrypted fields and fields the person may not read or write are never restored (422 when
named).

## Cost

Every update and delete asks whether its entity has time travel on (one primary-key lookup); an
entity with it on also writes one history row per change. The history is not part of the audit
hash chain: each change's audit event stays where it is.
