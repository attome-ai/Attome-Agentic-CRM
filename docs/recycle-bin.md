# Recycle bin

Deleting a record moves it to the recycle bin: it disappears from lists, searches and lookups but
stays in its table with `is_active = false` until it is restored or purged. A permanent delete is a
separate, rarer action.

## What a delete records

Every delete writes one row to the bin's ledger (`deletion`) in the same transaction:

- who deleted it and when;
- the reason, when one was given (`DELETE /api/v1/{entity}/{id}?reason=...`);
- the operation it belonged to: its kind (`request`, `agent`, `flow`, `bulk`, `import`, `merge`,
  `portal`, `migration`) and id. A request uses its `Attome-Operation-Id` header, or else its
  request id, so a client that deletes several records under one id can undo them together.

Records removed with it by a cascade (a lookup set to cascade on delete) are tracked with the
parent and come back with it.

Before deleting, `POST /api/v1/{entity}/delete-impact` with `{"ids": [...]}` reports, without
changing anything, the records the delete would cascade to, the records that block it, the
records it would leave pointing at a deleted record, and whether a reason is required.

## Restoring

| Route | Restores |
|---|---|
| `POST /api/v1/{entity}/{id}/restore` | One record, and the dependents removed with it |
| `POST /api/v1/bin/restore` with `{"items": [{"entity", "id"}]}` | Up to 500 records |
| `POST /api/v1/bin/operations/{operation_id}/restore` | Everything one operation deleted (the list's Undo) |

Each restore needs update access to the record, as a single restore does; a selection reports
the records that could not come back and why (`not_found`, `forbidden`, `conflict`, `invalid`).
A restore whose unique value another live record now holds is a `409`; a record whose lookup
points at a deleted record is refused until that record is restored; its failure entry then
carries `parent` (entity and id) when the caller may restore that record, and the bin page offers
**Restore that record too**, which restores the parent and then the record.

`GET /api/v1/{entity}/deleted` lists an entity's deleted records the caller could read, newest
first, with each one's reason and operation.

In the app, deactivating records in a list offers **Undo** for eight seconds, and each entity's
list links to its recycle bin.

## Per-entity rules

`PUT /api/v1/admin/bin-settings/{entity}` (administrators) sets:

| Setting | Meaning |
|---|---|
| `require_reason` | A person must give a reason to delete (`422 delete_reason_required` otherwise) |
| `retention_days` | Days a deleted record stays before it is purged; `null` follows `retention.entity_purge_grace_days` |
| `alert_threshold` | Deletions by one person within ten minutes that raise an alert (default 100) |
| `hard_delete_needs_approval` | A permanent delete waits for a second person |

The entity metadata admin screen has a **Recycle bin** section for these settings. Its retention
choices are the default, 7, 30, 365 and 2,555 days; there is no "keep forever", as the route
takes 1 to 3,650 days.

Purging goes through the retention sweep (propose, approve, execute): sensitive fields are
scrubbed, the audit key destroyed, and the bin entry closed. A record under legal hold is never
purged.

## Permanent delete

`DELETE /api/v1/{entity}/{id}/hard-delete` removes the row. It needs the entity's
`{entity}.hard_delete` privilege as well as `delete` (administrators hold every privilege), is
refused while any record points at the target, and is refused for a record under legal hold, by
anyone.

When the entity's bin setting has `hard_delete_needs_approval`, the route answers `202` with
`approval_request_id` instead: the delete waits for a second administrator, and runs as that
approver once approved (approval action `record.hard_delete`, which an approval policy can also
require for any entity).

