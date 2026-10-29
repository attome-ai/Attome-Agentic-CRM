# Contract migrations

Add first, remove later (roadmap AB8). A migration in `../migrations/` above the expand-only
baseline (0088) may only add structure: new tables, columns with defaults, indexes and grants.
`tests/migration_expand_only.rs` fails when one drops or renames a column or table, changes a
column's type or makes a column NOT NULL without a default.

Removing structure is a contract migration and lives here:

- Name it `NNNN_contract_<name>.sql`, numbered above every migration in `../migrations/`.
- List it in the release manifest with `eligible_after_days` (7 by default): the number of days
  after the release that stopped using the structure before the structure may go.
- It is applied only by `attome upgrade contract` (AB8-T7), never at boot, so a rollback to the
  previous release still finds every column and table that release reads.

## Existing migrations

Migrations 0001 to 0088 were read when the rule was introduced. None of them drops or renames a
table or column or changes a column's type; 0079 replaces a CHECK constraint on
`approval_request.status` (allowed: it widens the accepted values).

Two migrations above the baseline remove structure and were reviewed instead of moved, because
each was already committed when the rule caught it (a committed migration never changes: boot
checks its checksum). They are listed in `REVIEWED` in `tests/migration_expand_only.rs`:

- `0173_marketing_deliverability_reshape.sql` drops `marketing_deliverability_daily`,
  `marketing_dmarc_record` and `marketing_dmarc_report` only while they still have 0084's early
  shape, which no release's code reads or writes (the code already wrote 0164/0165's later
  columns), and recreates them in that later shape. No data is lost: the rollup is recomputed
  daily and no DMARC row could have been stored in the early shape.
- `0320_change_event_daily_partitions.sql` replaces `entity_change_event` with a copy partitioned
  by day on `created_at` (Y7-T3). It copies every row, then takes the old table's lock, adds the
  rows committed since the copy's snapshot, and only then drops the old table and renames the copy
  and its indexes to the old names. No row is lost. It also drops `change_consumer_applied`'s
  foreign key to the event, which a partitioned table's `(id, created_at)` key cannot carry; the
  prune job deletes a consumer's applied rows itself.
