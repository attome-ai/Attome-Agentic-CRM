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
