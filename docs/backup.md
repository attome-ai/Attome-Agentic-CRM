# Backups

## Solo: on by default

A Solo deployment (one server, `cache.backend = "memory"`) backs up its database every day:

- At `backup.hour` (UTC, default 2) the server runs `pg_dump` in custom format into
  `backup.dir` (default: a `backups` folder next to `config.json`).
- Archives are named by their UTC time, `attome-YYYYMMDD-HHMM.dump`; the newest `backup.keep`
  (default 7) are kept.
- `attome backup now` writes one at once.
- The PostgreSQL client tools must be installed (`pg_dump`); set `backup.pg_dump` to its path
  when it is not on the PATH. Turn the backup off with `backup.enabled = false`.

The archive sits on the same disk as the database unless `backup.dir` points elsewhere. That
protects against mistakes and corruption, not against losing the disk: point `backup.dir` at a
second disk or a network share, or copy the folder off the machine.

## Restoring

Restore an archive into an empty database, then point `database.dbname` at it:

```text
createdb -U postgres attome_restored
pg_restore -U postgres --no-owner --dbname attome_restored backups/attome-20261014-0200.dump
```

## Several servers

A deployment with several servers does not run the built-in backup (each node would dump the
same database). Use pgBackRest (full weekly, differential daily, WAL archiving, point-in-time
recovery) or the backups of the managed database host.
