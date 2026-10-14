# Backups

## Solo: on by default

A Solo deployment (one server, `cache.backend = "memory"`) backs up its database and its files
every day:

- At `backup.hour` (UTC, default 2) the server runs `pg_dump` in custom format into
  `backup.dir` (default: a `backups` folder next to `config.json`).
- Archives are named by their UTC time, `attome-YYYYMMDD-HHMM.dump`; the newest `backup.keep`
  (default 7) are kept.
- Right after the database, the files in object storage (attachments, brand assets) are copied
  into `backup.dir/files/`. Only new or changed files are read again, so a daily run stays quick.
  Beside each archive, `attome-YYYYMMDD-HHMM.files.json` lists every file that backup holds with
  its size and SHA-256. A copy no kept backup lists is removed. Turn file copies off with
  `backup.files = false`.
- If the file store cannot be reached, the database backup still counts; the server logs an error
  and the next run copies the files.
- `attome backup now` writes one at once.
- The PostgreSQL client tools must be installed (`pg_dump`); set `backup.pg_dump` to its path
  when it is not on the PATH. Turn the backup off with `backup.enabled = false`.

The backup sits on the same disk as the database unless `backup.dir` points elsewhere. That
protects against mistakes and corruption, not against losing the disk: point `backup.dir` at a
second disk or a network share, or copy the folder off the machine.

## Restoring

Stop the Attome server, then:

```sh
attome restore latest --yes          # the newest archive in backup.dir
attome restore attome-20261014-0200.dump --yes
```

Without `--yes` the command only says what it would replace. Before anything changes it writes a
backup of the database (and files) as they are now, named like any other archive, then runs
`pg_restore` in one transaction: if it fails, the database is unchanged.

Then it puts back the files that archive's `.files.json` lists: each one the store is missing, or
holds at another size, is checked against its SHA-256 and written back. Files added to the store
after the backup are left in place; the restored database does not refer to them.

To restore by hand into a new database instead:

```text
createdb -U postgres attome_restored
pg_restore -U postgres --no-owner --dbname attome_restored backups/attome-20261014-0200.dump
```

## Several servers

A deployment with several servers does not run the built-in backup (each node would dump the
same database). Use pgBackRest (full weekly, differential daily, WAL archiving, point-in-time
recovery) or the backups of the managed database host, and the object store's own versioning or
replication for files.
