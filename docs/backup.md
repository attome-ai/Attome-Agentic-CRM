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
- On the first day of each month, right after the backup, a restore drill restores it into a
  throwaway database, checks that migrations, entities and people are there, and drops it. Each
  drill appends its result, time and archive to `drills.jsonl` in the backup folder; the admin
  console shows the newest. `attome backup drill` runs one now.
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

### Erasures stay erased

Every erasure or retention purge also writes an entry to the erasure ledger, in object storage
under `erasure-ledger/`, outside the database a backup restores. After `attome restore`, the next
server start applies every ledger entry the restored database is missing (audit keys destroyed,
recovery-archive and release-report copies deleted, purged fields scrubbed) before it serves. If
the file store cannot be reached at that point the server refuses to start, so a restored database
never serves someone who was erased; start the file store and boot again. On an ordinary start an
unreadable ledger is logged and the server starts.

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

## Sandbox copies

`attome scratch create --name <database> [--from latest|<archive>]` makes a masked copy of this
deployment's database on the same PostgreSQL server (T5-T1): it restores a backup (a fresh one when
`--from` is left out) into the new database, then, before anything boots on it, masks every labelled
field (L10-T1): a Personal value becomes a fake derived from it with a key made for this copy and
never stored (the same value gets the same fake everywhere, so records still match; Arabic and
English names, Saudi and Emirati mobile numbers, ten-digit national ids, `example.invalid`
emails), a Financial value is moved to another record of the same field, and Health, Secret and
unlabelled sensitive values are cleared (a required column is faked instead, and a required
non-text column is left and listed). A field's options may name its rule:
`{"masking": "fake" | "null" | "shuffle" | "keep"}`. It then removes API keys, refresh and portal tokens,
connector OAuth tokens, SCIM tokens and pending reset, invitation and verification links, and marks
the database as a sandbox. A sandbox refuses to boot with email on unless `email.test_mode_catch_all`
is set, so it never mails a real person. `--mode sample --percent N` (1 to 99, default 10) keeps N% of the records of each customer-data
entity (every entity outside the platform layer that is not reference data, people's accounts
excepted), chosen by a hash of the id, plus every record they point at through a lookup, and
deletes the rest; platform entities and reference data are kept whole, and notes and other timeline
items of a removed record go with it. `--mode metadata` is not built yet.

`attome scratch verify --name <database>` (L10-T2) compares up to 200 records of every labelled field
between this deployment and the copy, record by record by hash, lists each field with how many
values are unchanged, and fails when a faked or cleared field still holds a source value (a shuffled
value may land on a record that held the same one, and a kept field is kept on purpose, so neither
counts).
