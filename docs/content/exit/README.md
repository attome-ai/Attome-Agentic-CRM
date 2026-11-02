# Leaving Attome: the exit guide

Your data is yours. This guide takes a deployment's data out of Attome and into another system or a
plain PostgreSQL database, with no Attome software needed afterwards. The export and the deletion
that may follow it are described in [the clean exit](../../clean-exit.md); this page is what to do
with the archive.

## 1. Get the archive

An administrator (`system.admin`) runs the export:

1. `POST /api/v1/admin/exit/export` starts it and answers its `id`.
2. `GET /api/v1/admin/exit/export/{id}` shows progress. When `status` is `done` it gives `sha256`,
   `bytes` and a `download_url` that works for 24 hours.
3. Download `attome-exit-<id>.zip` and check its hash before anything else:

   ```powershell
   (Get-FileHash .\attome-exit-<id>.zip -Algorithm SHA256).Hash.ToLower()
   ```

   ```sh
   sha256sum attome-exit-<id>.zip
   ```

   The value must equal `sha256` from step 2. Keep the archive and the hash together.

Exporting changes nothing; you can export as often as you like. Deleting the deployment is a
separate step that needs two other administrators to approve it (see the clean exit).

## 2. What is in it

| Path | Format | What |
|---|---|---|
| `data/<entity>.csv` | CSV, UTF-8, header row, RFC 4180 quoting | Every row of every entity, soft-deleted rows included (`is_active` is `f` for those). |
| `metadata/bundle.json` | JSON, `attome-bundle/v1` | The data model: entities, fields and their types, choice values, lookups, views, rules, roles. |
| `audit/audit_header.csv`, `audit/audit_detail.csv` | CSV | The audit log: who changed what and when, and the field-level before and after values. |
| `files/<key>` | As uploaded | Every stored file, under the key the records hold. |
| `README.txt` | Text | A short list of the above. |

### Reading the CSV files

Every entity table has these system columns, then one column per field:

| Column | Type | Meaning |
|---|---|---|
| `id` | UUID | The record's id. Lookups in other tables hold this value. |
| `created_at`, `modified_at` | timestamp with time zone (ISO 8601) | When the record was created and last changed. |
| `created_by`, `modified_by`, `owner_ref` | UUID | Ids of rows in `user_account.csv` (or a team in `team.csv` when `owner_type` is `1`). |
| `organization_ref` | UUID | The business unit (`organization.csv`). |
| `is_active` | `t`/`f` | `f` means the record was deleted (it was in the recycle bin). |
| `row_version` | integer | The record's change counter. |
| `owner_type` | integer | `0` a user owns the record, `1` a team. |

Field values follow the field's type in `metadata/bundle.json` (`entities[].attributes[]`,
`field_type`):

| `field_type` | In the CSV |
|---|---|
| `text`, `rich_text`, `icon`, `color`, `formula` | Text (`rich_text` is sanitised HTML). |
| `number`, `currency`, `rollup` | Decimal number with a `.` point. A currency field has a `<field>_currency` companion column with the ISO 4217 code. |
| `date`, `date_time`, `time` | ISO 8601. |
| `bool` | `t` or `f`. |
| `choice` | The stored value. A multi-choice field is a PostgreSQL array, `{value1,value2}`. The labels (Arabic and English) are in the attribute's `options`. |
| `lookup` | The id of a row in the table named by `lookup_entity`. |
| `file`, `image` | The storage key: the file is at `files/<key>` in the archive. A multi-file field is a JSON array of keys. |
| `geolocation`, `json` | JSON. |

Many-to-many relationships are their own tables, each row the two linked ids; the bundle's
`relationships` say which two entities each one joins (`entity_a`, `entity_b`), and the table's CSV
has a lookup column to each.

## 3. Load into plain PostgreSQL

`scripts/exit/load-postgres.mjs` in the Attome repository writes the SQL for you: one table per CSV,
typed from the bundle, with each table's and column's display name as a comment. It needs Node 18 or
later and nothing else, and works the same on Windows, macOS and Linux.

1. Extract the archive into a folder, say `attome-exit`.
2. Generate the SQL:

   ```sh
   node scripts/exit/load-postgres.mjs attome-exit --schema attome_exit
   ```

   Add `--foreign-keys` to also declare every lookup as a foreign key (`NOT VALID`, so rows pointing
   at records deleted long ago still load; run `ALTER TABLE ... VALIDATE CONSTRAINT` later if you
   want them checked).
3. From inside the folder, create the tables and load them with `psql` (PostgreSQL 13 or later):

   ```sh
   cd attome-exit
   psql "postgresql://user@host/dbname" -v ON_ERROR_STOP=1 -f schema.sql -f load.sql
   ```

   `load.sql` uses psql's `\copy`, so the files are read from your machine; no server file access is
   needed.
4. Check the counts: `SELECT count(*) FROM attome_exit.account;` should equal the CSV's line count
   minus the header (a quoted value may span lines, so compare with a CSV-aware tool when they
   differ).

The files under `files/` stay files: put them in any file store and keep the key as the path, so
the keys in the tables still find them.

## 4. Load into another system

Most CRMs and data tools import CSV. Per entity:

1. Map the columns using the bundle: each attribute's `display_name` is the label people knew, its
   `field_type` tells you the target type, and `options` holds a choice field's values and labels.
2. Import parents before children: a lookup's `lookup_entity` must be loaded first so the child's
   lookup can be matched. Keep Attome's `id` in an external id field of the target system and match
   lookups on it.
3. Decide what to do with deleted rows (`is_active = f`): most migrations leave them out.
4. Re-attach files by key: for each `file`/`image` value, upload `files/<key>` to the matching
   record.
5. Bring the audit log only if the target can hold history; otherwise keep the two audit CSVs as
   the record of who changed what.

The data model in `bundle.json` is also what to rebuild in the new system: entities, fields,
required flags, choice lists and lookups. Rules and views are there too, as Attome expressions and
query definitions, for reference.

## 5. Afterwards

Once the new system holds the data and you have checked it, an administrator may ask Attome to
delete everything (`POST /api/v1/admin/exit/delete` with the export's id and hash). Two other
administrators approve it; then every record, file and piece of metadata is deleted, and a signed
deletion certificate, `exit/<id>/deletion-certificate.json`, records what was deleted and the audit
chain's final hash. Keep the certificate with the archive.
