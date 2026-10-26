# Imports and exports

Records come into an entity from a CSV or XLSX file as an **import job**, and leave as an
**export**. Both run in the background, both apply the person's own record and field
security, and both can be read back: an exported file starts with `id` and `row_version`,
and importing it again updates exactly the records it came from, refusing any that changed
in between.

Throughput is not measured yet. The import batch sizes (2,000 rows validated and 500 applied
per transaction) and the export cap (200,000 rows) are design values; nothing here states how
many rows per second either path handles until the AA5 load measurement runs.

## An import, step by step

1. **Upload.** `POST /api/v1/{entity}/imports` with a `multipart/form-data` body: a `file`
   part (`.csv` or `.xlsx`) and an optional `options` part (JSON). The file is stored and the
   job is `uploaded`; uploading the same file to the same entity again answers the job made
   for it (200) instead of starting a second one. The upload is held to the deployment's
   request body limit (`http.max_body_bytes`, 10 MiB by default); a bigger file comes in as a
   recurring import's storage source.
2. **Stage.** The file is read (encoding detection, Excel quirks, Arabic digits, Hijri dates)
   and copied into `import_stage`, 10,000 rows per transaction, resumable from its cursor.
3. **Validate (the dry run).** Each row is mapped, its cells converted to the fields' types
   and checked with the same validator the record API uses; lookups are resolved, existing
   records matched, duplicate rules run. Nothing is written to the entity. The job gets
   `counts {create, update, skip, invalid, duplicates}` and becomes `validated`.
4. **Apply.** Valid rows are written 500 per transaction through the same create and update
   the bulk API uses. A stopped run resumes and applies every row once.
5. **Undo.** Created records are soft-deleted and updated ones restored, each only when it is
   unchanged since the import; the rest are listed in `counts.undo`.

`POST .../imports/{id}/dry-run`, `/apply`, `/undo` and `/cancel` queue each step;
`GET /api/v1/{entity}/imports` lists the jobs (an administrator's are all of them, anyone
else's their own) and `GET .../imports/{id}` shows one.

### Options

| Option | Meaning |
|---|---|
| `mapping` | `columns`: rules of `source` → `target`, `skip`, `split` (`separator`, `targets`) or `constant`. No rules maps each column to the field of the same name. `lookups`: per lookup field, `by` (`id`, `name`, `code`, `key`) and `field`. `create_missing`: a lookup value nothing holds is marked for creation instead of being an error. |
| `match_mode` | `create` (skip rows that exist), `update` (skip rows that do not), `upsert` (the default). |
| `match_columns` | The fields a row is matched on; without them a mapped `id` names the record. |
| `all_or_nothing` | Refuse to apply while any row is invalid; undo everything if a row fails. |
| `triggers_on` | Run workflow triggers and notifications for the imported rows (off by default: the change feed still records them). |
| `dry_run` | Stop after validation. |
| `schedule` | Make the job a recurring import (below). Administrators only. |
| `source_job_id` | This file fixes another job's error file. |

### Errors and the error file

A row's problems are `{field, code, message_key}`. `GET .../imports/{id}/errors` downloads the
invalid rows as CSV (UTF-8 with a byte order mark, so Excel reads Arabic): `attome_row`, the
file's columns in their original order, `error` in the reader's language (`Accept-Language`
`ar` or `en`), and an empty `fix` column. A `ui_text` label of `import.error.<code>` rewords a
message. Fix the rows and upload the file with `source_job_id`.

`GET .../imports/{id}/preview?limit=50` shows the first staged rows as mapped; every sensitive
attribute's value is masked.

### Exported files read back

An update matched by `id` uses the file's `row_version` (when it has one) as the version it
expects. A record someone changed after the export is refused with `changed_since_validation`
instead of being overwritten.

## The import policy

`GET`/`PUT /api/v1/admin/imports/policy/{entity}` (administrators; `PUT` takes `If-Match`, `0`
for a first policy):

| Field | Meaning |
|---|---|
| `max_rows` | The largest file, in rows; a bigger one fails at staging. |
| `approval_over_rows` | More staged rows than this need a second person's approval (`records.import_apply`) before applying. |
| `sensitive_needs_approval` | Mapping a sensitive attribute needs approval too (on by default). |
| `allowed_roles` | Role ids that may import; empty lets anyone who may create the entity's records. |
| `quiet_hours` | `[{"start": "22:00", "end": "06:00"}]` in the deployment's time: an apply due inside waits for the window's end. |

## Recurring imports

A job whose `options.schedule` holds `{cron, time_zone?, source}` is a template. Every minute
the server checks the templates that are due, fetches the file (`{"kind": "storage",
"location": "<object key>"}` or `{"kind": "https", "location": "<public URL>"}`, fetched through
the SSRF guard with a 60-second limit and a 50 MiB cap) and starts a new job with the
template's mapping and options. A file identical to one imported before starts nothing.

## Agents

`import.propose_mapping` proposes a field, transform and confidence for each column from five
sample values per column (never those of a column named after a sensitive field) and never
names a field the entity lacks. `import.status`, `import.error_rows` and `import.start` read
and apply jobs the agent's person could; `import.start` keeps within the agent session's daily
write limit.

## Exports

`POST /api/v1/{entity}/export` queues an export of the records the person may read, with the
columns they may read: `format` `csv`, `xlsx`, `json` or `parquet`, `columns`, `filter`,
`labels` and `split_rows`. `GET /api/v1/{entity}/export/{id}` answers its status and, when
done, a link per file part.

- Every file starts with `id` and `row_version`.
- `labels`: CSV and XLSX headers in the person's language (the attribute labels).
- Parquet: row groups of 50,000 rows, Snappy compression, every column as text.
- `split_rows` (Parquet, 1,000,000 by default): a new file part each time one fills.
- CSV and XLSX dates follow the person's calendar and digits settings; formula-like text is
  written as text.

## Warehouse export

For a data warehouse, the setting `integration.warehouse_entities` names the entities whose
record changes are exported (none by default). Every five minutes the server reads the change
feed after its own cursor (`attome-integration/warehouse-export`) and writes one Parquet file per
entity and hour of change, `warehouse/{entity}/{yyyy}/{mm}/{dd}/{HH}/{first}-{last}.parquet`:

- columns `_op` (`upsert` or `delete`), `_event_id`, `_changed_at`, `id`, `row_version` and the
  entity's attributes, every value as text; sensitive attributes are never exported;
- a record changed several times in one file appears once, as it is now; a deleted record is a
  tombstone with only its id;
- each file carries `attome.schema_version` (a hash of its columns) in its metadata.

The manifest is the table `warehouse_export_file` and its copy `warehouse/{entity}/manifest.json`.
The cursor moves only after the files are stored, and a repeated run writes the same object keys,
so a loader never sees an event twice under two names.
