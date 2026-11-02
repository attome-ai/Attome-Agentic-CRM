# Leaving Attome: the clean exit

A deployment that is leaving takes all of its data with it in open formats, then deletes everything,
with a signed certificate saying so (Y5-T5). Both steps need `system.admin`.

## 1. Export

`POST /api/v1/admin/exit/export` starts the export (one at a time) and answers its id.
`GET /api/v1/admin/exit/export/{id}` shows progress; once `done` it gives the archive's SHA-256, its size
and a download link that works for a day. The archive, `attome-exit-<id>.zip`, holds:

| Path | What |
|---|---|
| `data/<entity>.csv` | Every row of every entity, one CSV per entity with a header row. |
| `metadata/bundle.json` | The metadata: entities, fields, views, forms, rules (`attome-bundle/v1`). |
| `audit/audit_header.csv`, `audit/audit_detail.csv` | The audit log. |
| `files/` | Every stored file, under its storage key. |
| `README.txt` | This list. |

Download it, and check its SHA-256 against the one the API reported.

## 2. Delete

`POST /api/v1/admin/exit/delete` with `{"export_id": ..., "export_sha256": ...}` asks for the deletion.
The hash must match the export's: it shows the archive was fetched and checked. The deletion then waits
for **two administrators other than the one asking** to approve it in the approvals inbox; nothing is
deleted before that.

Within five minutes of the second approval, the deployment deletes every stored file (the archive
included) and empties every table but `exit_export` and the migration ledger. Then it writes the
**deletion certificate**: the export's id, hash and size, how many tables and files were deleted, the
audit chain's final hash, who asked and who approved, signed with the audit signing key, whose public
key is inside it. Since nobody can sign in afterwards, the certificate is also written to the object
store as `exit/<id>/deletion-certificate.json`.

Nothing can undo the deletion. Keep the archive and the certificate.

What to do with the archive, reading its files and loading them into plain PostgreSQL or another
system: [the exit guide](content/exit/README.md).
