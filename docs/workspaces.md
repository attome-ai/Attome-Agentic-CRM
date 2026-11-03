# Develop workspaces

A workspace is a place to change the model away from live: entities, fields, views, rules, roles
and the other configuration a changeset carries. It lives inside the deployment as its own
PostgreSQL schema, so making one is a single call and needs no second server.

## What a workspace holds

- **The metadata, with its rows:** every configuration table a changeset can change, and the model
  store (forms, pages, flows and the other model objects), copied from live when the workspace is
  made.
- **Every entity table, empty:** the same columns and indexes as live, with no records. Sample data
  or a masked copy of live records comes with a later release.
- **Nothing about people:** users, teams, organisations, units, positions and API keys stay shared
  with live, as do sessions, the audit trail and background jobs.

## Using it

| Call | What it does |
|---|---|
| `POST /api/v1/admin/workspaces` | Makes one: `{"name": "Sales rework", "purpose": "..."}` (name 1 to 100 characters). |
| `GET /api/v1/admin/workspaces` | Lists the workspaces not discarded, newest first (paged). |
| `GET /api/v1/admin/workspaces/{id}` | Shows one: its status, owner and how many tables it copied. |
| `DELETE /api/v1/admin/workspaces/{id}` | Discards an open workspace and drops its schema. |
| `GET /api/v1/admin/workspaces/{id}/publish` | Previews publishing: the plan against live and any conflicts. Writes nothing. |
| `POST /api/v1/admin/workspaces/{id}/publish` | Publishes it to live: `{}`, or `{"backup_ref": "..."}` on the production profile. |

Every call needs the data-model administration area, except publish, which needs the metadata
rollout privilege, as any changeset apply does. Making, discarding and publishing a workspace are
audited as configuration changes.

## Working inside one

Send any request with the header `X-Attome-Workspace: <workspace id>` and it runs inside that
workspace instead of live: entity, field and view changes, and records written, stay in the
workspace.

- Each open workspace is served by a process of its own (`attome serve --workspace <id>`),
  started by the live server on first use (ready within 30 seconds) and stopped after 15 idle
  minutes. Its database connections look in the workspace's schema first, then live's for the
  shared tables.
- The process listens on 127.0.0.1 only, runs no background jobs and accepts requests only from
  the live server that started it.
- The caller needs the data-model administration area or to own the workspace; anyone else gets
  `403`. An unknown or discarded workspace is `404`, and a header that is not a workspace id is
  `422`.

## Publishing

Making a workspace opens a changeset for it. Every metadata change made inside the workspace records
into that changeset, whatever changeset the request names.

Publishing does this:

1. It checks the live changes made since the workspace was made. A live change to an object the
   workspace also changes is a conflict, and publish is refused with `409 workspace_conflicts`.
   Retiring an entity counts as changing everything on it. The preview lists each conflict: the
   workspace's operation, the object, and the live changeset that changed it.
2. It closes the workspace's changeset.
3. It plans the changeset against live. A blocked plan is refused with `422`.
4. It queues the apply behind the same customer-test, governance and approval gates as any
   changeset apply.
5. It marks the workspace published.

If publish is refused before the close, the workspace is open again. If publish stops after the
close, call it again to resume.

Removals (the contract phase) are returned as `contract_apply_ids`. Apply them with
`POST /api/v1/admin/metadata/changesets/apply` once the rest has applied.

Discarding a workspace also abandons its changeset if it is empty.

Sample and masked data, idle expiry and the picker in the web app follow in the next releases
(roadmap T5-T5 to T5-T7).
