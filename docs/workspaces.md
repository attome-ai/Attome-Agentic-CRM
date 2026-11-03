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

Every call needs the data-model administration area. Making and discarding a workspace are audited
as configuration changes.

Working inside a workspace, publishing it to live with conflicts checked, sample and masked data,
idle expiry and the picker in the web app follow in the next releases (roadmap T5-T3 to T5-T7).
