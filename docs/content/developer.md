# Developer guide

For developers who call Attome's API from another system or build on its source.

## The API

Everything the web app does goes through the HTTP API under `/api/v1`. The OpenAPI document is at
`/api/v1/openapi.json` (and in the repository as `openapi.json`); the documentation site's API
reference is generated from it. `/api/v1/openapi/deployment.json` describes this deployment's own
entities and fields.

- **Authentication**: an API key (`Authorization: Bearer <key>`), a browser session, OIDC sign-in,
  or HMAC-signed server-to-server calls for integrations.
- **Records**: `GET/POST /api/v1/{entity}`, `GET/PATCH/DELETE /api/v1/{entity}/{id}`. An update needs
  `If-Match: "<row_version>"` from the record you read; a stale version answers 409.
- **Queries**: `POST /api/v1/query/execute` runs a stored query or a view with filters, keyset
  paging (`after_id`) and an optional exact total.
- **Lists** answer `{items, total, page, page_size}` (pages start at 1); unbounded lists use a cursor
  (`next_cursor`).
- **Retries**: send `Idempotency-Key` on a create or an action; a retry with the same key gets the
  first answer.
- **Errors** are `application/problem+json` with a stable `error` code; 422 names the field.
- **Versions**: [API versions](../api-versions.md) explains `Attome-Version` and how breaking changes
  are announced; [API workflows (Arazzo)](../api/arazzo/) show common sequences.
- **Changes**: event subscriptions (webhooks, `/api/v1/admin/events`) deliver record changes to
  another system, retried and with a dead-letter list; `GET /api/v1/live` streams them to a signed-in
  client.

`attome sdk generate <deployment.json>` writes typed Rust structs and TypeScript interfaces for a
deployment's entities.

## Building from source

Rust 1.97 (pinned in `rust-toolchain.toml`) on Windows or Linux, PostgreSQL 18 with pgvector for the
database tests, Node 22 for the web app:

```sh
cargo build -p attome
cd web && npm ci && npm run build:all
attome test --changed
cargo run -p attome-release --target-dir target/gate -- --check
```

[Testing](../testing.md) explains the test tiers; [CONTRIBUTING](https://github.com/attome-ai/Attome-Agentic-CRM/blob/main/CONTRIBUTING.md)
how to send a change. [Architecture](../architecture.md) maps the crates.
