# Developer guide

For developers who call Attome's API from another system or build on its source.

## The API

Everything the web app does goes through the HTTP API under `/api/v1`. The OpenAPI document is at
`/api/v1/openapi.json` (and in the repository as `openapi.json`); the documentation site's API
reference is generated from it. `/api/v1/openapi/deployment.json` describes this deployment's own
entities and fields.

- **Authentication**: an API key (`Authorization: ApiKey <public id>:<secret>`), a browser session,
  OIDC sign-in, or, for integrations, server-to-server calls: HMAC-signed, or with an OAuth access
  token (`Authorization: Bearer <token>`).
- **OAuth for integrations**: `POST /api/v1/oauth/token` (form-encoded, `grant_type=client_credentials`)
  gives an S2S client a ten-minute access token for its service user. The client proves itself
  with a JWT signed by its own key (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`;
  `iss` and `sub` its client id, `aud` the deployment's JWT issuer or the endpoint's URL, `exp` at
  most five minutes ahead, a `jti` used once) or with one of its keys' secrets in
  `Authorization: Basic`. An administrator sets the client's public key and scopes with
  `PATCH /api/v1/admin/s2s/clients/{id}` (`oauth_public_key_pem`, `oauth_scopes`). Each bearer
  request is checked against the client's present state like a signed one.
- **Records**: `GET/POST /api/v1/{entity}`, `GET/PATCH/DELETE /api/v1/{entity}/{id}`. An update needs
  `If-Match: "<row_version>"` from the record you read; a stale version answers 409.
- **Queries**: `POST /api/v1/query/execute` runs a stored query or a view with filters, keyset
  paging (`after_id`) and an optional exact total. Send `Accept: application/msgpack` for a
  smaller MessagePack answer: each row is an array in the order `data.fields` names.
- **Changes since**: `POST /api/v1/query/changes` with `{entity}` answers a cursor; send it back as
  `{entity, cursor}` to get the records added or changed since (`upserted`, as you may read them
  now), the ids deleted or no longer visible to you (`removed`, id only) and the next cursor. Use
  it to keep a local copy in step without re-reading the whole list.
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

### Concurrent edits

Every record carries a `row_version`. Send it back as `If-Match` on `PATCH`; when someone else saved
the record since you read it, the update is refused with `409 version_conflict`, and the body says
what changed, so you can show the differences instead of reloading blind:

```http
PATCH /api/v1/deal/0192f0c4-7d1e-7c3a-9b1e-5d6f8a9b0c1d
If-Match: "4"
Content-Type: application/json

{"amount": 125000}
```

```json
{
  "error": "version_conflict",
  "message": "version conflict",
  "current_version": 6,
  "current_state": {
    "last_changed_by": "Sara Ahmed",
    "last_changed_at": "2026-10-19T09:12:44Z",
    "changed_attributes": [
      {"name": "amount", "their_value": 120000,
       "changed_by": "Sara Ahmed", "changed_at": "2026-10-19T09:12:44Z"},
      {"name": "stage", "their_value": "Negotiation",
       "changed_by": "Omar Ali", "changed_at": "2026-10-19T08:55:02Z"}
    ],
    "hidden_changes": 1
  }
}
```

`changed_attributes` lists each attribute changed since your `If-Match`, newest change first, with
the other writer's value; `hidden_changes` counts changes to fields you may not read, whose values
are never shown. Retry with `If-Match: "6"` and the values you decide to keep.

To let the server merge for you, add `If-Match-Merge: attributes`. A stale update is then applied at
the current version when none of the attributes you send changed since your version, and the 200
answer lists the attributes others changed in `merged_over` (`merged_hidden` counts the ones you may
not read). With `Prefer: return=minimal` the answer is just:

```json
{"id": "0192f0c4-7d1e-7c3a-9b1e-5d6f8a9b0c1d", "row_version": 7, "merged_over": ["stage"]}
```

When another writer changed an attribute you send, or the record's history cannot account for the
versions in between, the answer is the same 409 as above.

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
