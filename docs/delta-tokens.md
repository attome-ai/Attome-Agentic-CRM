# Keeping a copy up to date: delta tokens

A client that keeps its own copy of a list, such as an integration, an offline app or a report
cache, can ask for only what changed since it last asked. It does not need to read the whole list
again.

## How it works

1. **Get a first token.** Call the list with `delta_token=latest`, for example
   `GET /api/v1/account?filter[status][eq]=active&delta_token=latest`. The answer has no records,
   only `next_token`.
2. **Ask what changed.** Call the same list, with the same filters, and `delta_token=<next_token>`.
   The answer is:

   ```json
   {
     "created": [ { "id": "…", "name": "…" } ],
     "updated": [ { "id": "…", "name": "…" } ],
     "deleted": [ "…" ],
     "next_token": "…",
     "has_more": false
   }
   ```

3. **Keep the new token.** Store `next_token` and use it next time. If `has_more` is true, call
   again at once: more changes are waiting.

`POST /api/v1/query/execute` takes the same `delta_token` for a stored query or a view, provided
it reads a single entity.

## What the three lists mean

| List | Meaning |
|---|---|
| `created` | Records made since the token that the list now holds, as the list shows them. |
| `updated` | Records changed since the token that the list now holds. |
| `deleted` | Records the list no longer holds. |

A record ends up in `deleted` in any of these cases:

- it was deleted;
- you may no longer read it;
- it no longer matches the list's filters.

Remove these from your copy. An id you never had is safe to ignore.

The list's own rules decide what comes back: its filters, your record access and your field
access. A field you may not read never travels.

## When a token is too old

The change feed keeps changes for `change_feed.retention_days` (30 by default). A token older than
that gets `410` with the error `resync_needed`. Read the whole list again, then start with a new
`latest` token.

A token is signed by the deployment. A token it did not issue gets `400 invalid_cursor`.

## For agents

The AI action `changes.since` does the same for an agent, on an entity's default list. It returns
up to 500 changes per call, with `next_token` and `has_more`. It runs as the person the agent works
for.

## Other ways to follow changes

`POST /api/v1/query/changes` follows one entity's changes with a cursor, without list filters.
Webhooks and subscriptions push changes as they happen.
