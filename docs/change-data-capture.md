# Change data capture

Every change to a record is written to the change feed in the same transaction as the change. Other
systems and the platform's own consumers read it from there. This page covers what you can read
and how.

| You want | Use |
|---|---|
| Another system follows every change to some entities, in order | A change-stream subscription |
| A copy of one list or query stays up to date | Delta tokens ([delta-tokens.md](delta-tokens.md)) |
| An agent catches up on what changed | The AI action `changes.since` |
| A first full copy, then the changes after it | An export, then its `stream_token` |

## Change-stream subscriptions

An administrator subscribes a server-to-server client to 1 to 50 entities:

- `GET` and `POST /api/v1/change-stream/subscriptions` list and create subscriptions.
- `PATCH` and `DELETE /api/v1/change-stream/subscriptions/{id}` change and remove one. Send the
  subscription's `row_version` (in the body for `PATCH`, as `?row_version=` for `DELETE`); a stale
  one gets `409`.

A subscription chooses:

| Setting | Effect |
|---|---|
| Operations | `create`, `update`, `delete`, `restore`, `merge`, `purge` (an erasure) and `schema`. |
| Changed attributes | Updates count only when one of these attributes changed. |
| `condition` | A rule over the record; only matching records are sent. |
| Payload | `id` (ids only), `changes` (also the changed attribute names) or `record` (the record as the client may read it now). |
| `allow_personal` | Whether attributes labelled personal may be sent. Sensitive attributes are never sent. |
| `expires_at` | When the subscription stops. |

Every subscription change is written to the audit log. Reading events is not.

## Reading the stream

Only the subscription's own client may read it. Anyone else gets `404`.

- `GET /api/v1/change-stream/{subscription}/events?cursor=&limit=` returns up to `limit` events
  (1 to 1,000) in commit order, with `next_cursor` and `has_more`. Without a cursor, reading
  starts from now.
- `GET /api/v1/change-stream/{subscription}/sse` sends the same events as server-sent events.
  Each page's last event carries the cursor as its id, so a client can reconnect from it. The
  connection is held for up to 15 minutes, then the client reconnects.

Delivery is at least once. Keep `next_cursor` only after you have applied the events, and apply
each event so that receiving it twice does no harm.

Each event carries `event_id`, `entity`, `record_id`, `operation`, `event_name`, `created_at`, and
the payload the subscription chose. Events are read through the client's own permissions:

- an entity the client may not read is skipped;
- a record it may no longer read is skipped;
- fields it may not read never travel.

## Erasure and schema changes

- When a record is erased, its subscribers get a `purge` event named `record.erased` with the
  entity and id only. Delete your copy, then confirm with
  `POST /api/v1/change-stream/{subscription}/erasure-confirmations` and `{"event_ids": [...]}`. The
  confirmation is kept as evidence of the erasure.
- When an administrator or a changeset changes an entity's definition (adding, renaming, retyping
  or removing a field, or changing a choice list), its subscribers get a `schema.<op>` event with
  the entity and attribute names. A schema event never carries values.

## A first copy without gaps

Export the data first. The finished export's status (`GET .../export/{id}`) carries `stream_token`.
Read a subscription from that token: it returns exactly the changes the export did not include.
Nothing is lost, and nothing comes twice.

## When a cursor is too old

The feed keeps changes for `change_feed.retention_days` (30 by default). A cursor or delta token
older than that gets `410 resync_needed`, never a silent gap. Copy the data again, then continue
from the new export's `stream_token`, or from a new `latest` token for a delta.

The feed is stored one day per partition. The daily prune creates the next three days ahead, and
removes a whole day once it is past the retention period and every consumer has finished with
it. A day that still holds a change some consumer has not read is kept, with a warning in the
log, until that consumer catches up or is expired.

## The platform's own consumers

Workflows, search, master data, the data catalogue, data quality, the ledger, service and sales
clocks, commissions, notifications, AI and the warehouse export also read the feed, each with its
own position. A consumer that falls too far behind is marked expired, so that old
changes can still be pruned:

- the limit is 168 hours for an outside consumer such as a webhook subscription, and 720 hours for
  the platform's own consumers;
- an expired consumer must resync;
- each expiry logs a warning and counts in `change_feed_consumer_expired_total`.

`GET /api/v1/admin/change-feed/consumers` and the Change Feed page under Governance show each
consumer's status, unread events, lag and last read. The metric `change_feed_consumer_lag_seconds`
reports the lag.

## Where a change came from

The feed records, on each change, who made it (a person, or an agent and its session), the
channel, and the flow run behind it. The record timeline ([record-timeline.md](record-timeline.md))
shows the same provenance.
