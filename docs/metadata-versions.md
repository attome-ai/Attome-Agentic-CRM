# Metadata versions: publish, switch and roll back

Entities, fields, forms, views and rules are metadata. Every server node holds the deployment's
metadata in memory, so a change must reach every node, and every node must switch to it at once.
This page is the operator's view of how that happens and what to do when it does not.

## How a change reaches every node

1. **Publish records a version.** Publishing cooks the model into a manifest, records it as the
   next numbered version in `metadata_artefact`, and moves the `metadata_current` pointer to it.
   Pointer moves are serialised by one deployment-wide advisory lock
   (`attome-model/version-pointer:current`): a second publish that arrives while one is cooking
   gets `409` and is retried, so an older cook can never become current after a newer one. The
   lock is kept global on purpose: publishes are rare, and a per-entity lock would let two
   publishes interleave their pointer moves.
2. **The doorbell rings.** Every pointer move, and every metadata change-log write, sends a
   Postgres `NOTIFY` on `attome_metadata_change`. Each node listens on its own direct database
   connection and catches up within moments.
3. **The safety-net poll.** A lost doorbell (a dropped connection, a stalled listener) is caught
   by a poll every `cache.metadata_poll_interval_secs` seconds (default 5). The poll compares the
   node's applied change-log watermark with the database's and catches up when behind; it also
   follows the current-version pointer.
4. **The node switches at once.** A node loads the new version's artefacts off the request path
   and swaps them in as one step, then records its `metadata_node_switch` row. A request sees
   either the old model or the new one, never a mix.

## Reading it

| Signal | Where | Meaning |
|---|---|---|
| `Attome-Metadata-Version` | header on every API response | The version the answering node serves. |
| `registry: false` | `/health/ready` | The node is not ready: it is behind the change log on two polls in a row, or could not load the current version. It returns to ready once a poll catches it up. |
| `metadata_switch_seconds` | metrics | Publish-to-switch time per node. Alert `MetadataSwitchSlow` fires when the p95 is over 30 s. |
| `registry_watermark_lag` | metrics | Change-log rows this node has not applied. |
| `registry_watermark_poll_forced_catchup_total` | metrics | Catch-ups the poll made because the doorbell was missed. A steady climb means the listener is not receiving. |
| Admin > Metadata versions | the app (`GET /api/v1/admin/metadata/versions`) | Every recorded version, the current one, and when each node switched. |

## What the browser does

The web app reads `Attome-Metadata-Version` from every response. The first value is its baseline;
a newer one means the model changed while the app was open. The app then drops its cached
metadata and reloads it on the next navigation, and an open form whose fields changed shows a
warning instead of silently saving against the old shape. The notice rides on a response header
rather than a push channel, so it needs no websocket and works through any proxy. A node that is
behind reports an older version, which the app ignores.

## A builder sees their own change

After a metadata write, the builder is pinned for a minute to the change-log position their write
reached (`attome-server:meta-pin:{user}`). On their next request a node that is behind catches
up first, waiting at most two seconds, and answers `503` (retry) if it still cannot. Without
Redis (Solo, one node) there is nothing to pin.

## Rolling back

A rollback moves the pointer back to a version already recorded; it never cooks, so it is quick. Drafts and
published objects are not changed: the next publish cooks them again, so roll back to buy time,
then fix and publish.

- Admin > Metadata versions > **Roll back**, or `POST /api/v1/admin/metadata/rollback` (to the
  version before the current one).
- `POST /api/v1/admin/metadata/versions/{version}/switch` makes any recorded version current.
- `GET /api/v1/admin/metadata/versions/{version}/nodes` shows which nodes have switched.

Every node follows the moved pointer through the same doorbell and poll as a publish.

## When a node stays behind

1. Check `/health/ready` on that node: `registry: false` keeps it out of the load balancer, so
   users are not served a stale model.
2. Check `registry_watermark_poll_forced_catchup_total`: if it climbs while `registry` stays
   false, the node cannot load the version (look for `metadata` errors in its log, often a
   database permission or a missing artefact).
3. A log line `Postgres/Redis are out of sync` means the database was restored to an earlier
   point; the node rebuilds its registry from scratch on its own.
4. Restarting the node always works: it loads the current version at boot before it reports
   ready.
