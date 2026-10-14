//! Generic Redis Stream producer/consumer-group helpers
//! (P-job-system-hardening (b)) — the transport for high-frequency data that
//! needs at-least-once delivery but not apalis's transactional Postgres
//! queue semantics (e.g. an access-log/audit trail). Durability model:
//! `XADD` lands an entry in the stream; a consumer group's `XREADGROUP` +
//! bulk write + `XACK` is what makes delivery at-least-once — an entry stays
//! unacknowledged (and later `XAUTOCLAIM`-reclaimable) if its consumer
//! crashes between reading it and acking it, so a crash mid-batch re-delivers
//! rather than silently drops. This is at-least-once **conditioned on Redis
//! itself surviving** — an unacked entry only survives a Redis
//! restart/failover if the deployment has enabled persistence for this
//! keyspace; that is a deployment-level requirement this module cannot
//! enforce from the client side.
//!
//! **That requirement is now configured, probed and alarmed (D-685/D-356);
//! the TODO that used to sit here is closed.** Compose sets `--snapshot_cron`
//! on every Dragonfly service, [`crate::persistence::probe`] reports whether
//! a policy is actually in force, and `RedisPersistenceDisabled` /
//! `RedisSnapshotStale` / `S2sAccessLogBacklogGrowing` in
//! `observability/alerts.yml` page on the three ways this can go wrong
//! (no policy, saves failing, backlog widening the unflushed window).
//!
//! Read the ceiling honestly before depending on it: Dragonfly has no AOF and
//! does not implement `WAIT` (both verified live against df-v1.39.0), so the
//! guarantee is **"loss is bounded by the snapshot interval"**, never
//! "nothing is lost". Data that needs a real per-write durability guarantee
//! belongs in PostgreSQL — see `xrm_s2s::telemetry`'s module doc for how the
//! access log lives with that bound rather than pretending it does not exist.
//!
//! **Verification against Dragonfly is a local gate, not CI.** A manual run
//! on 2026-07-30 found the bugs below. The `dragonfly-integration` CI job then
//! ran `tests/stream_buffer.rs` (7/7) against Dragonfly from 2026-09-13 until
//! CI was retired (956ef9247). Nothing re-runs it automatically now:
//! `scripts/test-attome-cache-backends.ps1` runs it against every
//! Dragonfly/Redis image `docker-compose.yml` pins, production's included
//! (attome-cache-hardening.md Phase 3), and CLAUDE.md's cadence table requires
//! that for any change here. Four real bugs were found and fixed in the process: (1) `read_group` originally decoded
//! its reply via `FromRedis::convert` straight off the wire, which does not
//! know about RESP2's extra array wrapper around XREAD*/XREADGROUP replies —
//! it failed with "Cannot convert to map" against a real RESP2 connection;
//! fixed by running the raw reply through `into_xread_response()`
//! (`flatten_array_values` first) as fred's own docs recommend for exactly
//! this pitfall. (2) That same conversion path does not accept a bare `Null`
//! reply (what a non-blocking read of an empty/fully-delivered stream
//! actually returns) — `read_group` now short-circuits `Null` to an empty
//! `Vec` before attempting the conversion. (3) Both production call sites
//! (this module's own tests and `xrm-s2s`'s telemetry consumer) pass
//! `block_ms: 0` meaning "don't block, return immediately" — but on the wire
//! Redis's `BLOCK 0` means the opposite, "block forever." `read_group` now
//! omits the `BLOCK` argument entirely when `block_ms == 0` instead of
//! passing `Some(0)`; before this fix, every poll of an idle stream would
//! hang until this function's own client-side timeout fired and returned an
//! error, never an empty result. (4) `pending_count`'s `NOGROUP`→zero
//! fallback only matched real Redis's error prefix; Dragonfly replies "ERR no
//! such key" instead for a stream that was never created — both are now
//! handled.

use std::time::Duration;

use attome_types::AppError;
use fred::interfaces::StreamsInterface;
use fred::prelude::*;
use fred::types::{XCap, XCapKind, XCapTrim, XID};

use crate::ops::{self, Primitive};
use crate::store::Store;
// BCA-13 moved both bounds to `crate::timeouts`: `BACKGROUND` is the plain
// round-trip bound, `STREAM_BLOCK_SLACK` the extra a blocking read adds to
// its own `block_ms` because the consumer legitimately waits inside Redis.
use crate::timeouts::{BACKGROUND, STREAM_BLOCK_SLACK};

/// One stream entry: its Redis-assigned id (`"<ms>-<seq>"`) and its ordered
/// field/value pairs, decoded from whatever the caller `XADD`ed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    pub id: String,
    pub fields: Vec<(String, String)>,
}

/// Appends `fields` to the stream at `stream_key`, capped to approximately
/// `maxlen_approx` entries via `MAXLEN ~` — an approximate (not exact) trim,
/// deliberately: exact trimming (`MAXLEN =`) is O(n) and would compete with
/// this stream's own write volume, while `~` trims in O(1) amortized by only
/// removing whole macro-nodes, per Redis's own documented XADD MAXLEN
/// tradeoff. This is what bounds the stream's memory footprint if a consumer
/// ever stalls, so every producer call must go through this, not a raw
/// unbounded `XADD`. Returns the assigned entry id.
pub async fn add(
    store: &Store,
    stream_key: &str,
    fields: Vec<(String, String)>,
    maxlen_approx: u64,
) -> Result<String, AppError> {
    // Streams have no in-process form: a consumer-group transport needs a
    // server. On the in-process store this is a typed "needs Redis" error.
    let redis = store.redis()?;
    let cap: XCap = (
        XCapKind::MaxLen,
        XCapTrim::AlmostExact,
        maxlen_approx as i64,
    )
        .try_into()
        .map_err(|e| AppError::internal(format!("stream_buffer: invalid MAXLEN cap: {e}")))?;

    let attempt = tokio::time::timeout(
        BACKGROUND,
        redis.xadd::<String, _, _, _, _>(stream_key, false, cap, XID::Auto, fields),
    )
    .await;
    ops::record_op(Primitive::Stream, &attempt);

    attempt
        .map_err(|_| AppError::internal(format!("stream xadd timed out (stream={stream_key})")))?
        .map_err(|e| AppError::internal(format!("stream xadd failed (stream={stream_key}): {e}")))
}

/// Idempotent consumer-group creation: `$` (only entries added after group
/// creation) is the right starting point here — every caller of this module
/// pairs group creation with a stream that either already exists or is
/// created in the same call (`MKSTREAM`), never with "replay everything ever
/// written." A `BUSYGROUP` error (group already exists) is swallowed, not
/// propagated — this is meant to be called at the top of every consumer
/// loop tick, not just once at startup, so it must be safe to call
/// repeatedly.
pub async fn ensure_group(store: &Store, stream_key: &str, group: &str) -> Result<(), AppError> {
    // Streams have no in-process form: a consumer-group transport needs a
    // server. On the in-process store this is a typed "needs Redis" error.
    let redis = store.redis()?;
    let attempt: Result<Result<(), RedisError>, tokio::time::error::Elapsed> =
        tokio::time::timeout(
            BACKGROUND,
            redis.xgroup_create(stream_key, group, XID::Max, true),
        )
        .await;
    // BUSYGROUP is the expected reply on every tick after the first; interpret
    // it before counting so the error series means a real failure.
    let attempt = attempt.map(|r| match r {
        Err(e) if e.to_string().contains("BUSYGROUP") => Ok(()),
        other => other,
    });
    ops::record_op(Primitive::Stream, &attempt);
    let result = attempt.map_err(|_| {
        AppError::internal(format!(
            "stream xgroup_create timed out (stream={stream_key})"
        ))
    })?;

    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(AppError::internal(format!(
            "stream xgroup_create failed (stream={stream_key}, group={group}): {e}"
        ))),
    }
}

/// fred's `XReadResponse<String, String, String, String>` reply shape:
/// `HashMap<stream_key, Vec<(id, HashMap<field, value>)>>`.
type ReadGroupReply =
    std::collections::HashMap<String, Vec<(String, std::collections::HashMap<String, String>)>>;

/// Decodes fred's [`ReadGroupReply`] into a flat, ordered `Vec<StreamEntry>`
/// for the one stream this caller asked about. A stream absent from the
/// reply (nothing new to read) yields an empty `Vec`, not an error — the
/// normal "no new entries this tick" case.
fn entries_for_stream(reply: ReadGroupReply, stream_key: &str) -> Vec<StreamEntry> {
    reply
        .into_iter()
        .find(|(key, _)| key == stream_key)
        .map(|(_, values)| {
            values
                .into_iter()
                .map(|(id, fields)| StreamEntry {
                    id,
                    fields: fields.into_iter().collect(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Reads up to `count` new (never-yet-delivered, `>`) entries for `consumer`
/// in `group`, blocking up to `block_ms` if none are immediately available.
/// `block_ms == 0` means non-blocking — return whatever's available right
/// now, per this function's own contract — which on the wire means passing
/// Redis's `BLOCK` option as absent, never `BLOCK 0`: `BLOCK 0` is Redis's
/// own sentinel for "block forever," the opposite of what a `0` here means
/// to every caller of this function (confirmed live: without this special
/// case, an empty stream just hangs until this function's own client-side
/// timeout kills the request and returns an error instead of an empty
/// `Vec` — silently turning "nothing to do this tick" into a logged failure
/// on every consumer poll of an idle stream).
/// `noack` is always `false` — every entry this reads stays pending until an
/// explicit `ack` call, which is the whole at-least-once mechanism this
/// module exists to provide; a caller that wants fire-and-forget delivery
/// should not be using a consumer group at all.
pub async fn read_group(
    store: &Store,
    stream_key: &str,
    group: &str,
    consumer: &str,
    count: u64,
    block_ms: u64,
) -> Result<Vec<StreamEntry>, AppError> {
    // Streams have no in-process form: a consumer-group transport needs a
    // server. On the in-process store this is a typed "needs Redis" error.
    let redis = store.redis()?;
    // `xreadgroup` (unlike `xreadgroup_map`) hands its raw reply straight to
    // `FromRedis::convert`, which does NOT know about RESP2's extra array
    // wrapper around XREAD*/XREADGROUP replies (documented pitfall in fred's
    // own `StreamsInterface::xread` doc comment) — it fails with "Cannot
    // convert to map" against a real RESP2 server. `into_xread_response()`
    // (`flatten_array_values(2)` first) is the fix for that — but it does
    // NOT handle the reply being a bare `Null` (confirmed live: a
    // non-blocking read of an empty/fully-delivered stream replies `Null`,
    // not an empty array/map), so that case is special-cased below rather
    // than routed through `xreadgroup_map` (which bakes the conversion in
    // with no chance to intercept `Null` first).
    let block_arg = if block_ms == 0 { None } else { Some(block_ms) };
    let client_timeout = Duration::from_millis(block_ms) + STREAM_BLOCK_SLACK;
    let attempt = tokio::time::timeout(
        client_timeout,
        redis.xreadgroup(
            group,
            consumer,
            Some(count),
            block_arg,
            false,
            vec![stream_key.to_owned()],
            vec![XID::NewInGroup],
        ),
    )
    .await;
    ops::record_op(Primitive::Stream, &attempt);

    let raw: RedisValue = attempt
        .map_err(|_| {
            AppError::internal(format!("stream xreadgroup timed out (stream={stream_key})"))
        })?
        .map_err(|e| {
            AppError::internal(format!(
                "stream xreadgroup failed (stream={stream_key}): {e}"
            ))
        })?;

    if raw.is_null() {
        return Ok(Vec::new());
    }
    let reply: ReadGroupReply = raw.into_xread_response().map_err(|e| {
        AppError::internal(format!(
            "stream xreadgroup: failed to decode reply (stream={stream_key}): {e}"
        ))
    })?;

    Ok(entries_for_stream(reply, stream_key))
}

/// Acknowledges `ids` in `group` — once acked, an entry is no longer pending
/// and will never be `autoclaim`ed. Call this only after the corresponding
/// bulk write has actually committed; acking before the write commits would
/// reopen the crash-loses-the-record gap this whole mechanism exists to close.
pub async fn ack(
    store: &Store,
    stream_key: &str,
    group: &str,
    ids: &[String],
) -> Result<(), AppError> {
    // Streams have no in-process form: a consumer-group transport needs a
    // server. On the in-process store this is a typed "needs Redis" error.
    let redis = store.redis()?;
    if ids.is_empty() {
        return Ok(());
    }
    let attempt = tokio::time::timeout(
        BACKGROUND,
        redis.xack::<i64, _, _, _>(stream_key, group, ids.to_vec()),
    )
    .await;
    ops::record_op(Primitive::Stream, &attempt);

    attempt
        .map_err(|_| AppError::internal(format!("stream xack timed out (stream={stream_key})")))?
        .map_err(|e| {
            AppError::internal(format!("stream xack failed (stream={stream_key}): {e}"))
        })?;
    Ok(())
}

/// Borrowing array accessor — fred 9's `RedisValue` has `is_array()` and the
/// consuming `into_array()` but no borrowing `as_array()`; this destructures
/// the public `Array` variant directly instead.
fn as_array(value: &RedisValue) -> Option<&Vec<RedisValue>> {
    match value {
        RedisValue::Array(items) => Some(items),
        _ => None,
    }
}

/// Manually parses one `[id, [field, value, field, value, ...]]` entry out
/// of a raw `RedisValue::Array` — used for `XAUTOCLAIM`'s reply, which has no
/// typed helper in fred (unlike `XREADGROUP`'s documented `XReadResponse`).
fn parse_entry(value: &RedisValue) -> Option<StreamEntry> {
    let items = as_array(value)?;
    let id = items.first()?.as_string()?;
    let flat = items.get(1).and_then(as_array)?;
    let fields = flat
        .chunks_exact(2)
        .filter_map(|pair| Some((pair[0].as_string()?, pair[1].as_string()?)))
        .collect();
    Some(StreamEntry { id, fields })
}

/// The id of an `XAUTOCLAIM` entry even when its payload cannot be decoded —
/// `[id, ...]`, where only element 0 can still be trusted.
fn entry_id(value: &RedisValue) -> Option<String> {
    as_array(value)?.first()?.as_string()
}

/// What one [`autoclaim_full`] pass found (BCA-23).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutoclaimResult {
    /// The raw `XAUTOCLAIM` scan cursor: hand it straight back as `start` on
    /// the next call (`"0-0"` restarts the scan from the beginning).
    ///
    /// Named `cursor`, not `next_cursor`, deliberately: this is not a paging
    /// envelope (D-347). It is the opaque token Redis itself returns, fed back
    /// verbatim; no page size, offset, or ordering decision lives here, and
    /// `attome_types::PaginatedResponse` has nothing to do with a stream scan.
    pub cursor: String,
    /// Entries this consumer now owns: process them, then `ack`.
    pub claimed: Vec<StreamEntry>,
    /// Pending ids whose stream entry no longer exists (trimmed by `MAXLEN ~`
    /// or explicitly deleted). Redis reports them so a caller can stop counting
    /// them as backlog — nothing can ever be delivered for them again.
    pub deleted_ids: Vec<String>,
    /// Pending ids that were claimed but whose payload did not parse.
    /// [`autoclaim_full`] acks these itself: an entry that cannot be decoded
    /// will never decode, so leaving it pending re-claimed it on every scan
    /// forever (BCA-F5).
    pub unparsed_ids: Vec<String>,
}

/// Decomposes an `XAUTOCLAIM` reply. Redis 7+/current Dragonfly answers with a
/// 3-element array `[next_cursor, claimed_entries, deleted_ids]`; Redis 6.2
/// answers with only the first two. Reading positionally tolerates either
/// shape, and — like `read_group` — a bare `Null` (an exhausted scan on some
/// servers) decomposes to an empty result rather than an error.
fn parse_autoclaim_reply(reply: &RedisValue) -> Result<AutoclaimResult, AppError> {
    if reply.is_null() {
        return Ok(AutoclaimResult::default());
    }
    let top = as_array(reply)
        .ok_or_else(|| AppError::internal("stream xautoclaim: reply was not an array"))?;

    let next_cursor = top
        .first()
        .and_then(RedisValue::as_string)
        .ok_or_else(|| AppError::internal("stream xautoclaim: missing next-cursor element"))?;

    let mut claimed = Vec::new();
    let mut unparsed_ids = Vec::new();
    if let Some(entries) = top.get(1).and_then(as_array) {
        for entry in entries {
            match parse_entry(entry) {
                Some(parsed) => claimed.push(parsed),
                // Keep the id so it can be acked; an entry with no readable id
                // at all cannot be acked and is reported as lost instead.
                None => {
                    if let Some(id) = entry_id(entry) {
                        unparsed_ids.push(id);
                    }
                }
            }
        }
    }

    let deleted_ids = top
        .get(2)
        .and_then(as_array)
        .map(|ids| ids.iter().filter_map(RedisValue::as_string).collect())
        .unwrap_or_default();

    Ok(AutoclaimResult {
        cursor: next_cursor,
        claimed,
        deleted_ids,
        unparsed_ids,
    })
}

/// Reclaims entries that have been pending (delivered, never acked) for at
/// least `min_idle_ms` — the recovery path for a consumer that crashed
/// between `read_group` and `ack`: those entries are still in the stream,
/// still in the pending entries list, and this call hands them to a fresh
/// consumer instead of leaving them stuck forever. Returns the next scan
/// cursor (feed it back in as `start` on the next call; `"0-0"` restarts the
/// scan from the beginning) and the entries claimed this call.
///
/// Kept as a two-tuple for the existing caller (`xrm_s2s::telemetry`); the
/// richer [`autoclaim_full`] carries the deleted and unparseable ids, and this
/// function still acks the unparseable ones (the fix for BCA-F5's "cycles
/// forever" defect is in the shared implementation, not opt-in).
pub async fn autoclaim(
    store: &Store,
    stream_key: &str,
    group: &str,
    consumer: &str,
    min_idle_ms: u64,
    start: &str,
    count: u64,
) -> Result<(String, Vec<StreamEntry>), AppError> {
    let result = autoclaim_full(
        store,
        stream_key,
        group,
        consumer,
        min_idle_ms,
        start,
        count,
    )
    .await?;
    Ok((result.cursor, result.claimed))
}

/// [`autoclaim`] with the loss accounting exposed (BCA-23). Every pass emits
/// `stream_buffer_entries_lost_total{stream,reason}` — `reason="deleted"` for
/// PEL ids whose entry is gone, `reason="unparsed"` for a claimed payload that
/// could not be decoded — so a stream quietly eating entries is a visible
/// signal instead of a growing pending count nobody can explain.
///
/// `stream_key` becomes a metric label, so callers must pass a bounded,
/// operator-known stream name (never a per-tenant or per-record key).
pub async fn autoclaim_full(
    store: &Store,
    stream_key: &str,
    group: &str,
    consumer: &str,
    min_idle_ms: u64,
    start: &str,
    count: u64,
) -> Result<AutoclaimResult, AppError> {
    // Streams have no in-process form: a consumer-group transport needs a
    // server. On the in-process store this is a typed "needs Redis" error.
    let redis = store.redis()?;
    let attempt = tokio::time::timeout(
        BACKGROUND,
        redis.xautoclaim(
            stream_key,
            group,
            consumer,
            min_idle_ms,
            XID::Manual(start.to_string().into()),
            Some(count),
            false,
        ),
    )
    .await;
    ops::record_op(Primitive::Stream, &attempt);

    let reply: RedisValue = attempt
        .map_err(|_| {
            AppError::internal(format!("stream xautoclaim timed out (stream={stream_key})"))
        })?
        .map_err(|e| {
            AppError::internal(format!(
                "stream xautoclaim failed (stream={stream_key}): {e}"
            ))
        })?;

    let result = parse_autoclaim_reply(&reply)?;

    // An entry whose payload cannot be decoded will never decode. Leaving it
    // pending meant every subsequent scan re-claimed it and every consumer
    // dropped it again, forever (BCA-F5). Ack it; a failure here is logged,
    // not fatal — the claim itself succeeded and the ids are still reported.
    if !result.unparsed_ids.is_empty()
        && let Err(e) = ack(store, stream_key, group, &result.unparsed_ids).await
    {
        tracing::warn!(
            stream = stream_key,
            error = %e,
            "stream autoclaim: could not ack unparseable pending entries; they will be re-claimed"
        );
    }

    for (reason, count) in [
        ("deleted", result.deleted_ids.len()),
        ("unparsed", result.unparsed_ids.len()),
    ] {
        if count > 0 {
            metrics::counter!(
                "stream_buffer_entries_lost_total",
                "stream" => stream_key.to_owned(),
                "reason" => reason,
            )
            .increment(count as u64);
        }
    }

    Ok(result)
}

/// Total pending (delivered, not yet acked) entry count for `group` on
/// `stream_key` — the summary form of `XPENDING` (no range/consumer
/// filters), used as this stream's consumer-lag gauge (guidelines §11 —
/// queue backlog must stay an observable signal). A `NOGROUP` error (the
/// group hasn't been created yet, e.g. a fresh deployment before the first
/// consumer tick) is treated as zero pending, not a failure — there is
/// nothing to be behind on yet.
pub async fn pending_count(store: &Store, stream_key: &str, group: &str) -> Result<i64, AppError> {
    // Streams have no in-process form: a consumer-group transport needs a
    // server. On the in-process store this is a typed "needs Redis" error.
    let redis = store.redis()?;
    let result: Result<Result<RedisValue, RedisError>, tokio::time::error::Elapsed> =
        tokio::time::timeout(BACKGROUND, redis.xpending(stream_key, group, ())).await;
    // Real Redis prefixes a missing group "NOGROUP"; Dragonfly (confirmed live)
    // replies "ERR no such key" for a stream that was never created. Both mean
    // nothing to be behind on yet, so they are interpreted before counting and
    // never land in the error series.
    let result = result.map(|r| match r {
        Ok(reply) => Ok(Some(reply)),
        Err(e) if e.to_string().contains("NOGROUP") || e.to_string().contains("no such key") => {
            Ok(None)
        }
        Err(e) => Err(e),
    });
    ops::record_op(Primitive::Stream, &result);
    let result = result.map_err(|_| {
        AppError::internal(format!("stream xpending timed out (stream={stream_key})"))
    })?;

    match result {
        Ok(None) => Ok(0),
        Ok(Some(reply)) => {
            let count = as_array(&reply)
                .and_then(|top| top.first())
                .and_then(RedisValue::as_i64)
                .ok_or_else(|| {
                    AppError::internal("stream xpending: unexpected summary reply shape")
                })?;
            Ok(count)
        }
        Err(e) => Err(AppError::internal(format!(
            "stream xpending failed (stream={stream_key}, group={group}): {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_entry_reads_id_and_flat_field_value_pairs() {
        let value = RedisValue::Array(vec![
            RedisValue::String("1700000000000-0".into()),
            RedisValue::Array(vec![
                RedisValue::String("method".into()),
                RedisValue::String("POST".into()),
                RedisValue::String("status".into()),
                RedisValue::String("200".into()),
            ]),
        ]);

        let entry = parse_entry(&value).expect("well-formed entry parses");
        assert_eq!(entry.id, "1700000000000-0");
        assert_eq!(
            entry.fields,
            vec![
                ("method".to_string(), "POST".to_string()),
                ("status".to_string(), "200".to_string()),
            ]
        );
    }

    #[test]
    fn parse_entry_rejects_a_non_array_value() {
        assert!(parse_entry(&RedisValue::Null).is_none());
    }

    #[test]
    fn entries_for_stream_returns_empty_when_the_stream_key_is_absent() {
        let reply = std::collections::HashMap::new();
        assert!(entries_for_stream(reply, "some-stream").is_empty());
    }

    #[test]
    fn entries_for_stream_extracts_only_the_requested_key() {
        let mut reply = std::collections::HashMap::new();
        reply.insert(
            "wanted-stream".to_string(),
            vec![(
                "1-0".to_string(),
                std::collections::HashMap::from([("f".to_string(), "v".to_string())]),
            )],
        );
        reply.insert("other-stream".to_string(), vec![]);

        let entries = entries_for_stream(reply, "wanted-stream");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "1-0");
    }

    fn well_formed_entry(id: &str) -> RedisValue {
        RedisValue::Array(vec![
            RedisValue::String(id.into()),
            RedisValue::Array(vec![
                RedisValue::String("k".into()),
                RedisValue::String("v".into()),
            ]),
        ])
    }

    /// BCA-23: Redis 7 / current Dragonfly answer
    /// `[cursor, claimed, deleted_ids]` — all three elements must be reported,
    /// and the deleted ids must not be counted as claimable entries.
    #[test]
    fn parse_autoclaim_reply_reads_cursor_claimed_and_deleted_ids() {
        let reply = RedisValue::Array(vec![
            RedisValue::String("0-0".into()),
            RedisValue::Array(vec![well_formed_entry("1-0"), well_formed_entry("2-0")]),
            RedisValue::Array(vec![RedisValue::String("3-0".into())]),
        ]);

        let parsed = parse_autoclaim_reply(&reply).expect("well-formed reply");
        assert_eq!(parsed.cursor, "0-0");
        let ids: Vec<String> = parsed.claimed.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["1-0".to_string(), "2-0".to_string()]);
        assert_eq!(parsed.deleted_ids, vec!["3-0".to_string()]);
        assert!(parsed.unparsed_ids.is_empty());
    }

    /// Redis 6.2 answers with only two elements; the deleted half must default
    /// to empty rather than fail the whole claim.
    #[test]
    fn parse_autoclaim_reply_tolerates_the_two_element_redis_6_shape() {
        let reply = RedisValue::Array(vec![
            RedisValue::String("9-0".into()),
            RedisValue::Array(vec![well_formed_entry("4-0")]),
        ]);

        let parsed = parse_autoclaim_reply(&reply).expect("two-element reply");
        assert_eq!(parsed.cursor, "9-0");
        assert_eq!(parsed.claimed.len(), 1);
        assert!(parsed.deleted_ids.is_empty());
        assert!(parsed.unparsed_ids.is_empty());
    }

    /// BCA-F5: an entry whose id is readable but whose payload is not must be
    /// reported as unparsed (so `autoclaim_full` can ack it), not silently
    /// dropped — dropping it is what made it cycle through every scan forever.
    #[test]
    fn parse_autoclaim_reply_reports_an_unparseable_entry_by_id() {
        let malformed = RedisValue::Array(vec![
            RedisValue::String("5-0".into()),
            RedisValue::String("not-an-array-of-fields".into()),
        ]);
        let reply = RedisValue::Array(vec![
            RedisValue::String("0-0".into()),
            RedisValue::Array(vec![well_formed_entry("1-0"), malformed]),
            RedisValue::Array(vec![]),
        ]);

        let parsed = parse_autoclaim_reply(&reply).expect("partly malformed reply");
        assert_eq!(
            parsed.claimed.len(),
            1,
            "the well-formed entry is still claimed"
        );
        assert_eq!(
            parsed.unparsed_ids,
            vec!["5-0".to_string()],
            "an id whose payload will never decode must be reported so it can be acked"
        );
    }

    /// A bare `Null` (an exhausted scan) decomposes to an empty claim, not an
    /// error — same posture `read_group` takes for the same reply shape.
    #[test]
    fn parse_autoclaim_reply_treats_null_as_an_empty_scan() {
        let parsed = parse_autoclaim_reply(&RedisValue::Null).expect("null reply");
        assert!(parsed.cursor.is_empty());
        assert!(parsed.claimed.is_empty());
        assert!(parsed.deleted_ids.is_empty());
        assert!(parsed.unparsed_ids.is_empty());
    }
}
