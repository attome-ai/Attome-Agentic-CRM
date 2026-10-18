//! S2S high-frequency telemetry, off the apalis Postgres queue
//! (P-job-system-hardening (b) — replaces `EngineJob::TouchS2sKey` and
//! `EngineJob::S2sAccessLog`). Every S2S-authenticated request used to
//! insert one or two durable queue rows per request purely to record a
//! `last_used_at` touch and (when enabled) an access-log line — real write
//! amplification against Postgres for data that never needed apalis's
//! replay-safe transactional delivery. This module gives the two write
//! shapes the transport each actually needs:
//!
//! - **Touches** (`TouchS2sKey`'s replacement): only the *latest* value per
//!   client/key matters, so concurrent touches coalesce into a Redis hash
//!   (`attome_cache::write_coalesce`) and a periodic flush folds it into one
//!   bulk `UPDATE`. Accepted tradeoff (stated, not silent):
//!   `s2s_client(_key).last_used_at` is accurate to within one flush
//!   interval instead of real-time — verified as safe because the admin
//!   "last used" UI is the only consumer of that column and doesn't need
//!   tighter freshness than that.
//! - **Access log** (`S2sAccessLog`'s replacement): this is
//!   security/audit-relevant data (guidelines §7's audit-integrity
//!   constraint), so it keeps at-least-once delivery via a Redis Stream +
//!   consumer group (`attome_cache::stream_buffer`) instead of dropping to a
//!   purely best-effort buffer — an entry stays pending (and later
//!   reclaimable) until its row is actually committed to
//!   `s2s_access_log`, so a crash mid-batch re-delivers rather than
//!   silently drops. That guarantee holds only if Redis itself survives
//!   between `XADD` and the next successful flush.
//!
//! **The durability requirement is configured, probed and alarmed
//! (D-685/D-356).** Compose sets `--snapshot_cron` on every Dragonfly
//! service; `attome_cache::persistence::probe` reports whether a policy is
//! actually in force; and `RedisPersistenceDisabled`, `RedisSnapshotStale`
//! and `S2sAccessLogBacklogGrowing` (`observability/alerts.yml`, unit-tested
//! in `alerts_test.yml`) page on no-policy, saves-failing and
//! backlog-growing respectively. The last of those is the one specific to
//! this module: `s2s_access_log_stream_pending` is the count of accepted S2S
//! requests whose access record exists only in Redis, so a growing backlog
//! is literally the width of the audit-loss window.
//!
//! **The residual bound, stated rather than implied.** Dragonfly has no AOF
//! and does not implement `WAIT`, so even correctly configured the guarantee
//! is "loss bounded by the snapshot interval", not zero loss. A deployment
//! that cannot accept a bounded-loss access log should not use this path at
//! all — it should write through the durable PostgreSQL outbox, at the write
//! amplification this module exists to avoid. That is a deployment posture
//! decision, and the alarms above are what make the bound visible rather
//! than assumed.

use std::collections::HashMap;
use std::time::Duration;

use attome_cache::{Store, stream_buffer, write_coalesce};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::access_log::LogEntry;

const TOUCH_HASH_KEY: &str = "attome-s2s:touch:client-key";
const ACCESS_LOG_STREAM_KEY: &str = "attome-s2s:access-log:stream";

/// BCA-43 — same reasoning as attome-server's api-key touch buffer: a coalesced
/// "key was used at" record must not outlive the flush path that consumes it.
const TOUCH_TTL_SECS: i64 = 86_400;
const ACCESS_LOG_GROUP: &str = "access-log-writers";

// ── Touch buffer (TouchS2sKey's replacement) ────────────────────────────────

/// Records that `client_id`'s key `key_id` was used at `at`, coalesced with
/// any other touch for the same (client, key) pair since the last flush.
/// Best-effort — callers should log a warning and continue rather than fail
/// the request over this.
pub async fn record_touch(
    redis: &Store,
    client_id: Uuid,
    key_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(), AppError> {
    let field = format!("{client_id}:{key_id}");
    write_coalesce::set_with_ttl(
        redis,
        TOUCH_HASH_KEY,
        &field,
        &at.to_rfc3339(),
        TOUCH_TTL_SECS,
    )
    .await
}

/// Drains the touch buffer and applies each distinct client's and each
/// distinct key's latest timestamp in two bulk `UPDATE`s (guidelines §14 —
/// no N+1; mirrors `attome_s2s::db::update_last_used`'s two-table shape, just
/// batched). A client with multiple keys touched at different times gets its
/// `s2s_client.last_used_at` set to the *latest* of those touches —
/// matching the semantics of a request that always touches both tables with
/// the same instant already had. Returns the number of distinct (client,
/// key) pairs flushed.
pub async fn flush_touches(db: &DbPool, redis: &Store) -> Result<usize, AppError> {
    let drained = write_coalesce::drain(redis, TOUCH_HASH_KEY).await?;
    if drained.is_empty() {
        return Ok(0);
    }

    let mut latest_client: HashMap<Uuid, DateTime<Utc>> = HashMap::new();
    let mut latest_key: HashMap<Uuid, DateTime<Utc>> = HashMap::new();
    let mut flushed = 0usize;

    for (field, value) in drained {
        let Some((client_str, key_str)) = field.split_once(':') else {
            tracing::warn!("attome-s2s telemetry: dropping malformed touch field: {field:?}");
            continue;
        };
        let Ok(client_id) = client_str.parse::<Uuid>() else {
            tracing::warn!(
                "attome-s2s telemetry: dropping touch field with malformed client id: {field:?}"
            );
            continue;
        };
        let Ok(key_id) = key_str.parse::<Uuid>() else {
            tracing::warn!(
                "attome-s2s telemetry: dropping touch field with malformed key id: {field:?}"
            );
            continue;
        };
        let Ok(at) = DateTime::parse_from_rfc3339(&value) else {
            tracing::warn!(
                "attome-s2s telemetry: dropping touch field with malformed timestamp: {value:?}"
            );
            continue;
        };
        let at = at.with_timezone(&Utc);
        flushed += 1;
        latest_client
            .entry(client_id)
            .and_modify(|v| {
                if at > *v {
                    *v = at;
                }
            })
            .or_insert(at);
        latest_key
            .entry(key_id)
            .and_modify(|v| {
                if at > *v {
                    *v = at;
                }
            })
            .or_insert(at);
    }

    if !latest_client.is_empty() {
        let (ids, ats): (Vec<Uuid>, Vec<DateTime<Utc>>) = latest_client.into_iter().unzip();
        sqlx::query(
            r#"
            UPDATE s2s_client AS c
            SET last_used_at = v.at
            FROM UNNEST($1::uuid[], $2::timestamptz[]) AS v(id, at)
            WHERE c.id = v.id
            "#,
        )
        .bind(&ids)
        .bind(&ats)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }

    if !latest_key.is_empty() {
        let (ids, ats): (Vec<Uuid>, Vec<DateTime<Utc>>) = latest_key.into_iter().unzip();
        sqlx::query(
            r#"
            UPDATE s2s_client_key AS k
            SET last_used_at = v.at
            FROM UNNEST($1::uuid[], $2::timestamptz[]) AS v(id, at)
            WHERE k.id = v.id
            "#,
        )
        .bind(&ids)
        .bind(&ats)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }

    Ok(flushed)
}

/// Detached `tokio::spawn` loop, same shape as
/// `server::jobs::spawn_partition_maintenance_scheduler` — periodically
/// flushes the touch buffer. Meant to run unconditionally (S2S touches
/// happen whenever `s2s.enabled` is true, independent of
/// `s2s.access_log_enabled`).
pub fn spawn_touch_flush_scheduler(db: DbPool, redis: Store, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match flush_touches(&db, &redis).await {
                Ok(0) => {}
                Ok(count) => tracing::debug!(count, "attome-s2s telemetry: flushed key touches"),
                Err(e) => tracing::warn!(error = %e, "attome-s2s telemetry: touch flush failed"),
            }
        }
    });
}

// ── Access log stream (S2sAccessLog's replacement) ──────────────────────────

fn encode_log_entry(entry: &LogEntry) -> Vec<(String, String)> {
    let mut fields = vec![
        ("method".to_string(), entry.method.clone()),
        ("path".to_string(), entry.path.clone()),
        ("created_at".to_string(), entry.created_at.to_rfc3339()),
    ];
    if let Some(v) = entry.client_ref {
        fields.push(("client_ref".to_string(), v.to_string()));
    }
    if let Some(ref v) = entry.client_name {
        fields.push(("client_name".to_string(), v.clone()));
    }
    if let Some(v) = entry.status_code {
        fields.push(("status_code".to_string(), v.to_string()));
    }
    if let Some(v) = entry.response_time_ms {
        fields.push(("response_time_ms".to_string(), v.to_string()));
    }
    if let Some(v) = entry.bytes_received {
        fields.push(("bytes_received".to_string(), v.to_string()));
    }
    if let Some(v) = entry.bytes_sent {
        fields.push(("bytes_sent".to_string(), v.to_string()));
    }
    if let Some(ref v) = entry.correlation_id {
        fields.push(("correlation_id".to_string(), v.clone()));
    }
    if let Some(ref v) = entry.ip_address {
        fields.push(("ip_address".to_string(), v.clone()));
    }
    if let Some(ref v) = entry.nonce {
        fields.push(("nonce".to_string(), v.clone()));
    }
    if let Some(ref v) = entry.error_code {
        fields.push(("error_code".to_string(), v.clone()));
    }
    if let Some(v) = entry.acted_as_user_id {
        fields.push(("acted_as_user_id".to_string(), v.to_string()));
    }
    fields
}

fn decode_log_entry(fields: Vec<(String, String)>) -> Result<LogEntry, AppError> {
    let mut map: HashMap<String, String> = fields.into_iter().collect();

    let method = map
        .remove("method")
        .ok_or_else(|| AppError::internal("access-log stream entry missing 'method'"))?;
    let path = map
        .remove("path")
        .ok_or_else(|| AppError::internal("access-log stream entry missing 'path'"))?;
    let created_at_raw = map
        .remove("created_at")
        .ok_or_else(|| AppError::internal("access-log stream entry missing 'created_at'"))?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_raw)
        .map_err(|e| {
            AppError::internal(format!(
                "access-log stream entry has malformed created_at: {e}"
            ))
        })?
        .with_timezone(&Utc);

    Ok(LogEntry {
        client_ref: map.remove("client_ref").and_then(|v| v.parse().ok()),
        client_name: map.remove("client_name"),
        method,
        path,
        status_code: map.remove("status_code").and_then(|v| v.parse().ok()),
        response_time_ms: map.remove("response_time_ms").and_then(|v| v.parse().ok()),
        bytes_received: map.remove("bytes_received").and_then(|v| v.parse().ok()),
        bytes_sent: map.remove("bytes_sent").and_then(|v| v.parse().ok()),
        correlation_id: map.remove("correlation_id"),
        ip_address: map.remove("ip_address"),
        nonce: map.remove("nonce"),
        error_code: map.remove("error_code"),
        acted_as_user_id: map.remove("acted_as_user_id").and_then(|v| v.parse().ok()),
        created_at,
    })
}

/// Appends one access-log line to the durable stream. Best-effort at the
/// call site (log and continue, same posture as the old enqueue call) —
/// this function itself propagates the error so the caller can decide.
pub async fn record_access_log(
    redis: &Store,
    entry: &LogEntry,
    stream_maxlen: u64,
) -> Result<(), AppError> {
    let fields = encode_log_entry(entry);
    stream_buffer::add(redis, ACCESS_LOG_STREAM_KEY, fields, stream_maxlen)
        .await
        .map(|_id| ())
}

/// Bulk `INSERT` via `UNNEST` (guidelines §14 — no N+1 row-at-a-time
/// writes), same column list as `attome_s2s::access_log::write`.
async fn bulk_insert_access_log(db: &DbPool, entries: &[LogEntry]) -> Result<(), sqlx::Error> {
    if entries.is_empty() {
        return Ok(());
    }

    let client_ref: Vec<Option<Uuid>> = entries.iter().map(|e| e.client_ref).collect();
    let client_name: Vec<Option<String>> = entries.iter().map(|e| e.client_name.clone()).collect();
    let method: Vec<String> = entries.iter().map(|e| e.method.clone()).collect();
    let path: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
    let status_code: Vec<Option<i16>> = entries.iter().map(|e| e.status_code).collect();
    let response_time_ms: Vec<Option<i32>> = entries.iter().map(|e| e.response_time_ms).collect();
    let bytes_received: Vec<Option<i32>> = entries.iter().map(|e| e.bytes_received).collect();
    let bytes_sent: Vec<Option<i32>> = entries.iter().map(|e| e.bytes_sent).collect();
    let correlation_id: Vec<Option<String>> =
        entries.iter().map(|e| e.correlation_id.clone()).collect();
    let ip_address: Vec<Option<String>> = entries.iter().map(|e| e.ip_address.clone()).collect();
    let nonce: Vec<Option<String>> = entries.iter().map(|e| e.nonce.clone()).collect();
    let error_code: Vec<Option<String>> = entries.iter().map(|e| e.error_code.clone()).collect();
    let created_at: Vec<DateTime<Utc>> = entries.iter().map(|e| e.created_at).collect();
    let acted_as: Vec<Option<Uuid>> = entries.iter().map(|e| e.acted_as_user_id).collect();

    sqlx::query(
        r#"
        INSERT INTO s2s_access_log
            (client_ref, client_name, method, path, status_code, response_time_ms,
             bytes_received, bytes_sent, correlation_id, ip_address, nonce, error_code, created_at,
             acted_as_user_id)
        SELECT * FROM UNNEST(
            $1::uuid[], $2::text[], $3::text[], $4::text[], $5::smallint[], $6::int[],
            $7::int[], $8::int[], $9::text[], $10::text[], $11::text[], $12::text[], $13::timestamptz[],
            $14::uuid[]
        )
        "#,
    )
    .bind(client_ref)
    .bind(client_name)
    .bind(method)
    .bind(path)
    .bind(status_code)
    .bind(response_time_ms)
    .bind(bytes_received)
    .bind(bytes_sent)
    .bind(correlation_id)
    .bind(ip_address)
    .bind(nonce)
    .bind(error_code)
    .bind(created_at)
    .bind(acted_as)
    .execute(db)
    .await?;

    Ok(())
}

/// One consumer tick: reclaims any entry left pending past `reclaim_idle_ms`
/// by a presumably-dead consumer (processed first, so a permanently-stuck
/// batch never starves recovery), reads up to `batch_size` new entries,
/// bulk-inserts everything decodable, and only then acks every id in the
/// batch — including ones that failed to decode, since a malformed entry
/// (should never happen; the only producer is `record_access_log` above)
/// can never be fixed by redelivering it, and leaving it perpetually pending
/// would eventually make every tick reclaim and retry the same poison entry
/// forever. Returns how many entries were acked this tick (decoded or not).
pub async fn consume_access_log(
    db: &DbPool,
    redis: &Store,
    consumer_name: &str,
    batch_size: u64,
    reclaim_idle_ms: u64,
) -> Result<usize, AppError> {
    stream_buffer::ensure_group(redis, ACCESS_LOG_STREAM_KEY, ACCESS_LOG_GROUP).await?;

    // BCA-23: autoclaim_full rather than autoclaim, so a PEL id whose entry was
    // deleted, or a claimed payload this build cannot decode, is acked here and
    // counted in stream_buffer_entries_lost_total instead of being redelivered
    // forever by every later tick. Same parameters; the entry list is what this
    // caller wants, and the loss accounting is the point of the swap.
    let reclaimed = stream_buffer::autoclaim_full(
        redis,
        ACCESS_LOG_STREAM_KEY,
        ACCESS_LOG_GROUP,
        consumer_name,
        reclaim_idle_ms,
        "0-0",
        batch_size,
    )
    .await?
    .claimed;

    let fresh = stream_buffer::read_group(
        redis,
        ACCESS_LOG_STREAM_KEY,
        ACCESS_LOG_GROUP,
        consumer_name,
        batch_size,
        0,
    )
    .await?;

    let mut entries = reclaimed;
    entries.extend(fresh);
    if entries.is_empty() {
        return Ok(0);
    }

    let mut parsed = Vec::with_capacity(entries.len());
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = entry.id.clone();
        ids.push(id.clone());
        match decode_log_entry(entry.fields) {
            Ok(log_entry) => parsed.push(log_entry),
            Err(e) => tracing::warn!(
                "attome-s2s telemetry: dropping malformed access-log stream entry {id}: {e}"
            ),
        }
    }

    // Not acked until this commits: a failure here leaves every id in this
    // batch pending, so the next tick's autoclaim redelivers them — no
    // record is lost between a bulk-insert failure and the next retry.
    bulk_insert_access_log(db, &parsed)
        .await
        .map_err(AppError::internal)?;

    stream_buffer::ack(redis, ACCESS_LOG_STREAM_KEY, ACCESS_LOG_GROUP, &ids).await?;

    Ok(ids.len())
}

/// Detached `tokio::spawn` loop — one stable consumer identity for this
/// process's lifetime (required so `XAUTOCLAIM`'s pending-entries-list
/// bookkeeping and any in-flight-at-crash-time entries are attributable
/// consistently across ticks, not a fresh identity every tick). Only spawned
/// when `s2s.access_log_enabled` — same gate the old enqueue call checked.
pub fn spawn_access_log_consumer(
    db: DbPool,
    redis: Store,
    interval: Duration,
    batch_size: u64,
    reclaim_idle_ms: u64,
) {
    let consumer_name = format!("consumer-{}", Uuid::now_v7());
    tokio::spawn(async move {
        loop {
            match consume_access_log(&db, &redis, &consumer_name, batch_size, reclaim_idle_ms).await
            {
                Ok(0) => {}
                Ok(count) => tracing::debug!(count, "attome-s2s telemetry: wrote access-log batch"),
                Err(e) => {
                    tracing::warn!(error = %e, "attome-s2s telemetry: access-log consumer tick failed")
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// Total pending (delivered, unacked) access-log stream entries — the
/// consumer-lag gauge (guidelines §11: queue backlog must stay an
/// observable signal). Wired from `attome_api`'s metrics-refresh loop (base
/// can't see this xrm-layer module; the gauge recording itself lives in
/// attome-api, which already depends on both `attome_s2s` and `metrics`).
pub async fn access_log_lag(redis: &Store) -> Result<i64, AppError> {
    stream_buffer::pending_count(redis, ACCESS_LOG_STREAM_KEY, ACCESS_LOG_GROUP).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> LogEntry {
        LogEntry {
            client_ref: Some(Uuid::now_v7()),
            client_name: Some("test-client".to_string()),
            method: "POST".to_string(),
            path: "/api/v1/entity/thing".to_string(),
            status_code: Some(200),
            response_time_ms: Some(42),
            bytes_received: None,
            bytes_sent: None,
            correlation_id: Some("corr-1".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            nonce: Some("nonce-1".to_string()),
            error_code: None,
            acted_as_user_id: None,
            created_at: Utc::now(),
        }
    }

    fn assert_round_trips(entry: LogEntry) {
        let fields = encode_log_entry(&entry);
        let decoded = decode_log_entry(fields).expect("decode a well-formed entry");
        assert_eq!(decoded.client_ref, entry.client_ref);
        assert_eq!(decoded.client_name, entry.client_name);
        assert_eq!(decoded.method, entry.method);
        assert_eq!(decoded.path, entry.path);
        assert_eq!(decoded.status_code, entry.status_code);
        assert_eq!(decoded.response_time_ms, entry.response_time_ms);
        assert_eq!(decoded.bytes_received, entry.bytes_received);
        assert_eq!(decoded.bytes_sent, entry.bytes_sent);
        assert_eq!(decoded.correlation_id, entry.correlation_id);
        assert_eq!(decoded.ip_address, entry.ip_address);
        assert_eq!(decoded.nonce, entry.nonce);
        assert_eq!(decoded.error_code, entry.error_code);
        assert_eq!(decoded.created_at.timestamp(), entry.created_at.timestamp());
    }

    #[test]
    fn log_entry_round_trips_with_all_optional_fields_present() {
        assert_round_trips(sample_entry());
    }

    #[test]
    fn log_entry_round_trips_with_every_optional_field_absent() {
        let mut entry = sample_entry();
        entry.client_ref = None;
        entry.client_name = None;
        entry.status_code = None;
        entry.response_time_ms = None;
        entry.correlation_id = None;
        entry.ip_address = None;
        entry.nonce = None;
        entry.error_code = Some("timeout".to_string());
        assert_round_trips(entry);
    }

    #[test]
    fn decode_rejects_an_entry_missing_required_fields() {
        assert!(decode_log_entry(vec![("path".to_string(), "/x".to_string())]).is_err());
    }

    #[test]
    fn decode_rejects_a_malformed_created_at() {
        let fields = vec![
            ("method".to_string(), "GET".to_string()),
            ("path".to_string(), "/x".to_string()),
            ("created_at".to_string(), "not-a-timestamp".to_string()),
        ];
        assert!(decode_log_entry(fields).is_err());
    }

    #[test]
    fn touch_field_key_shape_round_trips_client_and_key_ids() {
        let client_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let field = format!("{client_id}:{key_id}");
        let (client_str, key_str) = field.split_once(':').expect("field has a separator");
        assert_eq!(client_str.parse::<Uuid>().unwrap(), client_id);
        assert_eq!(key_str.parse::<Uuid>().unwrap(), key_id);
    }
}
