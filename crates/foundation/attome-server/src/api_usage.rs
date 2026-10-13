//! M61 Phase 1 (API Management, D-438) — per-route/per-identity request
//! counters. Same write-coalescing shape as `apikey_touch.rs`, but summed
//! (`write_coalesce::incr`/`HINCRBY`) rather than overwritten
//! (`write_coalesce::set`/`HSET`): every authenticated request adds one to a
//! Redis-buffered counter keyed by (day, method, route template, caller
//! identity), and a nightly `PlatformJob::ApiUsageRollup` tick
//! (`crates/server/src/jobs.rs`) drains the buffer into `api_usage`
//! (migration `0234_xrm_core_api_usage.sql`) — counts only, never a request
//! payload, header, or query string.
//!
//! One hash key, not one per day (`attome-server:api-usage:pending`): the day
//! is encoded *inside* each field rather than in the key name, so the
//! rollup job has exactly one key to `drain` regardless of how many
//! distinct days currently have unflushed data (today's, plus yesterday's if
//! a tick was ever missed) — no separate "which day-keys exist" index to
//! maintain. The flush claims that one key whole (see BSV-F20 below).
//!
//! BSV-F20 (A10) — a flush never loses what it drained. The pending hash is
//! claimed by `RENAME` into a staging key ([`STAGING_KEY`]), and the staging
//! key is deleted only after the upsert commits. A run whose insert fails
//! leaves the staging key in place, and the next run upserts it before it
//! claims anything new, so a DB error delays the counts instead of dropping
//! them. The nightly job runs on one worker at a time (the periodic
//! schedule's row CAS, D-618); two concurrent flushers could upsert the same
//! staging hash twice.
//!
//! Best-effort, not durable: `write_coalesce::incr` refreshes a defensive TTL
//! on every write so a buffer nobody ever flushes still self-expires rather
//! than growing unbounded (guidelines §5, D-027's "coherence concern,
//! degrade-and-recover" class — this is analytics, not a security control,
//! so losing an unflushed window is an accepted tradeoff, same posture
//! `apikey_touch`'s `last_used_at` staleness already accepts).

use attome_cache::{RedisPool, write_coalesce};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDate;
use fred::interfaces::{KeysInterface, LuaInterface};
use std::time::Duration;
use uuid::Uuid;

pub const HASH_KEY: &str = "attome-server:api-usage:pending";
/// Where a flush holds the counts it claimed until its upsert commits. `RENAME`
/// carries the pending hash's TTL over, so an abandoned staging hash still
/// self-expires.
pub const STAGING_KEY: &str = "attome-server:api-usage:flushing";
/// attome-cache's background bound: a flush is background work.
const CLAIM_TIMEOUT: Duration = attome_cache::timeouts::BACKGROUND;
/// A leftover staging hash is flushed first; the pending hash is renamed onto
/// it only once it is gone, so a failed run's counts are never overwritten.
///
/// KEYS[1] = pending, KEYS[2] = staging
const CLAIM_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[2]) == 0 then
  if redis.call('EXISTS', KEYS[1]) == 0 then
    return {}
  end
  redis.call('RENAME', KEYS[1], KEYS[2])
end
return redis.call('HGETALL', KEYS[2])
"#;
/// 3 days: comfortably longer than the once/day rollup interval
/// (`crates/server/src/jobs.rs::spawn_api_usage_rollup_scheduler`), so a
/// single missed tick never loses data — only a sustained multi-day outage
/// of both the worker and Redis persistence would.
const BUFFER_TTL_SECS: i64 = 3 * 24 * 60 * 60;
/// Record-separator (`\x1e`) — not a character any route template, HTTP
/// method, or UUID can contain, so splitting on it back into fields is
/// unambiguous without escaping.
const FIELD_SEP: char = '\u{1e}';

/// Who made the request, at the granularity `api_usage` aggregates
/// by. `ApiKey`/`User` carry the same `Uuid` shape but are never conflated —
/// `identity_kind` keeps them distinguishable in storage, since a UUID alone
/// doesn't say which table it came from.
#[derive(Debug, Clone, Copy)]
pub enum Identity {
    ApiKey(Uuid),
    User(Uuid),
    Anonymous,
}

impl Identity {
    fn kind(&self) -> &'static str {
        match self {
            Identity::ApiKey(_) => "api_key",
            Identity::User(_) => "user",
            Identity::Anonymous => "anonymous",
        }
    }

    fn label(&self) -> String {
        match self {
            Identity::ApiKey(id) | Identity::User(id) => id.to_string(),
            Identity::Anonymous => "anonymous".to_string(),
        }
    }
}

fn encode_field(day: NaiveDate, method: &str, route_template: &str, identity: &Identity) -> String {
    format!(
        "{day}{FIELD_SEP}{method}{FIELD_SEP}{route_template}{FIELD_SEP}{}{FIELD_SEP}{}",
        identity.kind(),
        identity.label()
    )
}

struct DecodedField {
    day: NaiveDate,
    method: String,
    route_template: String,
    identity_kind: String,
    identity_label: String,
}

fn decode_field(field: &str) -> Option<DecodedField> {
    let mut parts = field.splitn(5, FIELD_SEP);
    let day = parts.next()?.parse().ok()?;
    let method = parts.next()?.to_string();
    let route_template = parts.next()?.to_string();
    let identity_kind = parts.next()?.to_string();
    let identity_label = parts.next()?.to_string();
    Some(DecodedField {
        day,
        method,
        route_template,
        identity_kind,
        identity_label,
    })
}

/// Records one request against `route_template` by `identity` on `day` —
/// best-effort, callers should log a warning and continue rather than fail
/// the request over a telemetry write (same posture as `apikey_touch::
/// record_touch`).
pub async fn record(
    redis: &RedisPool,
    day: NaiveDate,
    method: &str,
    route_template: &str,
    identity: &Identity,
) -> Result<(), AppError> {
    let field = encode_field(day, method, route_template, identity);
    write_coalesce::incr(redis, HASH_KEY, &field, 1, BUFFER_TTL_SECS).await
}

/// Drains the usage buffer and upserts every distinct (day, method, route,
/// identity) counter into `api_usage` in one bulk statement per claim
/// (guidelines §14 — no N+1), summing into any existing row for the same key
/// rather than replacing it. A staging hash left by a failed run is flushed
/// before the pending hash is claimed (see the module doc). Returns how many
/// distinct (day, method, route, identity) rows were flushed.
pub async fn flush(db: &DbPool, redis: &RedisPool) -> Result<usize, AppError> {
    let mut rows = 0;
    // At most two claims: a leftover staging hash, then the pending one.
    for _ in 0..2 {
        let claimed = claim(redis).await?;
        if claimed.is_empty() {
            break;
        }
        rows += upsert(db, claimed).await?;
        release(redis).await?;
    }
    Ok(rows)
}

async fn claim(redis: &RedisPool) -> Result<Vec<(String, String)>, AppError> {
    let flat: Vec<String> = tokio::time::timeout(
        CLAIM_TIMEOUT,
        redis.eval(
            CLAIM_SCRIPT,
            vec![HASH_KEY.to_owned(), STAGING_KEY.to_owned()],
            Vec::<String>::new(),
        ),
    )
    .await
    .map_err(|_| AppError::internal("api_usage: claiming the usage buffer timed out"))?
    .map_err(|e| AppError::internal(format!("api_usage: claiming the usage buffer failed: {e}")))?;
    Ok(flat
        .chunks_exact(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect())
}

async fn release(redis: &RedisPool) -> Result<(), AppError> {
    let _: i64 = tokio::time::timeout(CLAIM_TIMEOUT, redis.del(STAGING_KEY))
        .await
        .map_err(|_| AppError::internal("api_usage: releasing the staging buffer timed out"))?
        .map_err(|e| {
            AppError::internal(format!(
                "api_usage: releasing the staging buffer failed: {e}"
            ))
        })?;
    Ok(())
}

async fn upsert(db: &DbPool, drained: Vec<(String, String)>) -> Result<usize, AppError> {
    let mut usage_dates = Vec::with_capacity(drained.len());
    let mut methods = Vec::with_capacity(drained.len());
    let mut routes = Vec::with_capacity(drained.len());
    let mut kinds = Vec::with_capacity(drained.len());
    let mut labels = Vec::with_capacity(drained.len());
    let mut counts: Vec<i64> = Vec::with_capacity(drained.len());

    for (field, value) in drained {
        let Some(decoded) = decode_field(&field) else {
            tracing::warn!("api_usage: dropping malformed field in usage buffer: {field:?}");
            continue;
        };
        let Ok(count) = value.parse::<i64>() else {
            tracing::warn!("api_usage: dropping malformed count in usage buffer: {value:?}");
            continue;
        };
        usage_dates.push(decoded.day);
        methods.push(decoded.method);
        routes.push(decoded.route_template);
        kinds.push(decoded.identity_kind);
        labels.push(decoded.identity_label);
        counts.push(count);
    }
    if usage_dates.is_empty() {
        return Ok(0);
    }

    let rows = usage_dates.len();
    sqlx::query(
        r#"
        INSERT INTO api_usage
            (id, usage_date, method, route_template, identity_kind, identity_label, request_count, updated_at)
        SELECT uuidv7(), v.usage_date, v.method, v.route_template, v.identity_kind, v.identity_label, v.request_count, NOW()
        FROM UNNEST($1::date[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[])
            AS v(usage_date, method, route_template, identity_kind, identity_label, request_count)
        ON CONFLICT (usage_date, method, route_template, identity_kind, identity_label)
        DO UPDATE SET request_count = api_usage.request_count + EXCLUDED.request_count,
                       updated_at = NOW()
        "#,
    )
    .bind(&usage_dates)
    .bind(&methods)
    .bind(&routes)
    .bind(&kinds)
    .bind(&labels)
    .bind(&counts)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 8, 28).expect("valid date")
    }

    #[test]
    fn a_field_round_trips_through_encode_decode_for_every_identity_kind() {
        for identity in [
            Identity::ApiKey(Uuid::now_v7()),
            Identity::User(Uuid::now_v7()),
            Identity::Anonymous,
        ] {
            let encoded = encode_field(day(), "GET", "/api/v1/{entity}", &identity);
            let decoded = decode_field(&encoded).expect("field must decode");
            assert_eq!(decoded.day, day());
            assert_eq!(decoded.method, "GET");
            assert_eq!(decoded.route_template, "/api/v1/{entity}");
            assert_eq!(decoded.identity_kind, identity.kind());
            assert_eq!(decoded.identity_label, identity.label());
        }
    }

    #[test]
    fn distinct_identities_never_encode_to_the_same_field() {
        let id = Uuid::now_v7();
        let api_key = encode_field(day(), "GET", "/api/v1/{entity}", &Identity::ApiKey(id));
        let user = encode_field(day(), "GET", "/api/v1/{entity}", &Identity::User(id));
        assert_ne!(
            api_key, user,
            "the same uuid as an api key vs a user must not collide in the buffer"
        );
    }

    #[test]
    fn decode_rejects_a_malformed_field() {
        assert!(decode_field("not-enough-parts").is_none());
        assert!(decode_field("").is_none());
    }

    #[test]
    fn decode_rejects_an_unparseable_date() {
        assert!(decode_field("not-a-date\u{1e}GET\u{1e}/x\u{1e}user\u{1e}abc").is_none());
    }
}
