//! S8-T4: which API version each API key and S2S client calls, route by
//! route, so an administrator can see who still calls a deprecated version
//! or route before it goes.
//!
//! The `api_version` layer counts one per call by an API key or an S2S
//! client (a browser always gets the current version) into a Redis buffer
//! keyed by (day, caller, version, route template, deprecated), the same
//! write-coalescing shape as [`crate::api_usage`]. The nightly
//! `ApiUsageRollup` job drains it into `api_version_usage` (migration 0251)
//! through the same claim-then-release steps, so a failed upsert delays the
//! counts instead of dropping them. Counts only: never a payload, header or
//! query string. Best-effort analytics: a Redis failure is logged and the
//! request goes on.

use attome_cache::{Store, write_coalesce};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::NaiveDate;
use uuid::Uuid;

pub const HASH_KEY: &str = "attome-server:api-version-usage:pending";
pub const STAGING_KEY: &str = "attome-server:api-version-usage:flushing";
/// Longer than the once-a-day rollup, as for `api_usage`.
const BUFFER_TTL_SECS: i64 = 3 * 24 * 60 * 60;
const FIELD_SEP: char = '\u{1e}';

/// Who called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    ApiKey(Uuid),
    S2sClient(Uuid),
}

impl Caller {
    fn kind(self) -> &'static str {
        match self {
            Self::ApiKey(_) => "api_key",
            Self::S2sClient(_) => "s2s_client",
        }
    }

    fn id(self) -> Uuid {
        match self {
            Self::ApiKey(id) | Self::S2sClient(id) => id,
        }
    }
}

/// One counter's buffer field. Pure.
pub fn encode_field(
    day: NaiveDate,
    caller: Caller,
    version: &str,
    route_template: &str,
    deprecated: bool,
) -> String {
    format!(
        "{day}{FIELD_SEP}{}{FIELD_SEP}{}{FIELD_SEP}{version}{FIELD_SEP}{}{FIELD_SEP}{route_template}",
        caller.kind(),
        caller.id(),
        u8::from(deprecated),
    )
}

/// A buffer field read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    pub day: NaiveDate,
    pub caller_kind: String,
    pub caller_id: Uuid,
    pub version: String,
    pub deprecated: bool,
    pub route_template: String,
}

/// [`encode_field`] reversed; `None` for anything malformed. Pure.
pub fn decode_field(field: &str) -> Option<Counter> {
    let mut parts = field.splitn(6, FIELD_SEP);
    let day = parts.next()?.parse().ok()?;
    let caller_kind = parts.next()?;
    if !matches!(caller_kind, "api_key" | "s2s_client") {
        return None;
    }
    let caller_id = parts.next()?.parse().ok()?;
    let version = parts.next()?.to_owned();
    let deprecated = match parts.next()? {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    let route_template = parts.next()?.to_owned();
    if version.is_empty() || route_template.is_empty() {
        return None;
    }
    Some(Counter {
        day,
        caller_kind: caller_kind.to_owned(),
        caller_id,
        version,
        deprecated,
        route_template,
    })
}

/// Counts one call; the caller logs a failure and carries on.
pub async fn record(
    redis: &Store,
    day: NaiveDate,
    caller: Caller,
    version: &str,
    route_template: &str,
    deprecated: bool,
) -> Result<(), AppError> {
    let field = encode_field(day, caller, version, route_template, deprecated);
    write_coalesce::incr(redis, HASH_KEY, &field, 1, BUFFER_TTL_SECS).await
}

/// Drains the buffer into `api_version_usage`, adding to any row already
/// there. Returns how many counters were written.
pub async fn flush(db: &DbPool, redis: &Store) -> Result<usize, AppError> {
    let mut rows = 0;
    for _ in 0..2 {
        let claimed = crate::api_usage::claim_keys(redis, HASH_KEY, STAGING_KEY).await?;
        if claimed.is_empty() {
            break;
        }
        rows += upsert(db, claimed).await?;
        crate::api_usage::release_key(redis, STAGING_KEY).await?;
    }
    Ok(rows)
}

async fn upsert(db: &DbPool, drained: Vec<(String, String)>) -> Result<usize, AppError> {
    let mut days = Vec::with_capacity(drained.len());
    let mut kinds = Vec::with_capacity(drained.len());
    let mut ids = Vec::with_capacity(drained.len());
    let mut versions = Vec::with_capacity(drained.len());
    let mut routes = Vec::with_capacity(drained.len());
    let mut deprecated = Vec::with_capacity(drained.len());
    let mut counts: Vec<i64> = Vec::with_capacity(drained.len());
    for (field, value) in drained {
        let (Some(counter), Ok(count)) = (decode_field(&field), value.parse::<i64>()) else {
            tracing::warn!("api_version_usage: dropping a malformed buffer entry");
            continue;
        };
        days.push(counter.day);
        kinds.push(counter.caller_kind);
        ids.push(counter.caller_id);
        versions.push(counter.version);
        routes.push(counter.route_template);
        deprecated.push(counter.deprecated);
        counts.push(count);
    }
    if days.is_empty() {
        return Ok(0);
    }
    let rows = days.len();
    sqlx::query(
        "INSERT INTO api_version_usage \
           (usage_date, caller_kind, caller_id, api_version, route_template, deprecated, request_count) \
         SELECT v.usage_date, v.caller_kind, v.caller_id, v.api_version, v.route_template, \
                v.deprecated, v.request_count \
         FROM UNNEST($1::date[], $2::text[], $3::uuid[], $4::text[], $5::text[], $6::bool[], \
                     $7::bigint[]) \
           AS v(usage_date, caller_kind, caller_id, api_version, route_template, deprecated, request_count) \
         ON CONFLICT (usage_date, caller_kind, caller_id, api_version, route_template) \
         DO UPDATE SET request_count = api_version_usage.request_count + EXCLUDED.request_count, \
                       deprecated = api_version_usage.deprecated OR EXCLUDED.deprecated",
    )
    .bind(&days)
    .bind(&kinds)
    .bind(&ids)
    .bind(&versions)
    .bind(&routes)
    .bind(&deprecated)
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
        NaiveDate::from_ymd_opt(2026, 10, 25).expect("valid date")
    }

    #[test]
    fn api_version_usage_field_round_trips() {
        let caller = Caller::S2sClient(Uuid::now_v7());
        let field = encode_field(day(), caller, "2026-10-01", "/api/v1/{entity}/{id}", true);
        let counter = decode_field(&field).expect("decodes");
        assert_eq!(counter.day, day());
        assert_eq!(counter.caller_kind, "s2s_client");
        assert_eq!(counter.caller_id, caller.id());
        assert_eq!(counter.version, "2026-10-01");
        assert!(counter.deprecated);
        assert_eq!(counter.route_template, "/api/v1/{entity}/{id}");
    }

    #[test]
    fn api_version_usage_keys_callers_and_versions_apart() {
        let id = Uuid::now_v7();
        let key = encode_field(day(), Caller::ApiKey(id), "v1", "/x", false);
        assert_ne!(
            key,
            encode_field(day(), Caller::S2sClient(id), "v1", "/x", false)
        );
        assert_ne!(
            key,
            encode_field(day(), Caller::ApiKey(id), "v2", "/x", false)
        );
    }

    #[test]
    fn api_version_usage_refuses_malformed_fields() {
        assert!(decode_field("").is_none());
        let good = encode_field(day(), Caller::ApiKey(Uuid::now_v7()), "v1", "/x", false);
        assert!(decode_field(&good.replacen("api_key", "user", 1)).is_none());
        assert!(decode_field(&good.replace("\u{1e}0\u{1e}", "\u{1e}x\u{1e}")).is_none());
    }

    #[tokio::test]
    async fn api_version_usage_counts_in_the_buffer() {
        let store = Store::memory();
        let caller = Caller::ApiKey(Uuid::now_v7());
        for _ in 0..3 {
            record(&store, day(), caller, "v1", "/api/v1/{entity}", true)
                .await
                .expect("counted");
        }
        let claimed = crate::api_usage::claim_keys(&store, HASH_KEY, STAGING_KEY)
            .await
            .expect("claimed");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].1, "3");
        assert!(decode_field(&claimed[0].0).is_some_and(|c| c.deprecated));
    }
}
