//! Redis/Dragonfly persistence probe (D-685) — answers "would this instance's
//! keyspace survive a restart?" so the deployment can alarm on the answer
//! instead of assuming it.
//!
//! **Why this exists.** `stream_buffer`'s at-least-once delivery and
//! `xrm_s2s`'s replay nonces (`s2s:nonce:{client}:{nonce}`, `SET NX EX 300`)
//! are both only as durable as the store under them, and that store's
//! persistence is a deployment-level setting no client can enforce.
//! Originally found manually 2026-08-12 against this repo's own dev
//! Dragonfly: no persistence flag was set on ANY Dragonfly service, `/data`
//! was empty, and `rdb_changes_since_last_success_save` stood at 16639 —
//! every restart dropped the whole keyspace, including in-window replay
//! nonces. Compose now sets `--snapshot_cron`; this probe is what makes a
//! *regression* of that setting visible rather than silent.
//!
//! **Verification against Dragonfly is a local gate, not CI.** The
//! `dragonfly-integration` CI job ran `tests/persistence.rs` (3/3) against
//! Dragonfly from 2026-09-13 until CI was retired (956ef9247). Nothing
//! re-runs it automatically now:
//! `scripts/test-attome-cache-backends.ps1` runs it against every
//! Dragonfly/Redis image `docker-compose.yml` pins (attome-cache-hardening.md
//! Phase 3), and CLAUDE.md's cadence table requires that for any change here.
//!
//! **What it can and cannot tell you.** It reports whether a persistence
//! policy is configured and how stale the last successful save is. It cannot
//! make any individual write durable: Dragonfly has no AOF and does not
//! implement `WAIT` (both verified live on df-v1.39.0, still true of the pinned
//! image), so the honest guarantee is "loss is bounded by the snapshot
//! interval", never "nothing is lost". Code that needs a real per-write
//! guarantee must write to PostgreSQL.
//!
//! **Portability.** Deliberately understands both servers, because this repo
//! runs Dragonfly in dev/production and real Redis in the `test` profile. The
//! field names below were captured on df-v1.39.0; `scripts/test-attome-cache-backends.ps1`
//! re-probes them on the image `docker-compose.yml` actually pins, so a field
//! rename in a newer Dragonfly fails the matrix rather than silently blinding
//! the alarm:
//!
//! | | Dragonfly (df-v2.0.0 pin) | Redis 7 |
//! |---|---|---|
//! | policy | `CONFIG GET snapshot_cron` | `CONFIG GET save` / `appendonly` |
//! | changes | `rdb_changes_since_last_success_save` | `rdb_changes_since_last_save` |
//! | last save | `last_success_save` | `rdb_last_save_time` |
//!
//! Both servers answer an unknown `CONFIG GET` parameter with an empty reply
//! rather than an error (verified live on both), so the probe simply asks for
//! all three keys and treats any non-empty answer as a configured policy — no
//! server-type detection, nothing to keep in sync with a version matrix.

use attome_types::AppError;
use fred::prelude::*;
use fred::types::{ClusterHash, CustomCommand, InfoKind};

use crate::ops::{self, Primitive};
// Matches the crate's background bound (BCA-13) — this runs on a
// metrics-refresh tick, so it must never outlive its interval waiting on a
// wedged connection.
use crate::timeouts::BACKGROUND;

/// A point-in-time answer to "would this keyspace survive a restart?".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersistenceStatus {
    /// Some persistence policy is configured (Dragonfly `snapshot_cron`, or
    /// Redis `save`/`appendonly yes`). `false` is the actionable alarm: the
    /// instance is running purely in memory.
    pub policy_configured: bool,
    /// Writes accumulated since the last successful save. Large and growing
    /// while `policy_configured` is true means saves are configured but
    /// failing — a different operator response than "no policy at all".
    pub changes_since_last_save: Option<i64>,
    /// Unix seconds of the last successful save, if one has ever completed.
    pub last_success_save: Option<i64>,
}

/// Reads `INFO persistence` and the three policy keys from `redis`.
///
/// Errors only on a failed/timed-out `INFO`; an unreadable `CONFIG GET` is
/// downgraded to "no policy" rather than propagated, deliberately — a server
/// that refuses `CONFIG` (ACL-restricted, or a managed provider that hides it)
/// should raise the persistence alarm for a human to confirm, not blind the
/// whole metrics tick by erroring out of the `INFO` result too.
pub async fn probe(store: &crate::store::Store) -> Result<PersistenceStatus, AppError> {
    // The in-process store has no snapshot policy to report, and its loss on
    // restart is by design (caches, windows and nonces are all short-lived), so
    // the "running purely in memory" alarm does not apply to it.
    let redis = match store {
        crate::store::Store::Redis(pool) => pool,
        crate::store::Store::Memory(_) => {
            return Ok(PersistenceStatus {
                policy_configured: true,
                changes_since_last_save: None,
                last_success_save: None,
            });
        }
    };
    let attempt = tokio::time::timeout(BACKGROUND, redis.info(Some(InfoKind::Persistence))).await;
    ops::record_op(Primitive::Persistence, &attempt);
    let raw: String = attempt
        .map_err(|_| AppError::internal("persistence probe: INFO timed out"))?
        .map_err(|e| AppError::internal(format!("persistence probe: INFO failed: {e}")))?;

    let mut status = parse_persistence_info(&raw);
    status.policy_configured = policy_configured(redis).await;
    Ok(status)
}

/// True when any of the three policy keys has a non-empty value. `save` needs
/// the extra emptiness check: Redis with snapshotting disabled still answers
/// `CONFIG GET save`, just with an empty string, so key-presence alone would
/// read a deliberately-unpersisted Redis as persistent.
async fn policy_configured(redis: &RedisPool) -> bool {
    for (param, is_enabled) in [
        (
            "snapshot_cron",
            (|v: &str| !v.is_empty()) as fn(&str) -> bool,
        ),
        ("save", |v: &str| !v.trim().is_empty()),
        ("appendonly", |v: &str| v.eq_ignore_ascii_case("yes")),
    ] {
        match config_get(redis, param).await {
            Ok(Some(value)) if is_enabled(&value) => return true,
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("persistence probe: CONFIG GET {param} failed: {e}");
            }
        }
    }
    false
}

/// `CONFIG GET <param>` through fred's escape hatch — `ConfigInterface` sits
/// behind the `i-config` feature this workspace does not enable, and enabling
/// a whole feature for one read-only diagnostic is not worth the compile
/// surface. Returns `Ok(None)` for an unknown parameter (both servers reply
/// with an empty array rather than an error — verified live on df-v1.39.0 and
/// redis:7).
async fn config_get(redis: &RedisPool, param: &str) -> Result<Option<String>, AppError> {
    let cmd = CustomCommand::new("CONFIG", ClusterHash::Random, false);
    let attempt = tokio::time::timeout(
        BACKGROUND,
        redis.custom(cmd, vec!["GET".to_string(), param.to_string()]),
    )
    .await;
    ops::record_op(Primitive::Persistence, &attempt);
    let reply: Vec<String> = attempt
        .map_err(|_| {
            AppError::internal(format!("persistence probe: CONFIG GET {param} timed out"))
        })?
        .map_err(|e| {
            AppError::internal(format!("persistence probe: CONFIG GET {param} failed: {e}"))
        })?;

    // Reply shape is a flat [name, value] pair; an unknown parameter yields [].
    Ok(reply.into_iter().nth(1))
}

/// Pure parser over an `INFO persistence` body. Accepts either server's field
/// names for the same two facts (see this module's doc comment) and ignores
/// everything else, so a new field in either server can never break it.
fn parse_persistence_info(body: &str) -> PersistenceStatus {
    let mut status = PersistenceStatus::default();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            // Dragonfly's name first, then Redis's — whichever the server sent.
            "rdb_changes_since_last_success_save" | "rdb_changes_since_last_save" => {
                status.changes_since_last_save = value.parse().ok();
            }
            // Both servers report 0 when no save has ever happened; treat that
            // as "never saved" rather than "saved at the epoch", so a
            // last-save-age gauge doesn't read as 56 years stale on a fresh
            // instance that simply hasn't hit its first interval yet.
            "last_success_save" | "rdb_last_save_time" => {
                status.last_success_save = value.parse().ok().filter(|&t: &i64| t > 0);
            }
            _ => {}
        }
    }

    status
}

/// A point-in-time answer to "how close is this instance to its ceiling?"
/// (BCA-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryStatus {
    /// Bytes the instance currently holds (`used_memory`).
    pub used_memory_bytes: u64,
    /// The configured ceiling in bytes (`maxmemory`), or `0` for "unset" —
    /// the actionable alarm, the same shape as
    /// [`PersistenceStatus::policy_configured`] being `false`. Before BCA-22
    /// no service in this repo set `--maxmemory` at all, so a runaway
    /// coordination keyspace would grow until the host killed it (BCA-F4).
    pub maxmemory_bytes: u64,
}

impl MemoryStatus {
    /// Fraction of the ceiling in use, or `None` when no ceiling is
    /// configured. `None` is not "fine" — it means the alert cannot fire.
    pub fn used_fraction(&self) -> Option<f64> {
        if self.maxmemory_bytes == 0 {
            None
        } else {
            Some(self.used_memory_bytes as f64 / self.maxmemory_bytes as f64)
        }
    }
}

/// Reads `INFO memory` and reports [`MemoryStatus`]. Both supported servers
/// answer with the same two field names, so — like [`probe`] — there is no
/// server-type detection to keep in sync with a version matrix.
pub async fn memory_probe(store: &crate::store::Store) -> Result<MemoryStatus, AppError> {
    let redis = match store {
        crate::store::Store::Redis(pool) => pool,
        // No separate server process: nothing to report or alarm on.
        crate::store::Store::Memory(_) => return Ok(MemoryStatus::default()),
    };
    let attempt = tokio::time::timeout(BACKGROUND, redis.info(Some(InfoKind::Memory))).await;
    ops::record_op(Primitive::Persistence, &attempt);
    let raw: String = attempt
        .map_err(|_| AppError::internal("memory probe: INFO memory timed out"))?
        .map_err(|e| AppError::internal(format!("memory probe: INFO memory failed: {e}")))?;
    Ok(parse_memory_info(&raw))
}

/// Pure parser over an `INFO memory` body. A missing or unparseable field
/// stays at its `Default` (0) rather than inventing a value — a `used_memory`
/// of 0 against a real `maxmemory` reads as an idle instance, which is the
/// safe direction for an alert, and a `maxmemory` of 0 correctly disables the
/// ratio rather than reporting a made-up ceiling.
fn parse_memory_info(body: &str) -> MemoryStatus {
    let mut status = MemoryStatus::default();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "used_memory" => status.used_memory_bytes = value.parse().unwrap_or(0),
            "maxmemory" => status.maxmemory_bytes = value.parse().unwrap_or(0),
            _ => {}
        }
    }

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured verbatim from the dev Dragonfly (df-v1.39.0) on 2026-08-12 —
    /// the actual unpersisted instance that motivated D-685, hence the large
    /// `rdb_changes_since_last_success_save` and empty `last_saved_file`.
    const DRAGONFLY_INFO: &str = "\
# Persistence
current_snapshot_perc:0
current_save_keys_processed:0
last_success_save:1786280000
last_saved_file:
last_success_save_duration_sec:0
loading:0
saving:0
rdb_changes_since_last_success_save:16639
rdb_bgsave_in_progress:0
rdb_last_bgsave_status:ok
last_failed_save:0
";

    /// Captured verbatim from the `test` profile's redis:7 on 2026-08-12.
    const REDIS_INFO: &str = "\
# Persistence
loading:0
async_loading:0
current_fork_perc:0.00
rdb_changes_since_last_save:3020
rdb_bgsave_in_progress:0
rdb_last_save_time:1786547067
rdb_last_bgsave_status:ok
rdb_saves:33
aof_enabled:0
";

    #[test]
    fn parses_dragonflys_field_names() {
        let status = parse_persistence_info(DRAGONFLY_INFO);
        assert_eq!(status.changes_since_last_save, Some(16639));
        assert_eq!(status.last_success_save, Some(1786280000));
    }

    #[test]
    fn parses_redis_field_names_for_the_same_two_facts() {
        let status = parse_persistence_info(REDIS_INFO);
        assert_eq!(status.changes_since_last_save, Some(3020));
        assert_eq!(status.last_success_save, Some(1786547067));
    }

    #[test]
    fn a_zero_last_save_time_reads_as_never_saved_not_the_epoch() {
        let status = parse_persistence_info("rdb_last_save_time:0\nrdb_changes_since_last_save:7");
        assert_eq!(
            status.last_success_save, None,
            "0 must not become a 1970 timestamp that reads as decades of staleness"
        );
        assert_eq!(status.changes_since_last_save, Some(7));
    }

    #[test]
    fn ignores_headers_blank_lines_and_unknown_fields() {
        let status = parse_persistence_info("# Persistence\n\nsome_new_field:1\nnot_a_pair\n");
        assert_eq!(status, PersistenceStatus::default());
    }

    #[test]
    fn a_malformed_value_is_dropped_rather_than_defaulted_to_zero() {
        let status = parse_persistence_info("rdb_changes_since_last_save:not-a-number");
        assert_eq!(
            status.changes_since_last_save, None,
            "an unparseable count must stay absent, never silently read as 0 pending changes"
        );
    }

    /// Captured shape from both supported servers (`INFO memory`). Dragonfly
    /// and Redis use the same two field names, which is what lets one parser
    /// cover the matrix (BCA-22).
    const MEMORY_INFO: &str = "\
# Memory
used_memory:1048576
used_memory_human:1.00M
used_memory_rss:2097152
maxmemory:8388608
maxmemory_policy:noeviction
";

    #[test]
    fn parse_memory_info_reads_used_and_max_memory() {
        let status = parse_memory_info(MEMORY_INFO);
        assert_eq!(status.used_memory_bytes, 1_048_576);
        assert_eq!(status.maxmemory_bytes, 8_388_608);
        assert_eq!(status.used_fraction(), Some(0.125));
    }

    /// No ceiling configured is a first-class answer, not a ratio of 1.0: the
    /// alert has to be able to tell "12.5 % of 8 MiB" from "no ceiling at
    /// all", which is the state BCA-22 exists to end.
    #[test]
    fn parse_memory_info_treats_an_unset_ceiling_as_no_ratio() {
        let status = parse_memory_info("used_memory:1048576\nmaxmemory:0");
        assert_eq!(status.maxmemory_bytes, 0);
        assert_eq!(status.used_fraction(), None);
    }

    /// A field this parser does not know must not become a value, and a
    /// malformed one must not become a made-up ceiling.
    #[test]
    fn parse_memory_info_ignores_unknown_and_malformed_fields() {
        let status = parse_memory_info("# Memory\n\nmem_fragmentation_ratio:1.1\nmaxmemory:oops");
        assert_eq!(status, MemoryStatus::default());
    }
}
