//! Plan 5.1: `audit_config` + attribute `is_audited`, cached and
//! consulted before the generic engine decides *whether* and *what* to
//! capture for an ordinary (non-mandatory-category) mutation.
//!
//! **Resolution order** (D-062/plan 5.1): field row -> entity row -> global
//! row -> default (audit all). A field row's `is_audited = false` excludes
//! only that field's detail row; the entity/global rows govern
//! `operation_mask` and `capture_snapshot` for the whole record.
//!
//! **Cache contract (coding-guidelines §5):**
//! - Source of truth: PostgreSQL (`audit_config`, an ordinary
//!   metadata-driven entity — reads use the generic table directly, since
//!   this crate has no dependency on the entity-CRUD query layer).
//! - Key: `attome-audit:policy:{entity}` (L2/Redis) and the same string (L1/
//!   moka), one cached [`AuditPolicy`] per entity, TTL below.
//! - TTL: 60s, matching `attome-security`'s `SecurityContextCache` precedent for
//!   a small, rarely-changed admin table (`cache.rs`) — same trade-off
//!   `module_configuration`'s hourly poll and `setting`'s
//!   change-log poll already accept for tables this shape and size.
//! - Invalidation: same-node synchronous, called by whatever writes
//!   `audit_config` right after its own commit (plan 5.2's mandatory
//!   writer) — see [`invalidate`]. Other nodes catch up on TTL expiry (a
//!   bounded staleness window is an accepted cost for policy, which governs
//!   *what gets captured*, not an access-control decision — see
//!   `module_configuration`'s identical precedent). No dedicated
//!   pub/sub channel: this table changes rarely enough that a second
//!   always-on subscriber connection per node is unearned complexity here,
//!   the same call `setting_store.rs` already made for a table this shape.
//! - Failure behavior: **fail-safe to audit all** on any Postgres or Redis
//!   error, or a cold cache that fails to populate — the opposite direction
//!   from the usual security "fail closed to deny," because for an audit
//!   trail, over-capturing is safe and under-capturing is the actual
//!   security defect (a missing event is unrecoverable; a redundant one
//!   is not). Never fails open to "don't audit."

use std::collections::HashSet;
use std::time::Duration;

use attome_cache::{HotCache, create_hot_cache};
use attome_core::EngineState;
use sqlx::Row;

use crate::model::AuditOperation;

const TTL_SECS: u64 = 60;
const MAX_ENTRIES: u64 = 2048;
const REDIS_PREFIX: &str = "attome-audit:policy";
/// Deliberately tighter than `attome_cache::timeouts::REQUEST_PATH`: every call is a
/// cache read/write/delete whose miss falls back to L1 or the database.
const OP_TIMEOUT: Duration = Duration::from_millis(200);

/// `audit_config.operation_mask` bit convention (plan 5.1; no prior
/// convention existed, defined here since this is the column's first real
/// consumer). Bits not listed are reserved; an unset bit for an operation not
/// in this list is never checked, so unknown operations always pass (the
/// mask only ever narrows, never widens, capture — same fail-safe posture as
/// the rest of this module).
const MASK_CREATE: i32 = 1 << 0;
const MASK_UPDATE: i32 = 1 << 1;
const MASK_SOFT_DELETE: i32 = 1 << 2;
const MASK_HARD_DELETE: i32 = 1 << 3;
const MASK_RESTORE: i32 = 1 << 4;
const MASK_ALL: i32 =
    MASK_CREATE | MASK_UPDATE | MASK_SOFT_DELETE | MASK_HARD_DELETE | MASK_RESTORE;

fn mask_bit(operation: AuditOperation) -> Option<i32> {
    match operation {
        AuditOperation::Create => Some(MASK_CREATE),
        AuditOperation::Update => Some(MASK_UPDATE),
        AuditOperation::SoftDelete => Some(MASK_SOFT_DELETE),
        AuditOperation::HardDelete => Some(MASK_HARD_DELETE),
        AuditOperation::Restore => Some(MASK_RESTORE),
        _ => None,
    }
}

/// The resolved policy for one entity. Cheap to clone (small, no heap beyond
/// the field-exclusion set, which is almost always empty).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditPolicy {
    pub is_audited: bool,
    pub operation_mask: i32,
    pub capture_snapshot: bool,
    pub excluded_fields: HashSet<String>,
}

impl AuditPolicy {
    /// The fail-safe default: every operation, every field, snapshots
    /// included. Used when no config row exists for an entity, and on any
    /// resolution error.
    pub fn audit_all() -> Self {
        Self {
            is_audited: true,
            operation_mask: MASK_ALL,
            capture_snapshot: true,
            excluded_fields: HashSet::new(),
        }
    }

    /// Plan 5.2: a mandatory-category event is never subject to this policy
    /// at all — call this only for ordinary (non-mandatory) writes.
    pub fn permits(&self, operation: AuditOperation) -> bool {
        if !self.is_audited {
            return false;
        }
        match mask_bit(operation) {
            Some(bit) => self.operation_mask & bit != 0,
            // An operation this mask has no bit for (bulk parent events,
            // business events, …) is never gated by it.
            None => true,
        }
    }

    pub fn field_excluded(&self, field_name: &str) -> bool {
        self.excluded_fields.contains(field_name)
    }
}

fn redis_key(entity_name: &str) -> String {
    format!("{REDIS_PREFIX}:{entity_name}")
}

/// One process-wide L1. `attome-security::cache` and `attome-ai`'s session cache
/// both keep their hot cache on a per-instance struct threaded through
/// `EngineState`; this resolver is a free function consulted from deep inside
/// `attome-records`'s mutation path with only `&EngineState` in hand, so a
/// `OnceLock` keeps the call site a plain function call rather than needing
/// a new field threaded onto `EngineState` for a cache this narrow.
static L1: std::sync::OnceLock<HotCache<AuditPolicy>> = std::sync::OnceLock::new();

fn l1() -> &'static HotCache<AuditPolicy> {
    L1.get_or_init(|| create_hot_cache(MAX_ENTRIES, TTL_SECS))
}

/// Resolves the effective policy for `entity_name`. Fail-safe: any Postgres
/// or Redis error, or the absence of a row, resolves to
/// [`AuditPolicy::audit_all`] — this function never returns an `Err` that
/// would let a caller skip auditing by accident.
pub async fn resolve(state: &EngineState, entity_name: &str) -> AuditPolicy {
    if let Some(policy) = l1().get(&redis_key(entity_name)).await {
        return policy;
    }

    if let Ok(Ok(Some(json))) =
        tokio::time::timeout(OP_TIMEOUT, state.base.redis.get(&redis_key(entity_name))).await
        && let Ok(policy) = serde_json::from_str::<AuditPolicy>(&json)
    {
        l1().insert(redis_key(entity_name), policy.clone()).await;
        return policy;
    }

    let policy = resolve_from_db(state, entity_name)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                entity = entity_name,
                "audit policy resolution failed — failing safe to audit_all",
            );
            AuditPolicy::audit_all()
        });

    if let Ok(json) = serde_json::to_string(&policy) {
        let _ = tokio::time::timeout(
            OP_TIMEOUT,
            state.base.redis.set(
                &redis_key(entity_name),
                &json,
                Some(std::time::Duration::from_secs(TTL_SECS)),
            ),
        )
        .await;
    }
    l1().insert(redis_key(entity_name), policy.clone()).await;

    policy
}

async fn resolve_from_db(
    state: &EngineState,
    entity_name: &str,
) -> Result<AuditPolicy, sqlx::Error> {
    // Field, entity and global rows in one query — cheapest single
    // round-trip that still lets us apply the field -> entity -> global
    // precedence in Rust, where the resolution rule is easy to read and test.
    let rows = sqlx::query(
        "SELECT entity_name, field_name, operation_mask, is_audited, capture_snapshot \
         FROM audit_config \
         WHERE is_active IS NOT FALSE AND (entity_name = $1 OR entity_name IS NULL)",
    )
    .bind(entity_name)
    .fetch_all(&state.base.db)
    .await?;

    let mut entity_row: Option<(Option<i32>, Option<bool>, Option<bool>)> = None;
    let mut global_row: Option<(Option<i32>, Option<bool>, Option<bool>)> = None;
    let mut excluded_fields = HashSet::new();

    for row in &rows {
        let row_entity_name: Option<String> = row.try_get("entity_name")?;
        let field_name: Option<String> = row.try_get("field_name")?;
        let operation_mask: Option<i32> = row.try_get("operation_mask")?;
        let is_audited: Option<bool> = row.try_get("is_audited")?;
        let capture_snapshot: Option<bool> = row.try_get("capture_snapshot")?;

        match field_name {
            // A field-level row always names its own entity (there is no
            // "global field" row) — filtered by the query's WHERE clause to
            // already be this entity's.
            Some(field_name) => {
                if is_audited == Some(false) {
                    excluded_fields.insert(field_name);
                }
            }
            // No field_name: this is either the entity-level row
            // (entity_name = $1) or the one global row (entity_name IS NULL)
            // — never both, since the query only ever returns one of each.
            None => {
                let slot = if row_entity_name.is_some() {
                    &mut entity_row
                } else {
                    &mut global_row
                };
                *slot = Some((operation_mask, is_audited, capture_snapshot));
            }
        }
    }

    let (operation_mask, is_audited, capture_snapshot) =
        entity_row
            .or(global_row)
            .unwrap_or((Some(MASK_ALL), Some(true), Some(true)));

    Ok(AuditPolicy {
        is_audited: is_audited.unwrap_or(true),
        operation_mask: operation_mask.unwrap_or(MASK_ALL),
        capture_snapshot: capture_snapshot.unwrap_or(true),
        excluded_fields,
    })
}

/// Called by whatever writes `audit_config` right after its own commit
/// (plan 5.2). Clears this node's L1 immediately (same-node reads are never
/// stale) and best-effort clears L2 (a failure here just means other nodes,
/// and this one on an L1 miss before the next write, see the stale entry for
/// up to `TTL_SECS` — the same accepted window `setting_store.rs`/
/// `module_configuration` already use for a table this shape).
pub async fn invalidate(state: &EngineState, entity_name: &str) {
    l1().invalidate(&redis_key(entity_name)).await;
    let _ = tokio::time::timeout(OP_TIMEOUT, state.base.redis.del(&redis_key(entity_name))).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_all_permits_every_masked_operation() {
        let p = AuditPolicy::audit_all();
        assert!(p.permits(AuditOperation::Create));
        assert!(p.permits(AuditOperation::Update));
        assert!(p.permits(AuditOperation::SoftDelete));
        assert!(p.permits(AuditOperation::HardDelete));
        assert!(p.permits(AuditOperation::Restore));
    }

    #[test]
    fn is_audited_false_blocks_every_operation_regardless_of_mask() {
        let p = AuditPolicy {
            is_audited: false,
            operation_mask: MASK_ALL,
            capture_snapshot: true,
            excluded_fields: HashSet::new(),
        };
        assert!(!p.permits(AuditOperation::Create));
    }

    #[test]
    fn operation_mask_narrows_specific_operations_only() {
        let p = AuditPolicy {
            is_audited: true,
            operation_mask: MASK_UPDATE, // only Update
            capture_snapshot: true,
            excluded_fields: HashSet::new(),
        };
        assert!(!p.permits(AuditOperation::Create));
        assert!(p.permits(AuditOperation::Update));
        assert!(!p.permits(AuditOperation::SoftDelete));
    }

    #[test]
    fn an_operation_outside_the_mask_convention_is_never_gated() {
        let p = AuditPolicy {
            is_audited: true,
            operation_mask: 0, // nothing set
            capture_snapshot: true,
            excluded_fields: HashSet::new(),
        };
        // BulkAccepted etc. have no mask bit -- never gated by operation_mask.
        assert!(p.permits(AuditOperation::BulkAccepted));
    }

    #[test]
    fn field_exclusion_is_exact_match_only() {
        let mut p = AuditPolicy::audit_all();
        p.excluded_fields.insert("salary".to_owned());
        assert!(p.field_excluded("salary"));
        assert!(!p.field_excluded("email"));
    }
}
