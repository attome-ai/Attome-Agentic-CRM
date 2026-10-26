//! Q10-T9: which privileges people actually use.
//!
//! Every successful entity-privilege check (`SecurityContextExt::require`
//! and `require_key` in xrm-security, the `Privilege` and `RecordScoped`
//! extractors here) calls [`record`], which adds one to an in-process count
//! per (person, privilege key). [`flush`], run every few minutes on each node,
//! moves the counts into `privilege_usage_daily` (migration 0297) with an
//! upsert that adds. An administrator's checks are not counted: they pass
//! without a privilege.
//!
//! - **Source of truth:** `privilege_usage_daily`; this map is a write
//!   buffer, so it is safe as process state (guidelines §5): losing it on a
//!   crash loses at most one flush interval of analytics, never access.
//! - **Bound:** at most [`MAX_KEYS`] (person, key) pairs between flushes;
//!   uses beyond it are dropped and counted in [`dropped`].
//! - Checks made outside these four functions (a handful of engine routes
//!   read `ctx.privileges` directly) are not counted, so a removal proposal
//!   is a draft for a person to judge, never an automatic change.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Most distinct (person, privilege key) pairs held between flushes.
pub const MAX_KEYS: usize = 50_000;

static USES: Mutex<Option<HashMap<(Uuid, String), i64>>> = Mutex::new(None);
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// One use of `privilege_key` by `user_id`.
pub fn record(user_id: Uuid, privilege_key: &str) {
    // A poisoned lock still holds whole counts; recovering it is safe.
    let mut guard = USES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let key = (user_id, privilege_key.to_owned());
    if let Some(n) = map.get_mut(&key) {
        *n += 1;
    } else if map.len() < MAX_KEYS {
        map.insert(key, 1);
    } else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Uses dropped because the buffer was full, since the process started.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

fn take() -> HashMap<(Uuid, String), i64> {
    USES.lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_default()
}

/// Puts counts a failed flush took back, within the same bound.
fn restore(counts: HashMap<(Uuid, String), i64>) {
    let mut guard = USES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    for (key, n) in counts {
        if let Some(m) = map.get_mut(&key) {
            *m += n;
        } else if map.len() < MAX_KEYS {
            map.insert(key, n);
        } else {
            DROPPED.fetch_add(u64::try_from(n).unwrap_or(0), Ordering::Relaxed);
        }
    }
}

/// Moves the buffered counts into today's rows (UTC). The number of rows
/// written. On a database error the counts are put back for the next flush.
pub async fn flush(db: &DbPool) -> Result<usize, AppError> {
    let counts = take();
    if counts.is_empty() {
        return Ok(0);
    }
    let mut users = Vec::with_capacity(counts.len());
    let mut keys = Vec::with_capacity(counts.len());
    let mut uses = Vec::with_capacity(counts.len());
    for ((user, key), n) in &counts {
        users.push(*user);
        keys.push(key.clone());
        uses.push(*n);
    }
    let result = sqlx::query(
        "INSERT INTO privilege_usage_daily (day, user_ref, privilege_key, uses) \
         SELECT (now() AT TIME ZONE 'UTC')::date, u, k, n \
         FROM UNNEST($1::uuid[], $2::text[], $3::bigint[]) AS t(u, k, n) \
         ON CONFLICT (day, user_ref, privilege_key) \
         DO UPDATE SET uses = privilege_usage_daily.uses + EXCLUDED.uses",
    )
    .bind(&users)
    .bind(&keys)
    .bind(&uses)
    .execute(db)
    .await;
    match result {
        Ok(_) => Ok(counts.len()),
        Err(error) => {
            restore(counts);
            Err(AppError::internal(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_add_up_per_person_and_key() {
        let user = Uuid::now_v7();
        record(user, "q10t9.read");
        record(user, "q10t9.read");
        record(user, "q10t9.update");
        let counts = take();
        assert_eq!(counts.get(&(user, "q10t9.read".to_owned())), Some(&2));
        assert_eq!(counts.get(&(user, "q10t9.update".to_owned())), Some(&1));
    }
}
