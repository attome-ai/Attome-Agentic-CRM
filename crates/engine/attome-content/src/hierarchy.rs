//! The page tree's hierarchy primitives — a narrow, purpose-built imitation
//! of the platform's established entity-hierarchy pattern (D-095/D-138),
//! not a reuse of that code: `content_page` is an infra table, so
//! `attome-api`'s `entity_crud::hierarchy` (wired to runtime-provisioned
//! entities only) does not apply here.
//!
//! `parent_page_id` is purely an editorial/organizational tree for the
//! page-list sidebar — independent of a page's `url_path` (see
//! `model::validate_url_path`). Moving a page in the tree never touches its
//! served URL.

use attome_db::DbPool;
use sqlx::PgConnection;
use uuid::Uuid;

/// Page trees are shallow by nature (editorial content, not a customer
/// record hierarchy) — bounded well under D-095's 100, both to fail fast on
/// a malformed chain and because the ancestor walk below is O(depth).
pub const MAX_HIERARCHY_DEPTH: i32 = 32;

/// Legacy whole-installation lock — one key for every page tree in every
/// space, so a reparent in one space made every concurrent reparent anywhere
/// else a `Conflict` (3.19). Superseded by [`try_lock_trees`], which keys
/// the lock on the space a tree lives in; this stays only until
/// `admin::move_page` switches to it, and must not gain new callers.
///
/// Non-blocking by design (D-095): the caller should surface a `false`
/// result as `Conflict`, not retry in a loop.
pub async fn try_lock_hierarchy(conn: &mut PgConnection) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-content/hierarchy")
        .fetch_one(conn)
        .await
}

/// The advisory-lock key for one page tree. A tree is identified by the
/// content space it lives in — the closest stable per-tree resource:
/// `content_space_id` is `NOT NULL`, never changes for a page, and
/// `admin::create_page`/`admin::move_page` both refuse a parent from another
/// space (D-369), so a page's whole ancestor chain shares one space and
/// serializing on it covers every cycle-guard read that `is_valid_new_parent`
/// makes. (A root page id would be the alternative, but the root changes
/// under a reparent, which is exactly the moment the key must be stable.)
///
/// Shape per guidelines §2, `"{crate}/{operation}:{resource}"`, under this
/// crate's registered namespace (D-351) — the prefix is unchanged from the
/// legacy key, so the `crates/server/tests/advisory_lock_namespaces.rs`
/// registry needs no new row.
fn tree_lock_key(space_id: Uuid) -> String {
    format!("attome-content/hierarchy:{space_id}")
}

/// The keys `try_lock_trees` acquires for `space_ids`, in acquisition order:
/// sorted and de-duplicated. Sorting is the deadlock guard — two mutations
/// that each touch trees A and B always request A before B, so neither can
/// hold one while waiting on the other. (These locks are non-blocking, so a
/// cycle would surface as a spurious `Conflict` rather than a hang, but the
/// ordering is what makes the `Conflict` deterministic instead of
/// order-dependent.) De-duplication keeps a same-tree move from taking the
/// same key twice — harmless for `pg_try_advisory_xact_lock` (re-entrant
/// within a session) but noise in the lock table.
fn tree_lock_keys(space_ids: &[Uuid]) -> Vec<String> {
    let mut ids: Vec<Uuid> = space_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids.into_iter().map(tree_lock_key).collect()
}

/// Non-blocking, per-tree advisory lock — mirrors D-095/D-138's per-entity
/// hierarchy lock, keyed on each tree's content space (see [`tree_lock_key`])
/// so reparents in unrelated spaces proceed concurrently. Pass every space a
/// mutation touches (the page's own, and the new parent's when they could
/// differ); the keys are taken in sorted order, see [`tree_lock_keys`].
///
/// `Ok(false)` means some tree is already being mutated by another
/// transaction: the caller should surface it as `Conflict`, not retry in a
/// loop (D-095). Any lock acquired before the failing one is released with
/// the caller's transaction, which a `Conflict` return rolls back.
pub async fn try_lock_trees(
    conn: &mut PgConnection,
    space_ids: &[Uuid],
) -> Result<bool, sqlx::Error> {
    for key in tree_lock_keys(space_ids) {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(&key)
            .fetch_one(&mut *conn)
            .await?;
        if !locked {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `false` means applying `new_parent_id` to `page_id` would create a
/// cycle — either `new_parent_id` genuinely is `page_id` or one of its
/// descendants, or the existing chain from `new_parent_id` upward exceeds
/// `MAX_HIERARCHY_DEPTH` without reaching a root, which is treated the same
/// as a real cycle (fail closed on a malformed chain rather than looping
/// forever). Caller must hold the tree's lock first (`try_lock_trees`, keyed
/// on the page's space) — this walk alone is not race-safe against a
/// concurrent reparent elsewhere in the same tree.
pub async fn is_valid_new_parent(
    conn: &mut PgConnection,
    page_id: Uuid,
    new_parent_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let Some(mut current) = new_parent_id else {
        return Ok(true);
    };
    for _ in 0..MAX_HIERARCHY_DEPTH {
        if current == page_id {
            return Ok(false);
        }
        let parent: Option<Uuid> = sqlx::query_scalar(
            "SELECT parent_page_id FROM content_page WHERE id = $1 AND is_deleted = FALSE",
        )
        .bind(current)
        .fetch_optional(&mut *conn)
        .await?
        .flatten();
        match parent {
            Some(p) => current = p,
            None => return Ok(true),
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct AncestorRow {
    pub id: Uuid,
    pub title: String,
    /// Distance from the queried page — 1 is its immediate parent.
    pub depth: i32,
}

/// Recursive-CTE ancestor walk for the editor's breadcrumb/tree — read-only,
/// no lock needed. Ordered furthest-ancestor-first, so callers can render it
/// directly left-to-right as a breadcrumb.
pub async fn ancestors(pool: &DbPool, page_id: Uuid) -> Result<Vec<AncestorRow>, sqlx::Error> {
    sqlx::query_as::<_, AncestorRow>(
        "WITH RECURSIVE chain AS ( \
            SELECT id, title, parent_page_id, 0 AS depth \
            FROM content_page WHERE id = $1 AND is_deleted = FALSE \
            UNION ALL \
            SELECT p.id, p.title, p.parent_page_id, chain.depth + 1 \
            FROM content_page p \
            JOIN chain ON p.id = chain.parent_page_id \
            WHERE p.is_deleted = FALSE AND chain.depth < $2 \
         ) \
         SELECT id, title, depth FROM chain WHERE id != $1 ORDER BY depth DESC",
    )
    .bind(page_id)
    .bind(MAX_HIERARCHY_DEPTH)
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // The live lock behaviour (two spaces mutate concurrently, the same
    // space conflicts) is `attome-api/tests/content_hierarchy_lock.rs`; these
    // pin the key derivation that behaviour depends on.

    #[test]
    fn tree_lock_key_is_namespaced_per_space() {
        let space = Uuid::parse_str("0198f0a1-0000-7000-8000-000000000001").unwrap();
        assert_eq!(
            tree_lock_key(space),
            "attome-content/hierarchy:0198f0a1-0000-7000-8000-000000000001",
            "key must keep the registered `attome-content/` prefix (D-351) and the \
             guidelines §2 `{{crate}}/{{operation}}:{{resource}}` shape"
        );
    }

    #[test]
    fn tree_lock_keys_are_sorted_regardless_of_argument_order() {
        let a = Uuid::parse_str("0198f0a1-0000-7000-8000-00000000000a").unwrap();
        let b = Uuid::parse_str("0198f0a1-0000-7000-8000-00000000000b").unwrap();
        assert_eq!(
            tree_lock_keys(&[b, a]),
            tree_lock_keys(&[a, b]),
            "a cross-tree move must request both locks in one stable order, \
             whichever tree is the source"
        );
        assert_eq!(
            tree_lock_keys(&[b, a]),
            vec![tree_lock_key(a), tree_lock_key(b)]
        );
    }

    #[test]
    fn tree_lock_keys_deduplicate_a_same_tree_move() {
        let a = Uuid::parse_str("0198f0a1-0000-7000-8000-00000000000a").unwrap();
        assert_eq!(tree_lock_keys(&[a, a]), vec![tree_lock_key(a)]);
        assert!(tree_lock_keys(&[]).is_empty());
    }
}
