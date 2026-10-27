//! U12-T1: company walls in the record filter.
//!
//! An organisation marked `is_company_wall` (platform changeset 0072) is the
//! root of a company: everything under it in the organisation tree
//! (`organization.organization_ref`) belongs to that company. A person every
//! one of whose organisations (home `user_account.organization_ref` plus
//! `user_account_mm_organization` memberships) sits inside some wall is
//! *confined* to those companies:
//!
//! - an entity they could read, update or delete at `Global` depth is
//!   capped to `BusinessUnit` depth ([`wall_level`]), so the record filter
//!   compares the record's `organization_ref` with an organisation set;
//! - that set ([`walled_org_ids`]) is every organisation inside their
//!   companies, narrowed to their own business units when a role already
//!   scoped them that way.
//!
//! Group access lifts the wall: a holder of `security.cross_company` (or
//! `system.admin`), directly or through a role or team, is never confined.
//! So is a person with any organisation outside every wall (a group head
//! office above the companies), and a person with no organisation at all.
//! Explicit record shares and ownership still apply across walls: they are
//! grants someone made on purpose.
//!
//! The wall flag is read through `to_jsonb(o)`, so a database whose
//! organisation table has not gained the column yet reads "no walls" rather
//! than failing every request.

use std::collections::BTreeSet;
use std::time::Duration;

use attome_db::DbPool;
use attome_server::security::AccessLevel;
use attome_types::AppError;
use uuid::Uuid;

/// The privilege that lifts company walls.
pub const CROSS_COMPANY: &str = "security.cross_company";

const QUERY_TIMEOUT: Duration = Duration::from_millis(500);
/// How far up the organisation tree a wall is looked for.
pub(crate) const MAX_DEPTH: i32 = 32;

/// The companies a person is confined to, from the nearest wall above each
/// of their organisations (`None` for an organisation outside every wall).
/// `None` when they are not confined. Pure.
pub fn confined_companies(seed_walls: &[Option<Uuid>]) -> Option<Vec<Uuid>> {
    if seed_walls.is_empty() {
        return None;
    }
    let walls: Option<BTreeSet<Uuid>> = seed_walls.iter().copied().collect();
    walls.map(|w| w.into_iter().collect())
}

/// The record-level depth a confined person gets: `Global` becomes
/// `BusinessUnit`; every narrower depth is already inside the wall. Pure.
pub fn wall_level(level: AccessLevel, confined: bool) -> AccessLevel {
    if confined && matches!(level, AccessLevel::Global) {
        AccessLevel::BusinessUnit
    } else {
        level
    }
}

/// The organisations a confined person's `BusinessUnit` filter compares
/// against: their own business units inside the companies when a role
/// scopes them that way (`business_units`), else every organisation inside
/// the companies. Pure.
pub fn walled_org_ids(business_units: Option<&[Uuid]>, company_orgs: &[Uuid]) -> Vec<Uuid> {
    let company: BTreeSet<Uuid> = company_orgs.iter().copied().collect();
    match business_units {
        Some(own) => own
            .iter()
            .copied()
            .filter(|o| company.contains(o))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        None => company.into_iter().collect(),
    }
}

async fn bounded<T>(
    what: &'static str,
    f: impl std::future::Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, AppError> {
    tokio::time::timeout(QUERY_TIMEOUT, f)
        .await
        .map_err(|_| AppError::internal(format!("{what} timed out")))?
        .map_err(AppError::internal)
}

/// The CTEs that decide confinement for the user bound as `$1`, with the
/// lifting privilege's key at `key_ph` and the walk's depth limit at
/// `depth_ph`. They need `held_roles` before them and `WITH RECURSIVE`.
/// Defines `wall_seeds` (the person's organisations), `wall_up` (each one's
/// path up the tree, stopping at the first wall), `wall_lifted` and
/// `wall_confined` (one boolean, the SQL form of [`confined_companies`]
/// with the lift applied).
pub(crate) fn confined_ctes(key_ph: &str, depth_ph: &str) -> String {
    format!(
        r#"
            wall_seeds AS (
                SELECT u.organization_ref AS seed
                FROM user_account u
                WHERE u.id = $1 AND u.organization_ref IS NOT NULL
                UNION
                SELECT m.organization_ref
                FROM user_account_mm_organization m
                WHERE m.user_ref = $1 AND m.is_deleted = false
            ),
            wall_up AS (
                SELECT s.seed, o.id, o.organization_ref AS parent,
                       COALESCE((to_jsonb(o) ->> 'is_company_wall')::boolean, false) AS wall,
                       0 AS depth
                FROM wall_seeds s JOIN organization o ON o.id = s.seed
                UNION ALL
                SELECT w.seed, o.id, o.organization_ref,
                       COALESCE((to_jsonb(o) ->> 'is_company_wall')::boolean, false),
                       w.depth + 1
                FROM wall_up w JOIN organization o ON o.id = w.parent
                WHERE NOT w.wall AND w.depth < {depth_ph}
            ),
            wall_lifted AS (
                SELECT EXISTS (
                    SELECT 1 FROM held_roles hr
                    JOIN role_mm_privilege rp ON rp.role_ref = hr.role_id AND rp.is_deleted = false
                    JOIN privilege p ON p.id = rp.privilege_ref AND p.is_active = true
                    WHERE p.key IN ({key_ph}, 'system.admin')
                ) OR EXISTS (
                    SELECT 1 FROM user_account_mm_privilege up
                    JOIN privilege p ON p.id = up.privilege_ref AND p.is_active = true
                    WHERE up.user_ref = $1 AND up.is_active = true
                      AND p.key IN ({key_ph}, 'system.admin')
                ) AS lifted
            ),
            wall_confined AS (
                SELECT NOT (SELECT lifted FROM wall_lifted)
                   AND EXISTS (SELECT 1 FROM wall_seeds)
                   AND NOT EXISTS (
                       SELECT 1 FROM wall_seeds s
                       WHERE NOT EXISTS (
                           SELECT 1 FROM wall_up w WHERE w.seed = s.seed AND w.wall))
                   AS confined
            )"#
    )
}

/// The companies `user_id` is confined to, or `None` when no wall applies.
/// One statement.
pub async fn confinement(db: &DbPool, user_id: Uuid) -> Result<Option<Vec<Uuid>>, AppError> {
    let sql = format!(
        r#"
            {held_roles},
            {walls}
            SELECT (SELECT lifted FROM wall_lifted),
                   (SELECT w.id FROM wall_up w WHERE w.seed = s.seed AND w.wall
                     ORDER BY w.depth LIMIT 1)
            FROM wall_seeds s
        "#,
        held_roles =
            crate::db::HELD_ROLES_CTE.replacen("WITH held_roles", "WITH RECURSIVE held_roles", 1),
        walls = confined_ctes("$2", "$3"),
    );
    let rows: Vec<(Option<bool>, Option<Uuid>)> = bounded(
        "company-wall resolution",
        sqlx::query_as(&sql)
            .bind(user_id)
            .bind(CROSS_COMPANY)
            .bind(MAX_DEPTH)
            .fetch_all(db),
    )
    .await?;
    if rows.iter().any(|(lifted, _)| lifted.unwrap_or(false)) {
        return Ok(None);
    }
    let walls: Vec<Option<Uuid>> = rows.into_iter().map(|(_, wall)| wall).collect();
    Ok(confined_companies(&walls))
}

/// Every organisation inside `companies` (the walls and all below them).
pub async fn company_org_ids(db: &DbPool, companies: &[Uuid]) -> Result<Vec<Uuid>, AppError> {
    bounded(
        "company organisation tree",
        sqlx::query_scalar(
            // Q10-T3: a prefix range on the indexed `unit_path`, as
            // `db::resolve_accessible_org_ids` reads it.
            r#"
            SELECT o.id FROM organization o WHERE o.id = ANY($1)
            UNION
            SELECT o.id
            FROM organization w
            JOIN organization o
              ON w.unit_path IS NOT NULL
             AND o.unit_path ~>=~ w.unit_path
             AND o.unit_path ~<~ (w.unit_path || 'g')
            WHERE w.id = ANY($1)
            "#,
        )
        .bind(companies)
        .fetch_all(db),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn company_walls_confine_only_when_every_org_is_walled() {
        assert_eq!(confined_companies(&[]), None, "no organisation");
        assert_eq!(
            confined_companies(&[Some(id(1)), Some(id(2)), Some(id(1))]),
            Some(vec![id(1), id(2)])
        );
        assert_eq!(
            confined_companies(&[Some(id(1)), None]),
            None,
            "a seat outside every wall (group office) lifts it"
        );
    }

    #[test]
    fn company_walls_cap_global_only() {
        assert_eq!(
            wall_level(AccessLevel::Global, true),
            AccessLevel::BusinessUnit
        );
        assert_eq!(wall_level(AccessLevel::Global, false), AccessLevel::Global);
        for level in [
            AccessLevel::BusinessUnit,
            AccessLevel::Team,
            AccessLevel::None,
        ] {
            assert_eq!(wall_level(level, true), level);
        }
    }

    #[test]
    fn company_walls_org_set() {
        let company = [id(10), id(11), id(12)];
        assert_eq!(walled_org_ids(None, &company), vec![id(10), id(11), id(12)]);
        // A business unit in another company is dropped.
        assert_eq!(
            walled_org_ids(Some(&[id(11), id(99)]), &company),
            vec![id(11)]
        );
        assert!(walled_org_ids(Some(&[id(99)]), &company).is_empty());
    }
}
