//! Q10-T8: conflicting-access rules (separation of duties).
//!
//! A rule names two things one person must not hold together: a role, a
//! privilege or a permission set on each side. Every grant that adds access
//! asks [`check_grant`] inside its own transaction, with what the grant
//! adds: a direct role, a team (its roles and the sets assigned to it) or a
//! permission set. A rule fires only when the grant completes the pair, so
//! an existing conflict does not block unrelated grants; it is listed by
//! [`current_conflicts`] instead. `refuse` mode is a 409 `role_conflict`;
//! `approval` mode sends a direct role grant to a second administrator
//! through the role-grant gate (D-195), with a reason required. A team or
//! set path has no approval of its own, so there an `approval` rule refuses
//! with `role_conflict_needs_approval`: grant the role directly instead.
//! Roles held through a team count, as the resolver counts them.

use std::collections::HashSet;

use attome_types::AppError;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// What a grant adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRef {
    Role(Uuid),
    /// Joining a team: its roles and the sets assigned to it.
    Team(Uuid),
    Set(Uuid),
}

/// One live rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ConflictRule {
    pub id: Uuid,
    /// `role`, `privilege` or `set`.
    pub left_kind: String,
    pub left_ref: Uuid,
    pub right_kind: String,
    pub right_ref: Uuid,
    /// `refuse` or `approval`.
    pub mode: String,
    pub reason: String,
}

/// What a grant would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictOutcome {
    None,
    Refuse(ConflictRule),
    NeedsApproval(ConflictRule),
}

/// The kinds a side may be.
pub const KINDS: [&str; 3] = ["role", "privilege", "set"];

/// What one person holds, by id.
#[derive(Debug, Default, Clone)]
struct Held {
    roles: HashSet<Uuid>,
    sets: HashSet<Uuid>,
    privileges: HashSet<Uuid>,
}

impl Held {
    fn holds(&self, kind: &str, id: Uuid) -> bool {
        match kind {
            "role" => self.roles.contains(&id),
            "set" => self.sets.contains(&id),
            "privilege" => self.privileges.contains(&id),
            _ => false,
        }
    }

    fn extend(&mut self, other: Held) {
        self.roles.extend(other.roles);
        self.sets.extend(other.sets);
        self.privileges.extend(other.privileges);
    }
}

async fn ids(
    conn: &mut sqlx::PgConnection,
    sql: &str,
    bind: Uuid,
) -> Result<HashSet<Uuid>, AppError> {
    let rows: Vec<Uuid> = sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// The privileges the roles and sets carry.
async fn privileges_of(
    conn: &mut sqlx::PgConnection,
    roles: &HashSet<Uuid>,
    sets: &HashSet<Uuid>,
) -> Result<HashSet<Uuid>, AppError> {
    let roles: Vec<Uuid> = roles.iter().copied().collect();
    let sets: Vec<Uuid> = sets.iter().copied().collect();
    let rows: Vec<Uuid> = sqlx::query_scalar(
        "SELECT privilege_ref FROM role_mm_privilege WHERE is_deleted = false AND role_ref = ANY($1) \
         UNION \
         SELECT privilege_ref FROM permission_set_privilege WHERE is_deleted = false AND set_ref = ANY($2)",
    )
    .bind(&roles)
    .bind(&sets)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

async fn held(conn: &mut sqlx::PgConnection, user_id: Uuid) -> Result<Held, AppError> {
    let roles = ids(
        conn,
        "SELECT ur.role_ref FROM user_account_mm_role ur \
         JOIN role r ON r.id = ur.role_ref AND r.is_deleted = false \
         WHERE ur.user_ref = $1 AND ur.is_deleted = false \
         UNION \
         SELECT rt.role_ref FROM user_account_mm_team ut \
         JOIN role_mm_team rt ON rt.team_ref = ut.team_ref AND rt.is_deleted = false \
         JOIN role r ON r.id = rt.role_ref AND r.is_deleted = false \
         WHERE ut.user_ref = $1 AND ut.is_deleted = false",
        user_id,
    )
    .await?;
    let sets = ids(conn, crate::db::HELD_SET_IDS, user_id).await?;
    let mut privileges = privileges_of(conn, &roles, &sets).await?;
    privileges.extend(
        ids(
            conn,
            "SELECT privilege_ref FROM user_account_mm_privilege \
             WHERE user_ref = $1 AND is_active = true",
            user_id,
        )
        .await?,
    );
    Ok(Held {
        roles,
        sets,
        privileges,
    })
}

async fn added(conn: &mut sqlx::PgConnection, grant: GrantRef) -> Result<Held, AppError> {
    let (roles, sets) = match grant {
        GrantRef::Role(id) => (HashSet::from([id]), HashSet::new()),
        GrantRef::Set(id) => (HashSet::new(), HashSet::from([id])),
        GrantRef::Team(team) => (
            ids(
                conn,
                "SELECT rt.role_ref FROM role_mm_team rt \
                 JOIN role r ON r.id = rt.role_ref AND r.is_deleted = false \
                 WHERE rt.team_ref = $1 AND rt.is_deleted = false",
                team,
            )
            .await?,
            ids(
                conn,
                "SELECT a.set_ref FROM permission_set_assignment a \
                 JOIN permission_set s ON s.id = a.set_ref AND s.is_deleted = false \
                 WHERE a.team_ref = $1 AND a.is_deleted = false \
                   AND (a.ends_at IS NULL OR a.ends_at > now())",
                team,
            )
            .await?,
        ),
    };
    let privileges = privileges_of(conn, &roles, &sets).await?;
    Ok(Held {
        roles,
        sets,
        privileges,
    })
}

/// Every live rule.
pub async fn live_rules(conn: impl sqlx::PgExecutor<'_>) -> Result<Vec<ConflictRule>, AppError> {
    let rows: Vec<(Uuid, String, Uuid, String, Uuid, String, String)> = sqlx::query_as(
        "SELECT id, left_kind, left_ref, right_kind, right_ref, mode, reason \
         FROM role_conflict_rule WHERE is_deleted = false ORDER BY created_at, id",
    )
    .fetch_all(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, left_kind, left_ref, right_kind, right_ref, mode, reason)| ConflictRule {
                id,
                left_kind,
                left_ref,
                right_kind,
                right_ref,
                mode,
                reason,
            },
        )
        .collect())
}

/// The rules a grant would set off for `user_id`: refusing ones first.
pub fn decide(
    rules: &[ConflictRule],
    before: &impl Fn(&str, Uuid) -> bool,
    after: &impl Fn(&str, Uuid) -> bool,
) -> ConflictOutcome {
    let fired: Vec<&ConflictRule> = rules
        .iter()
        .filter(|r| {
            after(&r.left_kind, r.left_ref)
                && after(&r.right_kind, r.right_ref)
                && !(before(&r.left_kind, r.left_ref) && before(&r.right_kind, r.right_ref))
        })
        .collect();
    if let Some(rule) = fired.iter().find(|r| r.mode == "refuse") {
        ConflictOutcome::Refuse((*rule).clone())
    } else if let Some(rule) = fired.first() {
        ConflictOutcome::NeedsApproval((*rule).clone())
    } else {
        ConflictOutcome::None
    }
}

/// Whether giving `user_id` what `grant` adds would complete a conflicting
/// pair. Run inside the grant's transaction so the answer and the write see
/// the same rows.
pub async fn check_grant(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    grant: GrantRef,
) -> Result<ConflictOutcome, AppError> {
    let rules = live_rules(&mut *conn).await?;
    if rules.is_empty() {
        return Ok(ConflictOutcome::None);
    }
    let before = held(conn, user_id).await?;
    let mut after = before.clone();
    after.extend(added(conn, grant).await?);
    Ok(decide(
        &rules,
        &|kind, id| before.holds(kind, id),
        &|kind, id| after.holds(kind, id),
    ))
}

/// The error a refused grant answers with.
pub fn refused() -> AppError {
    AppError::Conflict(
        "role_conflict: the grant would give a pair of access a conflict rule forbids",
    )
}

/// The error a team or set grant answers with when a rule asks for approval:
/// only a direct role grant can go to a second administrator.
pub fn needs_approval_elsewhere() -> AppError {
    AppError::Conflict(
        "role_conflict_needs_approval: a conflict rule needs a second administrator; grant the \
         role directly to route it for approval",
    )
}

/// [`check_grant`] for the paths without an approval route (team joins, a
/// team's new role, set assignments): any conflict refuses.
pub async fn refuse_any_conflict(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    grant: GrantRef,
) -> Result<(), AppError> {
    match check_grant(conn, user_id, grant).await? {
        ConflictOutcome::None => Ok(()),
        ConflictOutcome::Refuse(_) => Err(refused()),
        ConflictOutcome::NeedsApproval(_) => Err(needs_approval_elsewhere()),
    }
}

/// The users who hold `kind`/`id` now (roles and sets directly or through a
/// team, privileges through any of those or directly).
async fn holders(
    conn: &mut sqlx::PgConnection,
    kind: &str,
    id: Uuid,
) -> Result<HashSet<Uuid>, AppError> {
    let sql = match kind {
        "role" => {
            "SELECT ur.user_ref FROM user_account_mm_role ur \
             WHERE ur.role_ref = $1 AND ur.is_deleted = false \
             UNION \
             SELECT ut.user_ref FROM role_mm_team rt \
             JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref AND ut.is_deleted = false \
             WHERE rt.role_ref = $1 AND rt.is_deleted = false"
        }
        "set" => {
            "SELECT a.user_ref FROM permission_set_assignment a \
             WHERE a.set_ref = $1 AND a.user_ref IS NOT NULL AND a.is_deleted = false \
               AND (a.ends_at IS NULL OR a.ends_at > now()) \
             UNION \
             SELECT ut.user_ref FROM permission_set_assignment a \
             JOIN user_account_mm_team ut ON ut.team_ref = a.team_ref AND ut.is_deleted = false \
             WHERE a.set_ref = $1 AND a.is_deleted = false \
               AND (a.ends_at IS NULL OR a.ends_at > now())"
        }
        _ => {
            "SELECT ur.user_ref FROM role_mm_privilege rp \
             JOIN user_account_mm_role ur ON ur.role_ref = rp.role_ref AND ur.is_deleted = false \
             WHERE rp.privilege_ref = $1 AND rp.is_deleted = false \
             UNION \
             SELECT ut.user_ref FROM role_mm_privilege rp \
             JOIN role_mm_team rt ON rt.role_ref = rp.role_ref AND rt.is_deleted = false \
             JOIN user_account_mm_team ut ON ut.team_ref = rt.team_ref AND ut.is_deleted = false \
             WHERE rp.privilege_ref = $1 AND rp.is_deleted = false \
             UNION \
             SELECT up.user_ref FROM user_account_mm_privilege up \
             WHERE up.privilege_ref = $1 AND up.is_active = true \
             UNION \
             SELECT a.user_ref FROM permission_set_privilege sp \
             JOIN permission_set_assignment a ON a.set_ref = sp.set_ref AND a.is_deleted = false \
               AND a.user_ref IS NOT NULL AND (a.ends_at IS NULL OR a.ends_at > now()) \
             WHERE sp.privilege_ref = $1 AND sp.is_deleted = false"
        }
    };
    ids(conn, sql, id).await
}

/// One person holding both sides of a rule now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CurrentConflict {
    pub user_id: Uuid,
    pub rule_id: Uuid,
}

/// Everyone who holds both sides of a live rule today, by rule then user.
pub async fn current_conflicts(
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<CurrentConflict>, AppError> {
    let mut out = Vec::new();
    for rule in live_rules(&mut *conn).await? {
        let left = holders(conn, &rule.left_kind, rule.left_ref).await?;
        let right = holders(conn, &rule.right_kind, rule.right_ref).await?;
        let mut both: Vec<Uuid> = left.intersection(&right).copied().collect();
        both.sort();
        out.extend(both.into_iter().map(|user_id| CurrentConflict {
            user_id,
            rule_id: rule.id,
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(mode: &str, left: Uuid, right: Uuid) -> ConflictRule {
        ConflictRule {
            id: Uuid::now_v7(),
            left_kind: "role".into(),
            left_ref: left,
            right_kind: "privilege".into(),
            right_ref: right,
            mode: mode.into(),
            reason: "four eyes".into(),
        }
    }

    #[test]
    fn conflict_fires_only_when_the_grant_completes_the_pair() {
        let (role, privilege) = (Uuid::now_v7(), Uuid::now_v7());
        let rules = [
            rule("approval", role, privilege),
            rule("refuse", role, privilege),
        ];
        let none = |_: &str, _: Uuid| false;
        let has_priv = |k: &str, id: Uuid| k == "privilege" && id == privilege;
        let both = |k: &str, id: Uuid| {
            (k == "role" && id == role) || (k == "privilege" && id == privilege)
        };

        assert!(
            matches!(decide(&rules, &has_priv, &both), ConflictOutcome::Refuse(_)),
            "refuse wins"
        );
        assert_eq!(
            decide(&rules, &both, &both),
            ConflictOutcome::None,
            "an existing pair is listed, not blocked"
        );
        assert_eq!(decide(&rules, &none, &has_priv), ConflictOutcome::None);
        assert!(matches!(
            decide(&rules[..1], &has_priv, &both),
            ConflictOutcome::NeedsApproval(_)
        ));
    }
}
