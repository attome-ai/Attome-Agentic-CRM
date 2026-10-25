//! Q9-T1: the sign-in restrictions of the roles a person holds, read for
//! `attome_server::login_restrictions::evaluate` when a session is issued.
//!
//! Networks come from `role.ip_allowlist`; hours and countries from the
//! role's `role_auth_policy` row (`login_calendar_ref`, `allowed_countries`,
//! migration 0245). A calendar is loaded with what it inherits (Z12) and
//! asked whether `now` is working time; one that cannot be loaded counts as
//! closed, so a broken calendar refuses rather than opens sign-in.

use std::collections::HashMap;

use attome_server::login_restrictions::RoleSignInRule;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One held role's stored restrictions.
#[derive(Debug, sqlx::FromRow)]
struct RuleRow {
    ip_allowlist: Option<Vec<String>>,
    login_calendar_ref: Option<Uuid>,
    allowed_countries: Option<Vec<String>>,
}

/// The restrictions of every live role `user_id` holds, with each role's
/// calendar answered for `now`. Roles that restrict nothing are left out.
pub async fn load(
    db: &attome_db::DbPool,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<RoleSignInRule>, AppError> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.ip_allowlist, p.login_calendar_ref, p.allowed_countries \
           FROM user_account_mm_role ur \
           JOIN role r ON r.id = ur.role_ref AND r.is_deleted = false \
           LEFT JOIN role_auth_policy p ON p.role_ref = r.id \
          WHERE ur.user_ref = $1 AND ur.is_deleted = false",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut open: HashMap<Uuid, bool> = HashMap::new();
    let mut rules = Vec::new();
    for row in rows {
        let within_hours = match row.login_calendar_ref {
            None => None,
            Some(id) => Some(match open.get(&id) {
                Some(answer) => *answer,
                None => {
                    let answer = match attome_core::calendar::load_calendar(db, id).await? {
                        Ok(loaded) => loaded.calendar.is_working(now),
                        Err(unresolved) => {
                            tracing::warn!(
                                calendar_id = %id,
                                ?unresolved,
                                "sign-in: a role's sign-in calendar cannot be loaded; treated as closed"
                            );
                            false
                        }
                    };
                    open.insert(id, answer);
                    answer
                }
            }),
        };
        let rule = RoleSignInRule {
            networks: row.ip_allowlist.unwrap_or_default(),
            within_hours,
            countries: row.allowed_countries.unwrap_or_default(),
        };
        if rule != RoleSignInRule::default() {
            rules.push(rule);
        }
    }
    Ok(rules)
}
