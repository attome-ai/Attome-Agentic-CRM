//! A31-T4: a leaver's records move per each entity's leaver rule.
//!
//! An entity's settings may say `"access": { "leaver": "manager" | "team" |
//! "user:<email>" }` (`attome_security::ownership::LeaverRule`). Disabling a
//! person queues `attome_security::ownership::LEAVER_JOB`; the job calls
//! [`reassign`], which for each entity with a rule finds the new owner (a
//! person holding the position above the leaver's, the leaver's first team
//! by name, or the named user) and starts a mass reassign
//! (`attome_records::mass`, `reassign`) of the records the leaver owns, as
//! the administrator who disabled them: every record through its normal path
//! (access, audit, the change feed), in the background past the inline
//! threshold. An entity whose new owner cannot be found is skipped and named
//! in the log.

use attome_core::EngineState;
use attome_records::mass::{MassKind, MassStartBody};
use attome_records::query_spec::Condition;
use attome_security::ownership::LeaverRule;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// The new owner a rule names for `user`, as a mass reassign payload; `None`
/// when there is none.
async fn target(
    state: &EngineState,
    user: Uuid,
    rule: &LeaverRule,
) -> Result<Option<Value>, AppError> {
    let db = &state.base.db;
    Ok(match rule {
        LeaverRule::User(email) => Some(json!({ "user_email": email })),
        LeaverRule::Manager => sqlx::query_scalar::<_, String>(
            "SELECT u.email FROM user_account_mm_position me \
               JOIN position p ON p.id = me.position_ref \
               JOIN user_account_mm_position boss ON boss.position_ref = p.parent_position_ref \
               JOIN user_account u ON u.id = boss.user_ref \
              WHERE me.user_ref = $1 AND boss.user_ref <> $1 AND u.email IS NOT NULL \
                AND COALESCE(u.is_active, true) \
              ORDER BY u.email LIMIT 1",
        )
        .bind(user)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .map(|email| json!({ "user_email": email })),
        LeaverRule::Team => sqlx::query_scalar::<_, String>(
            "SELECT t.name FROM user_account_mm_team ut JOIN team t ON t.id = ut.team_ref \
              WHERE ut.user_ref = $1 AND ut.is_deleted = false AND t.name IS NOT NULL \
              ORDER BY t.name LIMIT 1",
        )
        .bind(user)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .map(|team| json!({ "team_name": team })),
    })
}

/// The records `user` owns. Pure.
pub fn owned_by(user: Uuid) -> Condition {
    Condition::And {
        all: vec![
            Condition::Compare {
                field: "owner_ref".to_owned(),
                op: "eq".to_owned(),
                value: Some(json!(user.to_string())),
            },
            Condition::Compare {
                field: "owner_type".to_owned(),
                op: "eq".to_owned(),
                value: Some(json!(0)),
            },
        ],
    }
}

/// Moves `user`'s records per `rules` (entity logical name, rule), as
/// `actor`; how many mass operations started.
pub async fn reassign_with(
    state: &EngineState,
    actor: Uuid,
    user: Uuid,
    rules: &[(String, LeaverRule)],
) -> Result<usize, AppError> {
    if rules.is_empty() {
        return Ok(0);
    }
    let ctx = attome_security::resolve_uncached(&state.base.db, actor).await?;
    if !ctx.is_admin {
        tracing::warn!(%actor, %user, "leaver reassignment: the disabling user is no longer an administrator");
        return Ok(0);
    }
    let mut started = 0;
    for (entity, rule) in rules {
        let Some(payload) = target(state, user, rule).await? else {
            tracing::warn!(%user, entity, ?rule, "leaver reassignment: no new owner found; records stay");
            continue;
        };
        let body = MassStartBody {
            filter: Some(owned_by(user)),
            kind: MassKind::Reassign,
            payload,
            reason: Some(format!("leaver: {user}")),
            confirm_estimate_rows: Some(i64::MAX),
        };
        match attome_records::mass::start(state, &ctx, entity, body, None).await {
            Ok(_) => started += 1,
            Err(error) => {
                tracing::warn!(%user, entity, %error, "leaver reassignment not started");
            }
        }
    }
    Ok(started)
}

/// The leaver job: every entity's rule from the loaded metadata.
pub async fn reassign(state: &EngineState, actor: Uuid, user: Uuid) -> Result<usize, AppError> {
    let rules: Vec<(String, LeaverRule)> = {
        let registry = state.entities.load();
        attome_security::ownership::leaver_rules()
            .iter()
            .filter_map(|(entity, rule)| {
                registry
                    .iter()
                    .find(|meta| meta.entity_id == *entity)
                    .map(|meta| (meta.logicalname.clone(), rule.clone()))
            })
            .collect()
    };
    reassign_with(state, actor, user, &rules).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_records_are_user_owned_rows() {
        let user = Uuid::from_u128(9);
        let text = serde_json::to_string(&owned_by(user)).unwrap();
        assert!(text.contains("owner_ref") && text.contains(&user.to_string()));
        assert!(text.contains("owner_type"));
    }
}
