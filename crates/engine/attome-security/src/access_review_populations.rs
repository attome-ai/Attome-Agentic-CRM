//! Q11-T2: access reviews of machine identities. Beside a role's holders, a
//! team's members and an entity's shares
//! ([`crate::admin`]'s access reviews), a campaign may re-certify:
//!
//! - `s2s_client`: every S2S client still active or suspended, one item per
//!   client, its subject the client's service user. Revoking it does what
//!   the S2S admin's revoke does: the client and its keys end.
//! - `agent`: every agent principal not yet revoked (AH3), its subject the
//!   agent's own account. Revoking it revokes the agent: its keys, its
//!   account and its sessions' authority end, its epoch moves.
//!
//! The subject is the item's requester, so the review's four-eyes check
//! (the decider is never the subject) holds as for people. Sharing rules
//! are not a population yet: revoking one means publishing a metadata
//! version without it, which a review decision cannot do in its own
//! transaction.

use attome_types::AppError;
use uuid::Uuid;

/// The machine-identity scopes this module serves.
pub const MACHINE_SCOPES: [&str; 2] = ["s2s_client", "agent"];

/// Every scope a campaign may name.
pub const ALL_SCOPES: [&str; 5] = ["role", "team", "entity_share", "s2s_client", "agent"];

/// Whether `scope` is one of this module's. Pure.
pub fn is_machine_scope(scope: &str) -> bool {
    MACHINE_SCOPES.contains(&scope)
}

/// The refusal for an unknown scope, naming every scope. Pure.
pub fn unknown_scope(scope: &str) -> AppError {
    AppError::Validation(format!(
        "scope must be one of {}, got '{scope}'",
        ALL_SCOPES.join(", ")
    ))
}

/// `(grant ref, subject user)` per item of a machine scope.
pub async fn population(
    db: &attome_db::DbPool,
    scope: &str,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    let sql = match scope {
        "s2s_client" => {
            "SELECT id, service_user_ref FROM s2s_client \
              WHERE is_deleted = FALSE AND status IN ('active', 'suspended') \
                AND service_user_ref IS NOT NULL \
              ORDER BY created_at, id"
        }
        "agent" => {
            "SELECT user_ref, user_ref FROM agent_principal \
              WHERE lifecycle_state <> 'revoked' ORDER BY created_at, user_ref"
        }
        other => return Err(unknown_scope(other)),
    };
    sqlx::query_as(sql)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)
}

/// Revokes one item's grant of a machine scope, in the decision's
/// transaction.
pub async fn revoke(
    tx: &mut sqlx::PgConnection,
    scope: &str,
    grant_ref: Uuid,
) -> Result<(), AppError> {
    match scope {
        "s2s_client" => {
            sqlx::query(
                "UPDATE s2s_client SET is_deleted = TRUE, status = 'revoked', updated_at = NOW() \
                  WHERE id = $1 AND is_deleted = FALSE",
            )
            .bind(grant_ref)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "UPDATE s2s_client_key SET status = 'revoked', revoked_at = NOW(), is_deleted = TRUE \
                  WHERE client_ref = $1 AND status = 'active'",
            )
            .bind(grant_ref)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        "agent" => {
            let moved = sqlx::query(
                "UPDATE agent_principal SET lifecycle_state = 'revoked', \
                        state_reason = 'access review', revoked_at = now(), \
                        row_version = row_version + 1 \
                  WHERE user_ref = $1 AND lifecycle_state <> 'revoked'",
            )
            .bind(grant_ref)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if moved.rows_affected() == 1 {
                sqlx::query(
                    "UPDATE api_key SET is_active = false WHERE user_ref = $1 AND is_active",
                )
                .bind(grant_ref)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                sqlx::query(
                    "UPDATE user_account SET is_active = false, auth_epoch = auth_epoch + 1 \
                      WHERE id = $1",
                )
                .bind(grant_ref)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
        }
        other => return Err(unknown_scope(other)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_scopes_are_known_and_named_in_the_refusal() {
        assert!(is_machine_scope("agent") && is_machine_scope("s2s_client"));
        assert!(!is_machine_scope("role"));
        for scope in MACHINE_SCOPES {
            assert!(ALL_SCOPES.contains(&scope));
        }
        let AppError::Validation(message) = unknown_scope("sharing") else {
            panic!("a validation error");
        };
        assert!(message.contains("s2s_client") && message.contains("agent"));
    }
}
