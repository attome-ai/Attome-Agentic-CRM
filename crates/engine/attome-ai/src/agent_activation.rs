//! AH7-T3: the permission test gates every activation.
//!
//! A save that makes an `ai_agent` definition active (status to
//! [`STARTABLE_STATUS`]), or changes the policy of an active one, runs the
//! agent's permission test ([`crate::permission_test::judge`]) inside the
//! save (`attome_core::record_check`) and refuses it with a 422 listing the
//! failing cases. So does a change to an `ai_agent_policy` that an active
//! agent uses, judged with the policy as it will be saved, for each such
//! agent up to [`MAX_AGENTS`].
//!
//! The test runs as the agent's owner (its `owner_ref`; the saving user on
//! create), with the policy and capability packs a session would hold. An
//! agent with no policy is not judged: no session can start from it
//! (D-505 §3). A write with no staff user behind it and no stored owner
//! (a bundle or system write) is not judged either: there is nobody whose
//! permissions to test.

use attome_core::EngineState;
use attome_core::record_check::{RecordCheck, RecordCheckFuture, RecordSave};
use attome_types::AppError;
use serde_json::{Map, Value};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::agent::{POLICY_ENTITY, STARTABLE_STATUS, SessionConstraints};
use crate::descriptor::RiskTier;
use crate::permission_test::Failure;

/// The most active agents one policy save judges.
pub const MAX_AGENTS: i64 = 100;
/// The most failing cases a refusal lists.
const LISTED: usize = 10;

/// A lookup's id as a body carries it: a string, or `{ "id": ... }`.
/// `None` for null or anything unreadable.
fn lookup(value: &Value) -> Option<Uuid> {
    let raw = match value {
        Value::String(id) => Some(id.as_str()),
        Value::Object(lookup) => lookup.get("id").and_then(Value::as_str),
        _ => None,
    };
    raw.and_then(|id| Uuid::parse_str(id.trim()).ok())
}

/// The 422 for a failed test. Pure.
pub fn refusal(failures: &[Failure]) -> AppError {
    let listed: Vec<String> = failures
        .iter()
        .take(LISTED)
        .map(|f| match &f.entity {
            Some(entity) => format!("{} on {entity}: {}", f.action_id, f.reason),
            None => format!("{}: {}", f.action_id, f.reason),
        })
        .collect();
    let more = if failures.len() > LISTED { "; ..." } else { "" };
    AppError::Validation(format!(
        "The agent's permission test failed ({} case(s)): {}{more}",
        failures.len(),
        listed.join("; ")
    ))
}

/// The failing cases for an agent owned by `owner` under the policy
/// `policy_ref`, with `overlay` (a policy save's fields) over the stored
/// policy.
async fn failures_for(
    state: &EngineState,
    owner: Uuid,
    policy_ref: Uuid,
    overlay: Option<&Map<String, Value>>,
) -> Result<Vec<Failure>, AppError> {
    let security = state.base.security.resolve(owner).await?;
    let record =
        match attome_records::entity_crud::read_record(state, &security, POLICY_ENTITY, policy_ref)
            .await
        {
            Ok(record) => record,
            Err(AppError::NotFound | AppError::Forbidden) => {
                return Err(AppError::Validation(
                    "the agent's owner cannot read its policy (policy_ref); assign a policy the \
                 owner can use before activating the agent"
                        .into(),
                ));
            }
            Err(e) => return Err(e),
        };
    let mut data = record.data().clone();
    if let (Some(overlay), Value::Object(fields)) = (overlay, &mut data) {
        for (k, v) in overlay {
            fields.insert(k.clone(), v.clone());
        }
    }
    let policy =
        crate::agent::parse_policy(&data, |id| crate::engine::REGISTRY.resolve(id).is_some())?;
    let packs =
        crate::capability_pack::resolve(state, &security, policy.capability_pack_refs.as_deref())
            .await?;
    let effective = crate::agent::combine_with_policy(
        SessionConstraints {
            risk_ceiling: RiskTier::Consequential,
            allowed_action_ids: None,
        },
        &policy,
        packs.action_ids,
    );
    Ok(crate::permission_test::judge(state, &security, &effective).failures)
}

type StoredAgent = (Option<String>, Option<Uuid>, Option<Uuid>);

/// An `ai_agent` save.
async fn on_agent(
    conn: &mut PgConnection,
    state: &EngineState,
    save: RecordSave<'_>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let stored: StoredAgent = match save.record_id {
        Some(id) => {
            sqlx::query_as("SELECT status::text, policy_ref, owner_ref FROM ai_agent WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(AppError::internal)?
                .unwrap_or_default()
        }
        None => (None, None, None),
    };
    let (stored_status, stored_policy, stored_owner) = stored;
    let status = match save.body.get("status") {
        Some(value) => value.as_str().map(str::to_owned),
        None => stored_status.clone(),
    };
    if status.as_deref() != Some(STARTABLE_STATUS) {
        return Ok(None);
    }
    let activating = stored_status.as_deref() != Some(STARTABLE_STATUS);
    if !activating && !save.body.contains_key("policy_ref") {
        return Ok(None);
    }
    let policy = match save.body.get("policy_ref") {
        Some(value) => lookup(value),
        None => stored_policy,
    };
    let (Some(policy), Some(owner)) = (policy, stored_owner.or(save.actor)) else {
        return Ok(None);
    };
    let failures = failures_for(state, owner, policy, None).await?;
    if failures.is_empty() {
        Ok(None)
    } else {
        Err(refusal(&failures))
    }
}

/// An `ai_agent_policy` save: every active agent using it, judged with the
/// policy as saved.
async fn on_policy(
    conn: &mut PgConnection,
    state: &EngineState,
    save: RecordSave<'_>,
) -> Result<Option<Map<String, Value>>, AppError> {
    let Some(policy) = save.record_id else {
        return Ok(None);
    };
    let agents: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, owner_ref FROM ai_agent \
          WHERE policy_ref = $1 AND status::text = $2 AND is_active IS DISTINCT FROM false \
          ORDER BY id LIMIT $3",
    )
    .bind(policy)
    .bind(STARTABLE_STATUS)
    .bind(MAX_AGENTS)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    for (agent, owner) in agents {
        let Some(owner) = owner else {
            continue;
        };
        let failures = failures_for(state, owner, policy, Some(save.body)).await?;
        if !failures.is_empty() {
            return Err(match refusal(&failures) {
                AppError::Validation(message) => {
                    AppError::Validation(format!("Active agent {agent}: {message}"))
                }
                other => other,
            });
        }
    }
    Ok(None)
}

/// The activation check, registered for `ai_agent` and `ai_agent_policy`
/// by `ActionModel::record_checks`.
#[derive(Debug)]
pub struct ActivationCheck;

impl RecordCheck for ActivationCheck {
    fn check<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        state: &'a EngineState,
        save: RecordSave<'a>,
    ) -> RecordCheckFuture<'a> {
        Box::pin(async move {
            match save.entity {
                "ai_agent" => on_agent(conn, state, save).await,
                POLICY_ENTITY => on_policy(conn, state, save).await,
                _ => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission_test::{Expect, Outcome};

    fn failure(action: &str, entity: Option<&str>) -> Failure {
        Failure {
            action_id: action.to_owned(),
            entity: entity.map(str::to_owned),
            expect: Expect::Refused,
            got: Outcome::Allowed,
            reason: "outside the allow-list",
        }
    }

    #[test]
    fn the_refusal_lists_the_failing_cases() {
        let failures = vec![
            failure("email.send", None),
            failure("record.get", Some("salary")),
        ];
        match refusal(&failures) {
            AppError::Validation(message) => {
                assert!(message.contains("2 case(s)"), "{message}");
                assert!(message.contains("email.send: outside"), "{message}");
                assert!(message.contains("record.get on salary"), "{message}");
                assert!(!message.ends_with("..."), "{message}");
            }
            other => panic!("expected a validation refusal, got {other:?}"),
        }
        let many: Vec<Failure> = (0..12).map(|_| failure("email.send", None)).collect();
        match refusal(&many) {
            AppError::Validation(message) => assert!(message.ends_with("; ..."), "{message}"),
            other => panic!("expected a validation refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_lookup_reads_either_shape() {
        let id = Uuid::now_v7();
        assert_eq!(lookup(&Value::String(id.to_string())), Some(id));
        assert_eq!(
            lookup(&serde_json::json!({ "id": id.to_string() })),
            Some(id)
        );
        assert_eq!(lookup(&Value::Null), None);
    }
}
