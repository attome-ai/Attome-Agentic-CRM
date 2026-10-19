//! Z7-T5: chains and fan-out over registered jobs ([`RegisteredJob`]).
//!
//! A chain runs a job after another: [`RegisteredJob::then`] attaches the
//! next job, and once the first succeeds the worker enqueues it
//! ([`after_success`]). A fan-out runs many jobs in parallel and one final
//! job when all of them have succeeded: [`fan_out`] writes a `job_group` row
//! counting the members and enqueues them, each member's success counts the
//! group down, and the member that brings it to zero enqueues the final job.
//!
//! **Exactly once.** apalis marks a job done after its handler returns, in
//! its own statement, so the follow-up cannot share that transaction. Each
//! job that has a follow-up carries a step id instead; [`after_success`]
//! records the step in `job_chain_step` and enqueues the follow-up (or
//! counts the group down) in one transaction, and a step already recorded
//! does nothing. A job retried after its follow-up was enqueued (the worker
//! died before apalis marked it done) therefore never enqueues it twice.
//! Handlers stay retry-safe as every job's must (guidelines §10).
//!
//! A member that ends in the dead letters never counts its group down, so
//! the final job does not run; replaying the member from the dead letters
//! finishes the group. Step rows older than 30 days are pruned with the job
//! history.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Job;
use crate::registry::{BoxError, RegisteredJob};

/// What follows a registered job once it succeeds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Continuation {
    /// This enqueued job's step: its follow-up is enqueued at most once.
    pub step: Uuid,
    /// The job to run next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then: Option<Box<RegisteredJob>>,
    /// The fan-out group this job is a member of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Uuid>,
}

impl RegisteredJob {
    /// This job, followed by `next` once it succeeds.
    #[must_use]
    pub fn then(mut self, next: RegisteredJob) -> Self {
        let group = self.next.as_ref().and_then(|c| c.group);
        self.next = Some(Continuation {
            step: Uuid::now_v7(),
            then: Some(Box::new(next)),
            group,
        });
        self
    }

    fn in_group(mut self, group: Uuid) -> Self {
        let then = self.next.take().and_then(|c| c.then);
        self.next = Some(Continuation {
            step: Uuid::now_v7(),
            then,
            group: Some(group),
        });
        self
    }
}

/// Enqueues `members` to run in parallel and `finally` once every one of
/// them has succeeded, in the caller's transaction; answers the group id.
/// With no members, `finally` is enqueued at once. `wrap` turns a registered
/// job into the application's job type.
pub async fn fan_out<J: Job>(
    tx: &mut attome_db::Tx<'_>,
    wrap: impl Fn(RegisteredJob) -> J,
    members: Vec<RegisteredJob>,
    finally: RegisteredJob,
) -> Result<Uuid, BoxError> {
    let group = Uuid::now_v7();
    if members.is_empty() {
        crate::enqueue_in_tx(tx, wrap(finally)).await?;
        return Ok(group);
    }
    let remaining = i32::try_from(members.len())?;
    sqlx::query(attome_db::tagged_sql!(
        "jobs.chain",
        "INSERT INTO job_group (id, remaining, finally) VALUES ($1, $2, $3)"
    ))
    .bind(group)
    .bind(remaining)
    .bind(serde_json::to_value(&finally)?)
    .execute(&mut **tx)
    .await?;
    for member in members {
        crate::enqueue_in_tx(tx, wrap(member.in_group(group))).await?;
    }
    Ok(group)
}

/// After a registered job succeeded: enqueues what follows it (`next` is
/// the job's own [`RegisteredJob::next`], taken before it ran), at most
/// once per step. Nothing to do without a continuation.
pub async fn after_success<J: Job>(
    pool: &attome_db::DbPool,
    next: Option<&Continuation>,
    wrap: impl Fn(RegisteredJob) -> J,
) -> Result<(), BoxError> {
    let Some(next) = next else {
        return Ok(());
    };
    let mut tx = attome_db::tx::begin(pool).await?;
    let first = sqlx::query(attome_db::tagged_sql!(
        "jobs.chain",
        "INSERT INTO job_chain_step (step) VALUES ($1) ON CONFLICT (step) DO NOTHING"
    ))
    .bind(next.step)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if first {
        if let Some(then) = &next.then {
            crate::enqueue_in_tx(&mut tx, wrap((**then).clone())).await?;
        }
        if let Some(group) = next.group {
            let finished: Option<serde_json::Value> = sqlx::query_scalar(attome_db::tagged_sql!(
                "jobs.chain",
                "UPDATE job_group SET remaining = remaining - 1, \
                     finished_at = CASE WHEN remaining = 1 THEN now() END \
                 WHERE id = $1 AND remaining > 0 \
                 RETURNING CASE WHEN remaining = 0 THEN finally END"
            ))
            .bind(group)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            if let Some(finally) = finished {
                let finally: RegisteredJob = serde_json::from_value(finally)?;
                crate::enqueue_in_tx(&mut tx, wrap(finally)).await?;
            }
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Removes step records and finished groups older than `days` days.
pub async fn prune(pool: &attome_db::DbPool, days: i32) -> Result<u64, sqlx::Error> {
    let steps = sqlx::query(attome_db::tagged_sql!(
        "jobs.chain",
        "DELETE FROM job_chain_step WHERE created_at < now() - make_interval(days => $1)"
    ))
    .bind(days)
    .execute(pool)
    .await?
    .rows_affected();
    let groups = sqlx::query(attome_db::tagged_sql!(
        "jobs.chain",
        "DELETE FROM job_group WHERE finished_at < now() - make_interval(days => $1)"
    ))
    .bind(days)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(steps + groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(name: &str) -> RegisteredJob {
        RegisteredJob {
            name: name.to_owned(),
            version: 1,
            payload: serde_json::Value::Null,
            next: None,
        }
    }

    #[test]
    fn a_chain_nests_and_keeps_its_wire_shape() {
        let chained = job("a").then(job("b").then(job("c")));
        let next = chained.next.as_ref().expect("a has a next");
        let b = next.then.as_ref().expect("then b");
        assert_eq!(b.name, "b");
        assert_eq!(
            b.next
                .as_ref()
                .and_then(|c| c.then.as_ref())
                .map(|c| c.name.as_str()),
            Some("c")
        );
        let wire = serde_json::to_value(&chained).expect("serialize");
        let back: RegisteredJob = serde_json::from_value(wire).expect("parse");
        assert_eq!(back, chained);
        let plain = serde_json::to_value(job("a")).expect("serialize");
        assert!(
            plain.get("next").is_none(),
            "no continuation, no key: {plain}"
        );
    }

    #[test]
    fn a_group_member_keeps_its_own_then() {
        let group = Uuid::now_v7();
        let member = job("a").then(job("b")).in_group(group);
        let next = member.next.expect("continuation");
        assert_eq!(next.group, Some(group));
        assert_eq!(next.then.map(|b| b.name), Some("b".to_owned()));
    }
}
