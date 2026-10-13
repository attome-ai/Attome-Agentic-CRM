//! D-786 — the metric service principal: the one identity every query-backed
//! metric snapshot runs under (D-522's "service principal for a fixed scope").
//!
//! **Identity.** One `user_account` row with the fixed, well-known id
//! [`METRIC_PRINCIPAL_ID`] (same convention `attome-workflow`'s
//! `workflow_system_user_id` uses): it has no password, no API key and no
//! federation link, and its `@internal.attome` address is reserved
//! (`attome_security::accounts::is_reserved_service_email`): every federated
//! link/create path and password register/login/reset refuse it, so nothing can
//! sign in as it. It holds exactly one role,
//! [`METRIC_ROLE_NAME`], shipped by `platform-bundles/attome-metric.json`.
//!
//! **Provisioning.** The role (and its one privilege,
//! [`METRIC_SNAPSHOT_PRIVILEGE`]) is platform-bundle content, applied at boot
//! like every other bundle role. The user row and its membership of that role
//! are ensured lazily by [`resolve`], the first time a query metric is computed
//! — engine-owned SQL, the same "lazily ensured, not seeded in a migration"
//! posture `attome-workflow` takes for its own system user. Both inserts are
//! `ON CONFLICT DO NOTHING`: an existing row is never modified, so an admin who
//! deactivates the user keeps it that way — that is the kill switch.
//! *Deactivate, don't delete*: a hard-deleted user, a hard-deleted membership
//! or a re-created role is silently re-provisioned on the next compute. The
//! one-time membership insert writes an `Access` / `Grant` security event in
//! its own transaction (guidelines §7), attributed to whoever triggered the
//! compute ([`Trigger`]).
//!
//! **Scope.** `query_exec::execute_stored_query` decides what the principal
//! may run: the stored query's `required_privilege` must be held (a query
//! without one is admin-only, and this principal is never admin). For an
//! admin-published query it also requires `{entity}.read` on each relation and
//! applies record-level scope at the principal's depth; the role ships with
//! [`METRIC_SNAPSHOT_PRIVILEGE`] only and an admin grants entity reads through
//! the role-grant admin API. **Not** "exactly what its roles grant" for a
//! platform-bundle query: those are published without the relation lint, so
//! their relation list is empty and no entity-read check or record scope
//! applies — `required_privilege` is the whole gate, and the SQL reads
//! whatever the SELECT-only readonly role can. That is the platform-bundle
//! trust boundary (compiled-in, developer-authored SQL);
//! `tests::shipped_snapshot_queries_are_single_value_aggregates` keeps every
//! bundle query carrying [`METRIC_SNAPSHOT_PRIVILEGE`] a single-row aggregate
//! that returns only a `value`.
//!
//! **Fail closed.** [`resolve`] refuses — and the snapshot is recorded
//! `failed` — when the role is missing, the user row is missing or inactive,
//! or the resolved context is an administrator (D-440's "never a superuser"
//! rule, applied to this unattended identity too).
use attome_audit::{
    AuditOperation, AuditSource,
    security::{MandatoryCategory, SecurityEvent, SecurityTx},
};
use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

/// Fixed id of the metric service principal's `user_account` row
/// ("METR" in the low bits). Never reused for anything else.
pub const METRIC_PRINCIPAL_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_4d45_5452_0001);

/// `user_account.user_name` / `email` of the principal.
const PRINCIPAL_USER_NAME: &str = "metric-service";
const PRINCIPAL_EMAIL: &str = "metric-service@internal.attome";

/// The role `platform-bundles/attome-metric.json` ships for the principal.
pub const METRIC_ROLE_NAME: &str = "Metric Service";

/// The privilege the role holds. A stored query whose `required_privilege` is
/// this key may be run by metric snapshots; nothing else in the platform
/// checks it.
pub const METRIC_SNAPSHOT_PRIVILEGE: &str = "attome_metric.snapshot";

/// Who triggered a compute: the audit actor and source for the one-time
/// provisioning event. The on-demand route passes its caller; the scheduled
/// sweep passes the principal itself as a background job.
#[derive(Debug, Clone, Copy)]
pub struct Trigger {
    pub actor: Uuid,
    pub source: AuditSource,
}

impl Trigger {
    /// `evaluated_by` as `compute_and_record` receives it: `None` or the
    /// principal's own id means the platform (a background job), anything else
    /// is the calling user (the API).
    pub fn from_evaluated_by(evaluated_by: Option<Uuid>) -> Self {
        match evaluated_by {
            Some(user) if user != METRIC_PRINCIPAL_ID => Self {
                actor: user,
                source: AuditSource::Api,
            },
            _ => Self {
                actor: METRIC_PRINCIPAL_ID,
                source: AuditSource::BackgroundJob,
            },
        }
    }
}

/// Why the principal could not be resolved. Every variant fails the snapshot
/// closed; the `Display` text is operator-actionable and carries no secret or
/// driver detail, so it is safe to persist as a snapshot's `error_message`.
#[derive(Debug)]
pub enum PrincipalError {
    RoleMissing,
    UserMissing,
    Disabled,
    IsAdmin,
    Internal(AppError),
}

impl std::fmt::Display for PrincipalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoleMissing => write!(
                f,
                "metric service principal unavailable: the '{METRIC_ROLE_NAME}' role does not exist"
            ),
            Self::UserMissing => write!(
                f,
                "metric service principal unavailable: its system user could not be provisioned"
            ),
            Self::Disabled => write!(
                f,
                "metric service principal is disabled (its system user is inactive)"
            ),
            Self::IsAdmin => write!(
                f,
                "metric service principal refused: it must not hold administrator rights"
            ),
            Self::Internal(_) => write!(
                f,
                "metric service principal could not be resolved; see server logs"
            ),
        }
    }
}

impl From<AppError> for PrincipalError {
    fn from(e: AppError) -> Self {
        Self::Internal(e)
    }
}

/// Ensures the principal exists (first use only) and returns its
/// `SecurityContext`, resolved fresh from PostgreSQL (`resolve_uncached`, the
/// D-440 discipline: a grant revoked a moment ago is already gone).
pub async fn resolve(
    state: &EngineState,
    trigger: Trigger,
) -> Result<SecurityContext, PrincipalError> {
    let db = &state.base.db;
    ensure(state, trigger).await?;

    let is_active: Option<Option<bool>> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(METRIC_PRINCIPAL_ID)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    match is_active {
        None => return Err(PrincipalError::UserMissing),
        Some(Some(true)) => {}
        Some(_) => return Err(PrincipalError::Disabled),
    }

    let ctx = attome_security::resolve_uncached(db, METRIC_PRINCIPAL_ID).await?;
    if ctx.is_admin {
        return Err(PrincipalError::IsAdmin);
    }
    Ok(ctx)
}

/// First-use provisioning. Reads first so the steady state is two cheap
/// SELECTs and no write; only a missing row opens the audited transaction.
async fn ensure(state: &EngineState, trigger: Trigger) -> Result<(), PrincipalError> {
    let db = &state.base.db;
    let role_id: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(METRIC_ROLE_NAME)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let role_id = role_id.ok_or(PrincipalError::RoleMissing)?;

    // Any membership row, live or soft-deleted, means provisioning already
    // happened; a soft-deleted one is an admin's decision and stays deleted.
    let (user_exists, membership_exists): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM user_account WHERE id = $1), \
                EXISTS (SELECT 1 FROM user_account_mm_role \
                        WHERE user_ref = $1 AND role_ref = $2)",
    )
    .bind(METRIC_PRINCIPAL_ID)
    .bind(role_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if user_exists && membership_exists {
        return Ok(());
    }

    // Concurrency: two first-use callers (a sweep tick and an on-demand
    // compute) both reach here; every insert is `ON CONFLICT DO NOTHING`, so
    // the loser writes nothing and rolls back without an event.
    let event = SecurityEvent::new(
        MandatoryCategory::Access,
        AuditOperation::Grant,
        trigger.actor,
        "user_account_mm_role",
        None,
    )
    .named("metric.service_principal.provisioned")
    .comment(format!(
        "metric service principal provisioned and granted the '{METRIC_ROLE_NAME}' role (D-786)"
    ))
    .source(trigger.source);
    let mut tx = SecurityTx::begin(state, event).await?;

    // `ON CONFLICT DO NOTHING` with no target: an unrelated row that happens
    // to hold this email makes the insert a no-op, and `resolve` then fails
    // closed with `UserMissing` rather than borrowing that user.
    let user_inserted = sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(METRIC_PRINCIPAL_ID)
    .bind(PRINCIPAL_USER_NAME)
    .bind(PRINCIPAL_EMAIL)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    let user_present: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_account WHERE id = $1)")
            .bind(METRIC_PRINCIPAL_ID)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !user_present {
        return Err(PrincipalError::UserMissing);
    }

    let membership_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2) \
         ON CONFLICT (user_ref, role_ref) DO NOTHING RETURNING id",
    )
    .bind(METRIC_PRINCIPAL_ID)
    .bind(role_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    match membership_id {
        Some(id) => {
            tx.event_mut().set_record_id(id);
            tx.commit().await?;
            tracing::info!(
                principal = %METRIC_PRINCIPAL_ID,
                role = METRIC_ROLE_NAME,
                "metric service principal provisioned (D-786)"
            );
        }
        None if user_inserted == 1 => {
            // User created by us, membership already there (a race with
            // another first use): still a write worth its event.
            tx.event_mut().set_operation(AuditOperation::Create);
            tx.commit().await?;
        }
        // Nothing written — dropping `tx` rolls back, no event.
        None => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caller_triggered_compute_is_attributed_to_the_caller() {
        let caller = Uuid::now_v7();
        let t = Trigger::from_evaluated_by(Some(caller));
        assert_eq!(t.actor, caller);
        assert!(matches!(t.source, AuditSource::Api));
        for sweep in [None, Some(METRIC_PRINCIPAL_ID)] {
            let t = Trigger::from_evaluated_by(sweep);
            assert_eq!(t.actor, METRIC_PRINCIPAL_ID);
            assert!(matches!(t.source, AuditSource::BackgroundJob));
        }
    }

    /// LOW 1 (review of D-786): a platform-bundle query has an empty relation
    /// list, so `required_privilege` is its only gate. Every such query that
    /// opts in to the metric principal must stay a single-row aggregate that
    /// returns a `value` and nothing that could list rows.
    #[test]
    fn shipped_snapshot_queries_are_single_value_aggregates() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../platform-bundles");
        let entries = std::fs::read_dir(&dir).expect("read platform-bundles");
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read bundle");
            let bundle: serde_json::Value = serde_json::from_str(&text).expect("bundle json");
            let queries = bundle["queries"].as_array().cloned().unwrap_or_default();
            for q in queries {
                if q["required_privilege"].as_str() != Some(METRIC_SNAPSHOT_PRIVILEGE) {
                    continue;
                }
                let sql = q["sql"].as_str().unwrap_or_default().to_ascii_lowercase();
                let name = q["name"].as_str().unwrap_or_default();
                assert!(sql.trim_start().starts_with("select "), "{name}: {sql}");
                assert!(
                    sql.contains(" as value"),
                    "{name} must return `value`: {sql}"
                );
                assert!(
                    ["count(", "sum(", "avg(", "min(", "max("]
                        .iter()
                        .any(|agg| sql.contains(agg)),
                    "{name} must aggregate: {sql}"
                );
                for forbidden in [" group by ", " limit ", " offset ", "select *"] {
                    assert!(
                        !sql.contains(forbidden),
                        "{name} contains {forbidden:?}: {sql}"
                    );
                }
            }
        }
    }
}
