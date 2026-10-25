//! Z10-T6: the `queue:<uuid>` approver token — every active member of a
//! service work queue. It lives here, not in attome-audit, so the audit
//! engine never depends on attome-service; boot installs it.

use attome_audit::approval_resolvers::{ApproverResolver, ResolveCtx, ResolveFuture};
use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// Resolves `queue:<uuid>` to the queue's active members.
pub struct QueueResolver;

impl ApproverResolver for QueueResolver {
    fn prefix(&self) -> &'static str {
        "queue"
    }

    fn validate(&self, rest: &str) -> Result<(), AppError> {
        Uuid::parse_str(rest).map(|_| ()).map_err(|_| {
            AppError::Validation(format!(
                "invalid approver token \"queue:{rest}\": queue: must be followed by a uuid"
            ))
        })
    }

    fn resolve<'a>(
        &'a self,
        state: &'a EngineState,
        rest: &'a str,
        _ctx: &'a ResolveCtx<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let Ok(queue) = Uuid::parse_str(rest) else {
                return Ok(Vec::new());
            };
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT m.user_ref FROM service_work_queue_member m \
                   JOIN user_account u ON u.id = m.user_ref \
                  WHERE m.queue_ref = $1 AND (m.is_active IS NULL OR m.is_active = true) \
                    AND (u.is_active IS NULL OR u.is_active = TRUE)",
            )
            .bind(queue)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(rows.into_iter().map(|(id,)| id).collect())
        })
    }
}
