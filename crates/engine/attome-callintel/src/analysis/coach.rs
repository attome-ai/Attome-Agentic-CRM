//! D22-T7: coaching on an analysed call.
//!
//! - [`create_task_from_finding`] turns a finding (a next step, most often)
//!   into a D14 task (`activity` of type `task`) through the record engine,
//!   on the call's deal when it has one, else on the call, owned by the
//!   call's owner; the finding keeps the task in `task_ref`, so asking again
//!   answers the same task.
//! - [`confirm_answer`] sets a scorecard answer's confirmed value. Only a
//!   manager of the call's owner may (anyone holding a position above the
//!   owner's in the position hierarchy, [`is_manager_of`]); the answer's
//!   `row_version` must match.
//! - [`add_comment`] adds a comment at a moment of the call (a reply when it
//!   names a parent): the owner, their managers, and peers holding
//!   `call_comment.create` may. The owner is notified of others' comments.
//! - [`comments`] reads them: the owner and their managers see all; anyone
//!   else sees only their own.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

/// The longest comment kept.
pub const MAX_COMMENT_CHARS: usize = 4000;
/// While a task is being made for a finding.
const CREATING: &str = "creating";

/// Whether `manager` holds a position above any of `user`'s.
pub async fn is_manager_of(
    state: &EngineState,
    manager: Uuid,
    user: Uuid,
) -> Result<bool, AppError> {
    if manager == user {
        return Ok(false);
    }
    sqlx::query_scalar(
        "WITH RECURSIVE above(id, depth) AS ( \
             SELECT p.parent_position_ref, 1 FROM user_account_mm_position m \
               JOIN position p ON p.id = m.position_ref AND p.is_deleted = false \
              WHERE m.user_ref = $2 AND m.is_deleted = false \
             UNION \
             SELECT p.parent_position_ref, a.depth + 1 FROM above a \
               JOIN position p ON p.id = a.id AND p.is_deleted = false \
              WHERE a.depth < 20) \
         SELECT EXISTS (SELECT 1 FROM above a \
                          JOIN user_account_mm_position m \
                            ON m.position_ref = a.id AND m.is_deleted = false \
                         WHERE m.user_ref = $1)",
    )
    .bind(manager)
    .bind(user)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

type FindingRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

/// The task made from `finding`, made now or before.
pub async fn create_task_from_finding(
    state: &EngineState,
    ctx: &SecurityContext,
    finding: Uuid,
) -> Result<Uuid, AppError> {
    ctx.require("activity", "create")?;
    let db = &state.base.db;
    let row: Option<FindingRow> = sqlx::query_as(
        "SELECT a.id, f.text, f.task_ref, a.owner_user, a.opportunity_id, a.activity_id \
           FROM call_finding f JOIN call_analysis a ON a.id = f.analysis_ref \
          WHERE f.id = $1 AND (f.is_active IS NULL OR f.is_active = true)",
    )
    .bind(finding)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((analysis, text, task, owner, opportunity, activity)) = row else {
        return Err(AppError::NotFound);
    };
    if let Some(task) = task.as_deref().and_then(|t| Uuid::parse_str(t).ok()) {
        return Ok(task);
    }
    let claimed =
        sqlx::query("UPDATE call_finding SET task_ref = $2 WHERE id = $1 AND task_ref IS NULL")
            .bind(finding)
            .bind(CREATING)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    if claimed.rows_affected() != 1 {
        return Err(AppError::Conflict("a task is being made from this finding"));
    }
    let (entity, record) = match (opportunity, activity) {
        (Some(o), _) if !o.is_empty() => ("opportunity", o),
        (_, Some(a)) => ("activity", a),
        _ => ("call_analysis", analysis.to_string()),
    };
    let text = text.unwrap_or_default();
    let subject: String = text.trim().chars().take(200).collect();
    let mut body = json!({
        "subject": if subject.is_empty() { "Next step from a call".to_owned() } else { subject },
        "activity_type": "task",
        "description": text,
        "entity_name": entity,
        "record_id": record,
    });
    if let Some(owner) = owner {
        body["owner_ref"] = json!(owner);
    }
    match attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, "activity", body)
        .await
    {
        Ok((task, _)) => {
            sqlx::query("UPDATE call_finding SET task_ref = $2 WHERE id = $1")
                .bind(finding)
                .bind(task.to_string())
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            Ok(task)
        }
        Err(error) => {
            sqlx::query("UPDATE call_finding SET task_ref = NULL WHERE id = $1 AND task_ref = $2")
                .bind(finding)
                .bind(CREATING)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            Err(error)
        }
    }
}

/// The owner of `analysis`.
async fn owner_of(state: &EngineState, analysis: Uuid) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT owner_user FROM call_analysis WHERE id = $1 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(analysis)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// A manager of the call's owner confirms a scorecard answer.
pub async fn confirm_answer(
    state: &EngineState,
    ctx: &SecurityContext,
    answer: Uuid,
    value: &str,
    expected_row_version: i64,
) -> Result<(), AppError> {
    if !["yes", "no", "unclear"].contains(&value) {
        return Err(AppError::Validation("value is yes, no or unclear".into()));
    }
    let analysis: Uuid = sqlx::query_scalar(
        "SELECT analysis_ref FROM call_scorecard_answer WHERE id = $1 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(answer)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let Some(owner) = owner_of(state, analysis).await? else {
        return Err(AppError::Forbidden);
    };
    if !is_manager_of(state, ctx.user_id, owner).await? {
        return Err(AppError::Forbidden);
    }
    let updated = sqlx::query(
        "UPDATE call_scorecard_answer SET confirmed_value = $2, confirmed_by = $3, \
                confirmed_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $4",
    )
    .bind(answer)
    .bind(value)
    .bind(ctx.user_id)
    .bind(expected_row_version)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::VersionConflict);
    }
    Ok(())
}

/// Adds a comment at `at_ms` of the call (a reply under `parent`); its id.
pub async fn add_comment(
    state: &EngineState,
    ctx: &SecurityContext,
    analysis: Uuid,
    at_ms: i64,
    body: &str,
    parent: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let body = body.trim();
    if body.is_empty() || body.chars().count() > MAX_COMMENT_CHARS {
        return Err(AppError::Validation(format!(
            "a comment is 1 to {MAX_COMMENT_CHARS} characters"
        )));
    }
    let owner = owner_of(state, analysis).await?;
    let me = ctx.user_id;
    let allowed = owner == Some(me)
        || match owner {
            Some(owner) => is_manager_of(state, me, owner).await?,
            None => false,
        }
        || ctx.require("call_comment", "create").is_ok();
    if !allowed {
        return Err(AppError::Forbidden);
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO call_comment (id, analysis_ref, at_ms, body, author, parent_ref, owner_ref, \
             is_active, row_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $5, true, 0)",
    )
    .bind(id)
    .bind(analysis)
    .bind(at_ms.max(0) as f64)
    .bind(body)
    .bind(me)
    .bind(parent)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(owner) = owner.filter(|o| *o != me) {
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(owner),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some("A comment on your call".to_owned()),
            body_html: None,
            body_text: Some(body.chars().take(300).collect()),
            route: Some(format!("/xrm/entity/call_analysis/{analysis}")),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(error) = attome_notification::dispatch::create_dispatch(
            &state.base.db,
            &state.base.config.notification,
            request,
        )
        .await
        {
            tracing::warn!(%analysis, %error, "call comment: the owner was not notified");
        }
    }
    Ok(id)
}

/// A comment as read.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CallComment {
    pub id: Uuid,
    pub at_ms: Option<f64>,
    pub body: Option<String>,
    pub author: Option<Uuid>,
    pub parent_ref: Option<Uuid>,
    pub created_at: Option<DateTime<Utc>>,
}

/// The comments on `analysis` the caller may read.
pub async fn comments(
    state: &EngineState,
    ctx: &SecurityContext,
    analysis: Uuid,
) -> Result<Vec<CallComment>, AppError> {
    let owner = owner_of(state, analysis).await?;
    let me = ctx.user_id;
    let sees_all = owner == Some(me)
        || match owner {
            Some(owner) => is_manager_of(state, me, owner).await?,
            None => false,
        };
    sqlx::query_as(
        "SELECT id, at_ms::float8 AS at_ms, body, author, parent_ref, created_at FROM call_comment \
          WHERE analysis_ref = $1 AND (is_active IS NULL OR is_active = true) \
            AND ($2 OR author = $3) \
          ORDER BY at_ms, created_at",
    )
    .bind(analysis)
    .bind(sees_all)
    .bind(me)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}
