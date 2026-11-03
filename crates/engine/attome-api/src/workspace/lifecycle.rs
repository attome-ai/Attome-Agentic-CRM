//! T5-T6: a workspace's life cycle.
//!
//! - **Idle expiry** ([`sweep`], the daily `WorkspaceExpirySweep` job): an
//!   open workspace unused for `metadata.workspace_idle_days` (30 unset) is
//!   discarded. Its owner is told in the app [`WARN_DAYS`] days before (at
//!   once when the idle time is shorter), and a workspace is discarded only
//!   a day or more after that warning; using it clears the warning. The
//!   sweep also drops the schema of a discarded workspace whose drop failed.
//! - **Refresh** ([`refresh`], `POST /api/v1/admin/workspaces/{id}/refresh`):
//!   brings in what live changed that the workspace has not made its own.
//!   Metadata rows live added are copied in and rows live changed are copied
//!   over, except rows an operation of the workspace's changeset names (its
//!   own changes, removals included). Entity tables live added are created
//!   (empty), and a column live added is added where the workspace's
//!   metadata now has its field. The workspace's process is stopped so the
//!   next request starts one that reads the refreshed metadata.
//! - **Storage**: the data a workspace starts with is checked against
//!   `metadata.workspace_data_max_mb` when it is made ([`super::data`]).

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::{EngineState, quote_ident};
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{COLUMNS, Workspace, discard_workspace, find, proxy, schema};

/// Days a workspace may stay unused when `metadata.workspace_idle_days` is
/// unset.
pub const DEFAULT_IDLE_DAYS: i64 = 30;
/// How many days before expiry the owner is warned.
pub const WARN_DAYS: i64 = 7;
/// Where the warning points.
const WORKSPACES_ROUTE: &str = "/xrm/admin/workspaces";

/// The configured idle time in days, at least one.
fn idle_days(state: &EngineState) -> i64 {
    state
        .base
        .config
        .metadata
        .workspace_idle_days
        .unwrap_or(DEFAULT_IDLE_DAYS)
        .max(1)
}

/// Unused days after which the owner is warned: [`WARN_DAYS`] before
/// expiry, or at once when the idle time is shorter. Pure.
pub fn warn_after_days(idle_days: i64) -> i64 {
    (idle_days - WARN_DAYS).max(0)
}

/// What one sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Workspaces whose owner was warned.
    pub warned: Vec<Uuid>,
    /// Workspaces discarded.
    pub discarded: Vec<Uuid>,
    /// Schemas of earlier discards dropped now.
    pub schemas_dropped: usize,
}

/// The daily job's body, at `now`.
pub async fn sweep(state: &EngineState, now: DateTime<Utc>) -> Result<SweepOutcome, AppError> {
    let idle = idle_days(state);
    let mut outcome = SweepOutcome::default();

    let warn_before = now - Duration::days(warn_after_days(idle));
    let warned: Vec<(Uuid, String, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE develop_workspace SET expiry_warned_at = $1 \
          WHERE status = 'open' AND expiry_warned_at IS NULL AND last_used_at < $2 \
         RETURNING id, name, owner_ref, last_used_at",
    )
    .bind(now)
    .bind(warn_before)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (id, name, owner, last_used) in warned {
        let expires = (last_used + Duration::days(idle)).max(now + Duration::days(1));
        warn_owner(state, owner, &name, last_used, expires).await;
        tracing::info!(workspace = %id, %owner, "workspace: the owner was warned of idle expiry");
        outcome.warned.push(id);
    }

    let expired: Vec<Workspace> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM develop_workspace \
          WHERE status = 'open' AND last_used_at < $1 \
            AND expiry_warned_at IS NOT NULL AND expiry_warned_at < $2 \
          ORDER BY last_used_at"
    ))
    .bind(now - Duration::days(idle))
    .bind(now - Duration::days(1))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for workspace in expired {
        let comment = format!(
            "workspace {} discarded: unused for {idle} days",
            workspace.name
        );
        match discard_workspace(state, Uuid::nil(), &workspace, &comment).await {
            Ok(()) => {
                tracing::info!(workspace = %workspace.id, "workspace: discarded after idle expiry");
                outcome.discarded.push(workspace.id);
            }
            // Used, published or discarded since it was read: not an error.
            Err(AppError::Conflict(_)) => {}
            Err(error) => return Err(error),
        }
    }

    let leftover: Vec<String> = sqlx::query_scalar(
        "SELECT w.schema_name FROM develop_workspace w \
          WHERE w.status = 'discarded' \
            AND EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = w.schema_name)",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for schema_name in leftover {
        match schema::drop_schema(&state.base.db_migrator, &schema_name).await {
            Ok(()) => outcome.schemas_dropped += 1,
            Err(error) => {
                tracing::warn!(schema = %schema_name, %error, "workspace: a discarded schema was not dropped");
            }
        }
    }
    Ok(outcome)
}

/// The in-app warning to `owner`. Best effort: a lost note is logged, and
/// the workspace is still discarded only a day or more after the warning
/// was recorded.
async fn warn_owner(
    state: &EngineState,
    owner: Uuid,
    name: &str,
    last_used: DateTime<Utc>,
    expires: DateTime<Utc>,
) {
    let request = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_owned(),
        recipient_user_ref: Some(owner),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned()]),
        subject: Some(format!("Workspace {name} will be discarded")),
        body_html: None,
        body_text: Some(format!(
            "The workspace {name} has not been used since {}. It will be discarded on {} \
             unless someone works in it before then. Publish what you want to keep.",
            last_used.format("%Y-%m-%d"),
            expires.format("%Y-%m-%d")
        )),
        route: Some(WORKSPACES_ROUTE.to_owned()),
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
        tracing::warn!(%owner, %error, "workspace: the expiry warning was not sent");
    }
}

/// What a refresh brought in.
#[derive(Debug, Default, Clone, Serialize, ToSchema)]
pub struct RefreshReport {
    pub workspace: Uuid,
    /// Metadata rows live added, copied in.
    pub metadata_rows_added: u64,
    /// Metadata rows live changed, copied over.
    pub metadata_rows_updated: u64,
    /// Entity tables live added, created empty.
    pub tables_added: Vec<String>,
    /// Columns live added, as `entity.field`.
    pub columns_added: Vec<String>,
}

/// The columns both copies of `table` have, in the workspace's order.
async fn shared_columns(
    db: &DbPool,
    live: &str,
    ws: &str,
    table: &str,
) -> Result<Vec<String>, AppError> {
    let live_columns = schema::writable_columns(db, live, table).await?;
    Ok(schema::writable_columns(db, ws, table)
        .await?
        .into_iter()
        .filter(|c| live_columns.contains(c))
        .collect())
}

/// Copies in the rows of metadata table `table` live added, and over the
/// rows live changed, leaving the rows `own` names. A live row whose unique
/// key the workspace already gave another row is left out. A table without
/// an `id` column is left as it is.
async fn refresh_metadata_table(
    db: &DbPool,
    live: &str,
    ws: &str,
    table: &str,
    own: &[Uuid],
    report: &mut RefreshReport,
) -> Result<(), AppError> {
    let columns = shared_columns(db, live, ws, table).await?;
    if !columns.iter().any(|c| c == "id") {
        return Ok(());
    }
    let source = format!("{}.{}", quote_ident(live), quote_ident(table));
    let target = format!("{}.{}", quote_ident(ws), quote_ident(table));
    let list = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    report.metadata_rows_added += sqlx::query(&format!(
        "INSERT INTO {target} ({list}) OVERRIDING SYSTEM VALUE \
         SELECT {list} FROM {source} l \
          WHERE NOT EXISTS (SELECT 1 FROM {target} w WHERE w.id = l.id) \
            AND NOT (l.id = ANY($1)) \
         ON CONFLICT DO NOTHING"
    ))
    .bind(own)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    let changed: Vec<&String> = columns.iter().filter(|c| *c != "id").collect();
    if changed.is_empty() {
        return Ok(());
    }
    let names = changed
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let from_live = changed
        .iter()
        .map(|c| format!("l.{}", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");
    let in_ws = changed
        .iter()
        .map(|c| format!("w.{}", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");
    // Compared as text: a json column has no equality operator.
    report.metadata_rows_updated += sqlx::query(&format!(
        "UPDATE {target} w SET ({names}) = ROW({from_live}) FROM {source} l \
          WHERE w.id = l.id AND NOT (w.id = ANY($1)) \
            AND ROW({in_ws})::text IS DISTINCT FROM ROW({from_live})::text"
    ))
    .bind(own)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(())
}

/// Adds to the workspace's copy of `table` each column live has that it
/// lacks, when the workspace's metadata has that field.
async fn refresh_columns(
    db: &DbPool,
    live: &str,
    ws: &str,
    table: &str,
    report: &mut RefreshReport,
) -> Result<(), AppError> {
    let missing: Vec<(String, String)> = sqlx::query_as(
        "SELECT a.attname::text, format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid = to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped \
            AND NOT EXISTS (SELECT 1 FROM pg_attribute b \
                             WHERE b.attrelid = to_regclass($2) AND b.attname = a.attname \
                               AND NOT b.attisdropped) \
          ORDER BY a.attnum",
    )
    .bind(format!("{}.{}", quote_ident(live), quote_ident(table)))
    .bind(format!("{}.{}", quote_ident(ws), quote_ident(table)))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (column, column_type) in missing {
        let known: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {ws}.attribute_info a \
                JOIN {ws}.entity_info e ON e.id = a.entity_ref \
               WHERE e.logicalname = $1 AND a.logicalname = $2)",
            ws = quote_ident(ws)
        ))
        .bind(table)
        .bind(&column)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if !known {
            continue;
        }
        let mut tx = attome_db::tx::begin(db).await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        // The type is the catalogue's own rendering of live's column.
        sqlx::query(&format!(
            "ALTER TABLE {}.{} ADD COLUMN IF NOT EXISTS {} {column_type}",
            quote_ident(ws),
            quote_ident(table),
            quote_ident(&column)
        ))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        report.columns_added.push(format!("{table}.{column}"));
    }
    Ok(())
}

/// Refresh a workspace
///
/// Brings in what live changed that the workspace has not made its own:
/// metadata rows live added or changed (except those the workspace's
/// changeset names), entity tables live added (empty) and columns live
/// added. The workspace's process restarts on its next request. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/refresh",
    operation_id = "refresh_workspace",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The workspace")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Refreshed", body = RefreshReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such workspace", body = ErrorResponse),
        (status = 409, description = "The workspace is not open", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn refresh(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<Json<RefreshReport>, AppError> {
    let workspace = find(&state, id).await?;
    if workspace.status != "open" {
        return Err(AppError::Conflict(
            "only an open workspace can be refreshed",
        ));
    }
    let ws: String = sqlx::query_scalar("SELECT schema_name FROM develop_workspace WHERE id = $1")
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !schema::is_workspace_schema(&ws) {
        return Err(AppError::internal(format!(
            "workspace {id}: {ws:?} is not a workspace schema"
        )));
    }
    let db = &state.base.db_migrator;
    let live = schema::live_schema(db).await?;
    let own: Vec<Uuid> = match workspace.changeset_ref {
        Some(changeset) => sqlx::query_scalar(
            "SELECT DISTINCT object_ref FROM changeset_operation \
              WHERE changeset_ref = $1 AND object_ref IS NOT NULL",
        )
        .bind(changeset)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
        None => Vec::new(),
    };

    let mut report = RefreshReport {
        workspace: id,
        ..RefreshReport::default()
    };
    let metadata = schema::metadata_tables();
    for table in &metadata {
        if schema::exists(db, &live, table).await? && schema::exists(db, &ws, table).await? {
            refresh_metadata_table(db, &live, &ws, table, &own, &mut report).await?;
        }
    }

    let mut entity_tables: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname::text FROM entity_info \
          WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL \
         UNION \
         SELECT join_table::text FROM relationship_info \
          WHERE is_active AND NOT is_deleted",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    entity_tables.sort();
    entity_tables.dedup();
    for table in entity_tables {
        if metadata.contains(&table.as_str())
            || schema::is_shared(&table)
            || !schema::exists(db, &live, &table).await?
        {
            continue;
        }
        if schema::exists(db, &ws, &table).await? {
            refresh_columns(db, &live, &ws, &table, &mut report).await?;
        } else {
            schema::copy_table(db, &live, &ws, &table, false).await?;
            report.tables_added.push(table);
        }
    }
    if !report.tables_added.is_empty() {
        schema::grant_runtime(db, &ws).await?;
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "develop_workspace",
            Some(id),
        )
        .named("workspace.refresh")
        .comment(format!(
            "workspace {} refreshed: {} metadata rows added, {} updated, {} tables, {} columns",
            workspace.name,
            report.metadata_rows_added,
            report.metadata_rows_updated,
            report.tables_added.len(),
            report.columns_added.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    proxy::stop(id).await;
    Ok(Json(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owner_is_warned_a_week_ahead_or_at_once() {
        assert_eq!(warn_after_days(30), 23);
        assert_eq!(warn_after_days(8), 1);
        assert_eq!(warn_after_days(7), 0);
        assert_eq!(warn_after_days(1), 0);
    }
}
