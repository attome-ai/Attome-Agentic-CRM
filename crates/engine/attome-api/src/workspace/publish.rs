//! T5-T4: publishing a workspace to live.
//!
//! A workspace's metadata writes record into its own changeset (opened when
//! the workspace is made; the proxy names it on every request it forwards).
//! Publishing goes through the changeset engine:
//!
//! 1. the workspace moves `open` → `publishing`, so no further write lands;
//! 2. live changes made since the workspace was made are checked against
//!    the workspace's ([`conflicts`]): a change to the same object refuses
//!    the publish (`409 workspace_conflicts`; the preview lists them);
//! 3. the changeset is closed, translated against the workspace's schema
//!    (its metadata is there, not live's);
//! 4. the closed document is planned against live and persisted, and its
//!    rows go through the apply route's gates ([`gated_apply`]): customer
//!    tests, governance, approval, then the `ApplyChangesets` job;
//! 5. the workspace is marked `published`.
//!
//! A refusal at 2 (or a blocked plan) returns the workspace to `open`. A
//! failure after 3 leaves it `publishing` with its changeset closed; calling
//! publish again resumes at 4.
//!
//! The preview (`GET .../publish`) runs 2 and 4 without writing: the draft
//! document is built in a transaction that is rolled back, and the plan is
//! not persisted.
//!
//! [`gated_apply`]: crate::changeset::apply_routes::gated_apply

use std::collections::HashSet;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_core::changeset::{ChangesetStatus, store};
use attome_security::MetadataRollout;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{Workspace, find};
use crate::changeset::apply_routes::{ApplyChangesetsAccepted, ApplyChangesetsBody, gated_apply};
use crate::changeset::close;
use crate::changeset::ledger::{ApplyPhase, ApplySource};
use crate::changeset::plan::{self, ChangesetPlan, PlanContext};

/// The refusal when live changed what the workspace changes.
pub const WORKSPACE_CONFLICTS: &str = "workspace_conflicts: live changed objects this workspace \
     changes since it was made; the publish preview lists them";

/// Most live operations read for the conflict check.
const MAX_LIVE_OPERATIONS: i64 = 20_000;

/// A live change to an object the workspace also changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PublishConflict {
    /// The workspace's operation, e.g. `add_field`.
    pub op: String,
    /// The object both sides changed, e.g. `{"entity": "deal", "field": "stage"}`.
    #[schema(value_type = Object)]
    pub target: Value,
    /// The live operation.
    pub live_op: String,
    /// The changeset that made the live change.
    pub live_changeset: String,
    pub live_at: DateTime<Utc>,
}

/// What publishing would do.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublishPreview {
    pub workspace: Uuid,
    /// Recorded metadata operations in the workspace.
    pub operations: i32,
    /// Live changes to the same objects; publish is refused while any.
    pub conflicts: Vec<PublishConflict>,
    /// The plan against live; `None` when the workspace changed nothing.
    pub plan: Option<ChangesetPlan>,
    /// No conflicts, something to publish, and nothing blocked.
    pub publishable: bool,
}

/// `POST .../publish`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishBody {
    /// The verified backup taken before this publish; required on the
    /// production profile, as for any changeset apply.
    #[serde(default)]
    pub backup_ref: Option<String>,
}

/// `POST .../publish`'s answer.
#[derive(Debug, Serialize, ToSchema)]
pub struct Published {
    pub workspace: Workspace,
    pub plan: ChangesetPlan,
    /// The queued apply (or the approval it waits on).
    pub apply: ApplyChangesetsAccepted,
    /// Contract rows (removals), applied with
    /// `POST /api/v1/admin/metadata/changesets/apply` once the expand rows
    /// succeeded; empty when there are none or they were queued here.
    pub contract_apply_ids: Vec<Uuid>,
}

/// One operation: its name and target.
#[derive(Debug, Clone)]
struct Change {
    op: String,
    target: Value,
}

/// One live operation and where it came from.
#[derive(Debug, Clone)]
struct LiveChange {
    change: Change,
    changeset: String,
    at: DateTime<Utc>,
}

/// The kind of object an operation changes: its name without the verb
/// (`add_field`, `update_field` and `retire_field` all change a `field`).
/// Pure.
fn object_of(op: &str) -> &str {
    const VERBS: &[&str] = &[
        "create_",
        "update_",
        "retire_",
        "reactivate_",
        "upsert_",
        "add_",
        "remove_",
        "set_",
        "clear_",
        "publish_",
        "ensure_",
        "grant_",
        "revoke_",
        "delete_",
        "rename_",
        "change_",
    ];
    VERBS
        .iter()
        .find_map(|verb| op.strip_prefix(verb))
        .unwrap_or(op)
}

/// The entity an operation's target names, if any. Pure.
fn entity_of(target: &Value) -> Option<&str> {
    target.get("entity").and_then(Value::as_str)
}

/// Whether two operations change the same object: the same kind of object
/// with the same target, or anything on an entity the other retires. Pure.
fn clash(ours: &Change, theirs: &Change) -> bool {
    if object_of(&ours.op) == object_of(&theirs.op) && ours.target == theirs.target {
        return true;
    }
    let retires = |c: &Change| c.op == "retire_entity";
    (retires(ours) || retires(theirs))
        && entity_of(&ours.target).is_some()
        && entity_of(&ours.target) == entity_of(&theirs.target)
}

/// Every workspace operation a live change clashes with, once per pair of
/// operation and live changeset. Pure.
fn conflicts(ours: &[Change], live: &[LiveChange]) -> Vec<PublishConflict> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for mine in ours {
        for theirs in live {
            if !clash(mine, &theirs.change) {
                continue;
            }
            let key = (
                mine.op.clone(),
                mine.target.to_string(),
                theirs.changeset.clone(),
            );
            if seen.insert(key) {
                out.push(PublishConflict {
                    op: mine.op.clone(),
                    target: mine.target.clone(),
                    live_op: theirs.change.op.clone(),
                    live_changeset: theirs.changeset.clone(),
                    live_at: theirs.at,
                });
            }
        }
    }
    out
}

/// The workspace changeset's operations.
async fn workspace_changes(state: &EngineState, changeset: Uuid) -> Result<Vec<Change>, AppError> {
    let rows: Vec<(String, Value)> = sqlx::query_as(
        "SELECT op, target FROM changeset_operation WHERE changeset_ref = $1 ORDER BY seq",
    )
    .bind(changeset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(op, target)| Change { op, target })
        .collect())
}

/// Live's metadata changes since `since`: operations recorded by live writes
/// (every changeset that is not a workspace's), and the operations of
/// changesets applied or queued for apply (an imported changeset, a
/// published workspace), other than `own`.
async fn live_changes(
    state: &EngineState,
    since: DateTime<Utc>,
    own: Uuid,
) -> Result<Vec<LiveChange>, AppError> {
    let recorded: Vec<(String, Value, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT o.op, o.target, c.name, o.recorded_at \
         FROM changeset_operation o JOIN changeset c ON c.id = o.changeset_ref \
         WHERE o.recorded_at > $1 AND o.changeset_ref <> $2 \
           AND NOT EXISTS (SELECT 1 FROM develop_workspace w WHERE w.changeset_ref = o.changeset_ref) \
         ORDER BY o.recorded_at LIMIT $3",
    )
    .bind(since)
    .bind(own)
    .bind(MAX_LIVE_OPERATIONS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let applied: Vec<(String, Value, DateTime<Utc>)> = sqlx::query_as(
        "SELECT ref, document, created_at FROM changeset_apply \
         WHERE created_at > $1 AND changeset_id <> $2 \
           AND status IN ('queued', 'claimed', 'applying', 'succeeded') \
         ORDER BY created_at LIMIT $3",
    )
    .bind(since)
    .bind(own)
    .bind(MAX_LIVE_OPERATIONS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut out: Vec<LiveChange> = recorded
        .into_iter()
        .map(|(op, target, changeset, at)| LiveChange {
            change: Change { op, target },
            changeset,
            at,
        })
        .collect();
    for (reference, document, at) in applied {
        let operations = document
            .get("operations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        out.extend(operations.into_iter().filter_map(|o| {
            Some(LiveChange {
                change: Change {
                    op: o.get("op")?.as_str()?.to_owned(),
                    target: o.get("target")?.clone(),
                },
                changeset: reference.clone(),
                at,
            })
        }));
    }
    Ok(out)
}

/// `"ws_<id>", "<live schema>"`: the workspace's schema first. Identifiers
/// are quoted; the workspace schema name is checked by its pattern.
async fn search_path(state: &EngineState, schema_name: &str) -> Result<String, AppError> {
    if !super::schema::is_workspace_schema(schema_name) {
        return Err(AppError::internal(format!(
            "workspace schema {schema_name:?} does not match its pattern"
        )));
    }
    let live: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(format!(
        "\"{schema_name}\", \"{}\"",
        live.replace('"', "\"\"")
    ))
}

fn plan_context(user: Uuid) -> PlanContext {
    PlanContext {
        source: ApplySource::Admin,
        requested_by: Some(user),
        trusted: false,
        accept_clashes: false,
    }
}

/// The workspace row with its schema name and changeset, for publishing.
async fn publishing_parts(
    state: &EngineState,
    id: Uuid,
) -> Result<(Workspace, String, Uuid), AppError> {
    let workspace = find(state, id).await?;
    let schema_name: String =
        sqlx::query_scalar("SELECT schema_name FROM develop_workspace WHERE id = $1")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let changeset = workspace.changeset_ref.ok_or(AppError::Conflict(
        "this workspace records no changeset; it was made before publishing existed",
    ))?;
    Ok((workspace, schema_name, changeset))
}

/// The preview, also the publish's first check.
async fn preview_of(
    state: &EngineState,
    user: Uuid,
    workspace: &Workspace,
    schema_name: &str,
    changeset: Uuid,
) -> Result<PublishPreview, AppError> {
    let ours = workspace_changes(state, changeset).await?;
    let live = live_changes(state, workspace.created_at, changeset).await?;
    let conflicts = conflicts(&ours, &live);
    let path = search_path(state, schema_name).await?;
    let plan = match close::draft(state, changeset, &path).await? {
        Some(document) => Some(
            plan::plan(state, &[document], plan_context(user))
                .await?
                .plan,
        ),
        None => None,
    };
    let publishable = conflicts.is_empty() && plan.as_ref().is_some_and(|p| p.applicable);
    Ok(PublishPreview {
        workspace: workspace.id,
        operations: i32::try_from(ours.len()).unwrap_or(i32::MAX),
        conflicts,
        plan,
        publishable,
    })
}

/// Moves the workspace between states; `false` when it was not in `from`.
async fn set_status(state: &EngineState, id: Uuid, from: &str, to: &str) -> Result<bool, AppError> {
    let moved = sqlx::query(
        "UPDATE develop_workspace SET status = $3, row_version = row_version + 1 \
         WHERE id = $1 AND status = $2",
    )
    .bind(id)
    .bind(from)
    .bind(to)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(moved.rows_affected() == 1)
}

/// Preview publishing a workspace
///
/// What publishing the workspace would change live: the plan of its changes
/// against live, and the live changes made since the workspace was made that
/// touch the same objects (publish is refused while there are any). Writes
/// nothing.
#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/publish",
    operation_id = "preview_workspace_publish",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The workspace")),
    responses(
        (status = 200, description = "Success", body = PublishPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such workspace", body = ErrorResponse),
        (status = 409, description = "The workspace is not open, or records no changeset", body = ErrorResponse),
        (status = 422, description = "The workspace's changes do not make a valid changeset", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn preview(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PublishPreview>, AppError> {
    let (workspace, schema_name, changeset) = publishing_parts(&state, id).await?;
    if workspace.status != "open" {
        return Err(AppError::Conflict(
            "only an open workspace can be previewed",
        ));
    }
    Ok(Json(
        preview_of(&state, ctx.user_id, &workspace, &schema_name, changeset).await?,
    ))
}

/// Publish a workspace
///
/// Applies the workspace's changes to live through the changeset engine:
/// closes its changeset, plans it against live, and queues the apply behind
/// the same customer-test, governance and approval gates as any changeset
/// apply. Refused when live changed the same objects since the workspace was
/// made. Calling it again resumes a publish that stopped after the close.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/publish",
    operation_id = "publish_workspace",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The workspace")),
    request_body = PublishBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Published: the apply is queued, or waits on an approval", body = Published),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin and metadata.rollout", body = ErrorResponse),
        (status = 404, description = "No such workspace", body = ErrorResponse),
        (status = 409, description = "workspace_conflicts, or the workspace is not open, or records no changeset", body = ErrorResponse),
        (status = 422, description = "Nothing to publish, a blocked plan, or backup_ref_required on the production profile", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn publish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<MetadataRollout>>,
    Path(id): Path<Uuid>,
    Json(body): Json<PublishBody>,
) -> Result<Json<Published>, AppError> {
    let (workspace, schema_name, changeset) = publishing_parts(&state, id).await?;
    let row = store::get(&state.base.db, changeset)
        .await?
        .ok_or_else(|| AppError::internal(format!("workspace {id}: its changeset is gone")))?;

    let document = match (workspace.status.as_str(), row.status) {
        ("open", ChangesetStatus::Open) => {
            if !set_status(&state, id, "open", "publishing").await? {
                return Err(AppError::Conflict(
                    "the workspace is already being published",
                ));
            }
            match close_checked(&state, ctx.user_id, &workspace, &schema_name, &row).await {
                Ok(document) => document,
                Err(error) => {
                    if let Err(revert) = set_status(&state, id, "publishing", "open").await {
                        tracing::warn!(workspace = %id, error = %revert, "workspace: not returned to open after a refused publish");
                    }
                    return Err(error);
                }
            }
        }
        // Resume: closed by an earlier publish that stopped before queueing.
        ("publishing", ChangesetStatus::Closed) => row.document.clone().ok_or_else(|| {
            AppError::internal(format!(
                "workspace {id}: its closed changeset has no document"
            ))
        })?,
        _ => {
            return Err(AppError::Conflict(
                "only an open workspace can be published",
            ));
        }
    };

    let plan_ctx = plan_context(ctx.user_id);
    let mut planned = plan::plan(&state, &[document], plan_ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    plan::persist(&mut tx, &mut planned, plan_ctx).await?;
    attome_db::tx::commit(tx).await?;
    let plan = planned.plan;
    if !plan.applicable {
        return Err(AppError::Validation(
            "the workspace's plan against live has blocked operations; see the publish preview"
                .into(),
        ));
    }

    let (phase, apply_ids, contract_apply_ids) = if plan.apply_ids.is_empty() {
        (
            ApplyPhase::Contract,
            plan.contract_apply_ids.clone(),
            Vec::new(),
        )
    } else {
        (
            ApplyPhase::Expand,
            plan.apply_ids.clone(),
            plan.contract_apply_ids.clone(),
        )
    };
    if apply_ids.is_empty() {
        return Err(AppError::Validation(
            "nothing to publish: live already has every change".into(),
        ));
    }
    let apply = gated_apply(
        &state,
        &ctx,
        ApplyChangesetsBody {
            apply_ids,
            phase,
            backup_ref: body.backup_ref,
        },
    )
    .await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let published: Option<Workspace> = sqlx::query_as(&format!(
        "UPDATE develop_workspace SET status = 'published', row_version = row_version + 1 \
         WHERE id = $1 AND status = 'publishing' RETURNING {}",
        super::COLUMNS
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(published) = published else {
        return Err(AppError::Conflict(
            "the workspace is already being published",
        ));
    };
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
        .named("workspace.publish")
        .comment(format!(
            "workspace {} published: changeset {changeset}, {} apply rows ({})",
            published.name,
            apply.apply_ids.len(),
            apply.status
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(workspace = %id, changeset = %changeset, "workspace published");
    // Nothing more runs inside a published workspace.
    super::proxy::stop(id).await;
    Ok(Json(Published {
        workspace: published,
        plan,
        apply,
        contract_apply_ids,
    }))
}

/// Steps 2 and 3: refuse on conflicts, an empty workspace or a blocked
/// draft plan, then close the changeset against the workspace's schema.
async fn close_checked(
    state: &EngineState,
    user: Uuid,
    workspace: &Workspace,
    schema_name: &str,
    row: &store::ChangesetRow,
) -> Result<Value, AppError> {
    let preview = preview_of(state, user, workspace, schema_name, row.id).await?;
    if !preview.conflicts.is_empty() {
        return Err(AppError::Conflict(WORKSPACE_CONFLICTS));
    }
    match &preview.plan {
        None => {
            return Err(AppError::Validation(
                "nothing to publish: the workspace changed nothing".into(),
            ));
        }
        Some(plan) if !plan.applicable => {
            return Err(AppError::Validation(
                "the workspace's plan against live has blocked operations; see the publish preview"
                    .into(),
            ));
        }
        Some(_) => {}
    }
    let path = search_path(state, schema_name).await?;
    let closed = close::close_in(state, user, row.id, row.row_version, Some(&path)).await?;
    closed
        .row
        .document
        .ok_or_else(|| AppError::internal("a closed changeset carries no document"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn change(op: &str, target: Value) -> Change {
        Change {
            op: op.into(),
            target,
        }
    }

    fn live(op: &str, target: Value) -> LiveChange {
        LiveChange {
            change: change(op, target),
            changeset: "auto-1".into(),
            at: Utc::now(),
        }
    }

    #[test]
    fn an_operation_changes_the_object_its_name_ends_in() {
        assert_eq!(object_of("add_field"), "field");
        assert_eq!(object_of("retire_field"), "field");
        assert_eq!(object_of("upsert_state_model"), "state_model");
        assert_eq!(object_of("grant_role_privilege"), "role_privilege");
        assert_eq!(object_of("revoke_role_privilege"), "role_privilege");
    }

    #[test]
    fn the_same_object_on_both_sides_conflicts() {
        let field = json!({"entity": "deal", "field": "stage"});
        let found = conflicts(
            &[change("add_field", field.clone())],
            &[live("update_field", field.clone())],
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].op, "add_field");
        assert_eq!(found[0].live_op, "update_field");
    }

    #[test]
    fn different_objects_do_not_conflict() {
        let entity = json!({"entity": "deal"});
        // The entity's state model is not the entity.
        assert!(
            conflicts(
                &[change("upsert_state_model", entity.clone())],
                &[live("update_entity", entity)],
            )
            .is_empty()
        );
        assert!(
            conflicts(
                &[change("add_field", json!({"entity": "deal", "field": "a"}))],
                &[live("add_field", json!({"entity": "deal", "field": "b"}))],
            )
            .is_empty()
        );
    }

    #[test]
    fn retiring_an_entity_conflicts_with_anything_on_it() {
        assert_eq!(
            conflicts(
                &[change("add_field", json!({"entity": "deal", "field": "a"}))],
                &[live("retire_entity", json!({"entity": "deal"}))],
            )
            .len(),
            1
        );
        assert!(
            conflicts(
                &[change("add_field", json!({"entity": "deal", "field": "a"}))],
                &[live("retire_entity", json!({"entity": "lead"}))],
            )
            .is_empty()
        );
    }

    #[test]
    fn one_conflict_per_operation_and_live_changeset() {
        let field = json!({"entity": "deal", "field": "stage"});
        let found = conflicts(
            &[change("add_field", field.clone())],
            &[
                live("update_field", field.clone()),
                live("update_field", field),
            ],
        );
        assert_eq!(found.len(), 1);
    }
}
