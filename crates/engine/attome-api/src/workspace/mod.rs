//! T5-T2 (V2-D274, V2-D1722): Develop workspaces inside the deployment.
//!
//! A workspace is a place to change the model away from live: its own
//! PostgreSQL schema (`ws_<id>`, [`schema`]) holding a copy of every metadata
//! table a changeset can change, with its rows, and an empty copy of every
//! entity table, so a builder or a building agent works on structure without
//! touching Run mode. Identity and access tables, sessions, audit and jobs
//! stay shared with live.
//!
//! - `POST /api/v1/admin/workspaces` makes one, with sample records, a masked
//!   share of live's, or none ([`data`], T5-T5);
//! - `GET /api/v1/admin/workspaces` and `.../{id}` list and show them;
//! - `DELETE /api/v1/admin/workspaces/{id}` discards one and drops its schema.
//!
//! - `GET`/`POST /api/v1/admin/workspaces/{id}/publish` preview and publish
//!   it to live through the changeset engine ([`publish`], T5-T4);
//! - `POST /api/v1/admin/workspaces/{id}/refresh` brings in live's changes
//!   the workspace has not made its own, and a daily job discards idle
//!   workspaces after warning their owners ([`lifecycle`], T5-T6).
//!
//! Requests run inside a workspace through [`proxy`] (T5-T3). Making a
//! workspace opens the changeset its metadata writes record into. Every
//! route but publish needs the data-model administration area (publish needs
//! the metadata rollout privilege, as any changeset apply); creating,
//! discarding and publishing are audited as configuration changes.

/// N12-T1: the entity and field build tools for agents.
pub mod build_tools;
pub mod data;
pub mod lifecycle;
pub mod proxy;
pub mod publish;
pub mod schema;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_core::changeset::{Layer, NewChangeset, store};
use attome_server::authz::{AdminArea, Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// One workspace.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub purpose: Option<String>,
    /// `open`, `in_review` (a builder's publish waits for the owner, T1-T3),
    /// `publishing`, `published` or `discarded`.
    pub status: String,
    pub owner_ref: Uuid,
    /// The changeset its metadata writes record into (T5-T4).
    pub changeset_ref: Option<Uuid>,
    /// Metadata tables copied with their rows.
    pub metadata_tables: i32,
    /// Entity and join tables copied empty.
    pub entity_tables: i32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub row_version: i64,
    /// T1-T3: the team whose builders work in it beside its owner.
    pub team_ref: Option<Uuid>,
    /// T1-T3: the owner's review a builder's publish waits on.
    pub review_request_ref: Option<Uuid>,
}

/// A new workspace.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWorkspace {
    /// 1 to 100 characters.
    pub name: String,
    /// What it is for, at most 1,000 characters.
    #[serde(default)]
    pub purpose: Option<String>,
    /// Its records: generated samples (the default), a masked share of
    /// live's, or none.
    #[serde(default)]
    pub data: Option<data::DataRequest>,
    /// T1-T3: a team whose builders work in it too; the caller's own team.
    #[serde(default)]
    pub team: Option<Uuid>,
}

/// A workspace just made, with what its data came to.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedWorkspace {
    #[serde(flatten)]
    pub workspace: Workspace,
    pub data: data::DataReport,
}

const COLUMNS: &str = "id, name, purpose, status, owner_ref, changeset_ref, metadata_tables, \
                       entity_tables, created_at, last_used_at, row_version, team_ref, \
                       review_request_ref";

/// T1-T3: the privilege that lets a person build in Develop workspaces (make
/// one, work in their own or their team's) without the data-model area.
pub const BUILD_PRIVILEGE: &str = "develop.build";
/// T1-T3: the privilege that lets a builder publish a workspace; without it
/// (or when owner review is on) a builder's publish waits for the owner.
pub const PUBLISH_PRIVILEGE: &str = "develop.publish";

/// Whether `ctx` builds in workspaces at all: the data-model area, or the
/// builder privilege. Pure.
pub(crate) fn is_builder(ctx: &SecurityContext) -> bool {
    AdminArea::DataModel.held_by(ctx) || ctx.privileges.contains(BUILD_PRIVILEGE)
}

/// Whether `ctx` may work in a workspace owned by `owner` and shared with
/// `team`: the data-model area, its owner, or a builder of its team. Pure.
pub(crate) fn may_enter(ctx: &SecurityContext, owner: Uuid, team: Option<Uuid>) -> bool {
    AdminArea::DataModel.held_by(ctx)
        || ctx.user_id == owner
        || (ctx.privileges.contains(BUILD_PRIVILEGE)
            && team.is_some_and(|t| ctx.team_ids.contains(&t)))
}

/// The refusal for a caller who does not build.
fn require_builder(ctx: &SecurityContext) -> Result<(), AppError> {
    if is_builder(ctx) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn checked(body: NewWorkspace) -> Result<(String, Option<String>, data::DataPlan), AppError> {
    let plan = data::checked(&body.data.unwrap_or_default())?;
    let name = body.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::Validation("name is 1 to 100 characters".into()));
    }
    let purpose = body
        .purpose
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty());
    if purpose.as_ref().is_some_and(|p| p.chars().count() > 1_000) {
        return Err(AppError::Validation(
            "purpose is at most 1,000 characters".into(),
        ));
    }
    Ok((name, purpose, plan))
}

/// Create a workspace
///
/// Makes a Develop workspace: its own schema with a copy of the metadata
/// (with its rows) and of every entity table, holding generated sample
/// records (the default), a masked share of live's, or none; every labelled
/// field is masked. The data's storage is estimated first and refused past
/// `metadata.workspace_data_max_mb`. Identity and access
/// tables stay shared with live. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces",
    operation_id = "create_workspace",
    tag = "admin",
    request_body = NewWorkspace,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = CreatedWorkspace),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "The name, purpose or data is out of bounds, or the data would pass the storage limit", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<NewWorkspace>,
) -> Result<(StatusCode, Json<CreatedWorkspace>), AppError> {
    require_builder(&ctx)?;
    let team = body.team;
    if let Some(team) = team
        && !(AdminArea::DataModel.held_by(&ctx) || ctx.team_ids.contains(&team))
    {
        return Err(AppError::Validation(
            "team: a workspace is shared with one of your own teams".into(),
        ));
    }
    let (name, purpose, plan) = checked(body)?;
    let estimated = data::check_storage(&state, plan).await?;
    let id = Uuid::now_v7();
    let schema_name = schema::schema_name(id);
    let copied = schema::create(&state.base.db_migrator, &schema_name).await?;
    let filled = data::fill(&state, &schema_name, plan, ctx.user_id, estimated).await;
    let report = match filled {
        Ok(report) => report,
        Err(error) => {
            if let Err(cleanup) = schema::drop_schema(&state.base.db_migrator, &schema_name).await {
                tracing::warn!(schema = %schema_name, error = %cleanup, "workspace: a schema whose data failed was not dropped");
            }
            return Err(error);
        }
    };
    let opened = store::open(
        &state.base.db,
        &workspace_changeset(&state, id, &name, purpose.as_deref()),
    )
    .await;
    let made = match opened {
        Ok(changeset) => {
            let made = record_created(
                &state,
                ctx.user_id,
                id,
                &name,
                purpose,
                &schema_name,
                changeset.id,
                copied,
                &report,
            )
            .await;
            if made.is_err()
                && let Err(cleanup) =
                    crate::changeset::close::abandon(&state, ctx.user_id, changeset.id, None).await
            {
                tracing::warn!(changeset = %changeset.id, error = %cleanup, "workspace: an unrecorded changeset was not abandoned");
            }
            made
        }
        Err(error) => Err(error),
    };
    let made = match (made, team) {
        (Ok(mut workspace), Some(team)) => {
            let shared = sqlx::query("UPDATE develop_workspace SET team_ref = $2 WHERE id = $1")
                .bind(workspace.id)
                .bind(team)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal);
            match shared {
                Ok(_) => {
                    workspace.team_ref = Some(team);
                    Ok(workspace)
                }
                Err(error) => Err(error),
            }
        }
        (other, _) => other,
    };
    match made {
        Ok(workspace) => Ok((
            StatusCode::CREATED,
            Json(CreatedWorkspace {
                workspace,
                data: report,
            }),
        )),
        Err(error) => {
            // The schema exists but nothing names it: take it back.
            if let Err(cleanup) = schema::drop_schema(&state.base.db_migrator, &schema_name).await {
                tracing::warn!(schema = %schema_name, error = %cleanup, "workspace: an unrecorded schema was not dropped");
            }
            Err(error)
        }
    }
}

/// The changeset a workspace's metadata writes record into: the layer
/// automatic changesets take, scope `workspace` (`platform` in the platform
/// layer), named after the workspace id. It has no author, so it is never
/// taken as anyone's one open changeset for a live write: only a request the
/// proxy forwards names it.
fn workspace_changeset(
    state: &EngineState,
    id: Uuid,
    name: &str,
    purpose: Option<&str>,
) -> NewChangeset {
    let layer = state.base.config.metadata.changesets.auto_layer;
    NewChangeset {
        layer,
        scope: if layer == Layer::Platform {
            "platform".into()
        } else {
            "workspace".into()
        },
        name: format!("workspace-{}", id.simple()),
        title: format!("Workspace: {name}").chars().take(200).collect(),
        description: purpose.unwrap_or_default().to_owned(),
        requires: serde_json::json!({}),
        author_ref: None,
        author_label: format!("workspace {id}"),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the workspace row's fields, written once"
)]
async fn record_created(
    state: &EngineState,
    user_id: Uuid,
    id: Uuid,
    name: &str,
    purpose: Option<String>,
    schema_name: &str,
    changeset: Uuid,
    copied: schema::CopySummary,
    report: &data::DataReport,
) -> Result<Workspace, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let workspace: Workspace = sqlx::query_as(&format!(
        "INSERT INTO develop_workspace \
            (id, name, purpose, schema_name, owner_ref, changeset_ref, metadata_tables, \
             entity_tables) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(name)
    .bind(&purpose)
    .bind(schema_name)
    .bind(user_id)
    .bind(changeset)
    .bind(copied.metadata_tables)
    .bind(copied.entity_tables)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            user_id,
            "develop_workspace",
            Some(id),
        )
        .named("workspace.create")
        .comment(format!(
            "workspace {name}: {} metadata tables, {} entity tables, {:?} data: {} records, \
             {} masked fields",
            copied.metadata_tables,
            copied.entity_tables,
            report.mode,
            report.records,
            report.masked_fields.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(workspace)
}

/// List workspaces
///
/// The workspaces not discarded, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces",
    operation_id = "list_workspaces",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<Workspace>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<Workspace>>, AppError> {
    require_builder(&ctx)?;
    let window = q.window();
    // T1-T3: a builder sees their own workspaces and their teams'.
    let everything = AdminArea::DataModel.held_by(&ctx);
    const VISIBLE: &str = "status <> 'discarded' \
        AND ($1 OR owner_ref = $2 OR team_ref = ANY($3))";
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM develop_workspace WHERE {VISIBLE}"
    ))
    .bind(everything)
    .bind(ctx.user_id)
    .bind(&ctx.team_ids)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<Workspace> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM develop_workspace WHERE {VISIBLE} \
         ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5"
    ))
    .bind(everything)
    .bind(ctx.user_id)
    .bind(&ctx.team_ids)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

async fn find(state: &EngineState, id: Uuid) -> Result<Workspace, AppError> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM develop_workspace WHERE id = $1 AND status <> 'discarded'"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Show a workspace
///
/// One workspace not discarded: its status, owner and how many tables it copied.
#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}",
    operation_id = "get_workspace",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The workspace")),
    responses(
        (status = 200, description = "Success", body = Workspace),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such workspace", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn show(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<Workspace>, AppError> {
    Ok(Json(find_for(&state, &ctx, id).await?))
}

/// The workspace `id` when `ctx` may work in it; another person's is not
/// found, as one that does not exist.
pub(crate) async fn find_for(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
) -> Result<Workspace, AppError> {
    require_builder(ctx)?;
    let workspace = find(state, id).await?;
    if may_enter(ctx, workspace.owner_ref, workspace.team_ref) {
        Ok(workspace)
    } else {
        Err(AppError::NotFound)
    }
}

/// Discard a workspace
///
/// Marks the workspace discarded and drops its schema with everything in it.
/// A published workspace is kept. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}",
    operation_id = "discard_workspace",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The workspace")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Discarded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such workspace", body = ErrorResponse),
        (status = 409, description = "The workspace is being published or was published", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn discard(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let workspace = find_for(&state, &ctx, id).await?;
    // A team builder works in it; only its owner or the data-model area throws it away.
    if !(AdminArea::DataModel.held_by(&ctx) || ctx.user_id == workspace.owner_ref) {
        return Err(AppError::Forbidden);
    }
    discard_workspace(
        &state,
        ctx.user_id,
        &workspace,
        &format!("workspace {} discarded", workspace.name),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Discards an open workspace: marks it discarded with its
/// `Configuration / HardDelete` event (`actor` nil for the expiry job), then
/// drops its schema, abandons its changeset when empty and stops its
/// process.
pub(crate) async fn discard_workspace(
    state: &EngineState,
    actor: Uuid,
    workspace: &Workspace,
    comment: &str,
) -> Result<(), AppError> {
    let id = workspace.id;
    if !matches!(workspace.status.as_str(), "open" | "in_review") {
        return Err(AppError::Conflict(
            "only an open workspace can be discarded",
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let schema_name: Option<String> = sqlx::query_scalar(
        "UPDATE develop_workspace SET status = 'discarded', row_version = row_version + 1 \
          WHERE id = $1 AND status IN ('open', 'in_review') RETURNING schema_name",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(schema_name) = schema_name else {
        return Err(AppError::Conflict(
            "only an open workspace can be discarded",
        ));
    };
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            actor,
            "develop_workspace",
            Some(id),
        )
        .named("workspace.discard")
        .comment(comment.to_owned()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    // After the commit: the row already says discarded, so a schema that
    // fails to drop here is only storage, left for the life-cycle job (T5-T6).
    if let Err(error) = schema::drop_schema(&state.base.db_migrator, &schema_name).await {
        tracing::warn!(workspace = %id, error = %error, "workspace: the discarded schema was not dropped");
    }
    // An empty changeset goes with it; one holding operations stays open,
    // as any changeset with recorded work does, until someone closes it.
    if let Some(changeset) = workspace.changeset_ref
        && let Err(error) = crate::changeset::close::abandon(state, actor, changeset, None).await
    {
        tracing::info!(workspace = %id, %changeset, error = %error, "workspace: its changeset was not abandoned");
    }
    proxy::stop(id).await;
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/workspaces", get(list).post(create))
        .route("/api/v1/admin/workspaces/{id}", get(show).delete(discard))
        .route(
            "/api/v1/admin/workspaces/{id}/publish",
            get(publish::preview).post(publish::publish),
        )
        .route(
            "/api/v1/admin/workspaces/{id}/refresh",
            axum::routing::post(lifecycle::refresh),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create,
    list,
    show,
    discard,
    publish::preview,
    publish::publish,
    lifecycle::refresh
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builders_enter_their_own_and_their_teams_workspaces() {
        let owner = Uuid::now_v7();
        let team = Uuid::now_v7();
        let mut builder =
            SecurityContext::human(Uuid::now_v7(), [BUILD_PRIVILEGE.to_owned()].into());
        assert!(is_builder(&builder));
        assert!(!may_enter(&builder, owner, Some(team)), "not on the team");
        builder.team_ids = vec![team];
        assert!(may_enter(&builder, owner, Some(team)));
        assert!(
            !may_enter(&builder, owner, None),
            "an unshared workspace stays the owner's"
        );
        assert!(may_enter(&builder, builder.user_id, None), "their own");

        let mut member = SecurityContext::human(Uuid::now_v7(), Default::default());
        member.team_ids = vec![team];
        assert!(!is_builder(&member));
        assert!(
            !may_enter(&member, owner, Some(team)),
            "a team member who does not build"
        );

        let modeller =
            SecurityContext::human(Uuid::now_v7(), ["admin.data_model".to_owned()].into());
        assert!(is_builder(&modeller) && may_enter(&modeller, owner, None));
    }

    #[test]
    fn names_and_purposes_are_bounded() {
        let ok = checked(NewWorkspace {
            name: "  Sales rework ".into(),
            purpose: Some("   ".into()),
            data: None,
            team: None,
        })
        .unwrap();
        assert_eq!((ok.0, ok.1), ("Sales rework".to_owned(), None));
        assert_eq!(ok.2.mode, data::DataMode::Sample);
        assert!(
            checked(NewWorkspace {
                name: " ".into(),
                purpose: None,
                data: None,
                team: None
            })
            .is_err()
        );
        assert!(
            checked(NewWorkspace {
                name: "x".repeat(101),
                purpose: None,
                data: None,
                team: None
            })
            .is_err()
        );
        assert!(
            checked(NewWorkspace {
                name: "ok".into(),
                purpose: Some("p".repeat(1_001)),
                data: None,
                team: None
            })
            .is_err()
        );
    }
}
