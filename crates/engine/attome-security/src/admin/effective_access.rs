//! Effective-access preview (P-rls-admin-ui addition). Read-only,
//! `system.admin`-gated. An admin editing a user's roles/teams/business units
//! needs to see what that configuration actually resolves to — this is the
//! "Effective access" half of the RLS admin UI's required "configured vs.
//! effective" view (the "Configured" half is just the raw
//! `user_roles::list_user_roles`/`teams::list_team_members`/
//! `organizations::list_organization_members` responses the UI already has).
//! Reuses `resolve_uncached` (the same bypass-every-cache path `attome-server`'s
//! worker-startup resolution already uses) rather than the cached resolver,
//! so a just-made change is reflected immediately in the preview instead of
//! racing the D-012 60s cache TTL. "Record-specific exceptions" (the third
//! required view) are deliberately NOT part of this response — those are
//! per-(entity, record) `record_share` rows, listed separately by
//! `shares::list_record_shares`, since a user-centric preview has no single
//! record to scope them to.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::db::RecordAction;
use crate::explain::AccessPath;

/// Q10-T10: name an entity (and an operation) to get the paths to it.
#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct EffectiveAccessQuery {
    /// An entity's logical name: the response then lists every role, team,
    /// set, conditional grant, position and direct grant that gives a level
    /// on it.
    #[serde(default)]
    entity: Option<String>,
    /// `read` (default), `update`, `delete`, `create`, `assign`, `share`,
    /// `export` or `bulk`.
    #[serde(default)]
    action: Option<String>,
}
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
struct EffectiveAccessRoleRef {
    id: Uuid,
    name: String,
}

#[derive(Serialize, ToSchema)]
struct EffectiveAccessTeamRef {
    id: Uuid,
    name: String,
    roles: Vec<EffectiveAccessRoleRef>,
}

#[derive(Serialize, ToSchema)]
struct EffectiveAccessOrgRef {
    id: Uuid,
    name: Option<String>,
}

/// The "configured" half: every raw assignment that feeds resolution, with
/// display names attached so the UI doesn't need N follow-up lookups.
#[derive(Serialize, ToSchema)]
struct ConfiguredAccess {
    direct_roles: Vec<EffectiveAccessRoleRef>,
    teams: Vec<EffectiveAccessTeamRef>,
    position: Option<EffectiveAccessRoleRef>,
    organizations: Vec<EffectiveAccessOrgRef>,
}

/// The "effective" half: `SecurityContext` fields as actually resolved right
/// now, uncached. `privileges` is sorted (the resolver's `HashSet` has no
/// stable order) so the UI renders a deterministic list, not one that
/// reshuffles on every refresh.
#[derive(Serialize, ToSchema)]
struct EffectiveAccess {
    is_admin: bool,
    privileges: Vec<String>,
    team_ids: Vec<Uuid>,
    accessible_org_ids: Vec<Uuid>,
    position_hierarchy_enabled: bool,
    subordinate_user_ids: Vec<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct EffectiveAccessPreview {
    user_id: Uuid,
    user_email: Option<String>,
    is_active: Option<bool>,
    configured: ConfiguredAccess,
    effective: EffectiveAccess,
    /// Q10-T10: with `?entity=`, every path to a level on it for `action`.
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<AccessPath>>,
}

impl std::fmt::Debug for EffectiveAccessPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectiveAccessPreview")
            .finish_non_exhaustive()
    }
}

/// A user's effective access
///
/// What a user can do on each entity once their roles, teams and grants are combined. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/users/{id}/effective-access",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The user"), EffectiveAccessQuery),
    responses(
        (status = 200, description = "Success", body = EffectiveAccessPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn effective_access_preview(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Users>>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<EffectiveAccessQuery>,
) -> Result<Json<EffectiveAccessPreview>, AppError> {
    let action = match query.action.as_deref().unwrap_or("read") {
        "read" => RecordAction::Read,
        "update" => RecordAction::Update,
        "delete" => RecordAction::Delete,
        "create" => RecordAction::Create,
        "assign" => RecordAction::Assign,
        "share" => RecordAction::Share,
        "export" => RecordAction::Export,
        "bulk" => RecordAction::Bulk,
        _ => {
            return Err(AppError::Validation(
                "action must be read, update, delete, create, assign, share, export or bulk".into(),
            ));
        }
    };
    let user_row: Option<(Option<String>, Option<bool>)> =
        sqlx::query_as("SELECT email, is_active FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (user_email, is_active) = user_row.ok_or(AppError::NotFound)?;

    let direct_role_rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT r.id, r.name FROM user_account_mm_role ur \
         JOIN role r ON r.id = ur.role_ref \
         WHERE ur.user_ref = $1 AND ur.is_deleted = false AND r.is_deleted = false \
         ORDER BY r.name",
    )
    .bind(user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let team_rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT t.id, t.name FROM user_account_mm_team ut \
         JOIN team t ON t.id = ut.team_ref \
         WHERE ut.user_ref = $1 AND ut.is_deleted = false AND t.is_deleted = false \
         ORDER BY t.name",
    )
    .bind(user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut teams = Vec::with_capacity(team_rows.len());
    for (team_id, team_name) in team_rows {
        let role_rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT r.id, r.name FROM role_mm_team rt \
             JOIN role r ON r.id = rt.role_ref \
             WHERE rt.team_ref = $1 AND rt.is_deleted = false AND r.is_deleted = false \
             ORDER BY r.name",
        )
        .bind(team_id)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        teams.push(EffectiveAccessTeamRef {
            id: team_id,
            name: team_name,
            roles: role_rows
                .into_iter()
                .map(|(id, name)| EffectiveAccessRoleRef { id, name })
                .collect(),
        });
    }

    let position_row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT p.id, p.name FROM user_account_mm_position mp \
         JOIN position p ON p.id = mp.position_ref \
         WHERE mp.user_ref = $1 AND mp.is_deleted = false AND p.is_deleted = false \
         ORDER BY p.name LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let org_rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT o.id, o.name FROM user_account_mm_organization m \
         JOIN organization o ON o.id = m.organization_ref \
         WHERE m.user_ref = $1 AND m.is_deleted = false \
         ORDER BY o.name",
    )
    .bind(user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let paths = match query.entity.as_deref().map(str::trim) {
        Some(entity) if !entity.is_empty() => {
            let entity_ref = super::shared::resolve_entity_ref(&state.base.db, entity).await?;
            Some(
                crate::explain::role_paths(&state.base.db, user_id, entity_ref, entity, action)
                    .await?,
            )
        }
        _ => None,
    };

    // Uncached on purpose — see the module doc comment above.
    let resolved = crate::resolve_uncached(&state.base.db, user_id).await?;
    let mut privileges: Vec<String> = resolved.privileges.into_iter().collect();
    privileges.sort();

    Ok(Json(EffectiveAccessPreview {
        user_id,
        user_email,
        is_active,
        configured: ConfiguredAccess {
            direct_roles: direct_role_rows
                .into_iter()
                .map(|(id, name)| EffectiveAccessRoleRef { id, name })
                .collect(),
            teams,
            position: position_row.map(|(id, name)| EffectiveAccessRoleRef { id, name }),
            organizations: org_rows
                .into_iter()
                .map(|(id, name)| EffectiveAccessOrgRef { id, name })
                .collect(),
        },
        effective: EffectiveAccess {
            is_admin: resolved.is_admin,
            privileges,
            team_ids: resolved.team_ids,
            accessible_org_ids: resolved.accessible_org_ids,
            position_hierarchy_enabled: resolved.position_hierarchy_enabled,
            subordinate_user_ids: resolved.subordinate_user_ids,
        },
        paths,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/users/{id}/effective-access",
        get(effective_access_preview),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(effective_access_preview))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
