//! T1-T2: an app's guided checklist — `GET /api/v1/admin/apps/{id}/checklist`.
//!
//! For each entity the app names (its `entities`, the A21 app's map of what
//! it holds), what is in place and what is missing before it is published:
//!
//! - **data**: the entity exists and has fields of its own;
//! - **screens**: a form for it in the model store, and a list view;
//! - **rules**: its active rules (informational: an entity may need none);
//! - **access**: roles holding its read privilege (none means nobody can
//!   open it);
//! - **tests**: customer tests that name it (T7) and whether their last run
//!   passed;
//! - **docs**: an Arabic label beside its English name.
//!
//! Each item carries the screen that fixes it. Reads only.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// One checklist item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ChecklistItem {
    /// `data`, `screens`, `rules`, `access`, `tests` or `docs`.
    pub area: &'static str,
    pub done: bool,
    /// `false` for an item an app may go without (rules).
    pub required: bool,
    pub detail: String,
    /// The screen that fixes it.
    pub fix: String,
}

/// One entity's checklist.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntityChecklist {
    pub entity: String,
    pub items: Vec<ChecklistItem>,
    /// Every required item done.
    pub ready: bool,
}

/// An app's checklist.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AppChecklist {
    pub app: Uuid,
    pub entities: Vec<EntityChecklist>,
    /// Every entity ready, and the app names at least one.
    pub ready: bool,
}

/// What the checklist reads about one entity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntityFacts {
    pub id: Option<Uuid>,
    pub fields: i64,
    pub forms: i64,
    pub views: i64,
    pub rules: i64,
    pub roles_reading: i64,
    pub tests: i64,
    pub tests_failing: i64,
    pub arabic_label: bool,
}

/// One entity's items from what was read. Pure.
pub fn items_for(entity: &str, facts: &EntityFacts) -> Vec<ChecklistItem> {
    let page = |id: Option<Uuid>| match id {
        Some(id) => format!("/xrm/admin/entities/{id}"),
        None => "/xrm/admin/entities".to_owned(),
    };
    let item = |area, done, required, detail: String, fix: String| ChecklistItem {
        area,
        done,
        required,
        detail,
        fix,
    };
    vec![
        item(
            "data",
            facts.id.is_some() && facts.fields > 0,
            true,
            match facts.id {
                None => format!("{entity} does not exist yet"),
                Some(_) => format!("{} field(s)", facts.fields),
            },
            page(facts.id),
        ),
        item(
            "screens",
            facts.forms > 0 && facts.views > 0,
            true,
            format!("{} form(s), {} view(s)", facts.forms, facts.views),
            "/xrm/admin/data-model".to_owned(),
        ),
        item(
            "rules",
            facts.rules > 0,
            false,
            format!("{} active rule(s)", facts.rules),
            "/xrm/admin/business-rules".to_owned(),
        ),
        item(
            "access",
            facts.roles_reading > 0,
            true,
            format!("{} role(s) may read it", facts.roles_reading),
            "/xrm/admin/roles".to_owned(),
        ),
        item(
            "tests",
            facts.tests > 0 && facts.tests_failing == 0,
            true,
            format!("{} test(s), {} failing", facts.tests, facts.tests_failing),
            "/xrm/admin/customer-tests".to_owned(),
        ),
        item(
            "docs",
            facts.arabic_label,
            true,
            if facts.arabic_label {
                "labelled in Arabic".to_owned()
            } else {
                "no Arabic label".to_owned()
            },
            page(facts.id),
        ),
    ]
}

async fn facts(state: &EngineState, entity: &str) -> Result<EntityFacts, AppError> {
    let db = &state.base.db;
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info WHERE logicalname = $1 AND is_active IS NOT FALSE",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = id else {
        return Ok(EntityFacts::default());
    };
    // Every count binds the entity's id as $1 and its name as $2.
    let count = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql).bind(id).bind(entity);
    let fields: i64 = count(
        "SELECT COUNT(*) FROM attribute_info \
          WHERE entity_ref = $1 AND is_active IS NOT FALSE AND logicalname <> ALL($3) \
            AND $2::text IS NOT NULL",
    )
    .bind(attome_core::ALL_SYSTEM_COLS)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let forms: i64 = count(
        "SELECT COUNT(DISTINCT o.id) FROM metadata_object o \
           JOIN metadata_object_version v ON v.object_id = o.id \
          WHERE o.kind = 'form' AND o.is_active AND v.doc->>'entity' = $1::text \
            AND $2::text IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let views: i64 = count(
        "SELECT COUNT(*) FROM view WHERE entity_logical_name = $1 AND is_active \
            AND $2::text IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let rules: i64 = count(
        "SELECT COUNT(*) FROM rule WHERE entity_logicalname = $2 AND is_active \
            AND $1::uuid IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let roles_reading: i64 = count(
        "SELECT COUNT(DISTINCT rp.role_ref) FROM role_mm_privilege rp \
           JOIN privilege p ON p.id = rp.privilege_ref \
          WHERE p.key = $2 || '.read' AND $1::uuid IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let (tests, tests_failing): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE r.passed IS FALSE) \
           FROM customer_test t \
           LEFT JOIN LATERAL (SELECT passed FROM customer_test_run \
                               WHERE test_id = t.id ORDER BY started_at DESC, id DESC LIMIT 1) r \
             ON true \
          WHERE t.is_active AND t.definition::text LIKE '%\"' || $1 || '\"%'",
    )
    .bind(entity)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let arabic_label: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM metadata_label \
                         WHERE object_kind = 'entity' AND locale = 'ar' AND NOT is_deleted \
                           AND (object_ref = $1 OR object_ref = $2::text))",
    )
    .bind(entity)
    .bind(id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(EntityFacts {
        id: Some(id),
        fields,
        forms,
        views,
        rules,
        roles_reading,
        tests,
        tests_failing,
        arabic_label,
    })
}

/// An app's checklist
///
/// For each entity the app names: whether it has fields, a form and a view,
/// rules, roles that may read it, passing customer tests and an Arabic label,
/// each with the screen that fixes it. Reads only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/apps/{id}/checklist",
    operation_id = "app_checklist",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The app")),
    responses(
        (status = 200, description = "Success", body = AppChecklist),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such app", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn checklist(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AppChecklist>, AppError> {
    let entities: Value = sqlx::query_scalar(
        "SELECT entities FROM app WHERE id = $1 AND is_active AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let names: Vec<String> = entities
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .take(200)
        .collect();
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let facts = facts(&state, &name).await?;
        let items = items_for(&name, &facts);
        let ready = items.iter().all(|i| i.done || !i.required);
        out.push(EntityChecklist {
            entity: name,
            items,
            ready,
        });
    }
    let ready = !out.is_empty() && out.iter().all(|e| e.ready);
    Ok(Json(AppChecklist {
        app: id,
        entities: out,
        ready,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/apps/{id}/checklist", get(checklist))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(checklist),
    components(schemas(AppChecklist, EntityChecklist, ChecklistItem))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_entity_is_ready_and_a_new_one_lists_what_is_missing() {
        let complete = EntityFacts {
            id: Some(Uuid::now_v7()),
            fields: 4,
            forms: 1,
            views: 2,
            rules: 0,
            roles_reading: 1,
            tests: 2,
            tests_failing: 0,
            arabic_label: true,
        };
        let items = items_for("visit", &complete);
        assert!(items.iter().all(|i| i.done || !i.required));
        assert!(
            !items.iter().find(|i| i.area == "rules").unwrap().done,
            "rules are optional"
        );

        let missing = items_for("visit", &EntityFacts::default());
        let open: Vec<&str> = missing
            .iter()
            .filter(|i| !i.done && i.required)
            .map(|i| i.area)
            .collect();
        assert_eq!(open, vec!["data", "screens", "access", "tests", "docs"]);
        assert!(missing[0].detail.contains("does not exist"));

        let failing = EntityFacts {
            tests_failing: 1,
            ..complete
        };
        assert!(
            !items_for("visit", &failing)
                .iter()
                .find(|i| i.area == "tests")
                .unwrap()
                .done
        );
    }
}
