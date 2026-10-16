//! Marketing list insight (roadmap E7-T7): how many people a list holds
//! (an estimate or the exact number), a sample, how many of them can be
//! reached for a purpose, why one person is or is not in it, and who was in
//! it on a past date. Everything is computed as the caller, without writing
//! anything, and never names a person the caller cannot read.

use std::collections::HashSet;

use attome_core::{EngineState, quote_ident};
use attome_security::{
    RecordAction, bind_rls_predicate, resolve_entity_access_level, rls_predicate,
};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::segment::evaluate;

/// `marketing_list.read`: may look into a list.
#[derive(Debug)]
pub struct ListRead;

impl PrivilegeKey for ListRead {
    const KEY: &'static str = "marketing_list.read";
}

/// People one sample shows.
pub const SAMPLE_SIZE: usize = 20;

type ListRow = (String, String, Option<String>, Option<i64>);

async fn list_info(state: &EngineState, list: Uuid) -> Result<ListRow, AppError> {
    sqlx::query_as::<_, ListRow>(
        "SELECT COALESCE(kind, 'static'), COALESCE(target_entity, 'contact'), query_id, \
                member_count::bigint \
         FROM marketing_list WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// The ids among `ids` of `entity` that `ctx` may read.
async fn readable(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    ids: &[Uuid],
) -> Result<HashSet<Uuid>, AppError> {
    let Some(entity_id) = state.entities.load().get(entity).map(|m| m.entity_id) else {
        return Ok(HashSet::new());
    };
    let level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity,
        RecordAction::Read,
    )
    .await?;
    let pred = rls_predicate(
        ctx,
        entity_id,
        "",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let sql = format!(
        "SELECT id FROM {} WHERE id = ANY($1) {}",
        quote_ident(entity),
        pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(ids);
    if let Some(p) = &pred {
        q = bind_rls_predicate(q, &p.binds);
    }
    Ok(q.fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .collect())
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CountQuery {
    /// Evaluate the list instead of estimating.
    #[serde(default)]
    pub exact: bool,
    /// Also count the people reachable for this consent purpose by email.
    pub purpose_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingListCount {
    pub list_id: Uuid,
    pub count: i64,
    /// `estimate` or `exact`.
    pub basis: String,
    /// People with active consent for the purpose, an email that is not
    /// suppressed, and no marketing sunset.
    pub reachable: Option<i64>,
}

/// The reachable people among `ids`, in one set-based query.
async fn reachable(
    state: &EngineState,
    entity: &str,
    ids: &[Uuid],
    purpose: &str,
) -> Result<i64, AppError> {
    let has = |col: &str| {
        state
            .entities
            .load()
            .get(entity)
            .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == col))
    };
    if !has("email") {
        return Ok(0);
    }
    let sunset = if has("marketing_sunset_at") {
        "AND t.marketing_sunset_at IS NULL"
    } else {
        ""
    };
    let sql = format!(
        "SELECT COUNT(*) FROM {} t \
         WHERE t.id = ANY($1) AND COALESCE(trim(t.email), '') <> '' {sunset} \
           AND EXISTS (SELECT 1 FROM consent_current c \
               WHERE c.subject_entity = $3 AND c.subject_id = t.id AND c.purpose_key = $2 \
                 AND c.channel IN ('email', 'any') AND c.status = 'granted') \
           AND NOT EXISTS (SELECT 1 FROM email_suppression s \
               WHERE lower(s.email) = lower(trim(t.email)))",
        quote_ident(entity)
    );
    sqlx::query_scalar(&sql)
        .bind(ids)
        .bind(purpose)
        .bind(entity)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/count",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list"), CountQuery),
    responses(
        (status = 200, description = "The list's size and, for a purpose, how many are reachable", body = MarketingListCount),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_marketing_list_count(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListRead>>,
    Path(list): Path<Uuid>,
    Query(q): Query<CountQuery>,
) -> Result<Json<MarketingListCount>, AppError> {
    let (kind, target, query, member_count) = list_info(&state, list).await?;
    let combinations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_list_combination WHERE list_ref = $1 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let need_people = q.exact || q.purpose_key.is_some();
    let people: Option<Vec<Uuid>> = if need_people {
        Some(
            evaluate(&state, &ctx, list, Vec::new())
                .await?
                .into_iter()
                .collect(),
        )
    } else {
        None
    };
    let (count, basis) = match &people {
        Some(people) if q.exact => (people.len() as i64, "exact"),
        _ => {
            let estimate = match (kind.as_str(), query.as_deref(), combinations) {
                ("segment", Some(query), 0) => match Uuid::parse_str(query.trim()) {
                    Ok(id) => {
                        attome_records::query_exec::estimate_stored_query_rows(&state, &ctx, id)
                            .await
                            .unwrap_or(member_count.unwrap_or(0))
                    }
                    Err(_) => member_count.unwrap_or(0),
                },
                _ => member_count.unwrap_or(0),
            };
            (estimate, "estimate")
        }
    };
    let reachable = match (&people, q.purpose_key.as_deref()) {
        (Some(people), Some(purpose)) => Some(reachable(&state, &target, people, purpose).await?),
        _ => None,
    };
    Ok(Json(MarketingListCount {
        list_id: list,
        count,
        basis: basis.into(),
        reachable,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingListSample {
    pub list_id: Uuid,
    pub target_entity: String,
    pub person_ids: Vec<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/sample",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list")),
    responses(
        (status = 200, description = "Up to 20 people of the list the caller may read", body = MarketingListSample),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_marketing_list_sample(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListRead>>,
    Path(list): Path<Uuid>,
) -> Result<Json<MarketingListSample>, AppError> {
    let (_, target, _, _) = list_info(&state, list).await?;
    let mut people: Vec<Uuid> = evaluate(&state, &ctx, list, Vec::new())
        .await?
        .into_iter()
        .collect();
    people.sort_unstable();
    let visible = readable(&state, &ctx, &target, &people).await?;
    let person_ids = people
        .into_iter()
        .filter(|p| visible.contains(p))
        .take(SAMPLE_SIZE)
        .collect();
    Ok(Json(MarketingListSample {
        list_id: list,
        target_entity: target,
        person_ids,
    }))
}

/// One step of why a person is in a list or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ExplainStep {
    /// `base` (the list's own query or members), then each combination.
    pub step: String,
    pub list_id: Uuid,
    /// Whether the step's list holds the person.
    pub holds: bool,
    /// Whether the person is in after this step.
    pub member_after: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingListExplanation {
    pub list_id: Uuid,
    pub person_id: Uuid,
    pub member: bool,
    pub steps: Vec<ExplainStep>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/explain/{person_id}",
    tag = "marketing",
    params(
        ("id" = Uuid, Path, description = "The marketing list"),
        ("person_id" = Uuid, Path, description = "The person"),
    ),
    responses(
        (status = 200, description = "Which step put the person in or left them out", body = MarketingListExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list, or a person the caller cannot read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_marketing_list_explain(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListRead>>,
    Path((list, person)): Path<(Uuid, Uuid)>,
) -> Result<Json<MarketingListExplanation>, AppError> {
    let (kind, target, query, _) = list_info(&state, list).await?;
    if !readable(&state, &ctx, &target, &[person])
        .await?
        .contains(&person)
    {
        return Err(AppError::NotFound);
    }
    let base_holds = match (kind.as_str(), query.as_deref()) {
        ("segment", Some(query)) => {
            let id = Uuid::parse_str(query.trim())
                .map_err(|_| AppError::Validation("segment.query_id_invalid".into()))?;
            !attome_records::query_exec::execute_stored_query_ids(
                &state,
                &ctx,
                id,
                Some(&[person]),
                Some(1),
            )
            .await?
            .is_empty()
        }
        _ => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM marketing_list_member WHERE list_id = $1 AND person_id = $2)",
        )
        .bind(list)
        .bind(person)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?,
    };
    let mut member = base_holds;
    let mut steps = vec![ExplainStep {
        step: "base".into(),
        list_id: list,
        holds: base_holds,
        member_after: member,
    }];
    let combos: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT operand_list_ref, operation FROM marketing_list_combination \
         WHERE list_ref = $1 AND operand_list_ref IS NOT NULL \
           AND (is_active IS NULL OR is_active = true) ORDER BY position NULLS LAST, id",
    )
    .bind(list)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for (operand, operation) in combos {
        let holds = evaluate(&state, &ctx, operand, vec![list])
            .await?
            .contains(&person);
        member = match operation.as_str() {
            "include" => member || holds,
            "intersect" => member && holds,
            "exclude" => member && !holds,
            _ => member,
        };
        steps.push(ExplainStep {
            step: operation,
            list_id: operand,
            holds,
            member_after: member,
        });
    }
    Ok(Json(MarketingListExplanation {
        list_id: list,
        person_id: person,
        member,
        steps,
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AsOfQuery {
    pub at: DateTime<Utc>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/members-as-of",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list"), AsOfQuery),
    responses(
        (status = 200, description = "The people in the list at that time that the caller may read", body = PaginatedResponse<Uuid>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_marketing_list_members_as_of(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListRead>>,
    Path(list): Path<Uuid>,
    Query(q): Query<AsOfQuery>,
) -> Result<Json<PaginatedResponse<Uuid>>, AppError> {
    let (_, target, _, _) = list_info(&state, list).await?;
    let window = attome_types::OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    // The last change per person up to `at`; those whose last change was
    // `entered` were in the list then.
    let people: Vec<Uuid> = sqlx::query_scalar(
        "SELECT person_id FROM ( \
             SELECT DISTINCT ON (person_id) person_id, change \
             FROM marketing_list_membership_event \
             WHERE list_id = $1 AND at <= $2 \
             ORDER BY person_id, at DESC, id DESC) last \
         WHERE change = 'entered' ORDER BY person_id",
    )
    .bind(list)
    .bind(q.at)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let visible = readable(&state, &ctx, &target, &people).await?;
    let shown: Vec<Uuid> = people.into_iter().filter(|p| visible.contains(p)).collect();
    let total = shown.len() as i64;
    let items = shown
        .into_iter()
        .skip(usize::try_from(window.offset).unwrap_or(0))
        .take(usize::try_from(window.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_marketing_list_count,
        get_marketing_list_sample,
        get_marketing_list_explain,
        get_marketing_list_members_as_of
    ),
    components(schemas(
        MarketingListCount,
        MarketingListSample,
        ExplainStep,
        MarketingListExplanation
    ))
)]
pub(crate) struct ApiDocFragment;
