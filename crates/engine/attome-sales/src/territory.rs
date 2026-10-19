//! D13-T3: territory realignment.
//!
//! Each enabled `territory_rule` is a Z11 condition over an account's
//! fields; an account belongs to the territory of the first rule (lowest
//! `priority`, then id) whose condition is plainly true. A condition that
//! does not compile or does not give a yes/no for the account never moves
//! it. Links made by hand (`account_territory.manual`) are never touched.
//!
//! **Preview** (`POST /api/v1/sales/territories/realign/preview`) lists the
//! accounts that would move, from which rule-made territory to which, over
//! at most [`PREVIEW_ACCOUNTS`] accounts. **Apply** (`POST
//! /api/v1/sales/territories/realign`) queues the `territory_realign` job,
//! which walks every account in batches and writes each change through the
//! generic mutation path as the person who asked: a new link is created,
//! an old rule-made one removed to the recycle bin, so the account's history
//! (audit and recycle bin) shows every move. It is idempotent: a second run
//! finds nothing left to move.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job type that applies a realignment.
pub const REALIGN_JOB: &str = "territory_realign";
/// Most accounts a preview looks at.
pub const PREVIEW_ACCOUNTS: i64 = 10_000;
/// Moves listed in a preview.
const PREVIEW_MOVES: usize = 500;
/// Accounts read per batch.
const BATCH: i64 = 200;

/// One rule, as loaded.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct TerritoryRule {
    pub id: Uuid,
    pub territory_ref: Uuid,
    pub condition: String,
}

/// An account that changes territory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Move {
    pub account_id: Uuid,
    pub account_name: Option<String>,
    /// The rule-made territory it leaves, if any.
    pub from_territory: Option<Uuid>,
    /// The territory it joins, if any rule now matches.
    pub to_territory: Option<Uuid>,
    /// The rule that matched.
    pub rule_id: Option<Uuid>,
}

/// A preview.
#[derive(Debug, Serialize, ToSchema)]
pub struct RealignPreview {
    pub accounts_scanned: u64,
    pub total_moves: u64,
    /// The first moves (at most 500).
    pub moves: Vec<Move>,
    /// More accounts exist than a preview looks at.
    pub truncated: bool,
}

/// A queued realignment.
#[derive(Debug, Serialize, ToSchema)]
pub struct RealignQueued {
    pub queued: bool,
}

/// Whether `condition` is plainly true for `account`. Pure.
pub fn matches(condition: &str, account: &Value) -> bool {
    let (schema, ctx) = attome_audit::approval::schema_and_context_for_payload(account);
    match attome_rules::compile(condition, &schema) {
        Ok(compiled) => matches!(compiled.eval(&ctx), Ok(attome_rules::Value::Bool(true))),
        Err(_) => false,
    }
}

/// The territory and rule of the first rule (in the given order) the account
/// matches. Pure.
pub fn first_match(rules: &[TerritoryRule], account: &Value) -> Option<(Uuid, Uuid)> {
    rules
        .iter()
        .find(|r| !r.condition.trim().is_empty() && matches(&r.condition, account))
        .map(|r| (r.territory_ref, r.id))
}

/// The move for one account, if its rule-made territory differs from the
/// rules' answer. Pure.
pub fn move_for(
    account_id: Uuid,
    account_name: Option<String>,
    current: Option<Uuid>,
    target: Option<(Uuid, Uuid)>,
) -> Option<Move> {
    let to = target.map(|t| t.0);
    (current != to).then(|| Move {
        account_id,
        account_name,
        from_territory: current,
        to_territory: to,
        rule_id: target.map(|t| t.1),
    })
}

async fn installed(state: &EngineState) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('territory_rule') IS NOT NULL AND to_regclass('account_territory') IS NOT NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn rules(state: &EngineState) -> Result<Vec<TerritoryRule>, AppError> {
    sqlx::query_as(
        "SELECT id, territory_ref, condition FROM territory_rule \
          WHERE coalesce(is_enabled, true) AND is_active IS NOT FALSE \
            AND territory_ref IS NOT NULL AND condition IS NOT NULL \
          ORDER BY priority NULLS LAST, id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// One page of accounts after `after`, as (id, name, all fields).
async fn accounts_page(
    state: &EngineState,
    after: Option<Uuid>,
) -> Result<Vec<(Uuid, Option<String>, Value)>, AppError> {
    sqlx::query_as(
        "SELECT a.id, a.name, to_jsonb(a) FROM account a \
          WHERE a.is_active IS NOT FALSE AND ($1::uuid IS NULL OR a.id > $1) \
          ORDER BY a.id LIMIT $2",
    )
    .bind(after)
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The rule-made territory of each account in `ids`.
async fn current_links(
    state: &EngineState,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, (Uuid, Uuid)>, AppError> {
    let rows: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "SELECT account_ref, territory_ref, id FROM account_territory \
          WHERE account_ref = ANY($1) AND is_active IS NOT FALSE AND manual IS NOT TRUE \
            AND territory_ref IS NOT NULL \
          ORDER BY created_at DESC",
    )
    .bind(ids)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = HashMap::new();
    for (account, territory, link) in rows {
        out.entry(account).or_insert((territory, link));
    }
    Ok(out)
}

fn require(ctx: &SecurityContext) -> Result<(), AppError> {
    ctx.require("account_territory", "create")?;
    ctx.require("account_territory", "delete")?;
    Ok(())
}

/// What a realignment would move.
pub async fn preview(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<RealignPreview, AppError> {
    require(ctx)?;
    if !installed(state).await? {
        return Err(AppError::NotFound);
    }
    let rules = rules(state).await?;
    let mut out = RealignPreview {
        accounts_scanned: 0,
        total_moves: 0,
        moves: Vec::new(),
        truncated: false,
    };
    let mut after = None;
    loop {
        let page = accounts_page(state, after).await?;
        let Some(last) = page.last().map(|p| p.0) else {
            break;
        };
        let ids: Vec<Uuid> = page.iter().map(|p| p.0).collect();
        let links = current_links(state, &ids).await?;
        for (id, name, fields) in page {
            out.accounts_scanned += 1;
            let current = links.get(&id).map(|l| l.0);
            if let Some(m) = move_for(id, name, current, first_match(&rules, &fields)) {
                out.total_moves += 1;
                if out.moves.len() < PREVIEW_MOVES {
                    out.moves.push(m);
                }
            }
        }
        if out.accounts_scanned >= PREVIEW_ACCOUNTS as u64 {
            out.truncated = true;
            break;
        }
        after = Some(last);
    }
    Ok(out)
}

/// Queues the realignment job for the person asking.
pub async fn queue(state: &EngineState, ctx: &SecurityContext) -> Result<RealignQueued, AppError> {
    require(ctx)?;
    if !installed(state).await? {
        return Err(AppError::NotFound);
    }
    let job = attome_core::jobs::JOB_TYPES
        .job(REALIGN_JOB, &json!({ "user_id": ctx.user_id }))
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_on_pool(
        &state.base.db,
        attome_core::jobs::EngineJob::Registered(job),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(RealignQueued { queued: true })
}

/// The job: moves every account whose rule-made territory changed, in
/// batches, as `user`. Answers how many moved.
pub async fn apply(state: &EngineState, user: Uuid) -> Result<u64, AppError> {
    let ctx = state.base.security.resolve(user).await?;
    require(&ctx)?;
    if !installed(state).await? {
        return Ok(0);
    }
    let rules = rules(state).await?;
    // One operation for the whole run, so its removals restore together.
    let origin = attome_records::entity_mutation::DeleteOrigin::new(
        attome_records::entity_mutation::DeleteKind::Bulk,
    )
    .reason(Some("territory realignment"));
    let mut moved = 0u64;
    let mut after = None;
    loop {
        let page = accounts_page(state, after).await?;
        let Some(last) = page.last().map(|p| p.0) else {
            break;
        };
        let ids: Vec<Uuid> = page.iter().map(|p| p.0).collect();
        let links = current_links(state, &ids).await?;
        for (id, name, fields) in page {
            let link = links.get(&id).copied();
            let Some(m) = move_for(id, name, link.map(|l| l.0), first_match(&rules, &fields))
            else {
                continue;
            };
            if let Some((territory, rule)) = m.to_territory.zip(m.rule_id) {
                attome_records::entity_crud::create_record_for(
                    state,
                    &ctx,
                    user,
                    "account_territory",
                    json!({
                        "account_ref": id.to_string(),
                        "territory_ref": territory.to_string(),
                        "rule_ref": rule.to_string(),
                        "manual": false,
                    }),
                )
                .await?;
            }
            if let Some((_, old_link)) = link {
                attome_records::entity_crud::delete_record_for(
                    state,
                    &ctx,
                    user,
                    "account_territory",
                    old_link,
                    None,
                    &origin,
                )
                .await?;
            }
            moved += 1;
        }
        after = Some(last);
    }
    tracing::info!(moved, %user, "territory realignment: applied");
    Ok(moved)
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/territories/realign/preview",
    tag = "sales",
    responses(
        (status = 200, description = "The accounts that would move", body = RealignPreview),
        (status = 403, description = "Caller may not create and delete account territories", body = attome_types::ErrorResponse),
        (status = 404, description = "Territories are not installed", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "computes the moves a realignment would make; writes nothing"
    )))),
)]
pub(crate) async fn post_preview(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
) -> Result<axum::Json<RealignPreview>, AppError> {
    Ok(axum::Json(preview(&state, &ctx).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/territories/realign",
    tag = "sales",
    responses(
        (status = 202, description = "The realignment job is queued", body = RealignQueued),
        (status = 403, description = "Caller may not create and delete account territories", body = attome_types::ErrorResponse),
        (status = 404, description = "Territories are not installed", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_realign(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
) -> Result<(axum::http::StatusCode, axum::Json<RealignQueued>), AppError> {
    Ok((
        axum::http::StatusCode::ACCEPTED,
        axum::Json(queue(&state, &ctx).await?),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_preview, post_realign))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(n: u128, territory: u128, condition: &str) -> TerritoryRule {
        TerritoryRule {
            id: Uuid::from_u128(n),
            territory_ref: Uuid::from_u128(territory),
            condition: condition.into(),
        }
    }

    #[test]
    fn territory_realign_first_rule_wins() {
        let rules = vec![
            rule(1, 100, r#"region == "central" and employees >= 500"#),
            rule(2, 200, r#"region == "central""#),
            rule(3, 300, "this is not an expression ("),
        ];
        let big = json!({ "region": "central", "employees": 900 });
        let small = json!({ "region": "central", "employees": 20 });
        let west = json!({ "region": "western", "employees": 20 });
        assert_eq!(
            first_match(&rules, &big),
            Some((Uuid::from_u128(100), Uuid::from_u128(1)))
        );
        assert_eq!(
            first_match(&rules, &small),
            Some((Uuid::from_u128(200), Uuid::from_u128(2)))
        );
        assert_eq!(
            first_match(&rules, &west),
            None,
            "a broken rule never matches"
        );
    }

    #[test]
    fn territory_realign_moves_only_what_changed() {
        let a = Uuid::from_u128(9);
        let t1 = Uuid::from_u128(100);
        let t2 = Uuid::from_u128(200);
        let r = Uuid::from_u128(1);
        assert_eq!(move_for(a, None, Some(t1), Some((t1, r))), None);
        let m = move_for(a, Some("Acme".into()), Some(t1), Some((t2, r))).unwrap();
        assert_eq!(
            (m.from_territory, m.to_territory, m.rule_id),
            (Some(t1), Some(t2), Some(r))
        );
        let out = move_for(a, None, Some(t1), None).unwrap();
        assert_eq!((out.from_territory, out.to_territory), (Some(t1), None));
        assert_eq!(
            move_for(a, None, None, Some((t2, r))).unwrap().to_territory,
            Some(t2)
        );
        assert_eq!(move_for(a, None, None, None), None);
    }
}
