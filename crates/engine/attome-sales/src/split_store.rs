//! Stored deal splits (roadmap D7-T4, D7-T5): the route that replaces an
//! opportunity's splits, and the recalculation of their stored amounts.
//!
//! `PUT /api/v1/sales/opportunities/{id}/splits` replaces every split in one
//! transaction under the opportunity's lock
//! (`attome-sales/opportunity:{id}`), checked by [`crate::splits`]'s rules,
//! and stores each split's amount. On a won deal the change is a proposal
//! instead: it waits on an approval ([`ACTION_SPLIT_CHANGE`]) with a
//! required reason, and is applied only if the deal has not changed since.
//!
//! [`recalculate_in_tx`] is the one place split amounts are computed; the
//! line and amount transactions call it so amounts never go stale, and
//! forecasting, quotas and commissions read the stored amounts rather than
//! computing their own. A deal with no splits counts as 100% revenue to its
//! owner.

use std::collections::BTreeMap;

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::splits::{AmountBasis, DealAmounts, Split, SplitError, SplitType};

/// The approval that applies a split change on a won deal.
pub const ACTION_SPLIT_CHANGE: &str = "sales.split_change";

/// Splits one deal may carry.
pub const MAX_SPLITS: usize = 200;

/// `opportunity.update`: may change a deal's splits.
#[derive(Debug)]
pub struct OpportunityUpdate;

impl PrivilegeKey for OpportunityUpdate {
    const KEY: &'static str = "opportunity.update";
}

fn dec(text: Option<&str>) -> Decimal {
    text.and_then(|t| t.trim().parse().ok())
        .unwrap_or(Decimal::ZERO)
}

fn lock_key(opportunity: Uuid) -> String {
    format!("attome-sales/opportunity:{opportunity}")
}

/// The deal's lock, shared by split and line changes so their amounts never
/// race.
pub(crate) async fn lock_deal(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
) -> Result<(), AppError> {
    lock(tx, opportunity).await
}

async fn lock(tx: &mut attome_db::Tx<'_>, opportunity: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(opportunity))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "this deal is being changed by another request",
        ))
    }
}

async fn split_types(tx: &mut attome_db::Tx<'_>) -> Result<Vec<SplitType>, AppError> {
    let rows: Vec<(Uuid, Option<String>, Option<bool>, Option<String>)> = sqlx::query_as(
        "SELECT id, name, must_total_100, amount_basis FROM sales_split_type \
         WHERE (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, strict, basis)| SplitType {
            id,
            name: name.unwrap_or_default(),
            must_total_100: strict.unwrap_or(false),
            basis: match basis.as_deref() {
                Some("one_time") => AmountBasis::OneTime,
                Some("recurring") => AmountBasis::Recurring,
                _ => AmountBasis::Total,
            },
        })
        .collect())
}

/// The deal's owner and the amounts its splits divide.
async fn deal_amounts(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
) -> Result<(Option<Uuid>, DealAmounts), AppError> {
    let deal: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT owner_ref, amount::text FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((owner, amount)) = deal else {
        return Err(AppError::NotFound);
    };
    let lines: Vec<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, line_total::text, line_kind FROM opportunity_line \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let mut amounts = DealAmounts {
        total: Decimal::ZERO,
        one_time: Decimal::ZERO,
        recurring: Decimal::ZERO,
        lines: BTreeMap::new(),
    };
    for (id, total, kind) in lines {
        let total = dec(total.as_deref());
        if kind.as_deref() == Some("recurring") {
            amounts.recurring += total;
        } else {
            amounts.one_time += total;
        }
        amounts.lines.insert(id, total);
    }
    amounts.total = match amount.as_deref() {
        Some(a) => dec(Some(a)),
        None => amounts.one_time + amounts.recurring,
    };
    Ok((owner, amounts))
}

async fn stored_splits(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
) -> Result<Vec<Split>, AppError> {
    let rows: Vec<(
        Uuid,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT s.id, s.split_type_ref, m.user_ref, s.line_ref, s.percent::text \
             FROM opportunity_split s \
             LEFT JOIN opportunity_team_member m ON m.id = s.member_ref \
             WHERE s.opportunity_ref = $1 AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(opportunity)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, split_type, member_user, line, percent)| {
            Some(Split {
                id,
                split_type: split_type?,
                member_user,
                line,
                percent: dec(percent.as_deref()),
            })
        })
        .collect())
}

/// Recomputes and stores every split amount of a deal, inside the caller's
/// transaction (which holds the deal's lock). The number of splits whose
/// amount changed.
pub async fn recalculate_in_tx(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
) -> Result<u64, AppError> {
    let types = split_types(tx).await?;
    let (owner, amounts) = deal_amounts(tx, opportunity).await?;
    let splits = stored_splits(tx, opportunity).await?;
    let computed =
        crate::splits::split_amounts(&types, &splits, &amounts, owner.unwrap_or(Uuid::nil()), 2);
    let mut changed = 0;
    for (id, amount) in computed {
        changed += sqlx::query(
            "UPDATE opportunity_split SET amount = $2::numeric, modified_at = now(), \
                 row_version = row_version + 1 \
             WHERE id = $1 AND amount IS DISTINCT FROM $2::numeric",
        )
        .bind(id)
        .bind(amount.to_string())
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    Ok(changed)
}

/// One split as a caller gives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SplitInput {
    /// The `opportunity_team_member` the split credits.
    pub member_id: Uuid,
    pub split_type_id: Uuid,
    /// For a split of one line rather than the whole deal.
    #[serde(default)]
    pub line_id: Option<Uuid>,
    /// Decimal text, e.g. `"60"` or `"33.34"`.
    pub percent: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SalesSplitsBody {
    pub splits: Vec<SplitInput>,
    /// Required when the deal is won.
    #[serde(default)]
    pub change_reason: Option<String>,
}

/// The splits after the change, or the approval a won deal's change waits
/// on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesSplitsOutcome {
    pub opportunity_id: Uuid,
    pub splits: Vec<StoredSplit>,
    pub approval_request_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct StoredSplit {
    pub id: Uuid,
    pub member_id: Uuid,
    pub split_type_id: Uuid,
    pub line_id: Option<Uuid>,
    pub percent: String,
    pub amount: Option<String>,
}

/// A won deal's proposed change, as stored in its approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitProposal {
    pub opportunity_id: Uuid,
    /// The deal's row_version when proposed; a changed deal makes the
    /// proposal stale.
    pub row_version: i64,
    pub splits: Vec<SplitInput>,
    pub change_reason: String,
    pub requested_by: Uuid,
}

fn split_errors(errors: &[SplitError]) -> AppError {
    let text = errors
        .iter()
        .map(|e| match e {
            SplitError::UnknownType(t) => format!("unknown split type {t}"),
            SplitError::UnknownLine(l) => format!("line {l} is not on this deal"),
            SplitError::NegativePercent(_) => "a percent is negative".to_owned(),
            SplitError::MustTotal100 {
                split_type,
                line,
                total,
            } => match line {
                Some(line) => {
                    format!("split type {split_type} on line {line} totals {total}%, not 100%")
                }
                None => format!("split type {split_type} totals {total}%, not 100%"),
            },
        })
        .collect::<Vec<_>>()
        .join("; ");
    AppError::Validation(text)
}

/// Checks a set of splits against the deal and replaces the stored ones,
/// inside a transaction that holds the deal's lock.
async fn replace_in_tx(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
    owner: Option<Uuid>,
    splits: &[SplitInput],
) -> Result<(), AppError> {
    if splits.len() > MAX_SPLITS {
        return Err(AppError::Validation(format!("at most {MAX_SPLITS} splits")));
    }
    let members: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, user_ref FROM opportunity_team_member \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let types = split_types(tx).await?;
    let (_, amounts) = deal_amounts(tx, opportunity).await?;
    let lines: Vec<Uuid> = amounts.lines.keys().copied().collect();
    let mut checked = Vec::with_capacity(splits.len());
    for (i, s) in splits.iter().enumerate() {
        let Some((_, user)) = members.iter().find(|(id, _)| *id == s.member_id) else {
            return Err(AppError::Validation(format!(
                "split {i}: member {} is not on this deal's team",
                s.member_id
            )));
        };
        let percent: Decimal = s
            .percent
            .trim()
            .parse()
            .map_err(|_| AppError::Validation(format!("split {i}: percent is not a number")))?;
        checked.push(Split {
            id: Uuid::now_v7(),
            split_type: s.split_type_id,
            member_user: *user,
            line: s.line_id,
            percent,
        });
    }
    crate::splits::validate_splits(&types, &checked, &lines).map_err(|e| split_errors(&e))?;
    sqlx::query("DELETE FROM opportunity_split WHERE opportunity_ref = $1")
        .bind(opportunity)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    for (split, input) in checked.iter().zip(splits) {
        sqlx::query(
            "INSERT INTO opportunity_split \
               (id, opportunity_ref, member_ref, split_type_ref, line_ref, percent, owner_ref) \
             VALUES ($1, $2, $3, $4, $5, $6::numeric, $7)",
        )
        .bind(split.id)
        .bind(opportunity)
        .bind(input.member_id)
        .bind(split.split_type)
        .bind(split.line)
        .bind(split.percent.to_string())
        .bind(owner)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    recalculate_in_tx(tx, opportunity).await?;
    Ok(())
}

async fn read_splits(
    db: &attome_db::DbPool,
    opportunity: Uuid,
) -> Result<Vec<StoredSplit>, AppError> {
    type Row = (
        Uuid,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, member_ref, split_type_ref, line_ref, percent::text, amount::text \
         FROM opportunity_split \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(opportunity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, member, split_type, line, percent, amount)| {
            Some(StoredSplit {
                id,
                member_id: member?,
                split_type_id: split_type?,
                line_id: line,
                percent: percent.unwrap_or_default(),
                amount,
            })
        })
        .collect())
}

/// Applies an approved split proposal, when the deal is unchanged since.
pub async fn do_apply_proposal(
    state: &EngineState,
    proposal: &SplitProposal,
    approver: Uuid,
) -> Result<SalesSplitsOutcome, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, proposal.opportunity_id).await?;
    let current: Option<(i64, Option<Uuid>)> = sqlx::query_as(
        "SELECT row_version, owner_ref FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(proposal.opportunity_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((version, owner)) = current else {
        return Err(AppError::NotFound);
    };
    if version != proposal.row_version {
        return Err(AppError::Conflict(
            "the deal changed after the split change was proposed; propose it again",
        ));
    }
    replace_in_tx(&mut tx, proposal.opportunity_id, owner, &proposal.splits).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "opportunity",
            proposal.opportunity_id,
            AuditOperation::Update,
            "sales.splits_changed",
            approver,
        )
        .comment(format!("approved split change: {}", proposal.change_reason)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(SalesSplitsOutcome {
        opportunity_id: proposal.opportunity_id,
        splits: read_splits(&state.base.db, proposal.opportunity_id).await?,
        approval_request_id: None,
    })
}

#[utoipa::path(
    put,
    path = "/api/v1/sales/opportunities/{id}/splits",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    request_body = SalesSplitsBody,
    responses(
        (status = 200, description = "The splits are replaced and their amounts stored", body = SalesSplitsOutcome),
        (status = 202, description = "The deal is won: the change waits on approval", body = SalesSplitsOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity", body = ErrorResponse),
        (status = 409, description = "The deal is being changed by another request", body = ErrorResponse),
        (status = 422, description = "The splits break a rule (a revenue type must total 100%, members must be on the team), or a won deal's change has no reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn put_sales_splits(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    Json(body): Json<SalesSplitsBody>,
) -> Result<(StatusCode, Json<SalesSplitsOutcome>), AppError> {
    replace_splits(&state, &ctx, opportunity, body).await
}

/// Replaces a deal's splits (or proposes the change on a won deal), as the
/// caller.
pub async fn replace_splits(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    opportunity: Uuid,
    body: SalesSplitsBody,
) -> Result<(StatusCode, Json<SalesSplitsOutcome>), AppError> {
    crate::flags::require(state, ctx, crate::flags::SPLITS).await?;
    if body.splits.iter().any(|s| s.line_id.is_some()) {
        crate::flags::require(state, ctx, crate::flags::LINE_SPLITS).await?;
    }
    let entity_id = state
        .entities
        .load()
        .get("opportunity")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity_id,
        "opportunity",
        opportunity,
        RecordAction::Update,
    )
    .await?;
    let deal: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT stage, row_version FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((stage, version)) = deal else {
        return Err(AppError::NotFound);
    };
    if stage.as_deref() == Some("closed_won") {
        let reason = body
            .change_reason
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .ok_or_else(|| {
                AppError::Validation(
                    "change_reason is required to change a won deal's splits".into(),
                )
            })?;
        let proposal = SplitProposal {
            opportunity_id: opportunity,
            row_version: version,
            splits: body.splits,
            change_reason: reason.to_owned(),
            requested_by: ctx.user_id,
        };
        let payload = serde_json::to_value(&proposal).map_err(AppError::internal)?;
        let request = attome_audit::approval::gate_regarding_required(
            state,
            ACTION_SPLIT_CHANGE,
            payload,
            ctx.user_id,
            Some(("opportunity", opportunity)),
        )
        .await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(SalesSplitsOutcome {
                opportunity_id: opportunity,
                splits: read_splits(&state.base.db, opportunity).await?,
                approval_request_id: Some(request.id),
            }),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, opportunity).await?;
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT owner_ref FROM opportunity WHERE id = $1")
        .bind(opportunity)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    replace_in_tx(&mut tx, opportunity, owner, &body.splits).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "opportunity",
            opportunity,
            AuditOperation::Update,
            "sales.splits_changed",
            ctx.user_id,
        )
        .comment(format!("{} splits", body.splits.len())),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::OK,
        Json(SalesSplitsOutcome {
            opportunity_id: opportunity,
            splits: read_splits(&state.base.db, opportunity).await?,
            approval_request_id: None,
        }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(put_sales_splits),
    components(schemas(SplitInput, SalesSplitsBody, SalesSplitsOutcome, StoredSplit))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_breaks_read_as_one_message() {
        let t = Uuid::from_u128(1);
        let err = split_errors(&[
            SplitError::MustTotal100 {
                split_type: t,
                line: None,
                total: Decimal::from(90),
            },
            SplitError::UnknownLine(Uuid::from_u128(2)),
        ]);
        let AppError::Validation(text) = err else {
            panic!("a validation error");
        };
        assert!(text.contains("totals 90%, not 100%"));
        assert!(text.contains("is not on this deal"));
    }

    #[test]
    fn a_proposal_round_trips_through_its_approval_request() {
        let proposal = SplitProposal {
            opportunity_id: Uuid::from_u128(1),
            row_version: 4,
            splits: vec![SplitInput {
                member_id: Uuid::from_u128(2),
                split_type_id: Uuid::from_u128(3),
                line_id: None,
                percent: "100".into(),
            }],
            change_reason: "territory move".into(),
            requested_by: Uuid::from_u128(5),
        };
        let back: Option<SplitProposal> =
            serde_json::from_value(serde_json::to_value(&proposal).unwrap_or_default()).ok();
        assert_eq!(back, Some(proposal));
    }

    #[test]
    fn the_lock_key_names_the_crate_and_deal() {
        assert_eq!(
            lock_key(Uuid::nil()),
            "attome-sales/opportunity:00000000-0000-0000-0000-000000000000"
        );
    }
}
