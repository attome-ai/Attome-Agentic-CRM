//! E15-T1: the touchpoints of won opportunities and their attribution
//! credit, computed nightly with the models in [`crate::attribution`].
//!
//! - **Touchpoints.** For an opportunity won at its `close_date`, the touches
//!   of its account's contacts (at most [`MAX_CONTACTS`]) in the
//!   [`LOOKBACK_DAYS`] before the close: their profile events (E23; the
//!   campaign is the event's `campaign_id` property, the channel its
//!   `channel` property or else its kind) and, with the marketing forms
//!   installed, their form submissions (channel `form`). At most
//!   [`MAX_TOUCHPOINTS`], the latest kept.
//! - **Credit.** Every model ([`MODELS`]) is computed and stored per
//!   touchpoint in `marketing_attribution_credit` (migration 0288): its
//!   share and its part of the won amount. An opportunity's credit is
//!   replaced in one transaction, and `marketing_attribution_run` records
//!   when, so the `marketing_attribution` job (nightly, at most
//!   [`BATCH`] opportunities a run) recomputes only opportunities won since,
//!   or changed after, their last computation. An opportunity without
//!   touches gets a run row and no credit.
//! - `GET /api/v1/marketing/opportunities/{id}/attribution?model=` reads one
//!   model's credit, by touchpoint and by campaign, for a caller who may
//!   read the opportunity.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::attribution::{Model, Touchpoint, attribute};

/// The registered job.
pub const JOB: &str = "marketing_attribution";
/// Opportunities one run computes.
pub const BATCH: i64 = 500;
/// How far before the close a touch counts.
pub const LOOKBACK_DAYS: i64 = 365;
/// Contacts of one account read.
pub const MAX_CONTACTS: i64 = 500;
/// Touchpoints one opportunity keeps (the latest).
pub const MAX_TOUCHPOINTS: i64 = 1_000;
/// The time-decay model's half-life.
pub const HALF_LIFE_DAYS: f64 = 7.0;
/// The stored models, by name.
pub const MODELS: [&str; 5] = [
    "first_touch",
    "last_touch",
    "linear",
    "u_shaped",
    "time_decay",
];

/// A stored model's [`Model`]. Pure.
pub fn model_of(name: &str) -> Option<Model> {
    match name {
        "first_touch" => Some(Model::FirstTouch),
        "last_touch" => Some(Model::LastTouch),
        "linear" => Some(Model::Linear),
        "u_shaped" => Some(Model::UShaped),
        "time_decay" => Some(Model::TimeDecay {
            half_life_days: HALF_LIFE_DAYS,
        }),
        _ => None,
    }
}

/// A touch with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredTouch {
    pub touch: Touchpoint,
    /// `profile_event` or `form_submission`.
    pub kind: &'static str,
}

/// One stored credit row, before writing. Pure.
#[derive(Debug, Clone, PartialEq)]
pub struct CreditRow {
    pub model: &'static str,
    pub touchpoint: Uuid,
    pub kind: &'static str,
    pub campaign: Option<Uuid>,
    pub channel: String,
    pub at: DateTime<Utc>,
    pub share: f64,
    pub amount: Option<f64>,
}

/// Every model's credit for `touches` of a deal closed at `closed_at`
/// worth `amount`. Pure.
pub fn credit_rows(
    touches: &[StoredTouch],
    closed_at: DateTime<Utc>,
    amount: Option<f64>,
) -> Vec<CreditRow> {
    let plain: Vec<Touchpoint> = touches.iter().map(|t| t.touch.clone()).collect();
    let by_id: BTreeMap<Uuid, &StoredTouch> = touches.iter().map(|t| (t.touch.id, t)).collect();
    let mut rows = Vec::new();
    for name in MODELS {
        let Some(model) = model_of(name) else {
            continue;
        };
        for credit in attribute(&plain, closed_at, model) {
            let Some(touch) = by_id.get(&credit.touchpoint) else {
                continue;
            };
            rows.push(CreditRow {
                model: name,
                touchpoint: credit.touchpoint,
                kind: touch.kind,
                campaign: touch.touch.campaign,
                channel: touch.touch.channel.clone(),
                at: touch.touch.at,
                share: credit.share,
                amount: amount.map(|a| a * credit.share),
            });
        }
    }
    rows
}

fn has_entity(state: &EngineState, name: &str) -> bool {
    state.entities.load().get(name).is_some()
}

/// The touches of `account`'s contacts in the lookback before `closed_at`.
async fn touches(
    state: &EngineState,
    account: Uuid,
    closed_at: DateTime<Utc>,
) -> Result<Vec<StoredTouch>, AppError> {
    let contacts: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM contact WHERE account_ref = $1 \
            AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $2",
    )
    .bind(account)
    .bind(MAX_CONTACTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if contacts.is_empty() {
        return Ok(Vec::new());
    }
    let from = closed_at - Duration::days(LOOKBACK_DAYS);
    let events: Vec<(Uuid, DateTime<Utc>, Option<String>, String)> = sqlx::query_as(
        "SELECT id, at, \
                CASE WHEN properties->>'campaign_id' ~* \
                          '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
                     THEN properties->>'campaign_id' END, \
                COALESCE(NULLIF(properties->>'channel', ''), kind) \
           FROM profile_event \
          WHERE contact_id = ANY($1) AND at >= $2 AND at <= $3 \
          ORDER BY at DESC, id DESC LIMIT $4",
    )
    .bind(&contacts)
    .bind(from)
    .bind(closed_at)
    .bind(MAX_TOUCHPOINTS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out: Vec<StoredTouch> = events
        .into_iter()
        .map(|(id, at, campaign, channel)| StoredTouch {
            touch: Touchpoint {
                id,
                at,
                campaign: campaign.and_then(|c| Uuid::parse_str(&c).ok()),
                channel,
            },
            kind: "profile_event",
        })
        .collect();
    if has_entity(state, "marketing_form_submission") {
        let as_text: Vec<String> = contacts.iter().map(Uuid::to_string).collect();
        let forms: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, created_at FROM marketing_form_submission \
              WHERE person_entity = 'contact' AND person_id = ANY($1) \
                AND created_at >= $2 AND created_at <= $3 \
                AND (is_active IS NULL OR is_active = true) \
              ORDER BY created_at DESC, id DESC LIMIT $4",
        )
        .bind(&as_text)
        .bind(from)
        .bind(closed_at)
        .bind(MAX_TOUCHPOINTS)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        out.extend(forms.into_iter().map(|(id, at)| StoredTouch {
            touch: Touchpoint {
                id,
                at,
                campaign: None,
                channel: "form".to_owned(),
            },
            kind: "form_submission",
        }));
    }
    out.sort_by(|a, b| {
        b.touch
            .at
            .cmp(&a.touch.at)
            .then(b.touch.id.cmp(&a.touch.id))
    });
    out.truncate(usize::try_from(MAX_TOUCHPOINTS).unwrap_or(1_000));
    Ok(out)
}

/// Computes and stores one won opportunity's credit; the rows written.
pub async fn compute_opportunity(
    state: &EngineState,
    opportunity: Uuid,
) -> Result<usize, AppError> {
    let row: Option<(Option<Uuid>, Option<DateTime<Utc>>, Option<f64>)> = sqlx::query_as(
        "SELECT account_ref, close_date, amount::float8 FROM opportunity \
          WHERE id = $1 AND stage::text = 'closed_won' \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((account, Some(closed_at), amount)) = row else {
        return Ok(0);
    };
    let rows = match account {
        Some(account) => credit_rows(
            &touches(state, account, closed_at).await?,
            closed_at,
            amount,
        ),
        None => Vec::new(),
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM marketing_attribution_credit WHERE opportunity_id = $1")
        .bind(opportunity)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !rows.is_empty() {
        let models: Vec<&str> = rows.iter().map(|r| r.model).collect();
        let ids: Vec<Uuid> = rows.iter().map(|r| r.touchpoint).collect();
        let kinds: Vec<&str> = rows.iter().map(|r| r.kind).collect();
        let campaigns: Vec<Option<Uuid>> = rows.iter().map(|r| r.campaign).collect();
        let channels: Vec<String> = rows.iter().map(|r| r.channel.clone()).collect();
        let times: Vec<DateTime<Utc>> = rows.iter().map(|r| r.at).collect();
        let shares: Vec<f64> = rows.iter().map(|r| r.share).collect();
        let amounts: Vec<Option<f64>> = rows.iter().map(|r| r.amount).collect();
        sqlx::query(
            "INSERT INTO marketing_attribution_credit \
                 (opportunity_id, model, touchpoint_id, touchpoint_kind, campaign_id, channel, \
                  touched_at, share, amount) \
             SELECT $1, * FROM UNNEST($2::text[], $3::uuid[], $4::text[], $5::uuid[], \
                                      $6::text[], $7::timestamptz[], $8::float8[], $9::float8[])",
        )
        .bind(opportunity)
        .bind(&models)
        .bind(&ids)
        .bind(&kinds)
        .bind(&campaigns)
        .bind(&channels)
        .bind(&times)
        .bind(&shares)
        .bind(&amounts)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "INSERT INTO marketing_attribution_run (opportunity_id, computed_at, touchpoints) \
         VALUES ($1, now(), $2) \
         ON CONFLICT (opportunity_id) DO UPDATE \
            SET computed_at = now(), touchpoints = EXCLUDED.touchpoints",
    )
    .bind(opportunity)
    .bind(i32::try_from(rows.len() / MODELS.len()).unwrap_or(i32::MAX))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(rows.len())
}

/// The nightly run: won opportunities not computed since they last changed.
pub async fn run(state: &EngineState) -> Result<u64, AppError> {
    if !has_entity(state, "opportunity") || !has_entity(state, "contact") {
        return Ok(0);
    }
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT o.id FROM opportunity o \
           LEFT JOIN marketing_attribution_run r ON r.opportunity_id = o.id \
          WHERE o.stage::text = 'closed_won' AND o.close_date IS NOT NULL \
            AND (o.is_active IS NULL OR o.is_active = true) \
            AND (r.opportunity_id IS NULL OR r.computed_at < o.modified_at) \
          ORDER BY o.close_date DESC, o.id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut done = 0;
    for opportunity in due {
        match compute_opportunity(state, opportunity).await {
            Ok(_) => done += 1,
            Err(error) => {
                tracing::warn!(%opportunity, %error, "attribution not computed");
            }
        }
    }
    if done > 0 {
        tracing::info!(opportunities = done, "marketing attribution computed");
    }
    Ok(done)
}

// ── Reading ──────────────────────────────────────────────────────────────────

/// `opportunity.read`.
#[derive(Debug)]
pub struct OpportunityRead;

impl PrivilegeKey for OpportunityRead {
    const KEY: &'static str = "opportunity.read";
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AttributionQuery {
    /// `first_touch`, `last_touch`, `linear` (default), `u_shaped` or
    /// `time_decay`.
    pub model: Option<String>,
}

/// One touchpoint's credit.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct TouchCredit {
    pub touchpoint_id: Uuid,
    pub touchpoint_kind: String,
    pub campaign_id: Option<Uuid>,
    pub channel: String,
    pub touched_at: DateTime<Utc>,
    pub share: f64,
    pub amount: Option<f64>,
}

/// One campaign's credit.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CampaignCredit {
    pub campaign_id: Uuid,
    pub share: f64,
    pub amount: Option<f64>,
}

/// An opportunity's credit under one model.
#[derive(Debug, Serialize, ToSchema)]
pub struct Attribution {
    pub opportunity_id: Uuid,
    pub model: String,
    /// When it was last computed; `None` when not yet.
    pub computed_at: Option<DateTime<Utc>>,
    pub touchpoints: Vec<TouchCredit>,
    pub by_campaign: Vec<CampaignCredit>,
}

/// Sums credits per campaign, touches without one left out. Pure.
pub fn campaign_totals(credits: &[TouchCredit]) -> Vec<CampaignCredit> {
    let mut totals: BTreeMap<Uuid, (f64, Option<f64>)> = BTreeMap::new();
    for credit in credits {
        if let Some(campaign) = credit.campaign_id {
            let entry = totals.entry(campaign).or_insert((0.0, None));
            entry.0 += credit.share;
            if let Some(amount) = credit.amount {
                entry.1 = Some(entry.1.unwrap_or(0.0) + amount);
            }
        }
    }
    totals
        .into_iter()
        .map(|(campaign_id, (share, amount))| CampaignCredit {
            campaign_id,
            share,
            amount,
        })
        .collect()
}

/// One opportunity's stored credit under `model`.
pub async fn read(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
    model: Option<&str>,
) -> Result<Attribution, AppError> {
    let model = model.unwrap_or("linear");
    if model_of(model).is_none() {
        return Err(AppError::Validation(format!(
            "model is one of {}",
            MODELS.join(", ")
        )));
    }
    if !has_entity(state, "opportunity")
        || !attome_records::entity_crud::referenced_record_visible(
            state,
            ctx,
            "opportunity",
            opportunity,
        )
        .await?
    {
        return Err(AppError::NotFound);
    }
    let computed_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT computed_at FROM marketing_attribution_run WHERE opportunity_id = $1",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let touchpoints: Vec<TouchCredit> = sqlx::query_as(
        "SELECT touchpoint_id, touchpoint_kind, campaign_id, channel, touched_at, share, \
                amount::float8 AS amount \
           FROM marketing_attribution_credit WHERE opportunity_id = $1 AND model = $2 \
          ORDER BY touched_at, touchpoint_id",
    )
    .bind(opportunity)
    .bind(model)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let by_campaign = campaign_totals(&touchpoints);
    Ok(Attribution {
        opportunity_id: opportunity,
        model: model.to_owned(),
        computed_at,
        touchpoints,
        by_campaign,
    })
}

/// An opportunity's attribution
///
/// How much of a won opportunity each marketing touch earned under one
/// model, by touch and by campaign; computed nightly.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/opportunities/{id}/attribution",
    operation_id = "opportunity_attribution",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The opportunity"), AttributionQuery),
    responses(
        (status = 200, description = "The credit under the model", body = Attribution),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks opportunity.read", body = ErrorResponse),
        (status = 404, description = "No such opportunity, or not readable", body = ErrorResponse),
        (status = 422, description = "An unknown model", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_attribution(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityRead>>,
    Path(opportunity): Path<Uuid>,
    Query(q): Query<AttributionQuery>,
) -> Result<Json<Attribution>, AppError> {
    read(&state, &ctx, opportunity, q.model.as_deref())
        .await
        .map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/marketing/opportunities/{id}/attribution",
        get(get_attribution),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_attribution),
    components(schemas(Attribution, TouchCredit, CampaignCredit))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(
        n: u128,
        days_before: i64,
        campaign: Option<u128>,
        close: DateTime<Utc>,
    ) -> StoredTouch {
        StoredTouch {
            touch: Touchpoint {
                id: Uuid::from_u128(n),
                at: close - Duration::days(days_before),
                campaign: campaign.map(Uuid::from_u128),
                channel: "email".into(),
            },
            kind: "profile_event",
        }
    }

    #[test]
    fn attribution_every_model_shares_sum_to_one() {
        let close = Utc::now();
        let touches = vec![
            touch(1, 30, Some(100), close),
            touch(2, 10, Some(101), close),
            touch(3, 1, None, close),
        ];
        let rows = credit_rows(&touches, close, Some(1000.0));
        for model in MODELS {
            let shares: f64 = rows
                .iter()
                .filter(|r| r.model == model)
                .map(|r| r.share)
                .sum();
            assert!((shares - 1.0).abs() < 1e-9, "{model}: {shares}");
            let amount: f64 = rows
                .iter()
                .filter(|r| r.model == model)
                .filter_map(|r| r.amount)
                .sum();
            assert!((amount - 1000.0).abs() < 1e-6, "{model}: {amount}");
        }
        let first: Vec<&CreditRow> = rows.iter().filter(|r| r.model == "first_touch").collect();
        let winner = first.iter().find(|r| r.share > 0.99).map(|r| r.touchpoint);
        assert_eq!(winner, Some(Uuid::from_u128(1)));
    }

    #[test]
    fn attribution_by_campaign_leaves_out_untagged_touches() {
        let credit = |campaign: Option<u128>, share: f64| TouchCredit {
            touchpoint_id: Uuid::now_v7(),
            touchpoint_kind: "profile_event".into(),
            campaign_id: campaign.map(Uuid::from_u128),
            channel: "email".into(),
            touched_at: Utc::now(),
            share,
            amount: Some(share * 100.0),
        };
        let totals = campaign_totals(&[
            credit(Some(7), 0.25),
            credit(Some(7), 0.25),
            credit(None, 0.5),
        ]);
        assert_eq!(totals.len(), 1);
        assert!((totals[0].share - 0.5).abs() < 1e-9);
        assert_eq!(totals[0].amount, Some(50.0));
        assert!(model_of("nope").is_none());
    }
}
