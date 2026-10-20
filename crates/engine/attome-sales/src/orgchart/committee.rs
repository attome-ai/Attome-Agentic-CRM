//! D23-T7: a deal's buying committee and its coverage gaps.
//!
//! [`deal_map`] answers, as the caller may read it: the account's chart
//! (D23-T5), each contact on the deal with their role, influence and
//! attitude (the last two only through the Deal Attitude field profile;
//! they belong to the deal's contact role, never to the contact), the
//! "influences" links between them (`record_relationship`), and the gaps.
//!
//! **Gaps** ([`coverage_gaps`], pure): every role the deal's current stage
//! requires (`opportunity_stage.required_contact_roles`, a JSON list of
//! role codes) that no contact on the deal holds, then every high-influence
//! contact nobody has met (no meeting activity regarding them in the last
//! [`MEETING_WINDOW_DAYS`] days). A caller who cannot read influence is not
//! shown the second kind, which would reveal it.
//!
//! **Stored, not recomputed per read.** The gaps are computed when the
//! deal's contact roles or the deal change: [`coverage_tick`] (the
//! `sales_deal_coverage` job) reads the change feed as [`CONSUMER`],
//! recomputes the affected deals, stores each deal's gaps in
//! `sales_deal_coverage`, and, when they changed, emits the named event
//! [`COVERAGE_EVENT`] on the opportunity in the same transaction for D19.
//! A feed row carries no payload, so D19 reads the gaps from the table. A
//! deal never computed yet is computed on read and not stored.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use super::chart::{OrgChart, account_chart};

/// A contact counts as met after a meeting this recent.
pub const MEETING_WINDOW_DAYS: i64 = 180;
/// The change-feed consumer.
pub const CONSUMER: &str = "attome-sales/deal_coverage";
/// The named event emitted on the opportunity when its gaps change.
pub const COVERAGE_EVENT: &str = "sales.coverage_gaps";
/// The registered job.
pub const JOB: &str = "sales_deal_coverage";
/// Contact roles read per deal.
const MAX_ROLES: i64 = 200;
/// Events read per tick.
const BATCH: i64 = 500;

/// What a gap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// A role the stage requires that no contact on the deal holds.
    MissingRole,
    /// A high-influence contact nobody has met lately.
    UnmetHighInfluence,
}

/// One coverage gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Gap {
    pub kind: GapKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<Uuid>,
}

/// One contact on the deal.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DealContact {
    pub contact_id: Uuid,
    pub full_name: Option<String>,
    pub role: Option<String>,
    pub is_primary: bool,
    /// Absent unless the caller holds the Deal Attitude profile.
    pub influence: Option<String>,
    pub attitude: Option<String>,
    /// A meeting regarding the contact in the last 180 days.
    pub met_recently: bool,
}

/// "From influences to".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct InfluenceLink {
    pub from_contact: Uuid,
    pub to_contact: Uuid,
}

/// A deal's buying committee.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DealMap {
    pub opportunity_id: Uuid,
    pub account_id: Option<Uuid>,
    /// The account's chart, when the account is readable.
    pub chart: Option<OrgChart>,
    pub contacts: Vec<DealContact>,
    pub influences: Vec<InfluenceLink>,
    pub required_roles: Vec<String>,
    pub gaps: Vec<Gap>,
    /// When the stored gaps were computed; `None` when computed for this read.
    pub gaps_computed_at: Option<DateTime<Utc>>,
}

/// The stage's required roles: a JSON list of role codes; anything else is
/// none. Pure.
pub fn parse_required(raw: Option<&str>) -> Vec<String> {
    raw.and_then(|r| serde_json::from_str::<Vec<String>>(r.trim()).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.trim().to_owned())
        .filter(|r| !r.is_empty())
        .collect()
}

/// The gaps; see the module doc. Required roles keep their order, each once.
/// Pure.
pub fn coverage_gaps(
    required_roles: &[String],
    roles_present: &[String],
    high_influence_unmet: &[Uuid],
) -> Vec<Gap> {
    let present: HashSet<&str> = roles_present.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut gaps: Vec<Gap> = required_roles
        .iter()
        .filter(|r| !present.contains(r.as_str()) && seen.insert(r.as_str()))
        .map(|r| Gap {
            kind: GapKind::MissingRole,
            role: Some(r.clone()),
            contact_id: None,
        })
        .collect();
    let mut unmet: Vec<Uuid> = high_influence_unmet.to_vec();
    unmet.sort();
    unmet.dedup();
    gaps.extend(unmet.into_iter().map(|c| Gap {
        kind: GapKind::UnmetHighInfluence,
        role: None,
        contact_id: Some(c),
    }));
    gaps
}

/// The deal's current stage's required roles (its pipeline's stage first).
async fn required_roles(state: &EngineState, opportunity: Uuid) -> Result<Vec<String>, AppError> {
    let raw: Option<Option<String>> = sqlx::query_scalar(
        "SELECT s.required_contact_roles FROM opportunity o \
           JOIN opportunity_stage s ON s.stage = o.stage::text \
                AND (s.pipeline IS NULL OR s.pipeline = o.pipeline::text) \
                AND (s.is_active IS NULL OR s.is_active = true) \
          WHERE o.id = $1 ORDER BY (s.pipeline IS NULL), s.id LIMIT 1",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(parse_required(raw.flatten().as_deref()))
}

/// The contacts among `contacts` met in the window.
async fn met_recently(state: &EngineState, contacts: &[Uuid]) -> Result<HashSet<Uuid>, AppError> {
    let ids: Vec<String> = contacts.iter().map(Uuid::to_string).collect();
    let met: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.regarding_id FROM activity a \
          WHERE a.activity_type::text = 'meeting' AND a.regarding_entity = 'contact' \
            AND a.regarding_id = ANY($1) AND (a.is_active IS NULL OR a.is_active = true) \
            AND COALESCE(a.activity_date::timestamptz, a.created_at) \
                >= now() - make_interval(days => $2)",
    )
    .bind(&ids)
    .bind(MEETING_WINDOW_DAYS as i32)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(met.iter().filter_map(|m| Uuid::parse_str(m).ok()).collect())
}

/// The deal's gaps from its rows, read by the engine (no user asking).
pub async fn compute_gaps(state: &EngineState, opportunity: Uuid) -> Result<Vec<Gap>, AppError> {
    let required = required_roles(state, opportunity).await?;
    let rows: Vec<(Option<String>, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT role::text, influence::text, contact_ref FROM opportunity_contact_role \
          WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $2",
    )
    .bind(opportunity)
    .bind(MAX_ROLES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let present: Vec<String> = rows.iter().filter_map(|(r, _, _)| r.clone()).collect();
    let high: Vec<Uuid> = rows
        .iter()
        .filter(|(_, i, _)| i.as_deref() == Some("high"))
        .filter_map(|(_, _, c)| *c)
        .collect();
    let met = met_recently(state, &high).await?;
    let unmet: Vec<Uuid> = high.into_iter().filter(|c| !met.contains(c)).collect();
    Ok(coverage_gaps(&required, &present, &unmet))
}

/// Recomputes and stores one deal's gaps; emits [`COVERAGE_EVENT`] when
/// they changed. Returns whether they changed.
pub async fn recompute(state: &EngineState, opportunity: Uuid) -> Result<bool, AppError> {
    let gaps = serde_json::to_value(compute_gaps(state, opportunity).await?)
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let before: Option<Value> = sqlx::query_scalar(
        "SELECT gaps FROM sales_deal_coverage WHERE opportunity_id = $1 FOR UPDATE",
    )
    .bind(opportunity)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if before.as_ref() == Some(&gaps) {
        attome_db::tx::commit(tx).await?;
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO sales_deal_coverage (opportunity_id, gaps, computed_at) VALUES ($1, $2, now()) \
         ON CONFLICT (opportunity_id) DO UPDATE SET gaps = EXCLUDED.gaps, computed_at = now()",
    )
    .bind(opportunity)
    .bind(&gaps)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_named(
        &mut tx,
        "opportunity",
        opportunity,
        attome_core::change_feed::ChangeOperation::Update,
        COVERAGE_EVENT,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// One tick of the coverage consumer; see the module doc. Returns the deals
/// whose gaps changed.
pub async fn coverage_tick(state: &EngineState) -> Result<usize, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut deals: Vec<Uuid> = events
        .iter()
        .filter(|e| e.entity_logicalname == "opportunity" && e.event_name.is_none())
        .map(|e| e.record_id)
        .collect();
    let role_rows: Vec<Uuid> = events
        .iter()
        .filter(|e| e.entity_logicalname == "opportunity_contact_role")
        .map(|e| e.record_id)
        .collect();
    if !role_rows.is_empty() {
        let owners: Vec<Option<Uuid>> = sqlx::query_scalar(
            "SELECT opportunity_ref FROM opportunity_contact_role WHERE id = ANY($1)",
        )
        .bind(&role_rows)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        deals.extend(owners.into_iter().flatten());
    }
    deals.sort();
    deals.dedup();
    let mut changed = 0;
    for deal in deals {
        if recompute(state, deal).await? {
            changed += 1;
        }
    }
    attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(changed)
}

fn text(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
}

fn uuid(data: &Value, key: &str) -> Option<Uuid> {
    data.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// The deal's committee as `ctx` may read it; see the module doc.
pub async fn deal_map(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
) -> Result<DealMap, AppError> {
    let deal =
        attome_records::entity_crud::read_record(state, ctx, "opportunity", opportunity).await?;
    let account_id = uuid(deal.data(), "account_ref");
    let chart = match account_id {
        Some(account) => account_chart(state, ctx, account, false, &HashSet::new(), None)
            .await
            .ok(),
        None => None,
    };

    let role_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM opportunity_contact_role \
          WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $2",
    )
    .bind(opportunity)
    .bind(MAX_ROLES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut contacts = Vec::new();
    for id in role_ids {
        // The record read applies row access and the field profile.
        let Ok(row) =
            attome_records::entity_crud::read_record(state, ctx, "opportunity_contact_role", id)
                .await
        else {
            continue;
        };
        let data = row.data();
        let Some(contact_id) = uuid(data, "contact_ref") else {
            continue;
        };
        let full_name = attome_records::entity_crud::read_record(state, ctx, "contact", contact_id)
            .await
            .ok()
            .and_then(|c| text(c.data(), "full_name"));
        contacts.push(DealContact {
            contact_id,
            full_name,
            role: text(data, "role"),
            is_primary: data.get("is_primary").and_then(Value::as_bool) == Some(true),
            influence: text(data, "influence"),
            attitude: text(data, "attitude"),
            met_recently: false,
        });
    }
    let ids: Vec<Uuid> = contacts.iter().map(|c| c.contact_id).collect();
    let met = met_recently(state, &ids).await?;
    for c in &mut contacts {
        c.met_recently = met.contains(&c.contact_id);
    }

    let id_text: Vec<String> = ids.iter().map(Uuid::to_string).collect();
    let links: Vec<(String, String)> = sqlx::query_as(
        "SELECT from_record_id, to_record_id FROM record_relationship \
          WHERE relationship_type = 'influences' AND from_entity_name = 'contact' \
            AND to_entity_name = 'contact' AND from_record_id = ANY($1) AND to_record_id = ANY($1) \
            AND is_active IS NOT FALSE",
    )
    .bind(&id_text)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let influences = links
        .into_iter()
        .filter_map(|(f, t)| {
            Some(InfluenceLink {
                from_contact: Uuid::parse_str(&f).ok()?,
                to_contact: Uuid::parse_str(&t).ok()?,
            })
        })
        .collect();

    let required = required_roles(state, opportunity).await?;
    let stored: Option<(Value, DateTime<Utc>)> = sqlx::query_as(
        "SELECT gaps, computed_at FROM sales_deal_coverage WHERE opportunity_id = $1",
    )
    .bind(opportunity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (mut gaps, gaps_computed_at) = match stored {
        Some((gaps, at)) => (
            serde_json::from_value::<Vec<Gap>>(gaps).unwrap_or_default(),
            Some(at),
        ),
        None => (compute_gaps(state, opportunity).await?, None),
    };
    if !ctx.has_field_read_grant("opportunity_contact_role", "influence") {
        gaps.retain(|g| g.kind != GapKind::UnmetHighInfluence);
    }
    Ok(DealMap {
        opportunity_id: opportunity,
        account_id,
        chart,
        contacts,
        influences,
        required_roles: required,
        gaps,
        gaps_computed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn missing_economic_buyer_is_a_gap() {
        let gaps = coverage_gaps(
            &s(&["economic_buyer", "champion", "economic_buyer"]),
            &s(&["champion", "user"]),
            &[],
        );
        assert_eq!(
            gaps,
            vec![Gap {
                kind: GapKind::MissingRole,
                role: Some("economic_buyer".into()),
                contact_id: None,
            }]
        );
        assert!(coverage_gaps(&s(&["champion"]), &s(&["champion"]), &[]).is_empty());
    }

    #[test]
    fn unmet_high_influence_contacts_follow_the_roles() {
        let a = Uuid::from_u128(2);
        let b = Uuid::from_u128(1);
        let gaps = coverage_gaps(&s(&["decision_maker"]), &[], &[a, b, a]);
        assert_eq!(gaps.len(), 3);
        assert_eq!(gaps[0].kind, GapKind::MissingRole);
        assert_eq!(gaps[1].contact_id, Some(b));
        assert_eq!(gaps[2].contact_id, Some(a));
    }

    #[test]
    fn required_roles_are_a_json_list() {
        assert_eq!(
            parse_required(Some(r#"["economic_buyer", " champion ", ""]"#)),
            s(&["economic_buyer", "champion"])
        );
        assert!(parse_required(Some("economic_buyer")).is_empty());
        assert!(parse_required(None).is_empty());
    }
}
