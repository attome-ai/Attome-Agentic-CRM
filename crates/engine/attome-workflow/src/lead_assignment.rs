//! D4-T1: lead assignment rule sets. A new lead, however it was created (a
//! form, email, chat, an import or the API), gets its owner from:
//!
//! 1. the owner of an earlier live lead with the same email or phone
//!    (`existing_lead`);
//! 2. else the owner of the live account whose `email_domain` is the lead's
//!    work-email domain (`account_owner`, free mail never matches);
//! 3. else the first enabled `lead_assignment_rule` (crm pack 0006), in
//!    `sort_order`, whose `condition_expression` holds for the lead and whose
//!    strategy finds someone among the active members of its team or role
//!    who are under its `daily_cap` (`rule`).
//!
//! The strategies are the assign node's (M11-T1, [`crate::assign`]); round
//! robin keeps its cursor per rule. The chosen owner, the reason and the
//! rule are written through the record engine (`update_record_for`), as the
//! rule's owner for a rule match and as the lead's owner otherwise, so
//! validation, audit and record rules apply. A lead that already carries an
//! `assignment_reason` is left alone, so a rerun assigns nothing twice; with
//! no match the lead keeps the owner it was created with.
//!
//! [`sweep`] reads the change feed with its own cursor ([`CONSUMER`]) and
//! handles each created lead; the cursor moves after the batch. A lead the
//! engine refuses to update (the identity lacks the access) is logged and
//! passed over; any other failure leaves the cursor for the next sweep.

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::assign::{self, Strategy};

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-workflow/lead-assignment";
/// The job's name.
pub const JOB: &str = "lead_assignment";
/// The round-robin cursor's node id for a rule (the rule id is the version).
pub const CURSOR_NODE: &str = "lead_assignment";
/// Change events read per sweep.
const BATCH: i64 = 200;
/// Rules read per lead.
const MAX_RULES: i64 = 100;

/// Why a lead got its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    ExistingLead,
    AccountOwner,
    Rule,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExistingLead => "existing_lead",
            Self::AccountOwner => "account_owner",
            Self::Rule => "rule",
        }
    }
}

/// One rule entry as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleEntry {
    pub id: Uuid,
    pub condition: Option<String>,
    pub strategy: Option<Strategy>,
    pub team: Option<Uuid>,
    pub role: Option<Uuid>,
    pub skills: Vec<String>,
    pub daily_cap: Option<i64>,
    pub author: Option<Uuid>,
}

fn uuid_of(row: &Value, key: &str) -> Option<Uuid> {
    row.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn text_of(row: &Value, key: &str) -> Option<String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

impl RuleEntry {
    /// A stored rule row (`to_jsonb`). Pure.
    pub fn from_row(row: &Value) -> Option<Self> {
        Some(Self {
            id: uuid_of(row, "id")?,
            condition: text_of(row, "condition_expression"),
            strategy: text_of(row, "strategy")
                .as_deref()
                .and_then(Strategy::parse),
            team: uuid_of(row, "team_ref"),
            role: uuid_of(row, "role_ref"),
            skills: text_of(row, "required_skills")
                .map(|s| {
                    s.split(',')
                        .map(|k| k.trim().to_owned())
                        .filter(|k| !k.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            daily_cap: row
                .get("daily_cap")
                .and_then(Value::as_f64)
                .map(|c| c as i64)
                .filter(|c| *c > 0),
            author: uuid_of(row, "owner_ref").or_else(|| uuid_of(row, "created_by")),
        })
    }

    /// Whether the rule's condition holds for `lead`; no condition always
    /// holds.
    pub fn matches(&self, lead: &Value) -> bool {
        self.condition
            .as_deref()
            .is_none_or(|src| crate::condition::expression_holds(src, lead))
    }
}

/// The candidates still under `cap` given today's counts. Pure.
pub fn under_cap(candidates: &[Uuid], today: &HashMap<Uuid, i64>, cap: Option<i64>) -> Vec<Uuid> {
    match cap {
        None => candidates.to_vec(),
        Some(cap) => candidates
            .iter()
            .copied()
            .filter(|c| today.get(c).copied().unwrap_or(0) < cap)
            .collect(),
    }
}

/// A phone number reduced to its digits (a leading `+` kept), for
/// comparing. Pure.
pub fn phone_key(phone: &str) -> Option<String> {
    let trimmed = phone.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= 6).then(|| {
        if trimmed.starts_with('+') {
            format!("+{digits}")
        } else {
            digits
        }
    })
}

fn has_attr(state: &EngineState, entity: &str, attr: &str) -> bool {
    state
        .entities
        .load()
        .get(entity)
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == attr))
}

/// The owner of an earlier live lead with `lead`'s email or phone.
async fn existing_lead_owner(
    state: &EngineState,
    id: Uuid,
    lead: &Value,
) -> Result<Option<Uuid>, AppError> {
    let email = text_of(lead, "email").map(|e| e.to_lowercase());
    let phone = text_of(lead, "phone").as_deref().and_then(phone_key);
    if email.is_none() && phone.is_none() {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT owner_ref FROM lead \
          WHERE id <> $1 AND owner_ref IS NOT NULL \
            AND (is_active IS NULL OR is_active = true) \
            AND (($2::text IS NOT NULL AND lower(trim(email)) = $2) \
              OR ($3::text IS NOT NULL AND regexp_replace(phone, '[^0-9+]', '', 'g') = $3)) \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(id)
    .bind(email)
    .bind(phone)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The owner of the live account with `lead`'s work-email domain.
async fn account_owner(state: &EngineState, lead: &Value) -> Result<Option<Uuid>, AppError> {
    if !has_attr(state, "account", "email_domain") {
        return Ok(None);
    }
    let Some(domain) =
        text_of(lead, "email").and_then(|e| attome_sales::enrichment::domain::work_domain(&e))
    else {
        return Ok(None);
    };
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT owner_ref FROM account WHERE email_domain = $1 \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY created_at, id LIMIT 1",
    )
    .bind(domain)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(owner.flatten())
}

/// Leads each candidate got from `rule` today.
async fn today_counts(
    state: &EngineState,
    rule: Uuid,
    candidates: &[Uuid],
) -> Result<HashMap<Uuid, i64>, AppError> {
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT owner_ref, COUNT(*) FROM lead \
          WHERE assignment_rule_ref = $1 AND owner_ref = ANY($2) \
            AND created_at >= date_trunc('day', now()) \
          GROUP BY owner_ref",
    )
    .bind(rule)
    .bind(candidates)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// The person `rule` gives `lead` to, if any.
async fn pick(
    state: &EngineState,
    rule: &RuleEntry,
    lead: &Value,
) -> Result<Option<Uuid>, AppError> {
    let Some(strategy) = rule.strategy else {
        return Ok(None);
    };
    let pool = assign::candidates(state, rule.team, None, rule.role).await?;
    let pool = if rule.daily_cap.is_some() && !pool.is_empty() {
        let today = today_counts(state, rule.id, &pool).await?;
        under_cap(&pool, &today, rule.daily_cap)
    } else {
        pool
    };
    if pool.is_empty() && strategy != Strategy::Territory {
        return Ok(None);
    }
    Ok(match strategy {
        Strategy::RoundRobin => assign::round_robin(state, rule.id, CURSOR_NODE, &pool).await?,
        Strategy::LeastLoaded => {
            let loads = assign::loads(state, "lead", &pool).await?;
            assign::least_loaded(&pool, &loads)
        }
        Strategy::Skills => {
            let held = assign::skills(state, &pool).await?;
            assign::best_skilled(&pool, &held, &rule.skills)
        }
        Strategy::Territory => match uuid_of(lead, "territory_ref") {
            Some(territory) => assign::territory_owner(state, territory).await?,
            None => None,
        },
        Strategy::Rule => None,
    })
}

/// Assigns one lead; `true` when it got an owner here.
pub async fn assign_lead(state: &EngineState, id: Uuid) -> Result<bool, AppError> {
    if !has_attr(state, "lead", "assignment_reason") {
        return Ok(false);
    }
    let lead: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(l) FROM lead l WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(lead) = lead else {
        return Ok(false);
    };
    if text_of(&lead, "assignment_reason").is_some() {
        return Ok(false);
    }
    let current = uuid_of(&lead, "owner_ref").or_else(|| uuid_of(&lead, "created_by"));

    let mut chosen: Option<(Uuid, Reason, Option<Uuid>, Option<Uuid>)> = None;
    if let Some(owner) = existing_lead_owner(state, id, &lead).await? {
        chosen = Some((owner, Reason::ExistingLead, None, current));
    } else if let Some(owner) = account_owner(state, &lead).await? {
        chosen = Some((owner, Reason::AccountOwner, None, current));
    } else if state.entities.load().get("lead_assignment_rule").is_some() {
        let rows: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(r) FROM lead_assignment_rule r \
              WHERE (r.is_active IS NULL OR r.is_active = true) \
                AND COALESCE(r.is_enabled, true) \
              ORDER BY r.sort_order NULLS LAST, r.name, r.id LIMIT $1",
        )
        .bind(MAX_RULES)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for rule in rows.iter().filter_map(RuleEntry::from_row) {
            if !rule.matches(&lead) {
                continue;
            }
            if let Some(owner) = pick(state, &rule, &lead).await? {
                chosen = Some((owner, Reason::Rule, Some(rule.id), rule.author));
                break;
            }
        }
    }
    let Some((owner, reason, rule, acting)) = chosen else {
        return Ok(false);
    };
    let Some(acting) = acting else {
        tracing::warn!(lead = %id, "lead assignment: no identity to write as");
        return Ok(false);
    };
    let version = lead.get("row_version").and_then(Value::as_i64).unwrap_or(0);
    let ctx = state.base.security.resolve_strict(acting).await?;
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        acting,
        "lead",
        id,
        version,
        json!({
            "owner_ref": owner.to_string(),
            "assignment_reason": reason.as_str(),
            "assignment_rule_ref": rule.map(|r| r.to_string()),
        }),
    )
    .await?;
    tracing::info!(lead = %id, %owner, reason = reason.as_str(), "lead assigned");
    Ok(true)
}

/// Assigns every lead created since the last sweep; returns how many got an
/// owner.
pub async fn sweep(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut assigned = 0;
    let mut seen = HashSet::new();
    for e in &events {
        if e.entity_logicalname != "lead"
            || !matches!(e.operation(), Some(ChangeOperation::Create))
            || !seen.insert(e.record_id)
        {
            continue;
        }
        match assign_lead(state, e.record_id).await {
            Ok(true) => assigned += 1,
            Ok(false) => {}
            Err(error @ (AppError::Forbidden | AppError::NotFound | AppError::Validation(_))) => {
                tracing::warn!(lead = %e.record_id, %error, "lead assignment: not assigned");
            }
            Err(error) => return Err(error),
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(assigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lead_assignment_rule_rows_parse() {
        let id = Uuid::now_v7();
        let team = Uuid::now_v7();
        let rule = RuleEntry::from_row(&json!({
            "id": id.to_string(),
            "condition_expression": "  country_code == \"SA\" ",
            "strategy": "round_robin",
            "team_ref": team.to_string(),
            "required_skills": "arabic, enterprise,",
            "daily_cap": 5,
        }))
        .expect("a rule");
        assert_eq!(rule.id, id);
        assert_eq!(rule.strategy, Some(Strategy::RoundRobin));
        assert_eq!(rule.team, Some(team));
        assert_eq!(rule.skills, ["arabic", "enterprise"]);
        assert_eq!(rule.daily_cap, Some(5));
        assert_eq!(rule.condition.as_deref(), Some("country_code == \"SA\""));
        let open = RuleEntry::from_row(&json!({ "id": id.to_string(), "daily_cap": 0 })).unwrap();
        assert_eq!(open.daily_cap, None);
        assert!(open.matches(&json!({ "country_code": "AE" })));
    }

    #[test]
    fn lead_assignment_caps_leave_out_full_people() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let today = HashMap::from([(a, 3)]);
        assert_eq!(under_cap(&[a, b], &today, Some(3)), [b]);
        assert_eq!(under_cap(&[a, b], &today, Some(4)), [a, b]);
        assert_eq!(under_cap(&[a, b], &today, None), [a, b]);
    }

    #[test]
    fn lead_assignment_phone_keys_compare_digits() {
        assert_eq!(
            phone_key("+966 50 000 0001").as_deref(),
            Some("+966500000001")
        );
        assert_eq!(phone_key("050-000-0001").as_deref(), Some("0500000001"));
        assert_eq!(phone_key("123"), None);
        assert_eq!(Reason::AccountOwner.as_str(), "account_owner");
    }
}
