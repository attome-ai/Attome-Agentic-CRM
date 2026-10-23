//! L9-T1: the enrichment runner.
//!
//! A configured source (an [`EnrichmentSource`]: a firmographics provider, a
//! company registry, an internal service) is asked about a record and
//! answers values for some of its fields. The runner never writes a record:
//! it turns each answer into a proposal (`enrichment_proposal`, migration
//! 0230) with the source and the time it was fetched, the provenance a
//! reviewer and the record's history need.
//!
//! - A field that is empty gets a `fill` proposal: safe to accept in bulk.
//! - A field that already holds a different value gets a `review`
//!   proposal: a person decides; enrichment never overwrites a filled field
//!   on its own.
//! - A value equal to the current one proposes nothing.
//!
//! Each provider has a daily call budget ([`Budget`], `enrichment_usage`):
//! once spent, the run stops calling that provider and reports the records
//! it skipped. A record already holding a pending proposal for a field from
//! the same source is not asked again for it (the proposal is updated).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// One value a source found for a field.
#[derive(Debug, Clone, PartialEq)]
pub struct SourcedValue {
    pub field: String,
    pub value: Value,
}

/// A source of field values.
pub trait EnrichmentSource: Send + Sync {
    /// The provider's name (`enrichment_usage.provider`, the proposals'
    /// `source`).
    fn name(&self) -> &str;

    /// The values the source knows for `record` of `entity`.
    fn lookup<'a>(
        &'a self,
        entity: &'a str,
        record: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SourcedValue>, AppError>> + Send + 'a>>;
}

/// What a proposal asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// The field is empty.
    Fill,
    /// The field holds another value; a person decides.
    Review,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalKind::Fill => "fill",
            ProposalKind::Review => "review",
        }
    }
}

/// One proposed field update, with its provenance.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Proposal {
    pub field: String,
    pub current: Value,
    pub proposed: Value,
    pub kind: ProposalKind,
    pub source: String,
    pub fetched_at: DateTime<Utc>,
}

fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// The proposals `found` makes for `record`: empty fields are filled,
/// filled ones that differ go to review, equal values propose nothing, and
/// fields the record does not have (not attributes of the entity, as the
/// caller read it) are ignored.
pub fn propose(
    record: &Value,
    found: &[SourcedValue],
    source: &str,
    fetched_at: DateTime<Utc>,
) -> Vec<Proposal> {
    let Some(fields) = record.as_object() else {
        return Vec::new();
    };
    found
        .iter()
        .filter(|v| !is_empty(&v.value))
        .filter_map(|v| {
            let current = fields.get(&v.field)?;
            let kind = if is_empty(current) {
                ProposalKind::Fill
            } else if *current == v.value {
                return None;
            } else {
                ProposalKind::Review
            };
            Some(Proposal {
                field: v.field.clone(),
                current: current.clone(),
                proposed: v.value.clone(),
                kind,
                source: source.to_owned(),
                fetched_at,
            })
        })
        .collect()
}

/// Calls left per provider for the day.
#[derive(Debug, Clone, Default)]
pub struct Budget {
    left: HashMap<String, u32>,
}

impl Budget {
    /// `limits` per provider minus what each already `used` today; a
    /// provider without a limit gets no calls.
    pub fn new(limits: &HashMap<String, u32>, used: &HashMap<String, u32>) -> Self {
        Budget {
            left: limits
                .iter()
                .map(|(p, limit)| {
                    (
                        p.clone(),
                        limit.saturating_sub(used.get(p).copied().unwrap_or(0)),
                    )
                })
                .collect(),
        }
    }

    /// Spends one call of `provider`; `false` when none is left.
    pub fn try_spend(&mut self, provider: &str) -> bool {
        match self.left.get_mut(provider) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        }
    }

    pub fn left(&self, provider: &str) -> u32 {
        self.left.get(provider).copied().unwrap_or(0)
    }
}

/// What one run did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RunSummary {
    pub asked: usize,
    pub proposals: usize,
    /// Records not asked because the provider's budget was spent.
    pub over_budget: Vec<Uuid>,
}

/// Asks `source` about each of `records` (id, current values) of `entity`
/// while its budget lasts, and stores the proposals. Writes no record.
pub async fn run(
    db: &attome_db::DbPool,
    source: &dyn EnrichmentSource,
    entity: &str,
    records: &[(Uuid, Value)],
    daily_limit: u32,
) -> Result<RunSummary, AppError> {
    let provider = source.name().to_owned();
    let used: i32 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT calls FROM enrichment_usage \
                           WHERE provider = $1 AND day = CURRENT_DATE), 0)",
    )
    .bind(&provider)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let mut budget = Budget::new(
        &HashMap::from([(provider.clone(), daily_limit)]),
        &HashMap::from([(provider.clone(), u32::try_from(used).unwrap_or(0))]),
    );
    let mut summary = RunSummary::default();
    for (id, record) in records {
        if !budget.try_spend(&provider) {
            summary.over_budget.push(*id);
            continue;
        }
        sqlx::query(
            "INSERT INTO enrichment_usage (provider, day, calls) VALUES ($1, CURRENT_DATE, 1) \
             ON CONFLICT (provider, day) DO UPDATE SET calls = enrichment_usage.calls + 1",
        )
        .bind(&provider)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        summary.asked += 1;
        let found = match source.lookup(entity, record).await {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(%error, provider = %provider, record = %id, "enrichment lookup failed");
                continue;
            }
        };
        for p in propose(record, &found, &provider, Utc::now()) {
            sqlx::query(
                "INSERT INTO enrichment_proposal \
                     (entity_logicalname, record_id, field, current_value, proposed_value, kind, \
                      source, fetched_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (entity_logicalname, record_id, field, source) WHERE status = 'pending' \
                 DO UPDATE SET current_value = EXCLUDED.current_value, \
                               proposed_value = EXCLUDED.proposed_value, kind = EXCLUDED.kind, \
                               fetched_at = EXCLUDED.fetched_at",
            )
            .bind(entity)
            .bind(id)
            .bind(&p.field)
            .bind(&p.current)
            .bind(&p.proposed)
            .bind(p.kind.as_str())
            .bind(&p.source)
            .bind(p.fetched_at)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            summary.proposals += 1;
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(field: &str, value: Value) -> SourcedValue {
        SourcedValue {
            field: field.into(),
            value,
        }
    }

    #[test]
    fn enrich_fills_empty_and_reviews_filled() {
        let record = json!({ "industry": null, "employees": 40, "website": "a.sa", "city": "" });
        let at = Utc::now();
        let found = [
            v("industry", json!("Retail")),
            v("employees", json!(55)),
            v("website", json!("a.sa")),
            v("city", json!("Riyadh")),
            v("not_a_field", json!("x")),
            v("industry_code", json!(null)),
        ];
        let proposals = propose(&record, &found, "registry", at);
        let kinds: Vec<(&str, ProposalKind)> = proposals
            .iter()
            .map(|p| (p.field.as_str(), p.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("industry", ProposalKind::Fill),
                ("employees", ProposalKind::Review),
                ("city", ProposalKind::Fill),
            ],
            "a filled field is never overwritten without review; equal values propose nothing"
        );
        assert!(
            proposals
                .iter()
                .all(|p| p.source == "registry" && p.fetched_at == at)
        );
        assert_eq!(proposals[1].current, json!(40));
    }

    #[test]
    fn enrich_budget_per_provider() {
        let mut budget = Budget::new(
            &HashMap::from([("registry".to_owned(), 3), ("crawler".to_owned(), 1)]),
            &HashMap::from([("registry".to_owned(), 2)]),
        );
        assert!(budget.try_spend("registry"));
        assert!(!budget.try_spend("registry"), "2 of 3 were used today");
        assert!(budget.try_spend("crawler"));
        assert!(!budget.try_spend("crawler"));
        assert!(!budget.try_spend("unknown"), "no limit, no calls");
        assert_eq!(budget.left("registry"), 0);
    }
}
