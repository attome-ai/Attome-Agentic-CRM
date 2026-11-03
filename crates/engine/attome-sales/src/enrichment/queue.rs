//! L9's queue (D24-T9's prerequisite): enrichment of a set of records by one
//! provider, run in the background.
//!
//! [`enqueue`] checks the provider, the entity and the caller's read access,
//! answers a cost estimate against the provider's daily budget, and queues
//! [`ENRICH_RECORDS`] in one transaction; the job ([`run_job`]) builds the
//! provider (one of D24-T5's free sources), reads the records as they are
//! then, skips those D24-T4 already matched by domain, and hands them to the
//! L9 runner, which proposes values and spends the budget. Nothing writes a
//! record: every result is a proposal a person accepts.
//!
//! The daily call budget per provider is the deployment setting
//! [`DAILY_LIMITS_SETTING`] (`{"registry": 100, ...}`); a provider it does
//! not name gets [`DEFAULT_DAILY_LIMIT`]. The registry reads the API key of
//! the integration connection named `wathq`, the National Address that of
//! `national_address`; the website needs none.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_integration::connector::adapters::national_address::{
    self, Language, NationalAddressClient,
};
use attome_integration::connector::adapters::wathq::{self, WathqClient};
use attome_integration::connector::sdk::{GuardedTransport, Secret};
use attome_integration::enrich::{EnrichmentSource, RunSummary};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::free_sources::{FETCH_TIMEOUT, NationalAddressSource, RegistrySource, WebsiteSource};

/// The job that enriches a set of records.
pub const ENRICH_RECORDS: attome_jobs::JobType = attome_jobs::JobType {
    lane: attome_jobs::registry::Lane::Batch,
    max_attempts: 1,
    max_concurrency: Some(2),
    ..attome_jobs::JobType::new("enrich_records", 1)
};

/// The most records one job enriches.
pub const MAX_RECORDS: usize = 500;

/// The providers a job may name.
pub const PROVIDERS: [&str; 3] = ["registry", "national_address", "website"];

/// The setting holding each provider's daily call budget.
pub const DAILY_LIMITS_SETTING: &str = "enrichment.daily_limits";

/// A provider's daily budget when the setting does not name it.
pub const DEFAULT_DAILY_LIMIT: u32 = 100;

/// The integration connection whose credential the registry and the
/// National Address use.
pub const REGISTRY_CONNECTION: &str = "wathq";
pub const NATIONAL_ADDRESS_CONNECTION: &str = "national_address";

/// [`ENRICH_RECORDS`]'s payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichPayload {
    pub entity: String,
    pub ids: Vec<Uuid>,
    pub provider: String,
    /// D24-T8: who queued the run; the Arabic name suggestions that follow
    /// an account run are made, and charged, as an agent of this person.
    #[serde(default)]
    pub requested_by: Option<Uuid>,
}

/// What a run would cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct Estimate {
    /// Provider calls the run would make at most (one per record).
    pub calls: usize,
    /// Calls left in the provider's budget today.
    pub budget_left: u32,
    /// Records the budget would not reach today.
    pub over_budget: usize,
}

/// The estimate for `calls` calls with `left` left in the budget. Pure.
pub fn estimate_of(calls: usize, left: u32) -> Estimate {
    let left_usize = usize::try_from(left).unwrap_or(usize::MAX);
    Estimate {
        calls,
        budget_left: left,
        over_budget: calls.saturating_sub(left_usize),
    }
}

/// `provider`'s daily budget from the setting.
pub fn daily_limit(state: &EngineState, provider: &str) -> u32 {
    let Some(descriptor) = attome_core::setting_registry().get(DAILY_LIMITS_SETTING) else {
        return DEFAULT_DAILY_LIMIT;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value
        .get(provider)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(DEFAULT_DAILY_LIMIT)
}

/// The calls `provider` has left today.
pub async fn budget_left(state: &EngineState, provider: &str) -> Result<u32, AppError> {
    let used: i32 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT calls FROM enrichment_usage \
                           WHERE provider = $1 AND day = CURRENT_DATE), 0)",
    )
    .bind(provider)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(daily_limit(state, provider).saturating_sub(u32::try_from(used).unwrap_or(0)))
}

/// What is wrong with a request before anything is queued, if anything.
/// Pure.
pub fn request_problem(provider: &str, ids: &[Uuid]) -> Option<String> {
    if !PROVIDERS.contains(&provider) {
        return Some(format!("provider: one of {}", PROVIDERS.join(", ")));
    }
    if ids.is_empty() || ids.len() > MAX_RECORDS {
        return Some(format!("between 1 and {MAX_RECORDS} records"));
    }
    None
}

/// The estimate for enriching `ids` of `entity` with `provider`, as `ctx`,
/// without queueing anything.
pub async fn estimate(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    ids: &[Uuid],
    provider: &str,
) -> Result<Estimate, AppError> {
    if let Some(problem) = request_problem(provider, ids) {
        return Err(AppError::Validation(problem));
    }
    ctx.require(entity, "read")?;
    if state.entities.load().get(entity).is_none() {
        return Err(AppError::NotFound);
    }
    Ok(estimate_of(ids.len(), budget_left(state, provider).await?))
}

/// Queues the enrichment of `ids` of `entity` with `provider`, as `ctx`
/// (who must read the entity); answers the estimate.
pub async fn enqueue(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    ids: Vec<Uuid>,
    provider: &str,
) -> Result<Estimate, AppError> {
    let estimate = estimate(state, ctx, entity, &ids, provider).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
            name: ENRICH_RECORDS.name.to_owned(),
            version: ENRICH_RECORDS.version,
            payload: json!(EnrichPayload {
                entity: entity.to_owned(),
                ids,
                provider: provider.to_owned(),
                requested_by: Some(ctx.user_id),
            }),
            next: None,
        }),
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(estimate)
}

/// The API key of the integration connection `name`, and its base URL.
async fn connection_key(state: &EngineState, name: &str) -> Result<(String, Secret), AppError> {
    let connection =
        attome_integration::connection::Connection::resolve(&state.base.db, name).await?;
    let credential = connection
        .credential(&state.base.db, &attome_integration::credential::ring(state))
        .await?
        .ok_or_else(|| AppError::Validation(format!("the connection {name} has no key")))?;
    let base = connection.base_url.clone();
    Ok((base, Secret::new(credential.with_value(str::to_owned))))
}

/// The records `ids` of `entity` as they are now (live ones only).
async fn read_records(
    state: &EngineState,
    entity: &str,
    ids: &[Uuid],
) -> Result<Vec<(Uuid, Value)>, AppError> {
    if state.entities.load().get(entity).is_none() {
        return Err(AppError::NotFound);
    }
    let sql = format!(
        "SELECT id, to_jsonb(t) FROM {} t \
          WHERE id = ANY($1) AND (is_active IS NULL OR is_active = true)",
        attome_core::quote_ident(entity)
    );
    let sql = attome_db::tag_dynamic("sales.enrich_read", &sql);
    sqlx::query_as::<_, (Uuid, Value)>(&sql)
        .bind(ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// One job's records, ready for a provider.
struct Batch<'a> {
    state: &'a EngineState,
    entity: &'a str,
    records: &'a [(Uuid, Value)],
    known: &'a HashSet<Uuid>,
    limit: u32,
}

impl Batch<'_> {
    async fn run(&self, source: &dyn EnrichmentSource) -> Result<RunSummary, AppError> {
        attome_integration::enrich::run(
            &self.state.base.db,
            source,
            self.entity,
            self.records,
            self.known,
            self.limit,
        )
        .await
    }
}

/// Runs one queued enrichment.
pub async fn run_job(state: &EngineState, payload: &EnrichPayload) -> Result<RunSummary, AppError> {
    if let Some(problem) = request_problem(&payload.provider, &payload.ids) {
        return Err(AppError::Validation(problem));
    }
    let records = read_records(state, &payload.entity, &payload.ids).await?;
    let mut known = HashSet::new();
    for (id, record) in &records {
        if super::domain::known_before_provider(state, record).await {
            known.insert(*id);
        }
    }
    let limit = daily_limit(state, &payload.provider);
    let client = attome_server::ssrf_guard::GuardedClient::new(FETCH_TIMEOUT.as_secs())
        .map_err(AppError::internal)?;
    let transport = GuardedTransport(client);
    let job = Batch {
        state,
        entity: &payload.entity,
        records: &records,
        known: &known,
        limit,
    };
    match payload.provider.as_str() {
        "registry" => {
            let (base, key) = connection_key(state, REGISTRY_CONNECTION).await?;
            let base = if base.is_empty() {
                wathq::DEFAULT_BASE_URL.to_owned()
            } else {
                base
            };
            let source = RegistrySource {
                client: WathqClient::new(&base, key, &transport),
                db: Some(&state.base.db),
            };
            job.run(&source).await
        }
        "national_address" => {
            let (base, key) = connection_key(state, NATIONAL_ADDRESS_CONNECTION).await?;
            let base = if base.is_empty() {
                national_address::DEFAULT_BASE_URL.to_owned()
            } else {
                base
            };
            let source = NationalAddressSource {
                client: NationalAddressClient::new(&base, key, &transport),
                language: Language::Arabic,
            };
            job.run(&source).await
        }
        _ => {
            let source = WebsiteSource::new()?;
            job.run(&source).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_names_a_known_provider_and_a_bounded_set() {
        let one = vec![Uuid::now_v7()];
        assert_eq!(request_problem("website", &one), None);
        assert!(request_problem("linkedin", &one).is_some());
        assert!(request_problem("registry", &[]).is_some());
        let many: Vec<Uuid> = (0..=MAX_RECORDS).map(|_| Uuid::now_v7()).collect();
        assert!(request_problem("registry", &many).is_some());
    }

    #[test]
    fn the_estimate_counts_what_the_budget_misses() {
        assert_eq!(
            estimate_of(120, 100),
            Estimate {
                calls: 120,
                budget_left: 100,
                over_budget: 20
            }
        );
        assert_eq!(estimate_of(5, 100).over_budget, 0);
    }

    /// D24-T8: a job queued before `requested_by` existed still reads, with
    /// no one to suggest Arabic names as.
    #[test]
    fn an_older_payload_has_no_requester() {
        let payload: EnrichPayload = serde_json::from_value(serde_json::json!({
            "entity": "account", "ids": [], "provider": "website"
        }))
        .unwrap();
        assert_eq!(payload.requested_by, None);
    }
}
