//! W1-T13: contracts from the business. A change-feed consumer (the D-358
//! cursor model) watches three kinds of record and drafts one contract per
//! source:
//!
//! - a `quote` whose status is `accepted` (D9) and an `order` whose status is
//!   `confirmed` (D10) give a `sales` contract draft with the account, value
//!   and currency, owned by the source's owner;
//! - a `service_work_request` filed under a contract type's intake offering
//!   (G2) gives a draft of that type, owned by the requester, and the request
//!   is resolved into it.
//!
//! The contract's `source_kind` and `source_id` are the link and the
//! idempotency key: a source already linked is skipped, under a
//! transaction-scoped advisory lock on the same key, so a replayed batch or a
//! second node drafts nothing twice. Each run also registers an intake
//! offering for every active contract type that has none
//! (`contract_type.intake_form_ref`).
//!
//! Only entities the deployment has are read: without the sales pack no
//! quote or order event can arrive, and an event for a missing record is
//! skipped.

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// This consumer's name in `change_consumer_cursor`; never reused.
pub const CONSUMER: &str = "attome-contract/business-links";

/// Events per batch, and batches per run (the run is every quarter hour).
pub const BATCH: i64 = 500;
pub const MAX_BATCHES: usize = 20;

/// Where a drafted contract came from (`contract.source_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Quote,
    Order,
    Intake,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quote => "quote",
            Self::Order => "order",
            Self::Intake => "intake",
        }
    }

    /// The source a change on `entity` may be, if any. Pure.
    pub fn for_entity(entity: &str) -> Option<Self> {
        match entity {
            "quote" => Some(Self::Quote),
            "order" => Some(Self::Order),
            "service_work_request" => Some(Self::Intake),
            _ => None,
        }
    }
}

/// What one run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinkRun {
    pub events: u64,
    pub drafts: u64,
    pub offerings: u64,
}

/// The draft a source gives.
#[derive(Debug)]
struct Draft {
    title: String,
    contract_type: Option<Uuid>,
    account: Option<Uuid>,
    value: Option<f64>,
    currency: Option<String>,
    owner: Option<Uuid>,
    organization: Option<Uuid>,
}

/// The contract currencies (the pack's `contract.currency` choices); another
/// currency is left empty for a person to set. Pure.
pub fn contract_currency(code: Option<&str>) -> Option<String> {
    const CHOICES: [&str; 5] = ["USD", "EUR", "GBP", "SAR", "AED"];
    let code = code?.trim().to_ascii_uppercase();
    CHOICES.contains(&code.as_str()).then_some(code)
}

/// One run: registers missing intake offerings, then drafts contracts for
/// the sources the feed names, batch by batch.
pub async fn run(state: &EngineState) -> Result<LinkRun, AppError> {
    let mut out = LinkRun::default();
    let (has_contract, has_type, has_offering) = {
        let registry = state.entities.load();
        (
            registry
                .get("contract")
                .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "source_kind")),
            registry.get("contract_type").is_some(),
            registry.get("service_offering").is_some(),
        )
    };
    if !has_contract {
        return Ok(out);
    }
    let db = &state.base.db;
    if has_type && has_offering {
        out.offerings = register_offerings(db).await?;
    }
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        out.events += events.len() as u64;
        let mut seen = std::collections::BTreeSet::new();
        for event in &events {
            let Some(source) = Source::for_entity(&event.entity_logicalname) else {
                continue;
            };
            if !seen.insert((source.as_str(), event.record_id)) {
                continue;
            }
            if state
                .entities
                .load()
                .get(&event.entity_logicalname)
                .is_none()
            {
                continue;
            }
            if link(state, source, event.record_id).await? {
                out.drafts += 1;
            }
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(out)
}

/// Drafts the contract for one source when it qualifies and has none yet.
/// Returns whether a draft was written.
async fn link(state: &EngineState, source: Source, id: Uuid) -> Result<bool, AppError> {
    let db = &state.base.db;
    let Some(draft) = draft_for(db, source, id).await? else {
        return Ok(false);
    };
    let mut tx = attome_db::tx::begin(db).await?;
    let key = format!("attome-contract/link:{}:{id}", source.as_str());
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&key)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        // Another worker holds this source; it drafts it.
        return Ok(false);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM contract WHERE source_kind = $1 AND source_id = $2)",
    )
    .bind(source.as_str())
    .bind(id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    let contract: Uuid = sqlx::query_scalar(
        "INSERT INTO contract \
           (title, status, contract_type_ref, counterparty_account_ref, contract_value, currency, \
            owner_ref, created_by, organization_ref, is_confidential, source_kind, source_id) \
         VALUES ($1, 'draft', $2, $3, $4, $5, $6, $6, $7, false, $8, $9) RETURNING id",
    )
    .bind(&draft.title)
    .bind(draft.contract_type)
    .bind(draft.account)
    .bind(draft.value)
    .bind(&draft.currency)
    .bind(draft.owner)
    .bind(draft.organization)
    .bind(source.as_str())
    .bind(id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(&mut tx, "contract", contract, ChangeOperation::Create)
        .await?;
    if source == Source::Intake {
        sqlx::query(
            "UPDATE service_work_request \
                SET status = 'converted', resolved_entity_name = 'contract', \
                    resolved_record_id = $2, row_version = row_version + 1 \
              WHERE id = $1 AND status <> 'converted'",
        )
        .bind(id)
        .bind(contract.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_core::change_feed::emit_tx(
            &mut tx,
            "service_work_request",
            id,
            ChangeOperation::Update,
        )
        .await?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "contract",
            contract,
            attome_audit::AuditOperation::Create,
            "contract.drafted_from_source",
            draft.owner.unwrap_or(Uuid::nil()),
        )
        .source(attome_audit::AuditSource::BackgroundJob)
        .comment(format!("drafted from {} {id}", source.as_str())),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(%contract, source = source.as_str(), %id, "W1-T13: contract drafted from its source");
    Ok(true)
}

/// The draft a source gives, or `None` when it does not (yet) qualify.
async fn draft_for(db: &DbPool, source: Source, id: Uuid) -> Result<Option<Draft>, AppError> {
    match source {
        Source::Quote | Source::Order => {
            let (sql, label) = if source == Source::Quote {
                (
                    "SELECT name, quote_number, account_ref, grand_total::float8, currency, owner_ref, \
                            organization_ref \
                       FROM quote WHERE id = $1 AND status = 'accepted' AND is_active IS NOT FALSE",
                    "Quote",
                )
            } else {
                (
                    "SELECT name, order_number, account_ref, grand_total::float8, currency, owner_ref, \
                            organization_ref \
                       FROM \"order\" WHERE id = $1 AND status = 'confirmed' AND is_active IS NOT FALSE",
                    "Order",
                )
            };
            type Row = (
                Option<String>,
                Option<String>,
                Option<Uuid>,
                Option<f64>,
                Option<String>,
                Option<Uuid>,
                Option<Uuid>,
            );
            let row: Option<Row> = sqlx::query_as(sql)
                .bind(id)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?;
            let Some((name, number, account, value, currency, owner, organization)) = row else {
                return Ok(None);
            };
            let sales_type: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM contract_type \
                  WHERE lower(name) = 'sales' AND is_active IS NOT FALSE ORDER BY id LIMIT 1",
            )
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            let reference = number.or(name).unwrap_or_else(|| id.to_string());
            Ok(Some(Draft {
                title: format!("{label} {reference}"),
                contract_type: sales_type,
                account,
                value,
                currency: contract_currency(currency.as_deref()),
                owner,
                organization,
            }))
        }
        Source::Intake => {
            let row: Option<(String, Uuid, Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
                "SELECT r.title, t.id, r.requester_id, r.organization_ref \
                   FROM service_work_request r \
                   JOIN contract_type t ON t.intake_form_ref = r.offering_id::text \
                  WHERE r.id = $1 AND r.status = 'new' AND t.is_active IS NOT FALSE \
                  ORDER BY t.id LIMIT 1",
            )
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            Ok(
                row.map(|(title, contract_type, requester, organization)| Draft {
                    title,
                    contract_type: Some(contract_type),
                    account: None,
                    value: None,
                    currency: None,
                    owner: requester,
                    organization,
                }),
            )
        }
    }
}

/// Gives every active contract type without one an intake offering
/// ("Contract request: <type>") and records it on the type. Returns how
/// many it registered.
async fn register_offerings(db: &DbPool) -> Result<u64, AppError> {
    let types: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM contract_type \
          WHERE intake_form_ref IS NULL AND is_active IS NOT FALSE ORDER BY id LIMIT 100",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut registered = 0;
    for (type_id, name) in types {
        let mut tx = attome_db::tx::begin(db).await?;
        let offering: Uuid = sqlx::query_scalar(
            "INSERT INTO service_offering \
               (name, category, description, default_priority, fulfilment, is_public, is_active) \
             VALUES ($1, 'other', $2, 'medium', 'contract', false, true) RETURNING id",
        )
        .bind(format!("Contract request: {name}"))
        .bind(format!(
            "Request a {name} contract; legal drafts it from this request."
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let set = sqlx::query(
            "UPDATE contract_type SET intake_form_ref = $2, row_version = row_version + 1 \
              WHERE id = $1 AND intake_form_ref IS NULL",
        )
        .bind(type_id)
        .bind(offering.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if set.rows_affected() != 1 {
            // A concurrent run registered it first; drop this one.
            continue;
        }
        attome_core::change_feed::emit_tx(
            &mut tx,
            "service_offering",
            offering,
            ChangeOperation::Create,
        )
        .await?;
        attome_core::change_feed::emit_tx(
            &mut tx,
            "contract_type",
            type_id,
            ChangeOperation::Update,
        )
        .await?;
        tx.commit().await.map_err(AppError::internal)?;
        registered += 1;
    }
    Ok(registered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_by_entity() {
        assert_eq!(Source::for_entity("quote"), Some(Source::Quote));
        assert_eq!(Source::for_entity("order"), Some(Source::Order));
        assert_eq!(
            Source::for_entity("service_work_request"),
            Some(Source::Intake)
        );
        assert_eq!(Source::for_entity("contract"), None);
    }

    #[test]
    fn only_contract_currencies_carry_over() {
        assert_eq!(contract_currency(Some("sar")), Some("SAR".to_owned()));
        assert_eq!(contract_currency(Some(" AED ")), Some("AED".to_owned()));
        assert_eq!(contract_currency(Some("EGP")), None);
        assert_eq!(contract_currency(None), None);
    }
}
