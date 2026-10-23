//! D24-T4: a lead or account matched to an existing account by its work
//! email's domain, before any enrichment provider is called.
//!
//! [`work_domain`] reads the domain of a work email (none for free mail).
//! [`match_account`] finds the live account with that `email_domain` (one
//! lookup on the filterable column) that the caller may read. The change-feed
//! consumer [`LEAD_DOMAIN_CONSUMER`] ([`sweep_new_leads`]) gives each new lead
//! with an email and no account the matching account as
//! `suggested_account_ref`, through the entity mutation path as the lead's
//! owner; it never touches the lead's own company fields. The enrichment
//! run (`attome_integration::enrich::run`) skips the records
//! [`known_before_provider`] says are already known, so no provider call is
//! spent on them.

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The change-feed consumer that suggests accounts for new leads.
pub const LEAD_DOMAIN_CONSUMER: &str = "attome-sales/lead-domain";

/// Change events read per sweep.
const SWEEP_BATCH: i64 = 200;

/// Accounts with one domain checked against the caller's access.
const CANDIDATES: i64 = 5;

/// Free mail domains: an address there names no company.
pub const FREE_MAIL: [&str; 7] = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "live.com",
    "proton.me",
];

/// The company domain of a work email: lowercase, without a leading
/// `mail.` or `www.`; `None` for free mail or an address with no domain.
pub fn work_domain(email: &str) -> Option<String> {
    let (_, domain) = email.trim().rsplit_once('@')?;
    let mut domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    for prefix in ["mail.", "www."] {
        if let Some(rest) = domain.strip_prefix(prefix) {
            domain = rest.to_owned();
        }
    }
    let valid = domain.contains('.')
        && !domain.starts_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    (valid && !FREE_MAIL.contains(&domain.as_str())).then_some(domain)
}

/// The live account with `domain` as its email domain that `ctx` may read.
pub async fn match_account(
    state: &EngineState,
    ctx: &SecurityContext,
    domain: &str,
) -> Result<Option<Uuid>, AppError> {
    let candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM account WHERE email_domain = $1 \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY created_at, id LIMIT $2",
    )
    .bind(domain)
    .bind(CANDIDATES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let (entity_id, _, _, _) =
        attome_records::entity_crud::resolve_entity(state, "account").await?;
    for id in candidates {
        match attome_records::entity_crud::require_record_access(
            state,
            ctx,
            entity_id,
            "account",
            id,
            attome_security::RecordAction::Read,
        )
        .await
        {
            Ok(()) => return Ok(Some(id)),
            Err(AppError::Forbidden | AppError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Whether a lead or account is already known here, so an enrichment
/// provider need not be asked: it links an account, or its work email's
/// domain is a live account's. A failed lookup reads as unknown (the
/// provider is asked, as before this check).
pub async fn known_before_provider(state: &EngineState, record: &Value) -> bool {
    let linked = ["suggested_account_ref", "converted_account_ref"]
        .iter()
        .any(|f| record.get(*f).is_some_and(|v| !v.is_null()));
    if linked {
        return true;
    }
    let domain = record
        .get("email")
        .and_then(Value::as_str)
        .and_then(work_domain)
        .or_else(|| {
            record
                .get("email_domain")
                .and_then(Value::as_str)
                .map(|d| d.trim().to_ascii_lowercase())
                .filter(|d| !d.is_empty())
        });
    let Some(domain) = domain else {
        return false;
    };
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM account WHERE email_domain = $1 \
                           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(&domain)
    .fetch_one(&state.base.db)
    .await
    {
        Ok(known) => known,
        Err(error) => {
            tracing::warn!(%error, "enrichment: known-account check failed; the provider is asked");
            false
        }
    }
}

/// Suggests an account for one new lead; whether it did.
async fn suggest_for_lead(state: &EngineState, lead: Uuid) -> Result<bool, AppError> {
    let row: Option<(
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        Option<Uuid>,
        i64,
    )> = sqlx::query_as(
        "SELECT email, converted_account_ref, suggested_account_ref, owner_ref, row_version \
               FROM lead WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(lead)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(email), None, None, Some(owner), row_version)) = row else {
        return Ok(false);
    };
    let Some(domain) = work_domain(&email) else {
        return Ok(false);
    };
    // As the lead's owner: the account is one they may read.
    let ctx = state.base.security.resolve(owner).await?;
    let Some(account) = match_account(state, &ctx, &domain).await? else {
        return Ok(false);
    };
    let written = attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        owner,
        "lead",
        lead,
        row_version,
        serde_json::json!({ "suggested_account_ref": account.to_string() }),
    )
    .await;
    match written {
        Ok(_) => Ok(true),
        // Edited since it was read: the user's own change wins, and a lead
        // its owner may not edit keeps no suggestion.
        Err(AppError::VersionConflict | AppError::VersionConflictAt { .. }) => Ok(false),
        Err(AppError::Forbidden) => {
            tracing::info!(%lead, "lead domain: owner may not update the lead; no suggestion");
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Suggests accounts for the leads created since the last sweep; how many
/// got one. Idempotent: a lead that has one is skipped.
pub async fn sweep_new_leads(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, LEAD_DOMAIN_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    // Without the CRM pack's lead and account there is nothing to do; the
    // cursor still moves past the batch.
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('lead') IS NOT NULL AND to_regclass('account') IS NOT NULL \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = 'lead' \
                           AND column_name = 'suggested_account_ref')",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut suggested = 0;
    if installed {
        let mut leads: Vec<Uuid> = events
            .iter()
            .filter(|e| {
                e.entity_logicalname == "lead"
                    && e.operation() == Some(attome_core::change_feed::ChangeOperation::Create)
            })
            .map(|e| e.record_id)
            .collect();
        leads.dedup();
        for lead in leads {
            if suggest_for_lead(state, lead).await? {
                suggested += 1;
            }
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, LEAD_DOMAIN_CONSUMER, &last).await?;
    Ok(suggested)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_mail_has_no_domain() {
        for email in [
            "sara@gmail.com",
            "Omar@Outlook.com",
            "a@hotmail.com",
            "b@yahoo.com",
            "c@icloud.com",
            "d@live.com",
            "e@proton.me",
        ] {
            assert_eq!(work_domain(email), None, "{email}");
        }
        assert_eq!(work_domain("no-at-sign"), None);
        assert_eq!(work_domain("x@localhost"), None);
        assert_eq!(work_domain("x@bad domain.com"), None);
    }

    #[test]
    fn subdomain_is_stripped() {
        assert_eq!(work_domain("Sara@Mail.Acme.SA").as_deref(), Some("acme.sa"));
        assert_eq!(work_domain("o@www.acme.com").as_deref(), Some("acme.com"));
        assert_eq!(
            work_domain(" ali@sales.acme.com ").as_deref(),
            Some("sales.acme.com"),
            "only mail. and www. are stripped"
        );
    }
}
