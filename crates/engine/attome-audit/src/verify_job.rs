//! Q16-T2: the audit chain is verified on a schedule, not only when an
//! operator runs `verify_audit_chain`. Once a week the `AuditChainVerify`
//! job runs the same checks ([`crate::verify::verify_chain_with_anchors`])
//! for every organization, records each result in
//! `audit_chain_verification` (migration 0117), and on any failure logs
//! `audit.chain_verify_failed` at `error` and counts
//! `audit_chain_verify_failures_total`, which the alert rules watch.
//!
//! Each run verifies the whole chain. Verifying only what was sealed since
//! the last verified batch needs a resumable verifier; until one exists, a
//! weekly full pass is the bound on how long tampering can go unseen.

use attome_db::DbPool;
use attome_storage::StorageClient;
use attome_types::AppError;
use uuid::Uuid;

use attome_core::AuditSigner;

/// What one run found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyRunSummary {
    pub organizations: usize,
    pub failed: usize,
}

/// Every organization with a chain: the `organization` rows, else the ones
/// audit headers name.
async fn organizations(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
    let orgs: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM organization")
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    if !orgs.is_empty() {
        return Ok(orgs);
    }
    sqlx::query_scalar(
        "SELECT DISTINCT organization_ref FROM audit_header WHERE organization_ref IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Verifies every organization's chain and records the results.
pub async fn run(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    store: Option<&StorageClient>,
) -> Result<VerifyRunSummary, AppError> {
    let mut summary = VerifyRunSummary::default();
    for org in organizations(db).await? {
        summary.organizations += 1;
        let report = crate::verify::verify_chain_with_anchors(db, signer, store, org).await?;
        let ok = report.is_ok();
        sqlx::query(
            "INSERT INTO audit_chain_verification \
                 (id, organization_ref, ok, headers_checked, batches_checked, errors) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(org)
        .bind(ok)
        .bind(i64::try_from(report.headers_checked).unwrap_or(i64::MAX))
        .bind(i64::try_from(report.batches_checked).unwrap_or(i64::MAX))
        .bind(serde_json::json!(report.errors))
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        if !ok {
            summary.failed += 1;
            metrics::counter!("audit_chain_verify_failures_total").increment(1);
            tracing::error!(
                event = "audit.chain_verify_failed",
                organization_ref = %org,
                errors = report.errors.len(),
                first = report.errors.first().map(String::as_str).unwrap_or(""),
                "audit chain verification failed; run verify_audit_chain for the full report"
            );
        }
    }
    Ok(summary)
}
