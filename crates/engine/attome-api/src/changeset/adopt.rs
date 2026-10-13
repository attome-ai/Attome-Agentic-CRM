//! Adopt (Solution 7 design §5.6): the development deployment keeps its own
//! applied ledger.
//!
//! A changeset closed on the development database already has its effects
//! there — they were made through the admin API while it was recorded. Once
//! its file is written to git (`write-closed.mjs` renumbers `seq`, so the
//! whole-document checksum no longer equals the server's), adopt marks it
//! applied: for each document, a local closed changeset with the same `id`
//! and the same `ops_hash` (sha256 over the JCS `operations` array, which the
//! renumbering does not touch) gets one ledger row per phase with
//! `status = 'adopted'` and the **file's** checksum. Development's ledger then
//! equals git, and a later plan of the same file reports it
//! `already_applied`.
//!
//! Only on a `required`-mode server (the development authoring mode): an
//! `auto`-mode deployment has no authored changesets to adopt. Refusals:
//! no such local changeset or not closed (404 / 409), a different
//! `ops_hash` (409 `changeset_ops_differ`), and the checksum refusal against
//! an existing ledger row (409 `changeset_checksum_mismatch`).

use attome_config::ChangesetMode;
use attome_core::changeset::{ChangesetStatus, store};
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use super::ledger::{self, ApplyPhase, ApplySource, ApplyStatus, NewApplyRow};
use super::plan::{self, Document};
use crate::bundle::PLATFORM_VERSION;

/// `adopt_requires_development`.
pub const ADOPT_REQUIRES_DEVELOPMENT: &str = "adopt_requires_development: adopt records \
     changesets this deployment authored; it is available only where metadata.changesets.mode \
     is \"required\"";

/// `changeset_ops_differ`.
pub const CHANGESET_OPS_DIFFER: &str = "changeset_ops_differ: the file's operations differ from \
     the changeset this deployment closed under the same id; it cannot be adopted";

/// `changeset_not_closed`.
pub const CHANGESET_NOT_CLOSED: &str =
    "changeset_not_closed: only a changeset this deployment closed can be adopted";

/// One adopted changeset.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdoptedChangeset {
    pub changeset_id: Uuid,
    #[serde(rename = "ref")]
    pub changeset_ref: String,
    pub checksum: String,
    /// The phases written as `adopted` by this call.
    pub adopted: Vec<ApplyPhase>,
    /// The phases the ledger already had (same checksum).
    pub already_recorded: Vec<ApplyPhase>,
}

/// Whether adopt is available on this deployment.
pub fn adopt_allowed(config: &attome_config::AppConfig) -> bool {
    config
        .metadata
        .changesets
        .effective_mode(&config.app.deployment_profile)
        == ChangesetMode::Required
}

/// Checks every document, then adopts them, all in the caller's
/// transaction (the route's audited one).
pub async fn adopt(
    tx: &mut attome_db::Tx<'_>,
    values: &[Value],
    actor: Uuid,
) -> Result<Vec<AdoptedChangeset>, AppError> {
    if values.is_empty() {
        return Err(AppError::Validation(
            "changesets: at least one document is required".into(),
        ));
    }
    if values.len() > plan::MAX_PLAN_DOCUMENTS {
        return Err(AppError::Validation(format!(
            "changesets: at most {} documents per adopt",
            plan::MAX_PLAN_DOCUMENTS
        )));
    }
    let mut docs: Vec<Document> = Vec::with_capacity(values.len());
    let mut problems = Vec::new();
    for (i, value) in values.iter().enumerate() {
        match plan::parse_document(value) {
            Ok(doc) => docs.push(doc),
            Err(errs) => {
                problems.extend(errs.into_iter().map(|e| format!("changesets[{i}]: {e}")));
            }
        }
    }
    if !problems.is_empty() {
        return Err(AppError::Validation(problems.join("; ")));
    }

    let mut out = Vec::with_capacity(docs.len());
    for doc in &docs {
        let local = store::get(&mut **tx, doc.id)
            .await?
            .ok_or(AppError::NotFound)?;
        if local.status != ChangesetStatus::Closed {
            return Err(AppError::Conflict(CHANGESET_NOT_CLOSED));
        }
        let file_hash = doc.ops_hash().map_err(AppError::Validation)?;
        if local.ops_hash.as_deref() != Some(file_hash.as_str()) {
            return Err(AppError::Conflict(CHANGESET_OPS_DIFFER));
        }
        let mut already = Vec::new();
        for (phase, checksum, _status) in ledger::checksums_of(tx, doc.id).await? {
            if checksum != doc.checksum {
                return Err(AppError::Conflict(ledger::CHANGESET_CHECKSUM_MISMATCH));
            }
            already.push(phase);
        }
        let reference = doc.reference();
        let plan_json = json!({ "applicable": true, "adopted": true, "operations": [] });
        let mut adopted = Vec::new();
        for phase in doc.phases() {
            if already.contains(&phase) {
                continue;
            }
            let inserted = ledger::insert_adopted(
                tx,
                &NewApplyRow {
                    changeset_id: doc.id,
                    changeset_ref: &reference,
                    layer: doc.layer.as_str(),
                    scope: &doc.scope,
                    seq: doc.seq,
                    phase,
                    checksum: &doc.checksum,
                    document: &doc.value,
                    plan: &plan_json,
                    status: ApplyStatus::Adopted,
                    source: ApplySource::Adopt,
                    platform_version: PLATFORM_VERSION,
                    requested_by: Some(actor),
                },
            )
            .await?;
            if inserted {
                adopted.push(phase);
            } else {
                already.push(phase);
            }
        }
        out.push(AdoptedChangeset {
            changeset_id: doc.id,
            changeset_ref: reference,
            checksum: doc.checksum.clone(),
            adopted,
            already_recorded: already,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::changeset::errors::code_of;

    #[test]
    fn the_refusals_carry_stable_codes() {
        assert_eq!(
            code_of(ADOPT_REQUIRES_DEVELOPMENT),
            "adopt_requires_development"
        );
        assert_eq!(code_of(CHANGESET_OPS_DIFFER), "changeset_ops_differ");
        assert_eq!(code_of(CHANGESET_NOT_CLOSED), "changeset_not_closed");
    }

    /// The renumbering `write-closed.mjs` does changes the checksum but not
    /// the operations hash adopt compares.
    #[test]
    fn renumbering_keeps_the_ops_hash() {
        let entry = crate::changeset::platform_index::PLATFORM_CHANGESETS
            .first()
            .expect("one compiled changeset");
        let mut value: Value = serde_json::from_str(entry.json).expect("json");
        let original = plan::parse_document(&value).expect("checks");
        value["seq"] = json!(original.seq + 7);
        value.as_object_mut().map(|m| m.remove("checksum"));
        let checksum = crate::changeset::jcs::document_checksum(&value).expect("checksum");
        value["checksum"] = json!(checksum);
        let renumbered = plan::parse_document(&value).expect("checks");
        assert_ne!(renumbered.checksum, original.checksum);
        assert_eq!(renumbered.ops_hash(), original.ops_hash());
    }
}
