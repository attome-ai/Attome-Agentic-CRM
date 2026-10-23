//! L3-T5: governed change at publish.
//!
//! A data domain with `governed_change` on (migration 0229) has its
//! entities' definitions changed only with its owners' or stewards'
//! approval. Before a changeset apply is queued
//! (`apply_routes::apply_changesets`), [`check`] reads the planned ledger
//! rows' operations; when one changes an entity (or an attribute of one) in
//! a governed domain, the apply is not queued. [`submit`] instead files an
//! M9 approval request ([`ACTION_GOVERNED_CHANGE`]) that those owners and
//! stewards decide (the requester excluded), carrying the apply request and
//! what it changes: for every field it deletes, retypes or renames, the L5
//! impact (`attome_core::lineage::impact`); for the rest, the list of
//! changed entities and attributes. Approved, the apply goes on exactly as
//! the route would have taken it (`approval_admin`'s dispatch arm): through
//! the `metadata.changeset_apply` approval where that is required, else
//! queued. An apply touching no governed domain is unchanged.
//!
//! After every apply run that finished, [`lapse_certifications`] marks each
//! certified entity whose definition hash changed `stale`.
//!
//! Record writes are not touched: the gate runs only at publish.

use std::collections::{BTreeMap, BTreeSet};

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::lineage::impact::{self, ChangeKind, MetadataChange};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use super::apply_routes::ApplyChangesetsBody;
use super::ledger;

/// The approval action a governed change waits on.
pub const ACTION_GOVERNED_CHANGE: &str = "governance.governed_change";

/// One change a governed apply makes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    pub entity: String,
    pub field: Option<String>,
    pub op: String,
}

/// What a governed apply needs approved.
#[derive(Debug, Clone)]
pub struct Governed {
    /// The governed domains it touches, with their names.
    pub domains: Vec<(Uuid, String)>,
    /// The changes to their entities.
    pub changes: Vec<Change>,
    /// The domains' owners and stewards, the requester excluded.
    pub approvers: Vec<Uuid>,
}

/// The entity and field changes of a ledger row's document.
pub fn document_changes(document: &Value) -> Vec<Change> {
    let Ok(doc) = super::plan::parse_document(document) else {
        return Vec::new();
    };
    doc.operations
        .iter()
        .filter(|op| !op.t("entity").is_empty())
        .map(|op| Change {
            entity: op.t("entity").to_owned(),
            field: Some(op.t("field"))
                .filter(|f| !f.is_empty())
                .map(str::to_owned),
            op: op.op.as_str().to_owned(),
        })
        .collect()
}

/// The impact kind of a change, for the operations whose impact is known.
pub fn change_kind(op: &str) -> Option<ChangeKind> {
    Some(match op {
        "delete_field" => ChangeKind::DeleteAttribute,
        "change_field_type" => ChangeKind::ChangeAttributeType,
        "rename_field" => ChangeKind::RenameAttribute,
        _ => return None,
    })
}

/// The governed part of an apply, or `None` when it touches no governed
/// domain.
pub async fn check(
    state: &EngineState,
    body: &ApplyChangesetsBody,
    requester: Uuid,
) -> Result<Option<Governed>, AppError> {
    let mut changes = BTreeSet::new();
    for id in &body.apply_ids {
        if let Some(row) = ledger::get(&state.base.db, *id).await? {
            changes.extend(document_changes(&row.document));
        }
    }
    if changes.is_empty() {
        return Ok(None);
    }
    let entities: Vec<String> = changes
        .iter()
        .map(|c| c.entity.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let governed: Vec<(String, Uuid, String)> = sqlx::query_as(
        "SELECT e.logicalname, d.id, d.name FROM entity_info e \
           JOIN data_domain d ON d.id = e.domain_ref \
          WHERE e.logicalname = ANY($1) AND d.governed_change AND NOT d.is_deleted",
    )
    .bind(&entities)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if governed.is_empty() {
        return Ok(None);
    }
    let governed_entities: BTreeSet<&str> = governed.iter().map(|(e, _, _)| e.as_str()).collect();
    let domains: BTreeMap<Uuid, String> = governed
        .iter()
        .map(|(_, id, name)| (*id, name.clone()))
        .collect();
    let domain_ids: Vec<Uuid> = domains.keys().copied().collect();
    let approvers: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_id FROM governance_role \
          WHERE domain_ref = ANY($1) AND role IN ('owner', 'steward') AND user_id <> $2 \
          ORDER BY user_id LIMIT 50",
    )
    .bind(&domain_ids)
    .bind(requester)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if approvers.is_empty() {
        return Err(AppError::Validation(
            "this change touches a governed data domain, which has no owner or steward (other \
             than you) to approve it"
                .into(),
        ));
    }
    Ok(Some(Governed {
        domains: domains.into_iter().collect(),
        changes: changes
            .into_iter()
            .filter(|c| governed_entities.contains(c.entity.as_str()))
            .collect(),
        approvers,
    }))
}

/// What the approvers see: the impact of each field change whose impact is
/// known, and every change.
async fn impact_of(state: &EngineState, changes: &[Change]) -> Result<Value, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let mut impacts = Vec::new();
    for change in changes {
        let Some(kind) = change_kind(&change.op) else {
            continue;
        };
        let report = impact::impact(
            &mut conn,
            &[MetadataChange {
                entity: change.entity.clone(),
                attribute: change.field.clone(),
                kind,
            }],
            impact::DEFAULT_DEPTH,
            |_, _| true,
        )
        .await?;
        impacts.push(json!({
            "entity": change.entity,
            "field": change.field,
            "op": change.op,
            "affected": report.affected.len(),
            "breaking": report.breaking,
        }));
    }
    Ok(json!({
        "changes": changes
            .iter()
            .map(|c| json!({ "entity": c.entity, "field": c.field, "op": c.op }))
            .collect::<Vec<_>>(),
        "impact": impacts,
    }))
}

/// Files the governed change's approval request; the apply waits for it.
pub async fn submit(
    state: &EngineState,
    body: &ApplyChangesetsBody,
    requester: Uuid,
    governed: Governed,
) -> Result<attome_approval::ApprovalRequest, AppError> {
    let impact = impact_of(state, &governed.changes).await?;
    let plan = attome_compliance::governance_policy::exception_plan(&governed.approvers);
    let payload = json!({
        "apply": body,
        "domains": governed
            .domains
            .iter()
            .map(|(id, name)| json!({ "id": id, "name": name }))
            .collect::<Vec<_>>(),
        "review": impact,
    });
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let backstop = attome_audit::approval::plan_backstop_ttl(&plan);
    let request = attome_approval::submit_with_plan_regarding_in_tx(
        &mut tx,
        ACTION_GOVERNED_CHANGE,
        payload,
        requester,
        plan,
        backstop,
        None,
        None,
    )
    .await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Submitted,
            requester,
            "approval_request",
            Some(request.id),
        )
        .named("governance.governed_change")
        .comment(format!(
            "changeset apply of {} row(s) waits for its data domains' approval",
            body.apply_ids.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(request)
}

/// Marks `stale` every certified entity whose definition changed since it
/// was certified. Best effort: a failure is logged, never the apply's.
pub async fn lapse_certifications(state: &EngineState) {
    let certified: Result<Vec<(String, String)>, sqlx::Error> = sqlx::query_as(
        "SELECT asset_ref, definition_hash FROM governance_certification \
          WHERE asset_kind = 'entity' AND status = 'certified' LIMIT 5000",
    )
    .fetch_all(&state.base.db)
    .await;
    let certified = match certified {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "certification lapse check could not read certifications");
            return;
        }
    };
    for (entity, hash) in certified {
        let current =
            attome_compliance::governance_policy::entity_definition_hash(state, &entity).await;
        let changed = match &current {
            Ok(Some((now, _))) => *now != hash,
            Ok(None) => true,
            Err(_) => false,
        };
        if changed
            && let Err(error) = sqlx::query(
                "UPDATE governance_certification SET status = 'stale' \
                  WHERE asset_kind = 'entity' AND asset_ref = $1 AND status = 'certified' \
                    AND definition_hash = $2",
            )
            .bind(&entity)
            .bind(&hash)
            .execute(&state.base.db)
            .await
        {
            tracing::warn!(%error, %entity, "certification could not be marked stale");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governed_change_reads_the_field_changes() {
        assert_eq!(
            change_kind("delete_field"),
            Some(ChangeKind::DeleteAttribute)
        );
        assert_eq!(change_kind("add_field"), None);
        assert!(document_changes(&json!({ "not": "a changeset" })).is_empty());
    }
}
