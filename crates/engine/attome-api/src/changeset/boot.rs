//! The boot path for platform changesets (Solution 7 design §5.7) and the
//! owner-layer stamp's imperative-seed keys (§2.2).
//!
//! **Source.** The platform's own definitions come from the compiled
//! `changesets/platform/*.json` ([`super::platform_index`]) through the
//! applied-changeset ledger. The older watermark-gated bundle path was removed
//! once the Phase 1.5 equivalence test passed (a fresh boot from changesets
//! equalled one from bundles and a second boot moved nothing, 2026-10-02);
//! `platform-bundles/*.json` stay the authoring source the changesets are
//! generated from (`scripts/changesets/from-bundle.mjs --all --check`).
//!
//! **Per compiled changeset** ([`apply_compiled`]): one indexed ledger read
//! per phase; the same checksum and `succeeded`/`adopted` skips it; a
//! different checksum is a boot error (a platform changeset is immutable
//! once shipped: the fix is a new one); otherwise it is planned (trusted: no
//! owner-layer or module check, D-478/D-383), queued and applied inline, no
//! approval, `source = 'boot'`. Expand operations always; contract
//! operations only for a changeset whose `requires.platform` floor is below
//! the running version (an earlier release introduced it, so that release is
//! verified).

use std::collections::BTreeSet;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;

use super::apply::{self, RunOutcome};
use super::layers::PlatformKeys;
use super::ledger::{self, ApplyPhase, ApplySource, ApplyStatus, NewApplyRow};
use super::plan::{self, Document};
use super::platform_index::{PLATFORM_CHANGESETS, PlatformChangeset};
use crate::bundle::PLATFORM_VERSION;

/// Boot call sites whose watermark key is not the bundle file's name.
const MODULE_ALIASES: &[(&str, &str)] = &[("api_key", "xrm-core-api_key")];

/// The platform bundle / changeset name a boot call site's `module` key
/// names.
pub fn definition_name(module: &str) -> &str {
    MODULE_ALIASES
        .iter()
        .find(|(alias, _)| *alias == module)
        .map_or(module, |(_, name)| name)
}

/// The compiled platform changeset converted from the platform bundle
/// `name`.
pub fn compiled(name: &str) -> Option<&'static PlatformChangeset> {
    PLATFORM_CHANGESETS.iter().find(|c| c.name == name)
}

/// Applies one platform definition at boot: the compiled changeset
/// converted from the platform bundle `module` names, through the ledger.
pub async fn apply_platform_definition(state: &EngineState, module: &str) -> Result<(), AppError> {
    let name = definition_name(module);
    let entry = compiled(name).ok_or_else(|| {
        AppError::internal(format!(
            "no compiled platform changeset was converted from the platform bundle {name:?};              run node scripts/changesets/from-bundle.mjs --all and              node scripts/changesets/gen-platform-index.mjs"
        ))
    })?;
    apply_compiled(state, entry).await
}

/// Applies every compiled platform changeset in folder order (the replay
/// tool's first step; boot applies them one call site at a time).
pub async fn apply_platform_changesets(state: &EngineState) -> Result<(), AppError> {
    for entry in PLATFORM_CHANGESETS {
        apply_compiled(state, entry).await?;
    }
    Ok(())
}

/// Parses a compiled changeset; a malformed one is a build defect.
pub fn parse_compiled(entry: &PlatformChangeset) -> Result<Document, AppError> {
    let value: Value = serde_json::from_str(entry.json).map_err(|e| {
        AppError::internal(format!(
            "platform changeset {} is not JSON: {e}",
            entry.file
        ))
    })?;
    plan::parse_document(&value).map_err(|errs| {
        AppError::internal(format!(
            "platform changeset {} does not check: {}",
            entry.file,
            errs.join("; ")
        ))
    })
}

/// Whether a platform changeset's contract operations run at this boot:
/// only when its floor is below the running version.
fn contract_due(doc: &Document) -> bool {
    match (
        plan::parse_version(&doc.requires.platform),
        plan::parse_version(PLATFORM_VERSION),
    ) {
        (Some(floor), Some(running)) => floor < running,
        _ => false,
    }
}

/// Plans, queues and applies one compiled platform changeset through the
/// ledger (module doc). Idempotent: a changeset already applied costs one
/// indexed read per phase.
pub async fn apply_compiled(
    state: &EngineState,
    entry: &PlatformChangeset,
) -> Result<(), AppError> {
    let doc = parse_compiled(entry)?;
    for phase in doc.phases() {
        if phase == ApplyPhase::Contract && !contract_due(&doc) {
            continue;
        }
        apply_phase(state, &doc, phase).await?;
    }
    Ok(())
}

async fn apply_phase(
    state: &EngineState,
    doc: &Document,
    phase: ApplyPhase,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let existing = ledger::find(&mut conn, doc.id, phase).await?;
    drop(conn);
    let apply_id = match existing {
        Some(row) if row.checksum != doc.checksum => {
            return Err(AppError::internal(format!(
                "platform changeset {} ({}) changed after it was applied here: the ledger holds \
                 {} and the binary carries {}. A shipped platform changeset is immutable; put \
                 the change in a new one.",
                doc.reference(),
                phase.as_str(),
                row.checksum,
                doc.checksum
            )));
        }
        Some(row) if row.status.is_done() => return Ok(()),
        Some(row) => {
            // Under the platform seed lock no other process applies platform
            // definitions, so a claim still held is a crashed boot's: take it
            // over now rather than waiting out the claim timeout.
            let mut tx = attome_db::tx::begin(db).await?;
            sqlx::query(
                "UPDATE changeset_apply \
                    SET status = 'queued', row_version = row_version + 1, updated_at = NOW() \
                  WHERE id = $1 AND status IN ('claimed', 'applying')",
            )
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            ledger::mark_queued(&mut tx, &[row.id], None, None).await?;
            attome_db::tx::commit(tx).await?;
            row.id
        }
        None => {
            let plan_json = plan::boot_plan_json(doc, phase);
            let reference = doc.reference();
            let mut tx = attome_db::tx::begin(db).await?;
            let id = ledger::upsert_planned(
                &mut tx,
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
                    status: ApplyStatus::Planned,
                    source: ApplySource::Boot,
                    platform_version: PLATFORM_VERSION,
                    requested_by: None,
                },
            )
            .await?;
            ledger::mark_queued(&mut tx, &[id], None, None).await?;
            attome_db::tx::commit(tx).await?;
            id
        }
    };
    match apply::run_one(state, apply_id).await? {
        RunOutcome::Applied(summary) => {
            tracing::info!(
                changeset = %doc.reference(),
                phase = phase.as_str(),
                written = summary.written,
                "platform changeset applied at boot"
            );
            Ok(())
        }
        RunOutcome::NotClaimed => Err(AppError::internal(format!(
            "platform changeset {} ({}) could not be claimed at boot",
            doc.reference(),
            phase.as_str()
        ))),
    }
}

// ── Owner-layer stamp: the imperative seeds' keys ───────────────────────────

/// `attome_project::utilization::seed`'s one stored query.
const UTILIZATION_QUERY: (&str, &str) = (
    "resource_allocation",
    "Resource Utilization % (Actual / Nominal Capacity, Last 28 Days)",
);

/// The logical keys the imperative boot seeds own, for
/// `layers::stamp_platform_owned` (design §2.2 step 2):
///
/// - `sidebar_seed.rs`: every live sidebar item the seed maintains — an item
///   no admin has customized (`is_customized = false`; the admin route sets
///   it and the seed never does, D-375's ownership boolean);
/// - `trd_engine::seed`: the `trd_*` entities and fields it provisions and the
///   list views/queries it seeds for them, not customized;
/// - `attome_project::seed_utilization`: its one report query;
/// - `attome_dashboard::seed`: none (it re-syncs the options of a field the
///   `attome-dashboard` platform definition already declares).
///
/// Read from live metadata after the seeds ran, so the set is exactly what
/// they left; the stamp only moves `project` rows to `platform` and never
/// back, and a row an admin customized is left to its layer.
pub async fn imperative_seed_keys(db: &DbPool) -> Result<PlatformKeys, AppError> {
    let mut keys = PlatformKeys::default();

    let sidebar: Vec<Vec<String>> = sqlx::query_scalar(
        "WITH RECURSIVE tree AS ( \
             SELECT id, ARRAY[name]::text[] AS path, is_customized FROM sidebar \
              WHERE parent_ref IS NULL AND is_deleted = false \
             UNION ALL \
             SELECT s.id, t.path || s.name::text, s.is_customized FROM sidebar s \
               JOIN tree t ON s.parent_ref = t.id \
              WHERE s.is_deleted = false AND cardinality(t.path) < 64 \
         ) \
         SELECT path FROM tree WHERE COALESCE(is_customized, false) = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    keys.sidebar.extend(sidebar);

    let trd_entities: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
          WHERE logicalname LIKE 'trd\\_%' AND COALESCE(is_customized, false) = false \
            AND COALESCE(is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    keys.entities.extend(trd_entities);

    let trd_fields: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.logicalname, a.logicalname FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
          WHERE e.logicalname LIKE 'trd\\_%' AND COALESCE(a.is_customized, false) = false \
            AND COALESCE(a.is_active, true) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    keys.attributes.extend(trd_fields);

    let trd_views: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.logicalname, v.name FROM view v \
           JOIN entity_info e ON e.id = v.entity_logical_name \
          WHERE e.logicalname LIKE 'trd\\_%' AND v.scope = 'system' AND v.is_active = true \
            AND COALESCE(v.is_customized, false) = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    keys.views.extend(trd_views);

    let trd_queries: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.logicalname, q.record_no FROM sql_query q \
           JOIN entity_info e ON e.id = q.entity_logical_name \
          WHERE e.logicalname LIKE 'trd\\_%' AND q.record_no IS NOT NULL \
            AND COALESCE(q.is_active, true) = true AND COALESCE(q.is_customized, false) = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    keys.queries.extend(trd_queries);

    keys.queries.insert((
        UTILIZATION_QUERY.0.to_owned(),
        UTILIZATION_QUERY.1.to_owned(),
    ));
    Ok(keys)
}

/// The names of the platform bundles boot applies through
/// [`apply_platform_definition`] that have a compiled changeset — every
/// one, which [`tests::every_boot_definition_has_a_compiled_changeset`]
/// proves against the bundle list.
pub fn compiled_names() -> BTreeSet<&'static str> {
    PLATFORM_CHANGESETS.iter().map(|c| c.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_boot_definition_has_a_compiled_changeset() {
        let names = compiled_names();
        for (bundle, json) in crate::changeset::layers::PLATFORM_BUNDLES {
            let parsed: Value = serde_json::from_str(json).expect("bundle parses");
            let empty = [
                "entities",
                "queries",
                "views",
                "roles",
                "privileges",
                "record_sets",
                "state_models",
                "relationships",
                "attribute_patches",
                "sidebar",
                "calendars",
                "apps",
                "rules",
                "field_security_profiles",
            ]
            .iter()
            .all(|k| parsed[*k].as_array().is_none_or(Vec::is_empty));
            assert_eq!(
                names.contains(bundle),
                !empty,
                "{bundle}: a platform bundle with content needs a compiled changeset"
            );
        }
        assert_eq!(definition_name("api_key"), "xrm-core-api_key");
        assert_eq!(definition_name("attome-audit"), "attome-audit");
        assert!(compiled(definition_name("api_key")).is_some());
    }

    #[test]
    fn every_compiled_changeset_parses_and_is_platform_expand_only() {
        for entry in PLATFORM_CHANGESETS {
            let doc = parse_compiled(entry).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(doc.scope, "platform", "{}", entry.file);
            assert_eq!(doc.phases(), [ApplyPhase::Expand], "{}", entry.file);
            assert!(
                doc.operations
                    .iter()
                    .all(|op| plan::unsupported(op.op).is_none()),
                "{}: carries an operation this release cannot apply",
                entry.file
            );
        }
    }
}
